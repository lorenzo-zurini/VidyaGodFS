// vgfs_tests — unmounted unit tests for the VidyaGodFS core.
// Strategy (see the overhaul plan): build REAL fixture trees / zips in a temp dir, construct a Spec
// directly, VfsState::Init, then drive Resolve / CollectChildren / the VfsOps surface. No mounting, no
// HostIO mocking — the POSIX shim is exercised for real. Fixtures are torn down per test.

#include "overlay.h"
#include "vfsops.h"
#include "layerspec.h"
#include "ziplayer.h"
#include "zipscan.h"
#include "vgdelta.h"
#include "bytesource.h"

#include <zip.h>

#include <algorithm>
#include <atomic>
#include <cstdio>
#include <cstring>
#include <unistd.h>
#include <fcntl.h>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <set>
#include <map>
#include <sstream>
#include <string>
#include <vector>

namespace fs = std::filesystem;

// ---- tiny harness ---------------------------------------------------------
static int g_fail = 0, g_checks = 0;
#define CHECK(cond) do { ++g_checks; if (!(cond)) { \
    std::cerr << "  FAIL " << __FILE__ << ":" << __LINE__ << "  " #cond "\n"; ++g_fail; } } while (0)
#define CHECK_EQ(a, b) do { ++g_checks; auto _a=(a); auto _b=(b); if (!(_a==_b)) { \
    std::cerr << "  FAIL " << __FILE__ << ":" << __LINE__ << "  " #a " == " #b "  (" << _a << " != " << _b << ")\n"; ++g_fail; } } while (0)
static std::vector<std::pair<std::string, std::function<void()>>> g_tests;
struct Reg { Reg(const char *n, std::function<void()> f) { g_tests.push_back({ n, std::move(f) }); } };
#define TEST(name) static void name(); static Reg reg_##name(#name, name); static void name()

// ---- fixture helpers ------------------------------------------------------
struct TmpDir {
    fs::path root;
    TmpDir() {
        root = fs::temp_directory_path() / ("vgfs_test_" + std::to_string(::getpid()) + "_" +
                                            std::to_string(reinterpret_cast<uintptr_t>(this)));
        fs::create_directories(root);
    }
    ~TmpDir() { std::error_code ec; fs::remove_all(root, ec); }
    fs::path operator/(const std::string &p) const { return root / p; }
    std::string str(const std::string &p = "") const { return (p.empty() ? root : root / p).string(); }
};

static void writeFile(const fs::path &p, const std::string &content) {
    fs::create_directories(p.parent_path());
    std::ofstream(p, std::ios::binary) << content;
}

// Author a STORE zip from (name → content) pairs; dir names end in '/'. Symlink entries: pass target as
// content and set the S_IFLNK external attribute.
static void writeStoreZip(const fs::path &zipPath, const std::vector<std::tuple<std::string, std::string, bool>> &entries) {
    fs::create_directories(zipPath.parent_path());
    int err = 0;
    zip_t *z = zip_open(zipPath.string().c_str(), ZIP_CREATE | ZIP_TRUNCATE, &err);
    if (!z) { std::cerr << "zip_open create failed\n"; ++g_fail; return; }
    for (auto &[name, content, isLink] : entries) {
        if (!name.empty() && name.back() == '/') { zip_dir_add(z, name.c_str(), ZIP_FL_ENC_UTF_8); continue; }
        zip_source_t *s = zip_source_buffer(z, content.data(), content.size(), 0);
        zip_int64_t idx = zip_file_add(z, name.c_str(), s, ZIP_FL_ENC_UTF_8);
        zip_set_file_compression(z, idx, ZIP_CM_STORE, 0);
        if (isLink) zip_file_set_external_attributes(z, idx, 0, ZIP_OPSYS_UNIX, (0120777u << 16));
    }
    zip_close(z);
}

static LayerSpec zipLayer(const std::string &src, const std::string &target = "") {
    LayerSpec L; L.type = LayerType::Zip; L.source = src; L.target = NormalizeVPath(target); return L;
}
static LayerSpec dirLayer(const std::string &src, const std::string &target = "", bool rw = false) {
    LayerSpec L; L.type = LayerType::Dir; L.source = src; L.target = NormalizeVPath(target); L.rw = rw; return L;
}

static std::set<std::string> readdirNames(VfsState &S, const std::string &vrel) {
    std::set<std::string> out;
    VfsReaddir(S, vrel, [&](const std::string &n) { out.insert(n); });
    return out;
}

// The core invariant Phase-1 bug #3 depends on: every name readdir lists must getattr-resolve.
static void checkReaddirSubsetGetattr(VfsState &S, const std::string &dir) {
    for (const std::string &n : readdirNames(S, dir)) {
        VfsAttr a; std::string child = dir.empty() ? n : dir + "/" + n;
        int e = VfsGetattr(S, child, a);
        if (e != 0) { std::cerr << "  FAIL readdir⊄getattr: '" << child << "' listed but getattr=" << e << "\n"; ++g_fail; }
        ++g_checks;
    }
}

// ==========================================================================
// Baseline behavior (Phase 0) — these should already pass on current code.
// ==========================================================================

TEST(zip_store_read_roundtrip) {
    TmpDir t;
    writeStoreZip(t / "a.zip", { { "hello.txt", "world!", false }, { "sub/", "", false }, { "sub/x.bin", "12345", false } });
    Spec sp; sp.layers = { zipLayer(t.str("a.zip")) };
    VfsState S; std::string err; CHECK(S.Init(sp, err));

    VfsAttr a;
    CHECK_EQ(VfsGetattr(S, "hello.txt", a), 0);
    CHECK(!a.isDir); CHECK_EQ(a.size, (uint64_t)6);
    CHECK_EQ(VfsGetattr(S, "sub", a), 0); CHECK(a.isDir);

    OpenFile *of = nullptr;
    CHECK_EQ(VfsOpen(S, "hello.txt", 0 /*O_RDONLY*/, of), 0);
    char buf[16] = {0}; ssize_t r = VfsRead(of, buf, sizeof(buf), 0);
    CHECK_EQ(r, (ssize_t)6); CHECK_EQ(std::string(buf, 6), std::string("world!"));
    VfsRelease(of);

    auto names = readdirNames(S, "");
    CHECK(names.count("hello.txt")); CHECK(names.count("sub"));
    checkReaddirSubsetGetattr(S, "");
    checkReaddirSubsetGetattr(S, "sub");
}

TEST(two_zip_layers_upper_masks) {
    TmpDir t;
    writeStoreZip(t / "base.zip",  { { "shared.txt", "BASE", false }, { "only_base.txt", "b", false } });
    writeStoreZip(t / "upper.zip", { { "shared.txt", "UPPER", false }, { "only_up.txt", "u", false } });
    Spec sp; sp.layers = { zipLayer(t.str("base.zip")), zipLayer(t.str("upper.zip")) }; // upper = higher priority
    VfsState S; std::string err; CHECK(S.Init(sp, err));

    OpenFile *of = nullptr; VfsOpen(S, "shared.txt", 0, of);
    char buf[8] = {0}; ssize_t r = VfsRead(of, buf, sizeof(buf), 0); VfsRelease(of);
    CHECK_EQ(std::string(buf, r), std::string("UPPER"));      // upper wins
    VfsAttr a;
    CHECK_EQ(VfsGetattr(S, "only_base.txt", a), 0);           // base still visible where not masked
    CHECK_EQ(VfsGetattr(S, "only_up.txt", a), 0);
    checkReaddirSubsetGetattr(S, "");
}

TEST(dir_layer_serves_files) {
    TmpDir t;
    writeFile(t / "src/foo.txt", "FOO");
    writeFile(t / "src/d/bar.txt", "BAR");
    Spec sp; sp.layers = { dirLayer(t.str("src")) };
    VfsState S; std::string err; CHECK(S.Init(sp, err));
    VfsAttr a; CHECK_EQ(VfsGetattr(S, "foo.txt", a), 0); CHECK_EQ(a.size, (uint64_t)3);
    CHECK_EQ(VfsGetattr(S, "d", a), 0); CHECK(a.isDir);
    checkReaddirSubsetGetattr(S, "");
    checkReaddirSubsetGetattr(S, "d");
}

TEST(writelayer_copyup_and_write) {
    TmpDir t;
    writeStoreZip(t / "base.zip", { { "doc.txt", "original", false } });
    Spec sp; sp.readOnly = false; sp.writelayer = t.str("wl"); sp.layers = { zipLayer(t.str("base.zip")) };
    VfsState S; std::string err; CHECK(S.Init(sp, err));

    OpenFile *of = nullptr;
    CHECK_EQ(VfsOpen(S, "doc.txt", 2 /*O_RDWR*/, of), 0);
    const char *nw = "changed!";
    CHECK(VfsWrite(S, of, nw, 8, 0) == 8);
    VfsRelease(of);
    // re-read reflects the write (from the writelayer copy-up)
    CHECK_EQ(VfsOpen(S, "doc.txt", 0, of), 0);
    char buf[16] = {0}; ssize_t r = VfsRead(of, buf, sizeof(buf), 0); VfsRelease(of);
    CHECK_EQ(std::string(buf, r), std::string("changed!"));
    CHECK(fs::exists(t / "wl/doc.txt"));  // copy-up landed in the writelayer
}

// A copy-up exists to be WRITTEN. A lower file that is read-only where it lives (a runner build mounted
// read-only serves every file 0555) must still copy up into a WRITABLE file — the open(O_WRONLY|O_TRUNC) that
// triggers the copy-up is what fails otherwise, and an in-place edit of a runner-provided wine hive was lost.
TEST(writelayer_copyup_of_readonly_lower_is_writable) {
    TmpDir t;
    fs::create_directories(t / "lower");
    writeFile(t / "lower/system.reg", "WINE REGISTRY\n");
    fs::permissions(t / "lower/system.reg", fs::perms::owner_read | fs::perms::owner_exec |
                    fs::perms::group_read | fs::perms::others_read, fs::perm_options::replace);   // 0544 (read-only)
    Spec sp; sp.readOnly = false; sp.writelayer = t.str("wl"); sp.layers = { dirLayer(t.str("lower")) };
    VfsState S; std::string err; CHECK(S.Init(sp, err));

    OpenFile *of = nullptr;
    CHECK_EQ(VfsOpen(S, "system.reg", 01001 /*O_WRONLY|O_TRUNC*/, of), 0);   // the hive rewrite's open
    const char *nw = "edited";
    CHECK(VfsWrite(S, of, nw, 6, 0) == 6);
    VfsRelease(of);
    CHECK(fs::exists(t / "wl/system.reg"));
    CHECK((fs::status(t / "wl/system.reg").permissions() & fs::perms::owner_write) != fs::perms::none);
    CHECK_EQ(VfsOpen(S, "system.reg", 0, of), 0);
    char buf[16] = {0}; ssize_t r = VfsRead(of, buf, sizeof(buf), 0); VfsRelease(of);
    CHECK_EQ(std::string(buf, r), std::string("edited"));
    // The original lower file is untouched (COW).
    CHECK((fs::status(t / "lower/system.reg").permissions() & fs::perms::owner_write) == fs::perms::none);
}

// A zipped program edited in place (a BinaryPatch rewrites it) must still run: the copy keeps the 0555 a zip entry
// is served with, plus the owner write bit — not a 0644 that drops the executable bit.
TEST(writelayer_copyup_of_a_zip_entry_keeps_it_executable) {
    TmpDir t;
    writeStoreZip(t / "build.zip", { { "bin/game", "\x7f" "ELF", false } });
    Spec sp; sp.readOnly = false; sp.writelayer = t.str("wl"); sp.layers = { zipLayer(t.str("build.zip")) };
    VfsState S; std::string err; CHECK(S.Init(sp, err));
    OpenFile *of = nullptr;
    CHECK_EQ(VfsOpen(S, "bin/game", 2 /*O_RDWR*/, of), 0);
    CHECK(VfsWrite(S, of, "!", 1, 1) == 1);
    VfsRelease(of);
    const auto p = fs::status(t / "wl/bin/game").permissions();
    CHECK((p & fs::perms::owner_exec) != fs::perms::none);
    CHECK((p & fs::perms::others_exec) != fs::perms::none);
    CHECK((p & fs::perms::owner_write) != fs::perms::none);
    VfsAttr a; CHECK_EQ(VfsGetattr(S, "bin/game", a), 0);
    CHECK((a.perms & 0111) == 0111);
}

// The listing says what each entry is: a zip's folders (implicit: no directory entries) list as folders, its files as
// files. An untyped listing (DT_UNKNOWN) made Xenia, which walks a game folder by d_type, see no folders at all.
TEST(a_typed_listing_says_which_entries_are_folders) {
    TmpDir t;
    writeStoreZip(t / "game.zip", { { "Languages/English/a.arl", "A", false }, { "default.xex", "X", false } });
    Spec sp; sp.layers = { zipLayer(t.str("game.zip")) };
    VfsState S; std::string err; CHECK(S.Init(sp, err));
    std::map<std::string, bool> dir;
    CHECK_EQ(VfsReaddirTyped(S, "", [&](const std::string &n, const VfsAttr &a) { dir[n] = a.isDir; }), 0);
    CHECK_EQ(dir.size(), (size_t)2);
    CHECK(dir["Languages"]);
    CHECK(!dir["default.xex"]);
    dir.clear();
    CHECK_EQ(VfsReaddirTyped(S, "Languages", [&](const std::string &n, const VfsAttr &a) { dir[n] = a.isDir; }), 0);
    CHECK(dir.count("English") && dir["English"]);
}

// Hard links: in the writelayer (a zipped file copied up first) and inside a kept passthrough folder, both names are
// one file — a write through one is read through the other.
TEST(hard_links_in_the_writelayer_and_a_kept_folder) {
    TmpDir t;
    writeStoreZip(t / "base.zip", { { "a.txt", "zip", false } });
    fs::create_directories(t / "keep");
    writeFile(t / "keep/k.txt", "kept");
    Spec sp; sp.readOnly = false; sp.writelayer = t.str("wl");
    sp.layers = { zipLayer(t.str("base.zip")) };
    sp.layers.push_back(dirLayer(t.str("keep"), "save", true));
    VfsState S; std::string err; CHECK(S.Init(sp, err));
    CHECK_EQ(VfsLink(S, "a.txt", "b.txt"), 0);
    CHECK(fs::equivalent(t / "wl/a.txt", t / "wl/b.txt"));
    CHECK_EQ(VfsLink(S, "save/k.txt", "save/k2.txt"), 0);
    CHECK(fs::equivalent(t / "keep/k.txt", t / "keep/k2.txt"));
    OpenFile *of = nullptr;
    CHECK_EQ(VfsOpen(S, "save/k2.txt", 2 /*O_RDWR*/, of), 0);
    CHECK(VfsWrite(S, of, "KEPT", 4, 0) == 4); VfsRelease(of);
    CHECK_EQ(VfsOpen(S, "save/k.txt", 0, of), 0);
    char buf[8] = {0}; ssize_t r = VfsRead(of, buf, sizeof buf, 0); VfsRelease(of);
    CHECK_EQ(std::string(buf, r), std::string("KEPT"));
    CHECK_EQ(VfsLink(S, "a.txt", "save/k.txt"), -EEXIST);
}

// A link that fails leaves a deleted name deleted: the whiteout goes only once the link exists.
TEST(a_failed_link_keeps_a_deleted_file_deleted) {
    TmpDir t;
    writeStoreZip(t / "base.zip", { { "cfg.ini", "lower", false } });
    Spec sp; sp.readOnly = false; sp.writelayer = t.str("wl"); sp.layers = { zipLayer(t.str("base.zip")) };
    VfsState S; std::string err; CHECK(S.Init(sp, err));
    CHECK_EQ(VfsUnlink(S, "cfg.ini"), 0);
    CHECK_EQ(VfsMkdir(S, "d", 0755), 0);
    CHECK(VfsLink(S, "d", "cfg.ini") != 0);      // the host refuses to hard-link a directory
    VfsAttr a; CHECK_EQ(VfsGetattr(S, "cfg.ini", a), -ENOENT);
}

TEST(zipscan_matches_libzip) {
    TmpDir t;
    writeStoreZip(t / "z.zip", { { "a.txt", "aaa", false }, { "dir/", "", false }, { "dir/b.txt", "bbbb", false } });
    HostIO::Fd fd = HostIO::Open(t.str("z.zip"), 0); CHECK(fd >= 0);
    HostIO::Stat st; HostIO::Fstat(fd, st);
    auto src = std::make_shared<FdByteSource>(fd, st.size, true);
    auto offs = zipscan::CentralDirOffsets(*src);
    CHECK(offs.count("a.txt")); CHECK(offs.count("dir/b.txt"));
    CHECK(zipscan::LocalDataOffset(*src, offs["a.txt"]) != UINT64_MAX);
}

// ==========================================================================
// Phase-1 bug proofs. Each documents current (buggy) behavior first via a
// disabled assert if needed, then the fixed expectation. Written as the
// fixed expectation directly — they FAIL on unfixed code, PASS after the fix.
// ==========================================================================

// Bug #3: opaque-dir readdir leak — File-layer/structural/implicit children of a lower layer must NOT
// leak into an opaque directory's listing, and readdir must never list a name getattr denies.
TEST(bug_opaque_readdir_subset_getattr) {
    TmpDir t;
    // lower: a dir layer providing d/lower.txt ; then delta/opaque semantics via a File layer child of d.
    writeFile(t / "lower/d/lower.txt", "L");
    writeFile(t / "extra.bin", "X");
    Spec sp; sp.readOnly = false; sp.writelayer = t.str("wl");
    LayerSpec lo = dirLayer(t.str("lower"));
    LayerSpec fl; fl.type = LayerType::File; fl.source = t.str("extra.bin"); fl.target = "d";
    sp.layers = { lo, fl };
    VfsState S; std::string err; CHECK(S.Init(sp, err));

    // make d opaque in the writelayer (delete-then-recreate scenario), then verify the invariant.
    VfsMkdir(S, "d", 0755);          // ensure d exists in wl
    MarkOpaque(S, "d");
    checkReaddirSubsetGetattr(S, "d");   // <-- the core invariant (Bug #3)
    checkReaddirSubsetGetattr(S, "");
}

// Bug #2 (SECURITY): a dir-layer symlink pointing at an absolute host path outside the layer source must
// NOT serve that host file (flatten must not escape the layer). rw layers stay exempt.
TEST(bug_dirlayer_symlink_host_escape) {
    TmpDir t;
    writeFile(t / "src/inside.txt", "OK");
    // an escaping absolute symlink inside the data dir-layer
    std::error_code ec;
    fs::create_symlink("/etc/hostname", t / "src/escape", ec);
    Spec sp; sp.layers = { dirLayer(t.str("src")) };   // flattenSymlinks defaults true on VfsState
    VfsState S; std::string err; CHECK(S.Init(sp, err));
    VfsAttr a;
    CHECK_EQ(VfsGetattr(S, "inside.txt", a), 0);        // normal file still served
    CHECK_EQ(VfsGetattr(S, "escape", a), -ENOENT);      // escaping link must be invisible
}

// Bug #1: a data dir-layer symlink to a DIRECTORY, under flatten, is served as a dir by getattr; copy-up
// must classify it as a dir too (not open it as a file).
TEST(bug_dirsymlink_copyup_as_dir) {
    TmpDir t;
    fs::create_directories(t / "src/realdir");
    writeFile(t / "src/realdir/inner.txt", "I");
    std::error_code ec;
    fs::create_symlink("realdir", t / "src/link", ec);   // relative link → target within the layer
    Spec sp; sp.readOnly = false; sp.writelayer = t.str("wl");
    sp.layers = { dirLayer(t.str("src")) };
    VfsState S; std::string err; CHECK(S.Init(sp, err));
    VfsAttr a;
    CHECK_EQ(VfsGetattr(S, "link", a), 0);
    CHECK(a.isDir);                                       // flatten serves the link as its target dir
    // Trigger a copy-up of the flattened dir (mkdir inside it) — must not misclassify as a file.
    int e = VfsMkdir(S, "link/newsub", 0755);
    CHECK_EQ(e, 0);
    CHECK(fs::is_directory(t / "wl/link"));               // copy-up produced a directory, not a file
}

// Bug #8: VfsUnlink of a lower-backed file must persist as a whiteout and getattr must then be ENOENT.
TEST(bug_unlink_persists_whiteout) {
    TmpDir t;
    writeStoreZip(t / "base.zip", { { "gone.txt", "bye", false } });
    Spec sp; sp.readOnly = false; sp.writelayer = t.str("wl"); sp.layers = { zipLayer(t.str("base.zip")) };
    VfsState S; std::string err; CHECK(S.Init(sp, err));
    CHECK_EQ(VfsUnlink(S, "gone.txt"), 0);
    VfsAttr a; CHECK_EQ(VfsGetattr(S, "gone.txt", a), -ENOENT);
    CHECK(!readdirNames(S, "").count("gone.txt"));
}

// Bug #4: renaming a lower-backed directory away must mask its whole subtree at the OLD path — no ghost
// children reachable by direct path even though the child was never individually whiteouted.
TEST(bug_dir_rename_masks_old_subtree) {
    TmpDir t;
    writeStoreZip(t / "base.zip", { { "d/", "", false }, { "d/child.txt", "c", false } });
    Spec sp; sp.readOnly = false; sp.writelayer = t.str("wl"); sp.layers = { zipLayer(t.str("base.zip")) };
    VfsState S; std::string err; CHECK(S.Init(sp, err));
    CHECK_EQ(VfsRename(S, "d", "d2"), 0);
    VfsAttr a;
    CHECK_EQ(VfsGetattr(S, "d", a), -ENOENT);
    CHECK_EQ(VfsGetattr(S, "d/child.txt", a), -ENOENT);   // ghost child at OLD path must be gone
    CHECK_EQ(VfsGetattr(S, "d2/child.txt", a), 0);        // moved to the new path
}

// A recreated directory over a deleted one must show its NEW (empty) content, not the masked old subtree.
TEST(dir_delete_then_recreate) {
    TmpDir t;
    writeStoreZip(t / "base.zip", { { "d/", "", false }, { "d/old.txt", "o", false } });
    Spec sp; sp.readOnly = false; sp.writelayer = t.str("wl"); sp.layers = { zipLayer(t.str("base.zip")) };
    VfsState S; std::string err; CHECK(S.Init(sp, err));
    CHECK_EQ(VfsUnlink(S, "d/old.txt"), 0);
    CHECK_EQ(VfsRmdir(S, "d"), 0);
    CHECK_EQ(VfsMkdir(S, "d", 0755), 0);           // recreate — removes d's whiteout, marks opaque
    VfsAttr a;
    CHECK_EQ(VfsGetattr(S, "d", a), 0); CHECK(a.isDir);
    CHECK_EQ(VfsGetattr(S, "d/old.txt", a), -ENOENT);   // old content stays masked
}

// Masks must survive a remount: a persisted writelayer's .wh. markers are re-seeded into the in-memory
// sets at Init (deletions keep masking across sessions).
TEST(masks_survive_remount) {
    TmpDir t;
    writeStoreZip(t / "base.zip", { { "gone.txt", "bye", false }, { "d/", "", false }, { "d/c.txt", "c", false } });
    Spec sp; sp.readOnly = false; sp.writelayer = t.str("wl"); sp.layers = { zipLayer(t.str("base.zip")) };
    {
        VfsState S; std::string err; CHECK(S.Init(sp, err));
        CHECK_EQ(VfsUnlink(S, "gone.txt"), 0);
        CHECK_EQ(VfsRename(S, "d", "d2"), 0);
    }
    // fresh mount over the SAME writelayer
    VfsState S2; std::string err2; CHECK(S2.Init(sp, err2));
    VfsAttr a;
    CHECK_EQ(VfsGetattr(S2, "gone.txt", a), -ENOENT);      // whiteout re-seeded
    CHECK_EQ(VfsGetattr(S2, "d/c.txt", a), -ENOENT);       // subtree mask re-seeded
    CHECK_EQ(VfsGetattr(S2, "d2/c.txt", a), 0);            // moved content still there
}

// Renaming a directory that CONTAINS whiteouts must keep those deletions working at the new path.
TEST(rename_carries_inner_whiteouts) {
    TmpDir t;
    writeStoreZip(t / "base.zip", { { "d/", "", false }, { "d/keep.txt", "k", false }, { "d/del.txt", "x", false } });
    Spec sp; sp.readOnly = false; sp.writelayer = t.str("wl"); sp.layers = { zipLayer(t.str("base.zip")) };
    VfsState S; std::string err; CHECK(S.Init(sp, err));
    CHECK_EQ(VfsUnlink(S, "d/del.txt"), 0);                // whiteout INSIDE d
    CHECK_EQ(VfsRename(S, "d", "d2"), 0);                  // markers travel with the wl dir
    VfsAttr a;
    CHECK_EQ(VfsGetattr(S, "d2/keep.txt", a), 0);
    CHECK_EQ(VfsGetattr(S, "d2/del.txt", a), -ENOENT);     // deletion still masks at the NEW path
}

// ---- delta round-trip (moved here from parent test intent for FS coverage) ----
TEST(delta_roundtrip_basic) {
    std::string base(4096, 'A'); for (int i = 0; i < 4096; i += 7) base[i] = 'a' + (i % 26);
    std::string tgt = base; tgt.insert(2000, "INSERTED-CHUNK-INSERTED-CHUNK"); tgt.resize(5000, 'Z');
    auto delta = vgdelta::GenerateDelta((const uint8_t *)base.data(), base.size(),
                                        (const uint8_t *)tgt.data(), tgt.size());
    CHECK(!delta.empty());
    auto baseSrc = std::make_shared<MemByteSource>(std::vector<uint8_t>(base.begin(), base.end()));
    std::string derr;
    auto ds = vgdelta::DeltaByteSource::Create(std::make_shared<MemByteSource>(delta), baseSrc, derr, false);
    CHECK(ds != nullptr);
    if (ds) {
        CHECK_EQ(ds->size(), tgt.size());
        std::vector<uint8_t> out(tgt.size());
        CHECK(ds->preadAll(out.data(), out.size(), 0));
        CHECK(std::memcmp(out.data(), tgt.data(), tgt.size()) == 0);
    }
}

// MULTI-BASE: one delta reconstructed against the CONCATENATION of several bases, in order. This is the primitive
// behind deduping a wine prefix against [wine || dxvk] — a COPY offset indexes across the whole stitched address
// space, so bytes that exist in EITHER base cost nothing.
//
// It had no test. `ConcatByteSource` shipped in July verified once by hand against a written-out mount spec, and
// nothing exercised it again; the package-side path that would have used it was only wired up today.
TEST(delta_over_concatenated_bases) {
    // Two disjoint bases with distinctive content, as [wine || dxvk] would be.
    std::string b1(3000, '\0'); for (size_t i = 0; i < b1.size(); ++i) b1[i] = char('a' + (i * 7) % 26);
    std::string b2(2500, '\0'); for (size_t i = 0; i < b2.size(); ++i) b2[i] = char('A' + (i * 11) % 26);

    // A target built from a run of the SECOND base, a run of the FIRST, and some novel bytes. If the concat is
    // ordered or offset wrongly, the reconstruction differs and the memcmp below fails.
    std::string tgt = b2.substr(500, 900) + std::string("NOVEL-BYTES-NOT-IN-EITHER-BASE") + b1.substr(1200, 1100);

    std::string concat = b1 + b2;                               // the order generation used...
    auto delta = vgdelta::GenerateDelta((const uint8_t *)concat.data(), concat.size(),
                                        (const uint8_t *)tgt.data(), tgt.size());
    CHECK(!delta.empty());
    // It must actually be deduping, not just storing the target: the shared runs are 2000 of ~2030 bytes.
    CHECK(delta.size() < tgt.size());

    // ...and the order composition must use. Parts stay separate ByteSources — nothing is materialised.
    std::vector<std::shared_ptr<ByteSource>> parts = {
        std::make_shared<MemByteSource>(std::vector<uint8_t>(b1.begin(), b1.end())),
        std::make_shared<MemByteSource>(std::vector<uint8_t>(b2.begin(), b2.end())),
    };
    auto cat = std::make_shared<ConcatByteSource>(parts);
    CHECK_EQ(cat->size(), b1.size() + b2.size());

    std::string derr;
    auto ds = vgdelta::DeltaByteSource::Create(std::make_shared<MemByteSource>(delta), cat, derr, false);
    CHECK(ds != nullptr);
    if (ds) {
        CHECK_EQ(ds->size(), tgt.size());
        std::vector<uint8_t> out(tgt.size());
        CHECK(ds->preadAll(out.data(), out.size(), 0));
        CHECK(std::memcmp(out.data(), tgt.data(), tgt.size()) == 0);

        // A read that STRADDLES the boundary between the two bases must be split and stitched correctly — the
        // one thing a naive concat gets wrong.
        std::vector<uint8_t> mid(64);
        CHECK(cat->preadAll(mid.data(), mid.size(), b1.size() - 32));
        CHECK(std::memcmp(mid.data(), b1.data() + b1.size() - 32, 32) == 0);
        CHECK(std::memcmp(mid.data() + 32, b2.data(), 32) == 0);
    }

    // ORDER IS LOAD-BEARING: composing the same delta over [b2 || b1] must NOT reproduce the target. Asserted
    // UNCONDITIONALLY — guarding this behind `if (wrong && ...)` runs zero CHECKs the day Create starts refusing
    // the swapped base, and the test would still report pass while proving nothing.
    std::vector<std::shared_ptr<ByteSource>> swapped = { parts[1], parts[0] };
    auto wrong = vgdelta::DeltaByteSource::Create(std::make_shared<MemByteSource>(delta),
                                                  std::make_shared<ConcatByteSource>(swapped), derr, false);
    CHECK(wrong != nullptr);                       // same total size, so it must still parse
    if (wrong) {
        CHECK_EQ(wrong->size(), tgt.size());
        std::vector<uint8_t> out(tgt.size());
        CHECK(wrong->preadAll(out.data(), out.size(), 0));
        CHECK(std::memcmp(out.data(), tgt.data(), tgt.size()) != 0);
    }
}

// A base declared AT THE MOUNT ROOT ("") used to be inexpressible: the spec's singular `baseTarget` key could not
// tell it apart from "no base declared", so the FS fell back to the delta's own target, reconstructed against the
// wrong bytes and skipped the layer. One key — an ordered list — removes the ambiguity by construction.
TEST(a_base_declared_at_the_root_is_not_confused_with_no_base) {
    TmpDir t;
    std::string body(6000, 'q'); for (size_t i = 0; i < body.size(); ++i) body[i] = char('a' + (i * 5) % 26);
    writeStoreZip(t / "root.zip", { { "fr.bin", body, false } });          // mounts at "" (the root)
    writeStoreZip(t / "decoy.zip", { { "fd.bin", std::string(6000, 'Z'), false } });  // mounts at "sub"

    const std::string want = body.substr(1000, 3000) + "NOVEL";
    writeStoreZip(t / "tgt.zip", { { "ft.bin", want, false } });

    auto slurp = [](const fs::path &p) {
        std::ifstream f(p, std::ios::binary);
        return std::string((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    };
    const std::string base = slurp(t / "root.zip"), tgt = slurp(t / "tgt.zip");
    auto delta = vgdelta::GenerateDelta((const uint8_t *)base.data(), base.size(),
                                        (const uint8_t *)tgt.data(), tgt.size());
    CHECK(!delta.empty());
    { std::ofstream o(t / "d.vgdelta", std::ios::binary); o.write((const char *)delta.data(), (std::streamsize)delta.size()); }

    // The delta mounts at "sub" — where the DECOY is — but declares its base at the root. Read the wrong base and
    // the reconstruction fails outright; read no base and the layer is skipped. Either way "sub/ft.bin" is absent.
    std::ostringstream js;
    js << "{\"mountpoint\":\"" << t.str("mnt") << "\",\"readonly\":true,\"layers\":["
       << "{\"type\":\"zip\",\"source\":\"" << t.str("root.zip") << "\",\"target\":\"\"},"
       << "{\"type\":\"zip\",\"source\":\"" << t.str("decoy.zip") << "\",\"target\":\"sub\"},"
       << "{\"type\":\"delta\",\"source\":\"" << t.str("d.vgdelta") << "\",\"target\":\"sub\","
       <<  "\"baseTargets\":[\"\"]}]}";
    writeFile(t / "spec.json", js.str());

    Spec sp; std::string err;
    CHECK(ParseSpec(t.str("spec.json"), sp, err));
    CHECK_EQ(sp.layers.size(), size_t(3));
    CHECK_EQ(sp.layers[2].baseTargets.size(), size_t(1));

    VfsState S;
    CHECK(S.Init(sp, err));
    OpenFile *of = nullptr;
    CHECK_EQ(VfsOpen(S, "sub/ft.bin", 0, of), 0);
    if (of) {
        std::string got(want.size(), '\0');
        CHECK_EQ(VfsRead(of, got.data(), got.size(), 0), (ssize_t)want.size());
        VfsRelease(of);
        CHECK(got == want);
    }
}

// A malformed base list is REFUSED, not quietly shortened: a concatenation missing one part is a base of the
// wrong SIZE, which fails the delta's size check and costs the layer its content with nothing said.
TEST(a_malformed_base_list_is_refused) {
    TmpDir t;
    writeStoreZip(t / "a.zip", { { "x", "x", false } });
    //The base list belongs to a DELTA layer — a zip has no byte-base, so hanging one on a zip would pin a
    //shape that means nothing and quietly assert the parser accepts it there.
    { std::ofstream o(t / "d.vgdelta", std::ios::binary); o << "x"; }
    auto spec = [&](const std::string &bases) {
        std::ostringstream js;
        js << "{\"mountpoint\":\"" << t.str("mnt") << "\",\"readonly\":true,\"layers\":["
           << "{\"type\":\"zip\",\"source\":\"" << t.str("a.zip") << "\",\"target\":\"a\"},"
           << "{\"type\":\"delta\",\"source\":\"" << t.str("d.vgdelta") << "\",\"target\":\"b\","
           <<  "\"baseTargets\":" << bases << "}]}";
        writeFile(t / "spec.json", js.str());
        Spec sp; std::string err;
        const bool ok = ParseSpec(t.str("spec.json"), sp, err);
        return std::make_pair(ok, err);
    };
    CHECK(!spec("[\"a\", 7]").first);                 // a non-string entry
    CHECK(!spec("\"a\"").first);                      // a bare string where a list belongs
    const auto Ok = spec("[\"a\"]");                  // ...and the well-formed shape still parses
    CHECK(Ok.first);
    if (!Ok.first) std::cerr << "    parse error was: " << Ok.second << "\n";
}

// END TO END, through the REAL handoff: the spec JSON VidyaGod writes → ParseSpec → VfsState::Init → a read.
// The pieces above (ConcatByteSource, DeltaByteSource) were already unit-tested while the FLOW into them was
// dead — `baseTargets` never appeared in a spec because the mount builder only read the singular key. A unit
// test that pins a function while nothing reaches it reads as coverage and is worse than none.
TEST(multi_base_delta_mounts_from_a_spec_file) {
    TmpDir t;
    // Two independent base archives at their own targets, as [wine || dxvk] would be.
    std::string fa(4000, 'x'); for (size_t i = 0; i < fa.size(); ++i) fa[i] = char('a' + (i * 7) % 26);
    std::string fb(3500, 'y'); for (size_t i = 0; i < fb.size(); ++i) fb[i] = char('A' + (i * 11) % 26);
    writeStoreZip(t / "a.zip", { { "fa.bin", fa, false } });
    writeStoreZip(t / "b.zip", { { "fb.bin", fb, false } });

    // The target archive: STOREd, so its entry bytes appear verbatim and the delta can COPY them out of the
    // bases' zip bytes. Its content is drawn from BOTH bases plus something novel.
    const std::string want = fb.substr(400, 1200) + "NOVEL-NOVEL-NOVEL" + fa.substr(900, 1500);
    writeStoreZip(t / "c.zip", { { "fc.bin", want, false } });

    auto slurp = [](const fs::path &p) {
        std::ifstream f(p, std::ios::binary);
        return std::string((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    };
    // The byte base is the CONCATENATION of the two base layers' composed views, in the spec's order.
    const std::string cat = slurp(t / "a.zip") + slurp(t / "b.zip");
    const std::string tgt = slurp(t / "c.zip");
    auto delta = vgdelta::GenerateDelta((const uint8_t *)cat.data(), cat.size(),
                                        (const uint8_t *)tgt.data(), tgt.size());
    CHECK(!delta.empty());
    CHECK(delta.size() < tgt.size());                       // it must be deduping, not just storing the target
    { std::ofstream o(t / "c.vgdelta", std::ios::binary); o.write((const char *)delta.data(), (std::streamsize)delta.size()); }

    // The spec exactly as VidyaGod's BuildLayerSpec writes it — `baseTargets` plural, in order.
    std::ostringstream js;
    js << "{\"mountpoint\":\"" << t.str("mnt") << "\",\"readonly\":true,\"layers\":["
       << "{\"type\":\"zip\",\"source\":\"" << t.str("a.zip") << "\",\"target\":\"a\"},"
       << "{\"type\":\"zip\",\"source\":\"" << t.str("b.zip") << "\",\"target\":\"b\"},"
       << "{\"type\":\"delta\",\"source\":\"" << t.str("c.vgdelta") << "\",\"target\":\"c\","
       <<  "\"baseTargets\":[\"a\",\"b\"]}]}";
    writeFile(t / "spec.json", js.str());

    Spec sp; std::string err;
    CHECK(ParseSpec(t.str("spec.json"), sp, err));
    CHECK_EQ(sp.layers.size(), size_t(3));
    CHECK_EQ(sp.layers[2].baseTargets.size(), size_t(2));
    if (sp.layers[2].baseTargets.size() == 2) {          // guarded: indexing past a failed size check aborts
        CHECK_EQ(sp.layers[2].baseTargets[0], std::string("a"));
        CHECK_EQ(sp.layers[2].baseTargets[1], std::string("b"));
    }

    VfsState S;
    CHECK(S.Init(sp, err));
    VfsAttr at;
    CHECK_EQ(VfsGetattr(S, "c/fc.bin", at), 0);             // the delta reconstructed against the concatenation
    CHECK_EQ(at.size, (uint64_t)want.size());
    OpenFile *of = nullptr;
    CHECK_EQ(VfsOpen(S, "c/fc.bin", 0, of), 0);
    if (of) {
        std::string got(want.size(), '\0');
        ssize_t r = VfsRead(of, got.data(), got.size(), 0);
        VfsRelease(of);
        CHECK_EQ(r, (ssize_t)want.size());
        CHECK(got == want);
    }
    // and the bases stay ordinary visible layers of their own
    CHECK_EQ(VfsGetattr(S, "a/fa.bin", at), 0);
    CHECK_EQ(VfsGetattr(S, "b/fb.bin", at), 0);
}

// A part's boundary is what its size() says, NOT what its pread happens to hand back. FdByteSource — the part
// type the real mount uses — forwards straight to ::pread on the fd, so on a file longer than the declared
// size it WILL return bytes past that size. The clamp in ConcatByteSource is the only thing standing between
// that and a silently mis-stitched address space: a COPY near the seam would pull the wrong base's bytes and
// the delta would reconstruct garbage, with no error anywhere.
struct OverReadingSource : ByteSource {
    std::vector<uint8_t> file;     // what the underlying storage actually holds
    uint64_t             declared; // what this source claims to be
    OverReadingSource(std::vector<uint8_t> f, uint64_t d) : file(std::move(f)), declared(d) {}
    ssize_t pread(void *buf, size_t n, uint64_t off) override {
        if (off >= file.size()) return 0;
        const size_t avail = file.size() - static_cast<size_t>(off);   // clamps to the FILE, not to declared
        const size_t want  = n < avail ? n : avail;
        std::memcpy(buf, file.data() + off, want);
        return static_cast<ssize_t>(want);
    }
    uint64_t size() const override { return declared; }
};

TEST(concat_part_boundary_is_defined_by_size) {
    std::vector<uint8_t> backing(64, 'x');
    for (size_t i = 32; i < 64; ++i) backing[i] = 'Z';       // past the declared end — must never be visible
    std::vector<std::shared_ptr<ByteSource>> parts = {
        std::make_shared<OverReadingSource>(backing, 32),
        std::make_shared<MemByteSource>(std::vector<uint8_t>(32, 'Y')),
    };
    auto cat = std::make_shared<ConcatByteSource>(parts);
    CHECK_EQ(cat->size(), uint64_t(64));

    std::vector<uint8_t> out(64, 0);
    CHECK(cat->preadAll(out.data(), out.size(), 0));
    CHECK_EQ(std::count(out.begin(), out.end(), 'Z'), 0);     // the over-read must be cut off at the seam
    CHECK(std::memcmp(out.data(), std::string(32, 'x').data(), 32) == 0);
    CHECK(std::memcmp(out.data() + 32, std::string(32, 'Y').data(), 32) == 0);

    // and the same read started INSIDE part 0, straddling the seam
    std::vector<uint8_t> mid(20, 0);
    CHECK(cat->preadAll(mid.data(), mid.size(), 22));
    CHECK(std::memcmp(mid.data(), std::string(10, 'x').data(), 10) == 0);
    CHECK(std::memcmp(mid.data() + 10, std::string(10, 'Y').data(), 10) == 0);
}

int main() {
    for (auto &[name, fn] : g_tests) {
        std::cerr << "[ RUN ] " << name << "\n";
        fn();
    }
    std::cerr << "\n" << (g_fail ? "FAILED " : "PASSED ") << g_checks << " checks, " << g_fail << " failures across "
              << g_tests.size() << " tests\n";
    return g_fail ? 1 : 0;
}

// KEEP-subtree durability: MODIFYING a file that exists only in a LOWER layer, under an rw-passthrough
// subtree, must copy up INTO the passthrough source (durable) — not the ephemeral writelayer. This was
// the "seeded config never persists the game's changes" hole: creates went durable, edits vanished.
TEST(passthrough_copyup_lands_durable) {
    TmpDir t;
    writeFile(t / "lower/cfg/settings.cfg", "xres 640\n");
    fs::create_directories(t / "durable/cfg");
    Spec sp; sp.readOnly = false; sp.writelayer = t.str("wl");
    LayerSpec lo = dirLayer(t.str("lower"));
    LayerSpec keep = dirLayer(t.str("durable/cfg"), "cfg", /*rw=*/true);   // KEEP passthrough over cfg/
    sp.layers = { lo, keep };
    VfsState S; std::string err; CHECK(S.Init(sp, err));

    // the seeded file is visible through the union
    VfsAttr a; CHECK_EQ(VfsGetattr(S, "cfg/settings.cfg", a), 0);

    // open-for-write (the game's config rewrite) …
    OpenFile *of = nullptr;
    CHECK_EQ(VfsOpen(S, "cfg/settings.cfg", 0x241 /*O_WRONLY|O_CREAT|O_TRUNC*/, of), 0);
    const char *nw = "xres 1920\n";
    CHECK(VfsWrite(S, of, nw, 10, 0) == 10);
    VfsRelease(of);

    // … lands in the DURABLE passthrough source, not the writelayer
    std::ifstream in(t / "durable/cfg/settings.cfg");
    std::string got((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    CHECK_EQ(got, std::string("xres 1920\n"));
    CHECK(!fs::exists(t / "wl/cfg/settings.cfg"));    // nothing leaked into the ephemeral layer

    // and reads see the new content
    OpenFile *rf = nullptr; CHECK_EQ(VfsOpen(S, "cfg/settings.cfg", 0, rf), 0);
    char buf[32] = {0}; ssize_t r = VfsRead(rf, buf, sizeof buf, 0); VfsRelease(rf);
    CHECK_EQ(std::string(buf, r), std::string("xres 1920\n"));
}

// A kept folder (rw passthrough) is the user's durable upper layer for its subtree. Deleting a file that only a
// LOWER layer provides used to fail with ENOENT (the passthrough unlinked a host file that did not exist): Proton's
// prefix setup died on it under a whole-runtime keep. The deletion is a durable marker in the kept folder itself.
static Spec keptOverLower(TmpDir &t, const std::string &target) {
    writeStoreZip(t / "lower.zip", {{"b.txt", "package b", false}, {"cfg/default.sav", "package save", false},
                                    {"cfg/sub/x.txt", "package x", false}});
    fs::create_directories(t / "durable");
    Spec sp; sp.readOnly = false; sp.writelayer = t.str("wl");
    sp.layers = { zipLayer(t.str("lower.zip")), dirLayer(t.str("durable"), target, /*rw=*/true) };
    return sp;
}

TEST(a_kept_folder_over_the_whole_runtime_can_delete_package_files) {
    TmpDir t; Spec sp = keptOverLower(t, "");
    VfsState S; std::string err; CHECK(S.Init(sp, err));
    VfsAttr a;
    CHECK_EQ(VfsUnlink(S, "b.txt"), 0);
    CHECK_EQ(VfsUnlink(S, "cfg/default.sav"), 0);
    CHECK_EQ(VfsGetattr(S, "b.txt", a), -ENOENT);
    CHECK_EQ(VfsGetattr(S, "cfg/default.sav", a), -ENOENT);
    CHECK_EQ(VfsUnlink(S, "b.txt"), -ENOENT);                  // gone is gone
    CHECK_EQ(VfsUnlink(S, "never-there.txt"), -ENOENT);
    auto root = readdirNames(S, ""), cfg = readdirNames(S, "cfg");
    CHECK(!root.count("b.txt")); CHECK(!cfg.count("default.sav")); CHECK(cfg.count("sub"));
    for (const auto &n : root) CHECK(n.rfind(".wh.", 0) != 0);  // markers never show
    for (const auto &n : cfg) CHECK(n.rfind(".wh.", 0) != 0);
}

TEST(deleting_a_lower_file_in_a_kept_folder_stays_deleted_next_launch) {
    TmpDir t; Spec sp = keptOverLower(t, "cfg");
    { VfsState S; std::string err; CHECK(S.Init(sp, err)); CHECK_EQ(VfsUnlink(S, "cfg/default.sav"), 0); }
    CHECK(fs::exists(t / "durable/.wh.default.sav"));          // the marker lives in the user's folder
    CHECK(!fs::exists(t / "wl/cfg/.wh.default.sav"));          // not in the per-session layer
    fs::remove_all(t / "wl");                                  // a new launch: fresh writelayer, same kept folder
    VfsState S2; std::string err; CHECK(S2.Init(sp, err));
    VfsAttr a; CHECK_EQ(VfsGetattr(S2, "cfg/default.sav", a), -ENOENT);
    CHECK(!readdirNames(S2, "cfg").count("default.sav"));
    CHECK_EQ(VfsGetattr(S2, "cfg/sub/x.txt", a), 0);           // the rest of the package is untouched
}

TEST(a_file_made_again_in_a_kept_folder_comes_back) {
    TmpDir t; Spec sp = keptOverLower(t, "cfg");
    VfsState S; std::string err; CHECK(S.Init(sp, err));
    CHECK_EQ(VfsUnlink(S, "cfg/default.sav"), 0);
    OpenFile *of = nullptr; CHECK_EQ(VfsCreate(S, "cfg/default.sav", 0644, 0x41 /*O_WRONLY|O_CREAT*/, of), 0);
    CHECK(VfsWrite(S, of, "mine", 4, 0) == 4); VfsRelease(of);
    VfsAttr a; CHECK_EQ(VfsGetattr(S, "cfg/default.sav", a), 0); CHECK_EQ(a.size, (uint64_t)4);
    CHECK(!fs::exists(t / "durable/.wh.default.sav"));
    CHECK(readdirNames(S, "cfg").count("default.sav"));
}

TEST(a_lower_folder_removed_in_a_kept_folder_and_made_again_is_empty) {
    TmpDir t; Spec sp = keptOverLower(t, "cfg");
    VfsState S; std::string err; CHECK(S.Init(sp, err));
    CHECK_EQ(VfsUnlink(S, "cfg/sub/x.txt"), 0);
    CHECK_EQ(VfsRmdir(S, "cfg/sub"), 0);
    VfsAttr a; CHECK_EQ(VfsGetattr(S, "cfg/sub", a), -ENOENT);
    CHECK(!readdirNames(S, "cfg").count("sub"));
    CHECK_EQ(VfsMkdir(S, "cfg/sub", 0755), 0);
    CHECK_EQ(VfsGetattr(S, "cfg/sub", a), 0); CHECK(a.isDir);
    CHECK(readdirNames(S, "cfg/sub").empty());                 // the package's old contents stay deleted
    CHECK_EQ(VfsGetattr(S, "cfg/sub/x.txt", a), -ENOENT);
    fs::remove_all(t / "wl");
    VfsState S2; CHECK(S2.Init(sp, err));
    CHECK(readdirNames(S2, "cfg/sub").empty());
    CHECK_EQ(VfsGetattr(S2, "cfg/sub/x.txt", a), -ENOENT);
}

TEST(renaming_a_lower_file_in_a_kept_folder_hides_the_old_name_for_good) {
    TmpDir t; Spec sp = keptOverLower(t, "cfg");
    { VfsState S; std::string err; CHECK(S.Init(sp, err)); CHECK_EQ(VfsRename(S, "cfg/default.sav", "cfg/slot1.sav"), 0); }
    fs::remove_all(t / "wl");
    VfsState S2; std::string err; CHECK(S2.Init(sp, err));
    VfsAttr a;
    CHECK_EQ(VfsGetattr(S2, "cfg/default.sav", a), -ENOENT);
    CHECK_EQ(VfsGetattr(S2, "cfg/slot1.sav", a), 0); CHECK_EQ(a.size, (uint64_t)12);
}

TEST(hard_linking_a_lower_file_in_a_kept_folder_links_its_kept_copy) {
    TmpDir t; Spec sp = keptOverLower(t, "cfg");
    VfsState S; std::string err; CHECK(S.Init(sp, err));
    CHECK_EQ(VfsLink(S, "cfg/default.sav", "cfg/backup.sav"), 0);
    VfsAttr a; CHECK_EQ(VfsGetattr(S, "cfg/backup.sav", a), 0); CHECK_EQ(a.size, (uint64_t)12);
    CHECK(fs::exists(t / "durable/default.sav") && fs::exists(t / "durable/backup.sav"));
    std::error_code ec; CHECK(fs::equivalent(t / "durable/default.sav", t / "durable/backup.sav", ec));
}

// Review findings (2026-10-21). A directory renamed after one of its package files was deleted used to move only the
// marker: its other package files were hidden at the old name and never copied — lost for good.
static Spec keptOverTwo(TmpDir &t, const std::string &target) {
    writeStoreZip(t / "lower.zip", {{"cfg/sub/x.txt", "package x", false}, {"cfg/sub/y.txt", "package y", false}});
    fs::create_directories(t / "durable");
    Spec sp; sp.readOnly = false; sp.writelayer = t.str("wl");
    sp.layers = { zipLayer(t.str("lower.zip")), dirLayer(t.str("durable"), target, /*rw=*/true) };
    return sp;
}

TEST(renaming_a_folder_after_deleting_one_of_its_package_files_keeps_the_rest) {
    TmpDir t; Spec sp = keptOverTwo(t, "cfg");
    {
        VfsState S; std::string err; CHECK(S.Init(sp, err));
        CHECK_EQ(VfsUnlink(S, "cfg/sub/y.txt"), 0);
        CHECK_EQ(VfsRename(S, "cfg/sub", "cfg/sub2"), 0);
        VfsAttr a;
        CHECK_EQ(VfsGetattr(S, "cfg/sub2/x.txt", a), 0);
        CHECK_EQ(VfsGetattr(S, "cfg/sub2/y.txt", a), -ENOENT);
        CHECK_EQ(VfsGetattr(S, "cfg/sub", a), -ENOENT);
    }
    fs::remove_all(t / "wl");
    VfsState S2; std::string err; CHECK(S2.Init(sp, err));
    VfsAttr a;
    CHECK_EQ(VfsGetattr(S2, "cfg/sub2/x.txt", a), 0); CHECK_EQ(a.size, (uint64_t)9);
    CHECK_EQ(VfsGetattr(S2, "cfg/sub2/y.txt", a), -ENOENT);
    CHECK_EQ(VfsGetattr(S2, "cfg/sub", a), -ENOENT);
    CHECK(readdirNames(S2, "cfg") == std::set<std::string>{"sub2"});
}

TEST(a_folder_renamed_onto_a_deleted_package_folder_does_not_bring_its_files_back) {
    TmpDir t; Spec sp = keptOverTwo(t, "cfg");
    VfsState S; std::string err; CHECK(S.Init(sp, err));
    CHECK_EQ(VfsUnlink(S, "cfg/sub/x.txt"), 0); CHECK_EQ(VfsUnlink(S, "cfg/sub/y.txt"), 0);
    CHECK_EQ(VfsRmdir(S, "cfg/sub"), 0);
    CHECK_EQ(VfsMkdir(S, "cfg/new", 0755), 0);
    CHECK_EQ(VfsRename(S, "cfg/new", "cfg/sub"), 0);
    CHECK(readdirNames(S, "cfg/sub").empty());
    fs::remove_all(t / "wl");
    VfsState S2; CHECK(S2.Init(sp, err));
    CHECK(readdirNames(S2, "cfg/sub").empty());
    VfsAttr a; CHECK_EQ(VfsGetattr(S2, "cfg/sub/x.txt", a), -ENOENT);
}

// A deletion that cannot be recorded fails; it never reports success while the file stays.
TEST(a_deletion_the_kept_folder_cannot_record_fails) {
    if (::geteuid() == 0) return;   // root ignores the permission this test relies on
    TmpDir t; Spec sp = keptOverLower(t, "cfg");
    VfsState S; std::string err; CHECK(S.Init(sp, err));
    fs::permissions(t / "durable", fs::perms::owner_read | fs::perms::owner_exec);
    CHECK(VfsUnlink(S, "cfg/default.sav") < 0);
    VfsAttr a; CHECK_EQ(VfsGetattr(S, "cfg/default.sav", a), 0);
    fs::permissions(t / "durable", fs::perms::owner_all);
}

TEST(a_create_that_fails_does_not_bring_a_deleted_file_back) {
    if (::geteuid() == 0) return;
    TmpDir t; Spec sp = keptOverLower(t, "cfg");
    VfsState S; std::string err; CHECK(S.Init(sp, err));
    CHECK_EQ(VfsUnlink(S, "cfg/default.sav"), 0);
    fs::permissions(t / "durable", fs::perms::owner_read | fs::perms::owner_exec);
    OpenFile *of = nullptr;
    CHECK(VfsCreate(S, "cfg/default.sav", 0644, 0x41, of) < 0);
    fs::permissions(t / "durable", fs::perms::owner_all);
    VfsAttr a; CHECK_EQ(VfsGetattr(S, "cfg/default.sav", a), -ENOENT);
}

// The kept folder's own root is a mount point: removing it empties it for good; it can be made again.
TEST(removing_the_kept_folders_root_empties_it_for_good) {
    TmpDir t; Spec sp = keptOverTwo(t, "cfg/sub");
    {
        VfsState S; std::string err; CHECK(S.Init(sp, err));
        CHECK_EQ(VfsUnlink(S, "cfg/sub/x.txt"), 0); CHECK_EQ(VfsUnlink(S, "cfg/sub/y.txt"), 0);
        CHECK_EQ(VfsRmdir(S, "cfg/sub"), 0);
        VfsAttr a; CHECK_EQ(VfsGetattr(S, "cfg/sub", a), -ENOENT);
        CHECK_EQ(VfsMkdir(S, "cfg/sub", 0755), 0);
        CHECK_EQ(VfsGetattr(S, "cfg/sub", a), 0);
        CHECK(readdirNames(S, "cfg/sub").empty());
    }
    fs::remove_all(t / "wl");
    VfsState S2; std::string err; CHECK(S2.Init(sp, err));
    CHECK(readdirNames(S2, "cfg/sub").empty());
    VfsAttr a; CHECK_EQ(VfsGetattr(S2, "cfg/sub/x.txt", a), -ENOENT);
}

TEST(a_kept_folder_refuses_names_that_look_like_its_markers) {
    TmpDir t; Spec sp = keptOverLower(t, "cfg");
    VfsState S; std::string err; CHECK(S.Init(sp, err));
    OpenFile *of = nullptr;
    CHECK_EQ(VfsCreate(S, "cfg/.wh.default.sav", 0644, 0x41, of), -EINVAL);
    CHECK_EQ(VfsMkdir(S, "cfg/.wh..wh..opq", 0755), -EINVAL);
    VfsAttr a; CHECK_EQ(VfsGetattr(S, "cfg/default.sav", a), 0);
}

// A marker left beside the user's own file of that name (a failed marker unlink) masks the package copy only.
TEST(a_stale_marker_never_hides_the_kept_folders_own_file) {
    TmpDir t; Spec sp = keptOverLower(t, "cfg");
    writeFile(t / "durable/default.sav", "mine");
    writeFile(t / "durable/.wh.default.sav", "");
    VfsState S; std::string err; CHECK(S.Init(sp, err));
    CHECK(readdirNames(S, "cfg").count("default.sav"));
    VfsAttr a; CHECK_EQ(VfsGetattr(S, "cfg/default.sav", a), 0); CHECK_EQ(a.size, (uint64_t)4);
}

// The same with a create the kernel refuses outright (O_CREAT|O_DIRECTORY → EINVAL) while the marker could be
// removed: the deleted file must stay deleted (the marker goes only once the new file exists).
TEST(a_refused_create_leaves_the_deleted_file_deleted) {
    TmpDir t; Spec sp = keptOverLower(t, "cfg");
    VfsState S; std::string err; CHECK(S.Init(sp, err));
    CHECK_EQ(VfsUnlink(S, "cfg/default.sav"), 0);
    OpenFile *of = nullptr;
    CHECK(VfsCreate(S, "cfg/default.sav", 0644, O_WRONLY | O_CREAT | O_DIRECTORY, of) < 0);
    VfsAttr a; CHECK_EQ(VfsGetattr(S, "cfg/default.sav", a), -ENOENT);
    CHECK(fs::exists(t / "durable/.wh.default.sav"));
}
