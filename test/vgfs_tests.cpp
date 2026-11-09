// vgfs_tests — unmounted unit tests for the VidyaGodFS core.
// Strategy (see the overhaul plan): build REAL fixture trees / zips in a temp dir, construct a Spec
// directly, VfsState::Init, then drive Resolve / CollectChildren / the VfsOps surface. No mounting, no
// HostIO mocking — the POSIX shim is exercised for real. Fixtures are torn down per test.

#include "overlay.h"
#include "treeplan.h"
#include "vfsops.h"
#include "layerspec.h"
#include "ziplayer.h"
#include "zipscan.h"
#include "vgdelta.h"
#include "bytesource.h"

#include <cerrno>
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

// A zip layer; its CID is its path here (one path, one file: what the app's CIDs are to the FS).
static LayerSpec zipLayer(const std::string &src, const std::string &target = "") {
    LayerSpec L; L.type = LayerType::Zip; L.source = src; L.cid = src; L.target = NormalizeVPath(target); return L;
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

// An archive link that resolves to a FILE inside the archive is served as that file (proton's default_pfx template
// links resolve only inside its own tree); every other link is served as the link it is, its target as stored:
// absolute (a Nix bundle's entrypoint into /nix/store), climbing out of the archive, to a folder, dangling. Listed,
// stat'ed as a link, readlink'ed, and recreated as a link by a copy-up (a rename). Teeth: hide the unresolvable links
// (the old rule: abs/out/dir/dangle vanish); flatten nothing (in.txt reads as a link); copy-up the link as a file.
TEST(zip_links_outside_the_archive_are_served_as_links) {
    TmpDir t;
    writeStoreZip(t / "a.zip", {
        { "app/real.txt", "content", false }, { "app/sub/", "", false }, { "app/sub/x.txt", "x", false },
        { "app/in.txt", "real.txt", true },                                  // resolves inside: a file
        { "app/entrypoint", "/nix/store/abc-bbport-0.1/bin/bbport", true },  // absolute
        { "app/out", "../../elsewhere/lib.so", true },                       // climbs out of the archive
        { "app/dirlink", "sub", true },                                      // to a folder
        { "app/dangle", "missing.txt", true } });                            // dangling
    Spec sp; sp.readOnly = false; sp.writelayer = t.str("wl"); sp.layers = { zipLayer(t.str("a.zip")) };
    VfsState S; std::string err; CHECK(S.Init(sp, err));

    VfsAttr a;
    CHECK_EQ(VfsGetattr(S, "app/in.txt", a), 0); CHECK(!a.isSymlink); CHECK_EQ(a.size, (uint64_t)7);
    std::string tgt;
    CHECK_EQ(VfsReadlink(S, "app/in.txt", tgt), -EINVAL);
    const std::vector<std::pair<std::string, std::string>> Links = {
        { "app/entrypoint", "/nix/store/abc-bbport-0.1/bin/bbport" }, { "app/out", "../../elsewhere/lib.so" },
        { "app/dirlink", "sub" }, { "app/dangle", "missing.txt" } };
    const auto names = readdirNames(S, "app");
    for (const auto &[Path, Target] : Links)
    {
        CHECK_EQ(VfsGetattr(S, Path, a), 0);
        CHECK(a.isSymlink);
        tgt.clear();
        CHECK_EQ(VfsReadlink(S, Path, tgt), 0);
        CHECK_EQ(tgt, Target);
        CHECK(names.count(Path.substr(4)));
    }
    checkReaddirSubsetGetattr(S, "app");
    //A rename copies the link up as a link, not as the bytes of its target.
    CHECK_EQ(VfsRename(S, "app/entrypoint", "app/entry2"), 0);
    std::error_code ec;
    CHECK(fs::is_symlink(fs::symlink_status(t / "wl/app/entry2", ec)));
    CHECK_EQ(fs::read_symlink(t / "wl/app/entry2", ec).string(), std::string("/nix/store/abc-bbport-0.1/bin/bbport"));
}

// A link entry whose stored target is longer than any path is no link: it does not exist in the layer, and nothing
// allocates the size the archive claims for it. Teeth: serve it (readlink allocates and returns 5000 bytes).
TEST(zip_link_with_an_outsized_target_does_not_exist) {
    TmpDir t;
    writeStoreZip(t / "a.zip", { { "app/ok.txt", "x", false }, { "app/huge", std::string(5000, 'a'), true } });
    Spec sp; sp.layers = { zipLayer(t.str("a.zip")) };
    VfsState S; std::string err; CHECK(S.Init(sp, err));
    VfsAttr a;
    CHECK_EQ(VfsGetattr(S, "app/huge", a), -ENOENT);
    std::string tgt;
    CHECK(VfsReadlink(S, "app/huge", tgt) != 0);
    CHECK(tgt.empty());
    CHECK(!readdirNames(S, "app").count("huge"));
    checkReaddirSubsetGetattr(S, "app");
}

// Case-insensitive names (a Windows mount): a program asks for "AGE2_X1\\DATA\\GRAPHICS.DRS" in a package that spells it
// "age2_x1/Data/graphics.drs"; the mount answers in the package's case, and a name being made keeps its own after
// the known part. For a name two layers spell, the lowest layer's spelling wins. Teeth: CanonicalCase returning its
// input finds nothing.
TEST(case_insensitive_names_take_the_package_case) {
    TmpDir t;
    writeStoreZip(t / "base.zip", { { "Data/graphics.drs", "drs", false }, { "Data/Sub/", "", false } });
    writeStoreZip(t / "patch.zip", { { "DATA/new.dat", "new", false } });
    Spec sp; sp.caseInsensitive = true;
    sp.layers = { zipLayer(t.str("base.zip"), "drive_c/749/age2_x1"), zipLayer(t.str("patch.zip"), "drive_c/749/age2_x1") };
    VfsState S; std::string err; CHECK(S.Init(sp, err));
    CHECK_EQ(CanonicalCase(S, "DRIVE_C/749/AGE2_X1/DATA/GRAPHICS.DRS"), std::string("drive_c/749/age2_x1/Data/graphics.drs"));
    CHECK_EQ(CanonicalCase(S, "drive_c/749/AGE2_X1/data/SUB"), std::string("drive_c/749/age2_x1/Data/Sub"));
    // A name only one layer has keeps that layer's spelling, so its zip finds it (packages make a name shared across
    // layers agree: the case resolver, FixCaseConflicts).
    CHECK_EQ(CanonicalCase(S, "drive_c/749/age2_x1/data/NEW.DAT"), std::string("drive_c/749/age2_x1/DATA/new.dat"));
    CHECK_EQ(CanonicalCase(S, "drive_c/749/age2_x1/data/Saves/Slot1.SAV"), std::string("drive_c/749/age2_x1/Data/Saves/Slot1.SAV"));
    CHECK_EQ(CanonicalCase(S, "Elsewhere/X"), std::string("Elsewhere/X"));
    VfsAttr a;
    CHECK_EQ(VfsGetattr(S, CanonicalCase(S, "drive_c/749/age2_x1/data/GRAPHICS.drs"), a), 0);
    CHECK_EQ(a.size, (uint64_t)3);
    CHECK_EQ(VfsGetattr(S, CanonicalCase(S, "drive_c/749/age2_x1/data/NEW.DAT"), a), 0);

    Spec cs = sp; cs.caseInsensitive = false;   // Linux: names as spelled
    VfsState C; CHECK(C.Init(cs, err));
    CHECK_EQ(CanonicalCase(C, "DRIVE_C/749/AGE2_X1/DATA/GRAPHICS.DRS"), std::string("DRIVE_C/749/AGE2_X1/DATA/GRAPHICS.DRS"));
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

// A delta reads the layer it NAMES, not the one beneath it at its target: here a decoy zip sits at the delta's
// target and the base is at the mount root. Teeth: base a delta on whatever lies beneath its target.
TEST(a_delta_reads_the_base_it_names_not_the_layer_beneath_it) {
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

    // The delta mounts at "sub" — where the DECOY is — but names the root zip. Read the wrong base and the
    // reconstruction fails outright, and "sub/ft.bin" is absent.
    std::ostringstream js;
    js << "{\"mountpoint\":\"" << t.str("mnt") << "\",\"readonly\":true,\"layers\":["
       << "{\"type\":\"zip\",\"source\":\"" << t.str("root.zip") << "\",\"target\":\"\",\"cid\":\"QmRoot\"},"
       << "{\"type\":\"zip\",\"source\":\"" << t.str("decoy.zip") << "\",\"target\":\"sub\",\"cid\":\"QmDecoy\"},"
       << "{\"type\":\"delta\",\"source\":\"" << t.str("d.vgdelta") << "\",\"target\":\"sub\","
       <<  "\"bases\":[\"QmRoot\"]}]}";
    writeFile(t / "spec.json", js.str());

    Spec sp; std::string err;
    CHECK(ParseSpec(t.str("spec.json"), sp, err));
    CHECK_EQ(sp.layers.size(), size_t(3));
    CHECK(sp.layers[2].bases == std::vector<std::string>{ "QmRoot" });

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

// A malformed base list is REFUSED, not quietly repaired: a concatenation missing one part, or reading a layer that is
// not there, is a base of the wrong bytes, which fails the delta's check and costs the layer its content with nothing
// said. And a delta that names nothing is refused: there is no implicit base.
TEST(a_malformed_base_list_is_refused) {
    TmpDir t;
    writeStoreZip(t / "a.zip", { { "x", "x", false } });
    //The base list belongs to a DELTA layer — a zip has no byte-base, so hanging one on a zip would pin a
    //shape that means nothing and quietly assert the parser accepts it there.
    { std::ofstream o(t / "d.vgdelta", std::ios::binary); o << "x"; }
    auto spec = [&](const std::string &bases) {
        std::ostringstream js;
        js << "{\"mountpoint\":\"" << t.str("mnt") << "\",\"readonly\":true,\"layers\":["
           << "{\"type\":\"zip\",\"source\":\"" << t.str("a.zip") << "\",\"target\":\"a\",\"cid\":\"QmA\"},"
           << "{\"type\":\"delta\",\"source\":\"" << t.str("d.vgdelta") << "\",\"target\":\"b\""
           << (bases.empty() ? "" : ",\"bases\":" + bases) << "}]}";
        writeFile(t / "spec.json", js.str());
        Spec sp; std::string err;
        const bool ok = ParseSpec(t.str("spec.json"), sp, err);
        return std::make_pair(ok, err);
    };
    CHECK(!spec("").first);                           // no bases: a delta names what it was built over
    CHECK(spec("[]").first);                          // an empty list parses: the plan reports the delta (it names no base)
    CHECK(!spec("[\"QmA\", 7]").first);               // a non-CID entry
    CHECK(!spec("[\"\"]").first);                     // an empty CID
    CHECK(!spec("\"QmA\"").first);                    // a bare CID where a list belongs
    CHECK(!spec("[\"QmA\", \"QmA\"]").first);         // one file named twice
    {   // a cid on a layer that is not a zip or a delta, and bases on a layer that is not a delta
        std::ostringstream js;
        js << "{\"mountpoint\":\"" << t.str("mnt") << "\",\"readonly\":true,\"layers\":["
           << "{\"type\":\"dir\",\"source\":\"" << t.str(".") << "\",\"target\":\"a\"},"
           << "{\"type\":\"dir\",\"source\":\"" << t.str(".") << "\",\"target\":\"c\",\"cid\":\"QmD\"}]}";
        writeFile(t / "spec.json", js.str());
        Spec sp; std::string err;
        CHECK(!ParseSpec(t.str("spec.json"), sp, err));       // only a zip or a delta carries a cid
        std::ostringstream js2;
        js2 << "{\"mountpoint\":\"" << t.str("mnt") << "\",\"readonly\":true,\"layers\":["
            << "{\"type\":\"zip\",\"source\":\"" << t.str("a.zip") << "\",\"target\":\"a\"},"
            << "{\"type\":\"zip\",\"source\":\"" << t.str("a.zip") << "\",\"target\":\"b\",\"bases\":[\"QmA\"]}]}";
        writeFile(t / "spec.json", js2.str());
        CHECK(!ParseSpec(t.str("spec.json"), sp, err));
    }
    const auto Ok = spec("[\"QmA\"]");                // ...and the well-formed shape still parses (a CID no layer carries is the plan's to report)
    CHECK(Ok.first);
    if (!Ok.first) std::cerr << "    parse error was: " << Ok.second << "\n";
}

// END TO END, through the REAL handoff: the spec JSON VidyaGod writes → ParseSpec → VfsState::Init → a read.
// The pieces above (ConcatByteSource, DeltaByteSource) were already unit-tested while the FLOW into them was
// dead — the bases never reached a spec because the mount builder only read the singular key. A unit
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

    // The spec exactly as VidyaGod's BuildLayerSpec writes it — each zip's `cid`, the delta's `bases` by CID, in order.
    std::ostringstream js;
    js << "{\"mountpoint\":\"" << t.str("mnt") << "\",\"readonly\":true,\"layers\":["
       << "{\"type\":\"zip\",\"source\":\"" << t.str("a.zip") << "\",\"target\":\"a\",\"cid\":\"QmA\"},"
       << "{\"type\":\"zip\",\"source\":\"" << t.str("b.zip") << "\",\"target\":\"b\",\"cid\":\"QmB\"},"
       << "{\"type\":\"delta\",\"source\":\"" << t.str("c.vgdelta") << "\",\"target\":\"c\","
       <<  "\"bases\":[\"QmA\",\"QmB\"]}]}";
    writeFile(t / "spec.json", js.str());

    Spec sp; std::string err;
    CHECK(ParseSpec(t.str("spec.json"), sp, err));
    CHECK_EQ(sp.layers.size(), size_t(3));
    CHECK(sp.layers[2].bases == (std::vector<std::string>{ "QmA", "QmB" }));

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

// One delta-built node contained TWICE at one target: whole, and again with a TAKE renaming a folder of it (a
// runner taking wine-mono-11.3.0 as "wine-mono" too, the link its build shipped). One file, placed twice: each delta
// copy surfaces (whole, and its renamed folder), and every placement of the base beneath them is hidden.
TEST(a_delta_chain_contained_twice_at_one_target_mounts_both) {
    TmpDir t;
    std::string f1(3000, 'q'); for (size_t i = 0; i < f1.size(); ++i) f1[i] = char('a' + (i * 5) % 26);
    std::string f2 = f1; f2.insert(1000, "VERSION-TWO-VERSION-TWO");
    writeStoreZip(t / "base.zip", { { "mono-1.0/lib.bin", f1, false } });
    writeStoreZip(t / "next.zip", { { "mono-2.0/lib.bin", f2, false } });
    auto slurp = [](const fs::path &p) {
        std::ifstream f(p, std::ios::binary);
        return std::string((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    };
    const std::string b = slurp(t / "base.zip"), n = slurp(t / "next.zip");
    auto delta = vgdelta::GenerateDelta((const uint8_t *)b.data(), b.size(), (const uint8_t *)n.data(), n.size());
    { std::ofstream o(t / "next.vgdelta", std::ios::binary); o.write((const char *)delta.data(), (std::streamsize)delta.size()); }
    std::ostringstream js;
    js << "{\"mountpoint\":\"" << t.str("mnt") << "\",\"readonly\":true,\"layers\":["
       << "{\"type\":\"zip\",\"source\":\"" << t.str("base.zip") << "\",\"target\":\"share/mono\",\"cid\":\"QmBase\"},"
       << "{\"type\":\"delta\",\"source\":\"" << t.str("next.vgdelta") << "\",\"target\":\"share/mono\",\"cid\":\"QmNext\",\"bases\":[\"QmBase\"]},"
       << "{\"type\":\"zip\",\"source\":\"" << t.str("base.zip") << "\",\"target\":\"share/mono\",\"cid\":\"QmBase\",\"submounts\":[\"mono-2.0:share/mono/mono\"]},"
       << "{\"type\":\"delta\",\"source\":\"" << t.str("next.vgdelta") << "\",\"target\":\"share/mono\",\"cid\":\"QmNext\",\"bases\":[\"QmBase\"],\"submounts\":[\"mono-2.0:share/mono/mono\"]}]}";
    writeFile(t / "spec.json", js.str());
    Spec sp; std::string err;
    CHECK(ParseSpec(t.str("spec.json"), sp, err));
    VfsState S;
    CHECK(S.Init(sp, err));
    VfsAttr at;
    CHECK_EQ(VfsGetattr(S, "share/mono/mono-2.0/lib.bin", at), 0);   // the first occurrence, whole
    CHECK_EQ(at.size, (uint64_t)f2.size());
    CHECK_EQ(VfsGetattr(S, "share/mono/mono/lib.bin", at), 0);       // the second: its folder, renamed
    CHECK_EQ(at.size, (uint64_t)f2.size());
    CHECK(VfsGetattr(S, "share/mono/mono-1.0/lib.bin", at) != 0);    // the chain's base is a byte input only
}

// A delta replaces its BASE, not everything at its target. A Steam game ships one zip per depot, and a language
// depot's files land in the game root beside the main depot's: its version chain (v1 zip + delta) at the root must
// hide v1's dropped file and leave the main depot alone. Teeth: the old rule (a delta masks every lower layer
// under its target) hid the whole game.
static std::string slurpFile(const fs::path &p) {
    std::ifstream f(p, std::ios::binary);
    return std::string((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
}
static void writeDelta(const fs::path &out, const std::string &base, const fs::path &tgtZip) {
    const std::string tgt = slurpFile(tgtZip);
    auto d = vgdelta::GenerateDelta((const uint8_t *)base.data(), base.size(), (const uint8_t *)tgt.data(), tgt.size());
    std::ofstream o(out, std::ios::binary); o.write((const char *)d.data(), (std::streamsize)d.size());
}
// A delta over the files it names (by their paths, the CIDs zipLayer and deltaLayer give them).
static LayerSpec deltaLayer(const std::string &src, const std::string &target, std::vector<std::string> bases) {
    LayerSpec L; L.type = LayerType::Delta; L.source = src; L.cid = src; L.target = NormalizeVPath(target); L.bases = std::move(bases);
    return L;
}

TEST(a_delta_hides_its_base_and_not_another_depot_beneath_it) {
    TmpDir t;
    std::string pak(5000, 'p'); for (size_t i = 0; i < pak.size(); ++i) pak[i] = char('a' + (i * 3) % 26);
    writeStoreZip(t / "main.zip", { { "Data/main.pak", "MAIN", false }, { "Localization/readme.txt", "MAIN-README", false } });
    writeStoreZip(t / "en1.zip", { { "Localization/english.pak", pak, false }, { "Localization/old.pak", "DROPPED", false } });
    writeStoreZip(t / "en2.zip", { { "Localization/english.pak", pak + "PATCHED", false } });
    writeDelta(t / "en2.vgdelta", slurpFile(t / "en1.zip"), t / "en2.zip");

    Spec sp; sp.readOnly = true;
    sp.layers = { zipLayer(t.str("main.zip")), zipLayer(t.str("en1.zip")), deltaLayer(t.str("en2.vgdelta"), "", { t.str("en1.zip") }) };
    VfsState S; std::string err;
    CHECK(S.Init(sp, err));
    VfsAttr at;
    CHECK_EQ(VfsGetattr(S, "Data/main.pak", at), 0);                     // the main depot shows through
    CHECK_EQ(VfsGetattr(S, "Localization/readme.txt", at), 0);           // even in a folder the delta also has
    CHECK_EQ(VfsGetattr(S, "Localization/english.pak", at), 0);          // the language depot at its newer version
    CHECK_EQ(at.size, (uint64_t)pak.size() + 7);
    CHECK(VfsGetattr(S, "Localization/old.pak", at) != 0);               // what the newer version dropped stays gone
    CHECK(readdirNames(S, "") == (std::set<std::string>{ "Data", "Localization" }));
    CHECK(readdirNames(S, "Localization") == (std::set<std::string>{ "english.pak", "readme.txt" }));
    checkReaddirSubsetGetattr(S, "Localization");
}

// A zip stacked over a delta is an ordinary layer above it, never folded into it: a no-CD exe over a delta-converted
// base wins (Halo CE served the retail SafeDisc exe when overlays above a chain were folded away). Teeth: hide or fold
// the layers above a delta at its target.
TEST(a_zip_above_a_delta_is_an_overlay_above_it) {
    TmpDir t;
    std::string game(4000, 'g'); for (size_t i = 0; i < game.size(); ++i) game[i] = char('a' + (i * 7) % 26);
    writeStoreZip(t / "v1.zip", { { "game.exe", game, false }, { "old.dll", "OLD", false } });
    writeStoreZip(t / "v2.zip", { { "game.exe", game + "V2", false } });
    writeStoreZip(t / "nocd.zip", { { "game.exe", "NOCD", false } });
    writeDelta(t / "v2.vgdelta", slurpFile(t / "v1.zip"), t / "v2.zip");
    Spec sp; sp.readOnly = true;
    sp.layers = { zipLayer(t.str("v1.zip")), deltaLayer(t.str("v2.vgdelta"), "", { t.str("v1.zip") }), zipLayer(t.str("nocd.zip")) };
    VfsState S; std::string err;
    CHECK(S.Init(sp, err));
    VfsAttr at;
    CHECK_EQ(VfsGetattr(S, "game.exe", at), 0);
    CHECK_EQ(at.size, (uint64_t)4);                                      // the overlay's exe
    CHECK(VfsGetattr(S, "old.dll", at) != 0);                            // v1, replaced by its delta
}

// A delta that does not reconstruct (it names the wrong bytes) mounts nothing, and HIDES nothing: what it named stays
// as it was, so the failure shows as the old version rather than an empty game. Teeth: hide a delta's bases before
// knowing it rebuilt.
TEST(a_delta_that_does_not_rebuild_hides_nothing) {
    TmpDir t;
    std::string game(4000, 'g'); for (size_t i = 0; i < game.size(); ++i) game[i] = char('a' + (i * 7) % 26);
    writeStoreZip(t / "v1.zip", { { "game.exe", game, false } });
    writeStoreZip(t / "other.zip", { { "other.bin", game + "OTHER-BYTES", false } });
    writeStoreZip(t / "v2.zip", { { "game.exe", game + "V2", false } });
    writeDelta(t / "v2.vgdelta", slurpFile(t / "v1.zip"), t / "v2.zip");
    Spec sp; sp.readOnly = true;
    sp.layers = { zipLayer(t.str("v1.zip")), zipLayer(t.str("other.zip")), deltaLayer(t.str("v2.vgdelta"), "", { t.str("other.zip") }) };
    VfsState S; std::string err;
    CHECK(S.Init(sp, err));
    VfsAttr at;
    CHECK_EQ(VfsGetattr(S, "game.exe", at), 0);
    CHECK_EQ(at.size, (uint64_t)game.size());                            // v1, the delta did not mount
    CHECK_EQ(VfsGetattr(S, "other.bin", at), 0);                         // the base it misnamed is still there
}

// A base surfacing at two places (a TAKE projecting two folders of one archive), one inside its delta and one outside,
// keeps the one outside: only a base hidden at EVERY place is a byte input only. Teeth: drop it when any place is
// inside the delta.
TEST(a_base_partly_outside_its_delta_keeps_the_rest) {
    TmpDir t;
    std::string game(4000, 'g'); for (size_t i = 0; i < game.size(); ++i) game[i] = char('a' + (i * 7) % 26);
    writeStoreZip(t / "v1.zip", { { "bin/game.exe", game, false }, { "docs/manual.txt", "MANUAL", false } });
    writeStoreZip(t / "v2.zip", { { "bin/game.exe", game + "V2", false } });
    writeDelta(t / "v2.vgdelta", slurpFile(t / "v1.zip"), t / "v2.zip");
    LayerSpec v1 = zipLayer(t.str("v1.zip"));
    v1.submounts = { { "bin", "g/bin" }, { "docs", "manual" } };
    Spec sp; sp.readOnly = true;
    sp.layers = { v1, deltaLayer(t.str("v2.vgdelta"), "g", { t.str("v1.zip") }) };
    VfsState S; std::string err;
    CHECK(S.Init(sp, err));
    VfsAttr at;
    CHECK_EQ(VfsGetattr(S, "manual/manual.txt", at), 0);                 // the place outside the delta
    CHECK_EQ(VfsGetattr(S, "g/bin/game.exe", at), 0);                    // the delta's own tree
    CHECK_EQ(at.size, (uint64_t)game.size() + 2);
}

// A bytes-only layer (a base no TAKE shows) is read by the delta that names it and surfaces nowhere. Teeth: surface it.
TEST(a_bytes_only_base_feeds_its_delta_and_shows_nowhere) {
    TmpDir t;
    std::string game(4000, 'g'); for (size_t i = 0; i < game.size(); ++i) game[i] = char('a' + (i * 7) % 26);
    writeStoreZip(t / "win.zip", { { "game.exe", game, false } });
    writeStoreZip(t / "mac.zip", { { "Game.app/game", game + "MAC", false } });
    writeDelta(t / "mac.vgdelta", slurpFile(t / "win.zip"), t / "mac.zip");
    LayerSpec win = zipLayer(t.str("win.zip"), "win");
    win.bytesOnly = true;
    Spec sp; sp.readOnly = true;
    sp.layers = { win, deltaLayer(t.str("mac.vgdelta"), "mac", { t.str("win.zip") }) };
    VfsState S; std::string err;
    CHECK(S.Init(sp, err));
    VfsAttr at;
    CHECK_EQ(VfsGetattr(S, "mac/Game.app/game", at), 0);
    CHECK(VfsGetattr(S, "win", at) != 0);
}

// One file placed twice beneath its delta (a package containing Base, and a Patch that contains Base again plus a
// delta over it): EVERY placement inside the delta's target is hidden, so what the new version dropped never leaks.
// Teeth: hide only the copy nearest the delta.
TEST(every_placement_of_a_base_beneath_its_delta_is_hidden) {
    TmpDir t;
    std::string game(4000, 'g'); for (size_t i = 0; i < game.size(); ++i) game[i] = char('a' + (i * 7) % 26);
    writeStoreZip(t / "v1.zip", { { "game.exe", game, false }, { "old.dll", "DROPPED", false } });
    writeStoreZip(t / "v2.zip", { { "game.exe", game + "V2", false } });
    writeDelta(t / "v2.vgdelta", slurpFile(t / "v1.zip"), t / "v2.zip");
    Spec sp; sp.readOnly = true;
    sp.layers = { zipLayer(t.str("v1.zip"), "g"), zipLayer(t.str("v1.zip"), "g"), deltaLayer(t.str("v2.vgdelta"), "g", { t.str("v1.zip") }) };
    VfsState S; std::string err;
    CHECK(S.Init(sp, err));
    VfsAttr at;
    CHECK(VfsGetattr(S, "g/old.dll", at) != 0);
    CHECK_EQ(VfsGetattr(S, "g/game.exe", at), 0);
    CHECK_EQ(at.size, (uint64_t)game.size() + 2);
}

// A base's bytes are its file's wherever it is placed — even above its delta (a macOS build listed before the Windows
// depots it is built over); only what lies BENEATH a delta is hidden by it. Teeth: look for bases beneath only.
TEST(a_base_placed_above_its_delta_still_gives_its_bytes) {
    TmpDir t;
    std::string game(4000, 'g'); for (size_t i = 0; i < game.size(); ++i) game[i] = char('a' + (i * 7) % 26);
    writeStoreZip(t / "win.zip", { { "game.exe", game, false } });
    writeStoreZip(t / "mac.zip", { { "Game.app/game", game + "MAC", false } });
    writeDelta(t / "mac.vgdelta", slurpFile(t / "win.zip"), t / "mac.zip");
    Spec sp; sp.readOnly = true;
    sp.layers = { deltaLayer(t.str("mac.vgdelta"), "", { t.str("win.zip") }), zipLayer(t.str("win.zip"), "") };
    VfsState S; std::string err;
    CHECK(S.Init(sp, err));
    VfsAttr at;
    CHECK_EQ(VfsGetattr(S, "Game.app/game", at), 0);
    CHECK_EQ(VfsGetattr(S, "game.exe", at), 0);                          // above it, so never hidden by it
}

// A delta naming a file nothing here carries, or two deltas naming each other, cannot rebuild: the plan says so by
// name, the mount leaves them out, and the rest mounts. Teeth: drop the problem; loop on the ring.
TEST(a_delta_with_no_file_for_its_base_or_a_ring_is_reported_and_left_out) {
    TmpDir t;
    writeStoreZip(t / "z.zip", { { "z.txt", "Z", false } });
    { std::ofstream(t / "a.vgdelta") << "x"; std::ofstream(t / "b.vgdelta") << "x"; std::ofstream(t / "c.vgdelta") << "x"; }
    Spec sp; sp.readOnly = true;
    sp.layers = { zipLayer(t.str("z.zip")), deltaLayer(t.str("a.vgdelta"), "a", { t.str("b.vgdelta") }),
                  deltaLayer(t.str("b.vgdelta"), "b", { t.str("a.vgdelta") }), deltaLayer(t.str("c.vgdelta"), "c", { "QmNowhere" }) };
    const TreePlan P = PlanTree(sp);
    CHECK(P.broken[1] && P.broken[2] && P.broken[3] && !P.broken[0]);
    CHECK_EQ(P.problems.size(), size_t(3));
    bool Named = false, Ring = false;
    for (const auto &Pr : P.problems) { Named = Named || Pr.find("QmNowhere") != std::string::npos; Ring = Ring || Pr.find("ring") != std::string::npos; }
    CHECK(Named && Ring);
    VfsState S; std::string err;
    CHECK(S.Init(sp, err));
    VfsAttr at;
    CHECK_EQ(VfsGetattr(S, "z.txt", at), 0);
    CHECK(VfsGetattr(S, "c", at) != 0);
}

// A bytes-only delta (no TAKE shows it; another delta reads it) appears nowhere, so it hides nothing: the base it was
// built over stays where the package placed it. Teeth: give a bytes-only layer its target as a place.
TEST(a_bytes_only_delta_hides_nothing) {
    TmpDir t;
    std::string game(4000, 'g'); for (size_t i = 0; i < game.size(); ++i) game[i] = char('a' + (i * 7) % 26);
    writeStoreZip(t / "v1.zip", { { "game.exe", game, false } });
    writeStoreZip(t / "v2.zip", { { "game.exe", game + "V2", false } });
    writeStoreZip(t / "v3.zip", { { "game.exe", game + "V23", false } });
    writeDelta(t / "v2.vgdelta", slurpFile(t / "v1.zip"), t / "v2.zip");
    writeDelta(t / "v3.vgdelta", slurpFile(t / "v2.zip"), t / "v3.zip");
    LayerSpec D2 = deltaLayer(t.str("v2.vgdelta"), "g", { t.str("v1.zip") });
    D2.bytesOnly = true;
    Spec sp; sp.readOnly = true;
    sp.layers = { zipLayer(t.str("v1.zip"), "g"), D2, deltaLayer(t.str("v3.vgdelta"), "out", { t.str("v2.vgdelta") }) };
    VfsState S; std::string err;
    CHECK(S.Init(sp, err));
    VfsAttr at;
    CHECK_EQ(VfsGetattr(S, "g/game.exe", at), 0);
    CHECK_EQ(at.size, (uint64_t)game.size());                            // v1, still there
    CHECK_EQ(VfsGetattr(S, "out/game.exe", at), 0);
    CHECK_EQ(at.size, (uint64_t)game.size() + 3);
}

// A delta over a bytes-only delta replaces what that one was rebuilt from too: v1 at g, v2 read only for its bytes,
// v3 at g over v2 — v1's dropped file does not leak. Teeth: replace only the CIDs a delta names itself.
TEST(a_delta_replaces_what_its_bases_were_rebuilt_from) {
    TmpDir t;
    std::string game(4000, 'g'); for (size_t i = 0; i < game.size(); ++i) game[i] = char('a' + (i * 7) % 26);
    writeStoreZip(t / "v1.zip", { { "game.exe", game, false }, { "old.dll", "DROPPED", false } });
    writeStoreZip(t / "v2.zip", { { "game.exe", game + "V2", false } });
    writeStoreZip(t / "v3.zip", { { "game.exe", game + "V23", false } });
    writeDelta(t / "v2.vgdelta", slurpFile(t / "v1.zip"), t / "v2.zip");
    writeDelta(t / "v3.vgdelta", slurpFile(t / "v2.zip"), t / "v3.zip");
    LayerSpec D2 = deltaLayer(t.str("v2.vgdelta"), "g", { t.str("v1.zip") });
    D2.bytesOnly = true;
    Spec sp; sp.readOnly = true;
    sp.layers = { zipLayer(t.str("v1.zip"), "g"), D2, deltaLayer(t.str("v3.vgdelta"), "g", { t.str("v2.vgdelta") }) };
    VfsState S; std::string err;
    CHECK(S.Init(sp, err));
    VfsAttr at;
    CHECK(VfsGetattr(S, "g/old.dll", at) != 0);
    CHECK_EQ(VfsGetattr(S, "g/game.exe", at), 0);
    CHECK_EQ(at.size, (uint64_t)game.size() + 3);
}

// Two versions of a chain that do not rebuild (a partial download: v3's and v4's deltas gone): the mount surfaces what
// each failure stopped hiding, until none is left — v2, not an empty tree. Teeth: stop re-planning after one round.
TEST(failures_found_while_surfacing_are_followed_down_the_chain) {
    TmpDir t;
    std::string game(4000, 'g'); for (size_t i = 0; i < game.size(); ++i) game[i] = char('a' + (i * 7) % 26);
    writeStoreZip(t / "v1.zip", { { "game.exe", game, false } });
    writeStoreZip(t / "v2.zip", { { "game.exe", game + "V2", false } });
    writeDelta(t / "v2.vgdelta", slurpFile(t / "v1.zip"), t / "v2.zip");
    Spec sp; sp.readOnly = true;
    sp.layers = { zipLayer(t.str("v1.zip"), "g"), deltaLayer(t.str("v2.vgdelta"), "g", { t.str("v1.zip") }),
                  deltaLayer(t.str("v3.vgdelta"), "g", { t.str("v2.vgdelta") }), deltaLayer(t.str("v4.vgdelta"), "g", { t.str("v3.vgdelta") }) };
    VfsState S; std::string err;
    CHECK(S.Init(sp, err));
    VfsAttr at;
    CHECK_EQ(VfsGetattr(S, "g/game.exe", at), 0);
    CHECK_EQ(at.size, (uint64_t)game.size() + 2);
}

// What hides a file a delta names reaches that delta's own bases beneath IT, not only beneath the delta: v2 (bytes only)
// sits below v1's placement, v3 above both replaces v2 — and so v1, though v1 lies above v2. Teeth: bound the inherited
// hiding by the delta that names the base instead of the one that hides.
TEST(inherited_hiding_reaches_up_to_the_delta_that_hides) {
    TmpDir t;
    std::string game(4000, 'g'); for (size_t i = 0; i < game.size(); ++i) game[i] = char('a' + (i * 7) % 26);
    writeStoreZip(t / "v1.zip", { { "game.exe", game, false }, { "old.dll", "DROPPED", false } });
    writeStoreZip(t / "v2.zip", { { "game.exe", game + "V2", false } });
    writeStoreZip(t / "v3.zip", { { "game.exe", game + "V23", false } });
    writeDelta(t / "v2.vgdelta", slurpFile(t / "v1.zip"), t / "v2.zip");
    writeDelta(t / "v3.vgdelta", slurpFile(t / "v2.zip"), t / "v3.zip");
    LayerSpec D2 = deltaLayer(t.str("v2.vgdelta"), "g", { t.str("v1.zip") });
    D2.bytesOnly = true;
    Spec sp; sp.readOnly = true;
    sp.layers = { D2, zipLayer(t.str("v1.zip"), "g"), deltaLayer(t.str("v3.vgdelta"), "g", { t.str("v2.vgdelta") }) };
    VfsState S; std::string err;
    CHECK(S.Init(sp, err));
    VfsAttr at;
    CHECK(VfsGetattr(S, "g/old.dll", at) != 0);
    CHECK_EQ(VfsGetattr(S, "g/game.exe", at), 0);
    CHECK_EQ(at.size, (uint64_t)game.size() + 3);
}

// A version chain holds one rebuilt map at a time: each base's bytes are released once the last delta over it is
// built, unless it surfaces. Teeth: keep every view built (a 900-version chain held 900 maps at mount).
TEST(a_chain_releases_each_version_once_the_next_is_built) {
    TmpDir t;
    std::string game(4000, 'g'); for (size_t i = 0; i < game.size(); ++i) game[i] = char('a' + (i * 7) % 26);
    writeStoreZip(t / "v0.zip", { { "game.exe", game, false } });
    Spec sp; sp.readOnly = true;
    sp.layers = { zipLayer(t.str("v0.zip"), "g") };
    std::string prev = slurpFile(t / "v0.zip");
    for (int v = 1; v <= 4; ++v)
    {
        const std::string n = "v" + std::to_string(v);
        writeStoreZip(t / (n + ".zip"), { { "game.exe", game + n, false } });
        writeDelta(t / (n + ".vgdelta"), prev, t / (n + ".zip"));
        prev = slurpFile(t / (n + ".zip"));
        sp.layers.push_back(deltaLayer(t.str(n + ".vgdelta"), "g", { sp.layers.back().cid }));
    }
    const TreePlan P = PlanTree(sp);
    std::vector<bool> Keep(sp.layers.size(), false);
    Keep.back() = true;
    LayerBytes B(sp, P, Keep);
    auto Top = B.Get(sp.layers.size() - 1);
    CHECK(Top != nullptr);
    CHECK_EQ(B.Held(), size_t(1));
}

// The tree's case conflicts, as the mount places names: a hidden base spells nothing, a TAKE-moved folder collides
// where it lands, and one file mounted twice is no conflict with itself. Renames follow the tree's first spelling,
// back through the mount that put the name there. Teeth: ignore masks; ignore mounts; compare sources.
TEST(case_conflicts_and_renames_follow_the_tree) {
    Spec sp; sp.readOnly = true;
    LayerSpec A = zipLayer("/a.zip"), B = zipLayer("/b.zip"), C = zipLayer("/c.zip"), A2 = zipLayer("/a.zip");
    C.submounts = { { "inner/Data", "data" } };              // its inner/Data lands at data
    sp.layers = { A, B, C, A2 };
    const std::map<size_t, std::vector<std::string>> E = {
        { 0, { "Data/x.dat", "Data/" } }, { 1, { "DATA/x.dat" } }, { 2, { "inner/Data/w.dat", "w.dat" } }, { 3, { "Data/x.dat" } } };
    const EntriesFn Fn = [&](size_t I) { return &E.at(I); };
    const TreePlan P = PlanTree(sp);
    const auto Cs = CaseConflicts(sp, P, Fn);
    CHECK_EQ(Cs.size(), size_t(1));                           // "data" once, a folder: DATA (b) against Data (a)
    if (!Cs.empty()) { CHECK_EQ(Cs[0].key, std::string("data")); CHECK(Cs[0].dir); CHECK_EQ(Cs[0].first, size_t(0)); CHECK_EQ(Cs[0].second, size_t(1)); }
    {   // c's folder lands at data: against a's Data/w.dat it collides where it lands, not where its source holds it
        Spec Two; Two.readOnly = true;
        Two.layers = { A, C };
        const std::map<size_t, std::vector<std::string>> E3 = { { 0, { "Data/w.dat" } }, { 1, { "inner/Data/w.dat" } } };
        const EntriesFn Fn3 = [&](size_t I) { return &E3.at(I); };
        CHECK_EQ(CaseConflicts(Two, PlanTree(Two), Fn3).size(), size_t(1));
    }
    {   // one cache across trees: a listing mounted at another place is prepared again, not reused from the first
        PreparedNames Cache;
        Spec At; At.readOnly = true;
        At.layers = { zipLayer("/a.zip", "data"), zipLayer("/b.zip") };
        const std::map<size_t, std::vector<std::string>> Ea = { { 0, { "x.dat" } }, { 1, { "DATA/x.dat" } } };
        Spec Root; Root.readOnly = true;
        Root.layers = { zipLayer("/a.zip", "elsewhere"), zipLayer("/b.zip") };
        const std::vector<std::string> Shared = { "x.dat" }, Other = { "DATA/x.dat" };
        const EntriesFn Fa = [&](size_t I) { return I == 0 ? &Shared : &Other; };
        CHECK_EQ(CaseConflicts(At, PlanTree(At), Fa, &Cache).size(), size_t(1));       // data/x.dat vs DATA/x.dat
        CHECK(CaseConflicts(Root, PlanTree(Root), Fa, &Cache).empty());                  // elsewhere/x.dat: nothing
        CHECK_EQ(CaseConflicts(At, PlanTree(At), Fa, &Cache).size(), size_t(1));       // and again, from the cache
        (void)Ea;
    }
    const auto R = CaseRenames(sp, P, Fn);
    CHECK(R.count(1) && R.at(1).at("DATA/x.dat") == "Data/x.dat");
    CHECK(!R.count(2));                                       // only its place would change case: not its entries to fix
    CHECK(!R.count(0) && !R.count(3));
    // A base hidden only partly (it reaches outside its delta) spells nothing where it is hidden; and names that collide
    // inside ONE archive are the upstream content's own, not a conflict between layers.
    {
        Spec P3; P3.readOnly = true;
        P3.layers = { zipLayer("/root.zip"), deltaLayer("/new.vgdelta", "g", { "/root.zip" }), zipLayer("/patch.zip", "g"), zipLayer("/own.zip", "o") };
        const std::map<size_t, std::vector<std::string>> E3 = { { 0, { "boot.ini", "g/LUXOR.exe" } }, { 1, { "readme.txt" } },
                                                                { 2, { "luxor.exe" } }, { 3, { "MAPS/foo", "maps/foo" } } };
        const EntriesFn Fn3 = [&](size_t I) { return &E3.at(I); };
        CHECK(CaseConflicts(P3, PlanTree(P3), Fn3).empty());
    }
    // A base hidden by its delta spells nothing.
    Spec sp2; sp2.readOnly = true;
    sp2.layers = { zipLayer("/old.zip", "g"), deltaLayer("/new.vgdelta", "g", { "/old.zip" }), zipLayer("/patch.zip", "g") };
    const std::map<size_t, std::vector<std::string>> E2 = { { 0, { "LUXOR.exe" } }, { 1, { "Luxor.exe" } }, { 2, { "LUXOR.exe" } } };
    const EntriesFn Fn2 = [&](size_t I) { return &E2.at(I); };
    const TreePlan P2 = PlanTree(sp2);
    const auto Cs2 = CaseConflicts(sp2, P2, Fn2);
    CHECK_EQ(Cs2.size(), size_t(1));
    if (!Cs2.empty()) { CHECK_EQ(Cs2[0].first, size_t(1)); CHECK_EQ(Cs2[0].second, size_t(2)); }
    const auto R2 = CaseRenames(sp2, P2, Fn2);
    CHECK(R2.count(2) && R2.at(2).at("LUXOR.exe") == "Luxor.exe");
}

// A base at ANOTHER address is hidden where the delta surfaces, wherever it was mounted: a game's CD
// music folder that a later release ships inside its own tree does not leak the tracks that release dropped, nor
// the folders only the old layout had. A base outside the delta's subtree keeps the rest of itself.
TEST(a_delta_hides_the_bases_it_names_under_itself_only) {
    TmpDir t;
    std::string game(4000, 'g'); for (size_t i = 0; i < game.size(); ++i) game[i] = char('a' + (i * 7) % 26);
    std::string track(3000, 't'); for (size_t i = 0; i < track.size(); ++i) track[i] = char('A' + (i * 5) % 26);
    writeStoreZip(t / "root.zip", { { "boot.ini", "ROOT", false }, { "g/old.cfg", "OLD-CFG", false } });
    writeStoreZip(t / "game.zip", { { "game.exe", game, false } });
    writeStoreZip(t / "music.zip", { { "track01.wav", track, false }, { "track02.wav", "DROPPED", false } });
    writeStoreZip(t / "cd/deep.zip", { { "x.bin", "DEEP", false } });    // mounted below a folder only the old layout had
    writeStoreZip(t / "new.zip", { { "game.exe", game + "1.1", false }, { "music/track01.wav", track, false } });
    writeDelta(t / "new.vgdelta", slurpFile(t / "root.zip") + slurpFile(t / "game.zip") + slurpFile(t / "music.zip")
                                      + slurpFile(t / "cd/deep.zip"), t / "new.zip");

    Spec sp; sp.readOnly = true;
    sp.layers = { zipLayer(t.str("root.zip")), zipLayer(t.str("game.zip"), "g"), zipLayer(t.str("music.zip"), "g/music"),
                  zipLayer(t.str("cd/deep.zip"), "g/cd/deep"),
                  deltaLayer(t.str("new.vgdelta"), "g", { t.str("root.zip"), t.str("game.zip"), t.str("music.zip"), t.str("cd/deep.zip") }) };
    VfsState S; std::string err;
    CHECK(S.Init(sp, err));
    VfsAttr at;
    CHECK_EQ(VfsGetattr(S, "g/game.exe", at), 0);
    CHECK_EQ(at.size, (uint64_t)game.size() + 3);
    CHECK_EQ(VfsGetattr(S, "g/music/track01.wav", at), 0);
    CHECK(VfsGetattr(S, "g/music/track02.wav", at) != 0);                // the dropped track
    CHECK(VfsGetattr(S, "g/cd", at) != 0);                                // a folder only a hidden base implied
    CHECK(VfsGetattr(S, "g/old.cfg", at) != 0);                           // the root base, under the delta
    CHECK_EQ(VfsGetattr(S, "boot.ini", at), 0);                           // ...keeps what lies outside it
    CHECK(readdirNames(S, "g") == (std::set<std::string>{ "game.exe", "music" }));
    CHECK(readdirNames(S, "g/music") == (std::set<std::string>{ "track01.wav" }));
    CHECK(readdirNames(S, "") == (std::set<std::string>{ "boot.ini", "g" }));
    checkReaddirSubsetGetattr(S, "g");
}

// A base named by a delta deep in a chain stays hidden under the chain's TOP: that delta is hidden whole by the top
// (a byte input only, it never surfaces), so it cannot hide anything itself; its bases carry up to whatever surfaces.
TEST(a_base_named_inside_a_chain_stays_hidden_under_its_top) {
    TmpDir t;
    std::string game(4000, 'g'); for (size_t i = 0; i < game.size(); ++i) game[i] = char('a' + (i * 7) % 26);
    writeStoreZip(t / "game.zip", { { "game.exe", game, false } });
    writeStoreZip(t / "music.zip", { { "track01.wav", "TRACK-ONE", false }, { "track02.wav", "DROPPED", false } });
    writeStoreZip(t / "v2.zip", { { "game.exe", game + "2", false }, { "music/track01.wav", "TRACK-ONE", false } });
    writeStoreZip(t / "v3.zip", { { "game.exe", game + "23", false }, { "music/track01.wav", "TRACK-ONE", false } });
    writeStoreZip(t / "root.zip", { { "boot.ini", "ROOT", false }, { "g/old.cfg", "OLD-CFG", false } });   // partly outside g
    writeDelta(t / "v2.vgdelta", slurpFile(t / "root.zip") + slurpFile(t / "game.zip") + slurpFile(t / "music.zip"), t / "v2.zip");
    writeDelta(t / "v3.vgdelta", slurpFile(t / "v2.zip"), t / "v3.zip");

    Spec sp; sp.readOnly = true;
    sp.layers = { zipLayer(t.str("root.zip")), zipLayer(t.str("game.zip"), "g"), zipLayer(t.str("music.zip"), "g/music"),
                  deltaLayer(t.str("v2.vgdelta"), "g", { t.str("root.zip"), t.str("game.zip"), t.str("music.zip") }), deltaLayer(t.str("v3.vgdelta"), "g", { t.str("v2.vgdelta") }) };
    VfsState S; std::string err;
    CHECK(S.Init(sp, err));
    VfsAttr at;
    CHECK(VfsGetattr(S, "g/old.cfg", at) != 0);                          // the root base, under the top (v2 never surfaced)
    CHECK_EQ(VfsGetattr(S, "boot.ini", at), 0);                          // ...and outside it, still there
    CHECK_EQ(VfsGetattr(S, "g/game.exe", at), 0);
    CHECK_EQ(at.size, (uint64_t)game.size() + 2);
    CHECK(VfsGetattr(S, "g/music/track02.wav", at) != 0);
    CHECK(readdirNames(S, "g/music") == (std::set<std::string>{ "track01.wav" }));
}

// A delta hides only what it names: a language depot's delta deduped over another address must not swallow the main
// depot beneath it at its target (whole, or the top of its own chain), and a zip a delta elsewhere names stays where it
// is. Teeth: hide what lies beneath a delta at its target.
TEST(a_delta_based_elsewhere_does_not_swallow_the_depot_beneath_it) {
    TmpDir t;
    std::string big(5000, 'b'); for (size_t i = 0; i < big.size(); ++i) big[i] = char('a' + (i * 11) % 26);
    writeStoreZip(t / "lang.zip", { { "Localization/english.pak", "ENGLISH", false } });
    writeStoreZip(t / "x.zip", { { "x.bin", big, false } });
    writeStoreZip(t / "main.zip", { { "game.exe", big + "MAIN", false } });
    writeDelta(t / "main.vgdelta", slurpFile(t / "x.zip"), t / "main.zip");
    {   // the language depot beneath a delta based at "x"
        Spec sp; sp.readOnly = true;
        sp.layers = { zipLayer(t.str("lang.zip")), zipLayer(t.str("x.zip"), "x"), deltaLayer(t.str("main.vgdelta"), "", { t.str("x.zip") }) };
        VfsState S; std::string err;
        CHECK(S.Init(sp, err));
        VfsAttr at;
        CHECK_EQ(VfsGetattr(S, "Localization/english.pak", at), 0);
        CHECK_EQ(VfsGetattr(S, "game.exe", at), 0);
        CHECK(VfsGetattr(S, "x/x.bin", at) != 0);                          // its base, inside its target
    }
    {   // the main depot's own chain beneath a language delta based at "x"
        writeStoreZip(t / "m1.zip", { { "game.exe", big, false } });
        writeStoreZip(t / "m2.zip", { { "game.exe", big + "V2", false } });
        writeDelta(t / "m2.vgdelta", slurpFile(t / "m1.zip"), t / "m2.zip");
        writeStoreZip(t / "l2.zip", { { "Localization/english.pak", big + "EN", false } });
        writeDelta(t / "l2.vgdelta", slurpFile(t / "x.zip"), t / "l2.zip");
        Spec sp; sp.readOnly = true;
        sp.layers = { zipLayer(t.str("m1.zip")), deltaLayer(t.str("m2.vgdelta"), "", { t.str("m1.zip") }), zipLayer(t.str("x.zip"), "x"),
                      deltaLayer(t.str("l2.vgdelta"), "", { t.str("x.zip") }) };
        VfsState S; std::string err;
        CHECK(S.Init(sp, err));
        VfsAttr at;
        CHECK_EQ(VfsGetattr(S, "game.exe", at), 0);
        CHECK_EQ(at.size, (uint64_t)big.size() + 2);
        CHECK_EQ(VfsGetattr(S, "Localization/english.pak", at), 0);
        CHECK(readdirNames(S, "") == (std::set<std::string>{ "Localization", "game.exe" }));
    }
    {   // a zip below every chain at "" is the byte view a delta elsewhere names
        writeStoreZip(t / "out.zip", { { "o.bin", big.substr(100, 4000) + "OUT", false } });
        writeDelta(t / "out.vgdelta", slurpFile(t / "main.zip"), t / "out.zip");
        Spec sp; sp.readOnly = true;
        sp.layers = { zipLayer(t.str("main.zip")), deltaLayer(t.str("out.vgdelta"), "out", { t.str("main.zip") }),
                      zipLayer(t.str("x.zip"), "x"), deltaLayer(t.str("l2.vgdelta"), "", { t.str("x.zip") }) };
        VfsState S; std::string err;
        CHECK(S.Init(sp, err));
        VfsAttr at;
        CHECK_EQ(VfsGetattr(S, "out/o.bin", at), 0);
        CHECK_EQ(VfsGetattr(S, "game.exe", at), 0);
    }
}

// Names match whatever their case on a case-insensitive mount, and the spelling that resolves is the one a VISIBLE
// layer has: a base hidden under its delta must not lend its spelling (readdir lists the delta's name, getattr on
// it must find it). Teeth: the case map took every layer, hidden or not, lowest first.
TEST(a_hidden_base_lends_no_spelling_to_a_case_insensitive_mount) {
    TmpDir t;
    std::string track(3000, 't'); for (size_t i = 0; i < track.size(); ++i) track[i] = char('A' + (i * 5) % 26);
    writeStoreZip(t / "game.zip", { { "game.exe", track + "G", false } });
    writeStoreZip(t / "music.zip", { { "Track01.wav", track, false } });
    writeStoreZip(t / "new.zip", { { "game.exe", track + "G2", false }, { "music/track01.wav", track, false } });
    writeDelta(t / "new.vgdelta", slurpFile(t / "game.zip") + slurpFile(t / "music.zip"), t / "new.zip");
    Spec sp; sp.readOnly = true; sp.caseInsensitive = true;
    sp.layers = { zipLayer(t.str("game.zip"), "h"), zipLayer(t.str("music.zip"), "h/music"),
                  deltaLayer(t.str("new.vgdelta"), "h", { t.str("game.zip"), t.str("music.zip") }) };
    VfsState S; std::string err;
    CHECK(S.Init(sp, err));
    VfsAttr at;
    CHECK(readdirNames(S, "h/music") == (std::set<std::string>{ "track01.wav" }));
    CHECK_EQ(CanonicalCase(S, "H/MUSIC/TRACK01.WAV"), std::string("h/music/track01.wav"));   // as the backend asks
    CHECK_EQ(VfsGetattr(S, CanonicalCase(S, "h/music/Track01.wav"), at), 0);
    checkReaddirSubsetGetattr(S, "h/music");
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
