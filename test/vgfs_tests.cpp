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

#include <atomic>
#include <cstdio>
#include <cstring>
#include <unistd.h>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <set>
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

int main() {
    for (auto &[name, fn] : g_tests) {
        std::cerr << "[ RUN ] " << name << "\n";
        fn();
    }
    std::cerr << "\n" << (g_fail ? "FAILED " : "PASSED ") << g_checks << " checks, " << g_fail << " failures across "
              << g_tests.size() << " tests\n";
    return g_fail ? 1 : 0;
}
