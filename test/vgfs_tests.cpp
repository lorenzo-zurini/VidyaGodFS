// vgfs_tests — unmounted unit tests for the VidyaGodFS core.
// Strategy (see the overhaul plan): build REAL fixture trees / zips in a temp dir, construct a Spec
// directly, VfsState::Init, then drive Resolve / CollectChildren / the VfsOps surface. No mounting, no
// HostIO mocking — the POSIX shim is exercised for real. Fixtures are torn down per test.

#include "test_guard.h"
#include <random>
#include <thread>
#include <condition_variable>
#include "overlay.h"
#include "hostio.h"
#include "treeplan.h"
#include "vfsops.h"
#include "layerspec.h"
#include "ziplayer.h"
#include "zipscan.h"
#include "vgdelta.h"
#include "bytesource.h"
#include "deflatelayer.h"
#include "coding.h"
#include "descbuilders.h"
#include <nlohmann/json.hpp>
#include "lz4family.h"
#include "lzxmakecab.h"
#include <lzma.h>
#include <lz4.h>
#include <lz4hc.h>
#include <lz4frame.h>
#include <zstd.h>
#include <chrono>
#include <zlib.h>

#include <cerrno>
#include <zip.h>

#include <algorithm>
#include <atomic>
#include <cstdio>
#include <cstring>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <set>
#include <map>
#include <tuple>
#include <iterator>
#include <mutex>
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
// A folder layer whose source does not change while mounted (package content, DefaultData): answered from a listing.
static LayerSpec fixedDirLayer(const std::string &src, const std::string &target = "") {
    LayerSpec L = dirLayer(src, target); L.fixed = true; return L;
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

// Submounts of one archive, case-insensitive: each spells what lies under its own subpath, walked from there — not the
// whole archive looked over once per submount. Teeth: look over every member for each submount (the walks grow with
// the archive, not with what each submount holds).
TEST(case_names_of_a_submount_come_from_its_own_subtree) {
    TmpDir t;
    std::vector<std::tuple<std::string, std::string, bool>> es = { { "Bin/Game.EXE", "g", false }, { "Docs/Read.ME", "r", false } };
    for (int I = 0; I < 500; ++I) es.push_back({ "Other/f" + std::to_string(I) + ".dat", "o", false });
    writeStoreZip(t / "pak.zip", es);
    LayerSpec L = zipLayer(t.str("pak.zip"), "");
    L.submounts = { { "Bin", "g/bin" }, { "Docs", "manual" } };
    Spec sp; sp.readOnly = true; sp.caseInsensitive = true; sp.layers = { L };
    const long long Before = DebugCaseWalks();
    VfsState S; std::string err; CHECK(S.Init(sp, err));
    CHECK(DebugCaseWalks() - Before < 10);
    CHECK_EQ(CanonicalCase(S, "G/BIN/GAME.exe"), std::string("g/bin/Game.EXE"));
    CHECK_EQ(CanonicalCase(S, "MANUAL/read.me"), std::string("manual/Read.ME"));
    VfsAttr a;
    CHECK_EQ(VfsGetattr(S, CanonicalCase(S, "g/BIN/game.exe"), a), 0);
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

// ---- byte patches (spec "patches") ----------------------------------------------------------------------------

static std::string readAll(VfsState &S, const std::string &v, size_t Chunk) {
    OpenFile *of = nullptr;
    if (VfsOpen(S, v, 0, of) != 0 || !of) return "<open failed>";
    std::string Out; std::vector<char> Buf(Chunk);
    for (uint64_t Off = 0;;) {
        const ssize_t N = VfsRead(of, Buf.data(), Buf.size(), Off);
        if (N <= 0) break;
        Out.append(Buf.data(), (size_t)N); Off += (uint64_t)N;
    }
    VfsRelease(of);
    return Out;
}
static BytePatch bytePatch(const std::string &Path, uint64_t At, const std::string &Bytes) {
    BytePatch B; B.path = Path; B.at = At; B.bytes.assign(Bytes.begin(), Bytes.end()); return B;
}

// A file a lower layer serves is read with its patches, whatever the reads' sizes and offsets (a run across two
// reads), a later patch winning where two cover a byte; the layer's own file is never written. Teeth: patches
// ignored; only a read that holds a whole run patched; the first patch winning.
TEST(patches_are_read_over_a_lower_file) {
    TmpDir t;
    std::string Body(100000, 'a');
    for (size_t I = 0; I < Body.size(); ++I) Body[I] = (char)('a' + I % 26);
    writeFile(t / "disc.iso", Body);
    writeStoreZip(t / "game.zip", { { "bin/game.exe", Body, false } });
    LayerSpec F; F.type = LayerType::File; F.source = t.str("disc.iso"); F.target = "media";
    Spec sp; sp.layers = { F, zipLayer(t.str("game.zip")) };
    sp.patches = { bytePatch("media/disc.iso", 200, "ABCD"), bytePatch("media/disc.iso", 198, "XYZ"),   // over the start of one before
                   bytePatch("media/disc.iso", 4095, "XYZ"), bytePatch("media/disc.iso", 4096, "Q"),
                   bytePatch("/bin/game.exe", 99998, "!!"), bytePatch("bin/game.exe", 10, "#") };
    VfsState S; std::string err; CHECK(S.Init(sp, err));
    std::string Want = Body; Want.replace(4095, 3, "XQZ"); Want.replace(198, 6, "XYZBCD");
    for (size_t Chunk : { (size_t)4096, (size_t)1000, (size_t)65536, (size_t)1 << 20 })
        CHECK(readAll(S, "media/disc.iso", Chunk) == Want);
    std::string WantExe = Body; WantExe[10] = '#'; WantExe.replace(99998, 2, "!!");
    CHECK(readAll(S, "bin/game.exe", 777) == WantExe);
    std::ifstream In(t / "disc.iso", std::ios::binary); std::stringstream Disk; Disk << In.rdbuf();
    CHECK(Disk.str() == Body);
    //A read the backend would hand the kernel from the file itself (splice) does not, where it holds a patch.
    OpenFile *of = nullptr;
    CHECK_EQ(VfsOpen(S, "media/disc.iso", 0, of), 0);
    int Fd = -1; uint64_t Pos = 0; size_t Len = 0;
    CHECK(!VfsReadFrom(of, 10, 4090, Fd, Pos, Len));
    CHECK(VfsReadFrom(of, 10, 5000, Fd, Pos, Len));
    CHECK(VfsReadFrom(of, 198, 0, Fd, Pos, Len));
    CHECK(!VfsReadFrom(of, 199, 0, Fd, Pos, Len));
    VfsRelease(of);
    CHECK_EQ(VfsOpen(S, "bin/game.exe", 0, of), 0);
    CHECK(!VfsReadFrom(of, 1, 10, Fd, Pos, Len));
    CHECK(VfsReadFrom(of, 1, 11, Fd, Pos, Len));
    VfsRelease(of);
}

// A copy-up of a patched file copies it as it was read, patches in — from a folder or an archive, made at a write
// through a lazy handle or an open that writes — and is then read as it is. A file the writelayer already serves is
// not patched. Teeth: a copy-up without the patches (the game's first write loses them); patches laid over the copy.
TEST(patches_go_into_a_copy_up_and_not_over_a_writelayer_file) {
    TmpDir t;
    writeFile(t / "lower/a.bin", "0123456789");
    writeFile(t / "lower/b.bin", "0123456789");
    writeFile(t / "lower/c.bin", "0123456789");
    writeFile(t / "lower/d.bin", "0123456789");
    writeStoreZip(t / "z.zip", { { "z.bin", "0123456789", false } });
    writeFile(t / "wl/c.bin", "abcdefghij");
    Spec sp; sp.readOnly = false; sp.writelayer = t.str("wl"); sp.layers = { dirLayer(t.str("lower")), zipLayer(t.str("z.zip")) };
    sp.patches = { bytePatch("a.bin", 2, "AB"), bytePatch("b.bin", 2, "AB"), bytePatch("c.bin", 2, "AB"), bytePatch("z.bin", 8, "ZZ"),
                   bytePatch("d.bin", 5, "D") };
    VfsState S; std::string err; CHECK(S.Init(sp, err));
    OpenFile *of = nullptr;
    CHECK_EQ(VfsOpen(S, "a.bin", 2 /*O_RDWR*/, of), 0);                 // lazy: the copy waits for the write
    char B[16] = {0};
    CHECK_EQ(VfsRead(of, B, 10, 0), (ssize_t)10);
    CHECK_EQ(std::string(B, 10), std::string("01AB456789"));
    CHECK(VfsWrite(S, of, "x", 1, 0) == 1);
    CHECK_EQ(VfsRead(of, B, 10, 0), (ssize_t)10);
    CHECK_EQ(std::string(B, 10), std::string("x1AB456789"));
    VfsRelease(of);
    CHECK_EQ(VfsOpen(S, "b.bin", 01001 /*O_WRONLY|O_TRUNC*/, of), 0);   // a rewrite: nothing to keep
    VfsRelease(of);
    CHECK_EQ(VfsOpen(S, "z.bin", 1 /*O_WRONLY*/, of), 0);               // an open that writes: copied up at the open
    CHECK(VfsWrite(S, of, "y", 1, 0) == 1);
    VfsRelease(of);
    std::ifstream A(t / "wl/a.bin", std::ios::binary); std::stringstream AS; AS << A.rdbuf();
    CHECK_EQ(AS.str(), std::string("x1AB456789"));
    CHECK_EQ(readAll(S, "a.bin", 4), std::string("x1AB456789"));
    CHECK_EQ(readAll(S, "b.bin", 4), std::string(""));
    CHECK_EQ(readAll(S, "z.bin", 3), std::string("y1234567ZZ"));
    CHECK_EQ(readAll(S, "c.bin", 4), std::string("abcdefghij"));
    //A handle whose file was deleted under it writes a copy of its own: of what it read, patches in.
    CHECK_EQ(VfsOpen(S, "d.bin", 2 /*O_RDWR*/, of), 0);
    CHECK_EQ(VfsUnlink(S, "d.bin"), 0);
    CHECK(VfsWrite(S, of, "w", 1, 0) == 1);
    CHECK_EQ(VfsRead(of, B, 10, 0), (ssize_t)10);
    CHECK_EQ(std::string(B, 10), std::string("w1234D6789"));
    VfsRelease(of);
}

// Patch paths take the package's case where names match whatever their case; a malformed patch refuses the spec.
TEST(patches_take_the_package_case_and_a_bad_one_refuses_the_spec) {
    TmpDir t;
    writeFile(t / "src/Data/Game.EXE", "0123456789");
    writeStoreZip(t / "z.zip", { { "Bin/Tool.EXE", "0123456789", false } });
    Spec sp; sp.caseInsensitive = true; sp.layers = { fixedDirLayer(t.str("src")), zipLayer(t.str("z.zip")) };
    sp.patches = { bytePatch("data/game.exe", 0, "Z"), bytePatch("BIN/tool.exe", 9, "Y") };
    VfsState S; std::string err; CHECK(S.Init(sp, err));
    CHECK_EQ(readAll(S, "Data/Game.EXE", 4), std::string("Z123456789"));   // a folder's name, as the host spells it
    CHECK_EQ(readAll(S, CanonicalCase(S, "bin/TOOL.exe"), 4), std::string("012345678Y"));
    Spec Out;
    std::string E;
    CHECK(ParseSpecText(R"({"mountpoint":"/m","layers":[],"patches":[{"path":"a","at":3,"bytes":"0aFF"}]})", Out, E));
    CHECK(Out.patches.size() == 1 && Out.patches[0].at == 3 && Out.patches[0].bytes == std::vector<uint8_t>({ 0x0a, 0xff }));
    for (const char *Bad : { R"([{"path":"a","at":3,"bytes":"0"}])", R"([{"path":"a","at":3,"bytes":"zz"}])",
                             R"([{"path":"","at":3,"bytes":"00"}])", R"([{"path":"a","at":-1,"bytes":"00"}])",
                             R"([{"path":"a","bytes":"00"}])", R"({})" })
    {
        Spec X; std::string Why;
        CHECK(!ParseSpecText(std::string(R"({"mountpoint":"/m","layers":[],"patches":)") + Bad + "}", X, Why));
    }
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

// A mount over a kept folder (saves, mods: thousands of files) learns its deletion markers from one listing of it,
// typed by the listing: a stat per entry to learn whether it was a folder made a large kept folder seconds of stats
// at every mount. A marker deep inside is still found. Teeth: stat every entry again (hundreds of stats).
TEST(a_kept_folder_is_seeded_without_a_stat_per_entry) {
    TmpDir t;
    for (int I = 0; I < 300; ++I) writeFile(t / ("saves/s" + std::to_string(I) + ".sav"), "x");
    writeFile(t / "saves/deep/er/.wh.gone.sav", "");
    writeFile(t / "base/deep/er/gone.sav", "old");
    Spec sp; sp.readOnly = false; sp.writelayer = t.str("wl");
    sp.layers = { dirLayer(t.str("base")), dirLayer(t.str("saves"), "", true) };
    const long long Before = HostIO::DebugLstats();
    VfsState S; std::string err; CHECK(S.Init(sp, err));
    CHECK(HostIO::DebugLstats() - Before < 50);
    VfsAttr a;
    CHECK_EQ(VfsGetattr(S, "deep/er/gone.sav", a), -ENOENT);   // the marker deep inside was seen
    CHECK_EQ(VfsGetattr(S, "s7.sav", a), 0);
}

// A small read-only folder layer above the content (DefaultData: the package's edits) is listed at the mount: a name
// it does not hold is passed by without a stat of the host — every lookup in the mount stat'd it. What it holds is
// served; one holding a link is not listed (a path through a linked folder cannot be known without the host).
// Teeth: stat it at every lookup (a stat per miss); list one with a link (the path through it is lost).
TEST(a_small_read_only_folder_layer_is_passed_by_without_a_stat) {
    TmpDir t;
    std::vector<std::tuple<std::string, std::string, bool>> es;
    for (int I = 0; I < 50; ++I) es.push_back({ "game/f" + std::to_string(I) + ".dat", "z", false });
    writeStoreZip(t / "game.zip", es);
    writeFile(t / "dd/game/settings.ini", "edited");
    fs::create_directories(t / "real/sub");
    writeFile(t / "real/sub/x.txt", "x");
    std::error_code ec;
    fs::create_directories(t / "linked", ec);
    fs::create_symlink(t / "real/sub", t / "linked/sub", ec);
    Spec sp; sp.readOnly = true; sp.layers = { zipLayer(t.str("game.zip")), fixedDirLayer(t.str("dd")), fixedDirLayer(t.str("linked")) };
    VfsState S; std::string err; CHECK(S.Init(sp, err));
    VfsAttr a;
    const long long Before = HostIO::DebugLstats();
    for (int I = 0; I < 50; ++I) CHECK_EQ(VfsGetattr(S, "game/f" + std::to_string(I) + ".dat", a), 0);
    const long long Stats = HostIO::DebugLstats() - Before;
    CHECK(Stats < 60);                                              // the linked layer's stat each; none for DefaultData
    CHECK_EQ(VfsGetattr(S, "game/settings.ini", a), 0);
    CHECK_EQ(a.size, (uint64_t)6);
    CHECK_EQ(VfsGetattr(S, "sub/x.txt", a), 0);                     // through the link: found on the host
}

// Only a folder layer the spec says is fixed is answered from a listing: one another mount fills, or the user's, finds
// a file put there after the mount. A fixed one with a folder it cannot list, or (folded) a name past ASCII, asks the
// host. Listing it stats only what its listing does not type. Teeth: list every read-only folder layer; take a folder
// it cannot read for empty; list a folded non-ASCII name; stat every regular file while listing.
TEST(only_a_fixed_folder_layer_is_answered_from_a_listing) {
    TmpDir t;
    fs::create_directories(t / "late");
    for (int I = 0; I < 100; ++I) writeFile(t / ("fixed/f" + std::to_string(I)), "x");
    writeFile(t / "shut/d/in.txt", "in");
    writeFile(t / "wide/\xc3\x9c.txt", "u");
    const long long ListStats = HostIO::DebugLstats();
    Spec sp; sp.readOnly = true;
    sp.layers = { dirLayer(t.str("late")), fixedDirLayer(t.str("fixed")), fixedDirLayer(t.str("shut"), "s") };
    VfsState S; std::string err; CHECK(S.Init(sp, err));
    CHECK(HostIO::DebugLstats() - ListStats < 20);                  // 100 typed files listed without a stat each
    writeFile(t / "late/new.txt", "new");                            // filled after the mount
    VfsAttr a;
    CHECK_EQ(VfsGetattr(S, "new.txt", a), 0);
    // A folder that cannot be listed: its files are still found (the host is asked).
    fs::permissions(t / "shut/d", fs::perms::owner_exec);
    VfsState S2; CHECK(S2.Init(sp, err));
    CHECK_EQ(VfsGetattr(S2, "s/d/in.txt", a), 0);
    fs::permissions(t / "shut/d", fs::perms::owner_all);
    // Folded, a name past ASCII: not listed (a miss asks the host, which matches what FoldCase cannot).
    Spec sw; sw.readOnly = true; sw.caseInsensitive = true; sw.layers = { fixedDirLayer(t.str("wide")) };
    VfsState S3; CHECK(S3.Init(sw, err));
    const long long Miss = HostIO::DebugLstats();
    CHECK(VfsGetattr(S3, "nothing.txt", a) != 0);
    CHECK(HostIO::DebugLstats() - Miss >= 1);
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

// An installer deleting thousands of a package's files: each stays deleted, one made again shows, and the deletion
// mask is copied whole only now and then — not at every delete (10,000 deletes were 50 M string copies). Teeth: fold
// at every change (as many folds as deletes); lose the changes at a fold (a deleted file comes back).
TEST(many_deletes_keep_their_mask_small_to_change) {
    TmpDir t;
    std::vector<std::tuple<std::string, std::string, bool>> es;
    for (int I = 0; I < 3000; ++I) es.push_back({ "data/f" + std::to_string(I) + ".bin", "x", false });
    writeStoreZip(t / "base.zip", es);
    Spec sp; sp.readOnly = false; sp.writelayer = t.str("wl");
    LayerSpec Z; Z.type = LayerType::Zip; Z.source = t.str("base.zip"); Z.target = "";
    sp.layers = { Z };
    VfsState S; std::string err; CHECK(S.Init(sp, err));
    const long long Folds = DebugMaskFolds();
    int Gone = 0;
    for (int I = 0; I < 3000; ++I) Gone += VfsUnlink(S, "data/f" + std::to_string(I) + ".bin") == 0;
    CHECK_EQ(Gone, 3000);
    CHECK(DebugMaskFolds() - Folds < 30);
    VfsAttr a;
    int Hidden = 0;
    for (int I = 0; I < 3000; ++I) Hidden += VfsGetattr(S, "data/f" + std::to_string(I) + ".bin", a) == -ENOENT;
    CHECK_EQ(Hidden, 3000);
    OpenFile *of = nullptr;
    CHECK_EQ(VfsCreate(S, "data/f1234.bin", 0644, O_WRONLY, of), 0);   // made again: shows
    if (of) VfsRelease(of);
    CHECK_EQ(VfsGetattr(S, "data/f1234.bin", a), 0);
    CHECK_EQ(VfsGetattr(S, "data/f1235.bin", a), -ENOENT);
}

// A file opened to read and write is copied up at its first change, not at the open: old games open their data files
// read-write and never write them (each open copied gigabytes into the writelayer, every launch). Every handle on it
// reads the change once one is made; a truncate by path counts as one; a file deleted while open is not brought back
// by a write. Teeth: copy at the open again (a copy with nothing written); a second handle that keeps reading below
// (it misses the first one's write); a truncate by path not seen by an open handle.
TEST(a_file_opened_to_read_and_write_is_copied_only_when_changed) {
    TmpDir t;
    writeStoreZip(t / "base.zip", { { "data/big.dat", "0123456789", false }, { "data/gone.dat", "bye", false } });
    writeFile(t / "host/cfg.ini", "a=1");
    Spec sp; sp.readOnly = false; sp.writelayer = t.str("wl");
    sp.layers = { zipLayer(t.str("base.zip")), dirLayer(t.str("host")) };
    VfsState S; std::string err; CHECK(S.Init(sp, err));
    const long long Opens = DebugLazyOpens(), Copies = DebugLazyCopies();
    OpenFile *A = nullptr, *B = nullptr;
    CHECK_EQ(VfsOpen(S, "data/big.dat", O_RDWR, A), 0);
    CHECK_EQ(VfsOpen(S, "data/big.dat", O_RDWR, B), 0);
    CHECK(!fs::exists(t / "wl/data/big.dat"));                        // opened, nothing copied
    char buf[16] = {0};
    CHECK_EQ(VfsRead(A, buf, 10, 0), (ssize_t)10);
    CHECK_EQ(std::string(buf, 10), std::string("0123456789"));
    CHECK_EQ(VfsWrite(S, A, "AB", 2, 0), (ssize_t)2);                   // the first change: copied now
    CHECK(fs::exists(t / "wl/data/big.dat"));
    CHECK_EQ(VfsRead(B, buf, 10, 0), (ssize_t)10);                      // the other handle reads the change
    CHECK_EQ(std::string(buf, 10), std::string("AB23456789"));
    CHECK_EQ(DebugLazyOpens() - Opens, 2LL);
    CHECK_EQ(DebugLazyCopies() - Copies, 1LL);
    VfsRelease(A); VfsRelease(B);
    // Opened and closed without a change: no copy.
    OpenFile *C = nullptr;
    CHECK_EQ(VfsOpen(S, "cfg.ini", O_RDWR, C), 0);
    CHECK_EQ(VfsRead(C, buf, 3, 0), (ssize_t)3);
    VfsRelease(C);
    CHECK(!fs::exists(t / "wl/cfg.ini"));
    // A truncate by path is a change every open handle sees.
    OpenFile *D = nullptr;
    CHECK_EQ(VfsOpen(S, "cfg.ini", O_RDWR, D), 0);
    CHECK_EQ(VfsTruncate(S, "cfg.ini", nullptr, 1), 0);
    CHECK_EQ(VfsRead(D, buf, 3, 0), (ssize_t)1);
    CHECK_EQ(VfsTruncate(S, "cfg.ini", D, 0), 0);                     // and one through the handle
    VfsAttr a;
    CHECK_EQ(VfsGetattr(S, "cfg.ini", a), 0);
    CHECK_EQ(a.size, (uint64_t)0);
    VfsRelease(D);
    // Deleted while open: a write goes to the handle's own file (POSIX: an unlinked file stays writable through its
    // handles) and does not bring it back, nor leave anything in the writelayer.
    OpenFile *E = nullptr;
    CHECK_EQ(VfsOpen(S, "data/gone.dat", O_RDWR, E), 0);
    CHECK_EQ(VfsUnlink(S, "data/gone.dat"), 0);
    CHECK_EQ(VfsWrite(S, E, "x", 1, 0), (ssize_t)1);
    CHECK_EQ(VfsRead(E, buf, 3, 0), (ssize_t)3);
    CHECK_EQ(std::string(buf, 3), std::string("xye"));
    CHECK_EQ(VfsGetattr(S, "data/gone.dat", a), -ENOENT);
    VfsRelease(E);
    for (const auto &e : fs::recursive_directory_iterator(t / "wl"))
        CHECK(e.path().filename().string().rfind(".wh..vgfs-copy.", 0) != 0);
}

// A handle opened to read a lower file follows its copy-up: a write through a lazy handle (or a truncating open)
// copies the file up, and what every reader reads from then on is the copy. Left on the lower file, a reader read the
// file as it was before (a game reading back its own saved settings got the old ones). Teeth: no marker for read-only
// opens; a marker that is told of the copy but not opened into.
TEST(a_reader_reads_what_a_lazy_writer_wrote) {
    TmpDir t;
    writeStoreZip(t / "base.zip", { { "z.dat", "zzzzzzzzzz", false } });
    writeFile(t / "host/cfg.ini", "a=1");
    writeFile(t / "host/t.ini", "long text");
    Spec sp; sp.readOnly = false; sp.writelayer = t.str("wl");
    sp.layers = { zipLayer(t.str("base.zip")), dirLayer(t.str("host")) };
    VfsState S; std::string err; CHECK(S.Init(sp, err));
    char buf[16] = {0};
    for (const char *P : { "cfg.ini", "z.dat" })
    {
        OpenFile *W = nullptr, *R = nullptr;
        CHECK_EQ(VfsOpen(S, P, O_RDWR, W), 0);
        CHECK_EQ(VfsOpen(S, P, O_RDONLY, R), 0);
        CHECK_EQ(VfsWrite(S, W, "XY", 2, 0), (ssize_t)2);
        CHECK_EQ(VfsRead(R, buf, 2, 0), (ssize_t)2);
        CHECK_EQ(std::string(buf, 2), std::string("XY"));
        int fd = -1; uint64_t pos = 0; size_t len = 0;                     // the splice path reads the copy too
        CHECK(VfsReadFrom(R, 2, 0, fd, pos, len));
        CHECK_EQ(pread(fd, buf, 2, (off_t)pos), (ssize_t)2);
        CHECK_EQ(std::string(buf, 2), std::string("XY"));
        CHECK(VfsWrite(S, R, "Q", 1, 0) < 0);                              // opened to read: never written through
        VfsRelease(W); VfsRelease(R);
    }
    // A truncating open copies up too: an older reader sees it.
    OpenFile *R = nullptr, *T = nullptr;
    CHECK_EQ(VfsOpen(S, "t.ini", O_RDONLY, R), 0);
    CHECK_EQ(VfsOpen(S, "t.ini", O_WRONLY | O_TRUNC, T), 0);
    CHECK_EQ(VfsRead(R, buf, 9, 0), (ssize_t)0);
    VfsRelease(R); VfsRelease(T);
}

// A lazy handle whose name changes before its first write writes the file it was opened on, wherever that is now —
// never what the name names since. Renamed: the moved file (the rename copied it up, the handle holds the copy).
// Replaced by another file, or deleted and made again: a copy of its own, the name left as it is. Teeth: look the
// copy up by its path at the write (each case writes into the file at the name); keep a marker on a replaced name;
// keep one on a name made again (deleted first, or not).
TEST(a_lazy_writer_writes_its_own_file_after_its_name_changes) {
    TmpDir t;
    writeFile(t / "host/f.dat", "old-f");
    writeFile(t / "host/r.dat", "old-r");
    writeFile(t / "host/u.dat", "old-u");
    writeFile(t / "host/c.dat", "old-c");
    Spec sp; sp.readOnly = false; sp.writelayer = t.str("wl"); sp.layers = { dirLayer(t.str("host")) };
    VfsState S; std::string err; CHECK(S.Init(sp, err));
    auto Read = [&](const char *P) {
        OpenFile *H = nullptr; char b[32] = {0};
        if (VfsOpen(S, P, O_RDONLY, H) != 0) return std::string("(none)");
        const ssize_t n = VfsRead(H, b, sizeof b, 0); VfsRelease(H);
        return std::string(b, n > 0 ? (size_t)n : 0);
    };
    auto Make = [&](const char *P, const char *Text) {
        OpenFile *H = nullptr;
        CHECK_EQ(VfsCreate(S, P, 0644, O_WRONLY | O_TRUNC, H), 0);
        CHECK_EQ(VfsWrite(S, H, Text, std::strlen(Text), 0), (ssize_t)std::strlen(Text));
        VfsRelease(H);
    };
    char buf[16] = {0};
    // Renamed, and a new file made at its old name.
    OpenFile *A = nullptr;
    CHECK_EQ(VfsOpen(S, "f.dat", O_RDWR, A), 0);
    CHECK_EQ(VfsRename(S, "f.dat", "g.dat"), 0);
    Make("f.dat", "NEW-f");
    CHECK_EQ(VfsWrite(S, A, "Z", 1, 0), (ssize_t)1);
    CHECK_EQ(Read("g.dat"), std::string("Zld-f"));
    CHECK_EQ(Read("f.dat"), std::string("NEW-f"));
    VfsRelease(A);
    // Replaced by a rename over it.
    OpenFile *B = nullptr;
    CHECK_EQ(VfsOpen(S, "r.dat", O_RDWR, B), 0);
    Make("other.dat", "OTHER");
    CHECK_EQ(VfsRename(S, "other.dat", "r.dat"), 0);
    CHECK_EQ(VfsWrite(S, B, "Z", 1, 0), (ssize_t)1);
    CHECK_EQ(Read("r.dat"), std::string("OTHER"));
    CHECK_EQ(VfsRead(B, buf, 5, 0), (ssize_t)5);
    CHECK_EQ(std::string(buf, 5), std::string("Zld-r"));                 // it reads its own change
    VfsRelease(B);
    // Deleted and made again.
    OpenFile *C = nullptr;
    CHECK_EQ(VfsOpen(S, "u.dat", O_RDWR, C), 0);
    CHECK_EQ(VfsUnlink(S, "u.dat"), 0);
    Make("u.dat", "NEW-u");
    CHECK_EQ(VfsWrite(S, C, "Z", 1, 0), (ssize_t)1);
    CHECK_EQ(Read("u.dat"), std::string("NEW-u"));
    VfsRelease(C);
    // Made again over it, with no delete first (a create the kernel sends on a name it last saw missing).
    OpenFile *D = nullptr;
    CHECK_EQ(VfsOpen(S, "c.dat", O_RDWR, D), 0);
    Make("c.dat", "NEW-c");
    CHECK_EQ(VfsWrite(S, D, "Z", 1, 0), (ssize_t)1);
    CHECK_EQ(Read("c.dat"), std::string("NEW-c"));
    VfsRelease(D);
}

// A name changed in the windows where a handle is between looking and acting — a copy-up being written, an open between
// resolving its name and taking its marker — never makes a write land in the file the name holds now: an atomic save
// (written beside, renamed over) during a lazy writer's first copy stays as saved; one landing while a handle opens
// is not the handle's file either; a name deleted then is written to the handle's own copy. Teeth: the copy-up
// renamed over what is at the name; an open's marker taken without looking whether its name changed.
TEST(a_name_changed_while_a_handle_acts_keeps_what_it_names) {
    for (const char *Window : { "copy-before-rename", "open-before-marker", "open-before-marker:unlink" })
    {
        TmpDir t;
        writeFile(t / "host/save.dat", "OLDSAVE");
        Spec sp; sp.readOnly = false; sp.writelayer = t.str("wl"); sp.layers = { dirLayer(t.str("host")) };
        VfsState S; std::string err; CHECK(S.Init(sp, err));
        const std::string W = Window;
        const bool Unlink = W.find(":unlink") != std::string::npos;
        const std::string Point = W.substr(0, W.find(':'));
        bool Fired = false;
        S.debugHook = [&](const char *At) {
            if (Fired || Point != At) return;
            Fired = true;
            if (Unlink) { CHECK_EQ(VfsUnlink(S, "save.dat"), 0); return; }
            OpenFile *T = nullptr;
            CHECK_EQ(VfsCreate(S, "save.tmp", 0644, O_WRONLY | O_TRUNC, T), 0);
            CHECK_EQ(VfsWrite(S, T, "NEWSAVE", 7, 0), (ssize_t)7);
            VfsRelease(T);
            CHECK_EQ(VfsRename(S, "save.tmp", "save.dat"), 0);
        };
        OpenFile *A = nullptr;
        CHECK_EQ(VfsOpen(S, "save.dat", O_RDWR, A), 0);
        if (!A) continue;
        CHECK_EQ(VfsWrite(S, A, "Z", 1, 0), (ssize_t)1);
        CHECK(Fired);
        char b[16] = {0};
        CHECK_EQ(VfsRead(A, b, 7, 0), (ssize_t)7);
        CHECK_EQ(std::string(b, 7), std::string("ZLDSAVE"));            // its own file, changed
        S.debugHook = nullptr;
        OpenFile *R = nullptr;
        if (Unlink) { VfsAttr a; CHECK_EQ(VfsGetattr(S, "save.dat", a), -ENOENT); }
        else
        {
            CHECK_EQ(VfsOpen(S, "save.dat", O_RDONLY, R), 0);
            char c[16] = {0};
            if (R) CHECK_EQ(VfsRead(R, c, 7, 0), (ssize_t)7);
            CHECK_EQ(std::string(c, 7), std::string("NEWSAVE"));        // the save, as saved
            if (R) VfsRelease(R);
        }
        VfsRelease(A);
    }
}

// A lazy writer's first write while a save is renamed over its name (the rename done, its markers not off yet) waits
// for the change and writes its own copy — never the file renamed in. Teeth: adopt a copy found at the name while a
// name change runs.
TEST(a_first_write_during_a_rename_over_its_name_writes_its_own_copy) {
    TmpDir t;
    writeFile(t / "host/save.dat", "OLDSAVE");
    Spec sp; sp.readOnly = false; sp.writelayer = t.str("wl"); sp.layers = { dirLayer(t.str("host")) };
    VfsState S; std::string err; CHECK(S.Init(sp, err));
    OpenFile *A = nullptr;
    CHECK_EQ(VfsOpen(S, "save.dat", O_RDWR, A), 0);
    if (!A) return;
    OpenFile *T = nullptr;
    CHECK_EQ(VfsCreate(S, "save.tmp", 0644, O_WRONLY | O_TRUNC, T), 0);
    CHECK_EQ(VfsWrite(S, T, "NEWSAVE", 7, 0), (ssize_t)7);
    VfsRelease(T);
    std::thread Writer;
    std::atomic<ssize_t> Wrote{ -100 };
    S.debugHook = [&](const char *At) {
        if (std::string(At) != "rename-before-detach" || Writer.joinable()) return;
        Writer = std::thread([&] { Wrote = VfsWrite(S, A, "Z", 1, 0); });
        std::this_thread::sleep_for(std::chrono::milliseconds(150));
    };
    CHECK_EQ(VfsRename(S, "save.tmp", "save.dat"), 0);
    if (Writer.joinable()) Writer.join();
    S.debugHook = nullptr;
    CHECK_EQ(Wrote.load(), (ssize_t)1);
    char b[16] = {0};
    OpenFile *R = nullptr;
    CHECK_EQ(VfsOpen(S, "save.dat", O_RDONLY, R), 0);
    if (R) { CHECK_EQ(VfsRead(R, b, 7, 0), (ssize_t)7); VfsRelease(R); }
    CHECK_EQ(std::string(b, 7), std::string("NEWSAVE"));
    CHECK_EQ(VfsRead(A, b, 7, 0), (ssize_t)7);
    CHECK_EQ(std::string(b, 7), std::string("ZLDSAVE"));
    VfsRelease(A);
}

// "Delete the old folder, move the staged one into place" (every patcher and installer): the folder there is the new
// one alone — the package's old files below it never show through. A folder moved over a non-empty one is refused
// (ENOTEMPTY), a folder over a file and a file over a folder too. Teeth: no opaque mark after the move (old.txt back);
// no emptiness check (the two merge).
TEST(a_folder_moved_over_a_deleted_or_full_one_never_merges_with_it) {
    TmpDir t;
    writeFile(t / "host/data/old.txt", "old");
    writeFile(t / "host/full/keep.txt", "keep");
    writeFile(t / "host/afile", "f");
    std::filesystem::create_directories(t / "host/emptydir");
    Spec sp; sp.readOnly = false; sp.writelayer = t.str("wl"); sp.layers = { dirLayer(t.str("host")) };
    VfsState S; std::string err; CHECK(S.Init(sp, err));
    CHECK_EQ(VfsUnlink(S, "data/old.txt"), 0);
    CHECK_EQ(VfsRmdir(S, "data"), 0);
    CHECK_EQ(VfsMkdir(S, "data.new", 0755), 0);
    OpenFile *N = nullptr;
    CHECK_EQ(VfsCreate(S, "data.new/new.txt", 0644, O_WRONLY | O_TRUNC, N), 0);
    if (N) VfsRelease(N);
    CHECK_EQ(VfsRename(S, "data.new", "data"), 0);
    CHECK(readdirNames(S, "data") == (std::set<std::string>{"new.txt"}));
    CHECK_EQ(VfsMkdir(S, "other", 0755), 0);
    CHECK_EQ(VfsRename(S, "other", "full"), -ENOTEMPTY);
    CHECK(readdirNames(S, "full") == (std::set<std::string>{"keep.txt"}));
    CHECK_EQ(VfsRename(S, "other", "afile"), -ENOTDIR);
    CHECK_EQ(VfsRename(S, "afile", "other"), -EISDIR);
    CHECK_EQ(VfsRename(S, "afile", "emptydir"), -EISDIR);   // a folder only below: nothing on the host to refuse it
    // Remounted: the same.
    VfsState R; CHECK(R.Init(sp, err));
    CHECK(readdirNames(R, "data") == (std::set<std::string>{"new.txt"}));
}

// A folder renamed over the same empty folder again and again (a cache rebuilt by "write aside, move into place"):
// each one works — the package's empty folder below and the markers a replaced folder held never make the host
// refuse. And a folder that hid deleted children below replaces them for good. Teeth: marking opaque over an empty
// lower folder (the second rename: ENOTEMPTY); no sweep of the replaced folder's markers (ENOTEMPTY); no opaque mark
// after the sweep (the deleted child back).
TEST(a_folder_replaced_again_and_again_moves_into_place_each_time) {
    TmpDir t;
    std::filesystem::create_directories(t / "host/cache");
    writeFile(t / "host/saves/old.sav", "old");
    Spec sp; sp.readOnly = false; sp.writelayer = t.str("wl"); sp.layers = { dirLayer(t.str("host")) };
    VfsState S; std::string err; CHECK(S.Init(sp, err));
    for (int I = 0; I < 3; ++I)
    {
        CHECK_EQ(VfsMkdir(S, "cache.tmp", 0755), 0);
        OpenFile *N = nullptr;
        CHECK_EQ(VfsCreate(S, "cache.tmp/c.bin", 0644, O_WRONLY | O_TRUNC, N), 0);
        if (N) VfsRelease(N);
        CHECK_EQ(VfsRename(S, "cache.tmp", "cache"), 0);
        CHECK(readdirNames(S, "cache") == (std::set<std::string>{"c.bin"}));
        CHECK_EQ(VfsUnlink(S, "cache/c.bin"), 0);
    }
    CHECK_EQ(VfsUnlink(S, "saves/old.sav"), 0);                    // saves/ is now empty as merged, a marker inside
    CHECK_EQ(VfsMkdir(S, "saves.new", 0755), 0);
    CHECK_EQ(VfsRename(S, "saves.new", "saves"), 0);
    CHECK(readdirNames(S, "saves").empty());
    VfsState R; CHECK(R.Init(sp, err));
    CHECK(readdirNames(R, "saves").empty());                       // old.sav stays deleted, remounted too
}

// Inside a folder made opaque (moved over a deleted one), an emptied subfolder is empty: the package's old files
// below it are no children of it, and a folder moves into its place. Teeth: CollectChildren blind to an opaque
// parent (ENOTEMPTY).
TEST(an_emptied_folder_under_an_opaque_one_takes_a_folder_moved_over_it) {
    TmpDir t;
    writeFile(t / "host/Data/maps/m1.map", "old map");
    Spec sp; sp.readOnly = false; sp.writelayer = t.str("wl"); sp.layers = { dirLayer(t.str("host")) };
    VfsState S; std::string err; CHECK(S.Init(sp, err));
    CHECK_EQ(VfsUnlink(S, "Data/maps/m1.map"), 0);
    CHECK_EQ(VfsRmdir(S, "Data/maps"), 0);
    CHECK_EQ(VfsRmdir(S, "Data"), 0);
    CHECK_EQ(VfsMkdir(S, "Data.new", 0755), 0);
    CHECK_EQ(VfsMkdir(S, "Data.new/maps", 0755), 0);
    CHECK_EQ(VfsRename(S, "Data.new", "Data"), 0);               // Data: opaque over the deleted one
    CHECK(readdirNames(S, "Data/maps").empty());
    CHECK_EQ(VfsMkdir(S, "maps.new", 0755), 0);
    CHECK_EQ(VfsRename(S, "maps.new", "Data/maps"), 0);
    CHECK(readdirNames(S, "Data/maps").empty());
}

// On a case-insensitive mount a rename that changes only a folder's case renames it (an installer normalising
// names); it is not "a non-empty folder in the way". Teeth: the destination checked against the folder itself.
TEST(a_case_only_rename_on_a_case_insensitive_mount_renames) {
    TmpDir t;
    writeFile(t / "host/keep.txt", "k");
    Spec sp; sp.readOnly = false; sp.writelayer = t.str("wl"); sp.layers = { dirLayer(t.str("host")) }; sp.caseInsensitive = true;
    VfsState S; std::string err; CHECK(S.Init(sp, err));
    CHECK_EQ(VfsMkdir(S, "data", 0755), 0);
    OpenFile *N = nullptr;
    CHECK_EQ(VfsCreate(S, "data/x.txt", 0644, O_WRONLY | O_TRUNC, N), 0);
    if (N) VfsRelease(N);
    CHECK_EQ(VfsRename(S, "data", "Data"), 0);
}

// FS-16: on a case-insensitive mount a deletion holds whatever case the program spelled it in. A folder layer's own
// files keep the caller's spelling (only registered names are made canonical), so `del DATA\X.TXT` of Data/x.txt was
// masked as DATA/X.TXT and the next open of data\x.txt served the deleted file. Markers left that way on disk (a
// Windows writelayer, a kept folder) hide it at the next mount too, in a listing as in a lookup. Teeth: the masks keyed
// as spelled (live, seeded, or in the listing); a kept folder's masks unfolded.
TEST(a_deletion_on_a_case_insensitive_mount_hides_the_name_in_any_case) {
    TmpDir t;
    writeFile(t / "host/Data/x.txt", "x");
    writeFile(t / "host/Data/y.txt", "y");
    writeFile(t / "host/Data/z.txt", "z");
    writeFile(t / "host/Saves/b.sav", "lower b");
    writeFile(t / "host/Saves/c.sav", "lower c");
    writeFile(t / "keep/a.sav", "kept a");
    writeFile(t / "host/Opq/w.txt", "w");
    writeFile(t / "host/Saves/Sub/q.sav", "lower q");
    writeFile(t / "wl/Data/.wh.X.TXT", "");      // deleted as DATA\X.TXT, an earlier session
    writeFile(t / "wl/OPQ/.wh..wh..opq", "");    // made again as OPQ over the package's Opq
    writeFile(t / "keep/.wh.B.SAV", "");         // a kept folder's marker, spelled likewise
    writeFile(t / "keep/SUB/.wh..wh..opq", "");  // and its folder made again over the package's Sub
    writeFile(t / "keep/.wh.A.SAV", "");         // a marker beside the folder's own a.sav: never hides its own
    Spec sp; sp.readOnly = false; sp.writelayer = t.str("wl"); sp.caseInsensitive = true;
    sp.layers = { dirLayer(t.str("host")), dirLayer(t.str("keep"), "Saves", true) };
    {
        VfsState S; std::string err; CHECK(S.Init(sp, err));
        CHECK(Resolve(S, "Data/x.txt").kind == HitKind::None);
        CHECK(!readdirNames(S, "Data").count("x.txt"));
        CHECK(readdirNames(S, "Data").count("y.txt"));
        CHECK(Resolve(S, "Saves/b.sav").kind == HitKind::None);
        CHECK(!readdirNames(S, "Saves").count("b.sav"));
        CHECK(readdirNames(S, "Saves").count("a.sav") && readdirNames(S, "Saves").count("c.sav"));
        CHECK(Resolve(S, "Opq/w.txt").kind == HitKind::None);
        CHECK(Resolve(S, "Saves/Sub/q.sav").kind == HitKind::None);
        const Layer *K = KeptLayerFor(S, "Saves/a.sav");
        CHECK(K != nullptr);
        if (!K) return;
        CHECK(KeptMasked(*K, "Saves/B.Sav"));
        // made live, in yet another case: the mask a lookup in any spelling finds
        CHECK_EQ(CreateWhiteout(S, "DATA/Y.TXT"), 0);
        CHECK(IsWhiteouted(S, "data/y.txt"));
        CHECK(Resolve(S, "Data/y.txt").kind == HitKind::None);
        CHECK_EQ(HideLower(S, "Saves/C.SAV"), 0);
        CHECK(KeptHidden(S, "Saves/c.sav"));   // the target, Saves, is a registered name: CanonicalCase spells it
        CHECK(Resolve(S, "Saves/c.sav").kind == HitKind::None);
        CHECK_EQ(UnhideLower(S, "Saves/C.Sav"), 0);
        CHECK(!KeptHidden(S, "Saves/c.sav"));
        CHECK_EQ(KeptMarkOpaque(S, "Saves/NEW"), 0);
        CHECK(KeptOpaqueDir(*K, "Saves/new"));
        KeptRenamePrefix(S, "Saves/new", "Saves/Renamed");
        CHECK(KeptOpaqueDir(*K, "Saves/RENAMED"));
        CHECK(!KeptOpaqueDir(*K, "Saves/NEW"));
        KeptDropMarkersUnder(S, "Saves/RENAMED");
        CHECK(!KeptOpaqueDir(*K, "Saves/renamed"));
        // a folder's deletion masks what is under it, whatever case it was deleted in
        CHECK_EQ(CreateWhiteout(S, "DATA"), 0);
        CHECK(IsUnderWhiteout(S, "Data/z.txt"));
        CHECK_EQ(RemoveWhiteout(S, "data"), 0);
        CHECK(!IsUnderWhiteout(S, "Data/z.txt"));
        // made again (opaque) in one case, masking the lower layers in another
        CHECK_EQ(MarkOpaque(S, "DATA"), 0);
        CHECK(IsUnderOpaque(S, "Data/z.txt"));
        UnmarkOpaque(S, "data");
        CHECK(!IsUnderOpaque(S, "Data/z.txt"));
        // a folder moved takes its deletions along, named in any case
        RenameMaskPrefix(S, "data", "Moved");
        CHECK(IsWhiteouted(S, "MOVED/X.TXT"));
        CHECK(!IsWhiteouted(S, "Data/x.txt"));
    }
    // Case-sensitive (Linux): names as spelled, as before.
    Spec cs = sp; cs.caseInsensitive = false;
    VfsState C; std::string err; CHECK(C.Init(cs, err));
    CHECK(Resolve(C, "Data/x.txt").kind != HitKind::None);
}

// FS-17: a create the kernel did not check first (WinFsp's CREATE_NEW, or a stale negative entry) is answered by the
// layers: a name only a lower layer has is taken, and a file is made only in a folder that is there. Teeth: O_EXCL
// checked on the writelayer copy only (an empty file shadows the package's); the parent's writelayer chain made.
TEST(an_exclusive_create_over_a_lower_name_is_refused_and_a_missing_folder_is_not_made) {
    TmpDir t;
    writeFile(t / "host/a.txt", "package");
    Spec sp; sp.readOnly = false; sp.writelayer = t.str("wl"); sp.layers = { dirLayer(t.str("host")) };
    VfsState S; std::string err; CHECK(S.Init(sp, err));
    OpenFile *N = nullptr;
    CHECK_EQ(VfsCreate(S, "a.txt", 0644, O_WRONLY | O_CREAT | O_EXCL, N), -EEXIST);
    CHECK(N == nullptr);
    CHECK(!fs::exists(t / "wl/a.txt"));
    VfsAttr A;
    CHECK_EQ(VfsGetattr(S, "a.txt", A), 0);
    CHECK_EQ(A.size, (uint64_t)7);
    CHECK_EQ(VfsCreate(S, "nodir/x.txt", 0644, O_WRONLY | O_CREAT, N), -ENOENT);
    CHECK(!fs::exists(t / "wl/nodir"));
    CHECK_EQ(VfsCreate(S, "a.txt/x", 0644, O_WRONLY | O_CREAT, N), -ENOTDIR);
    CHECK_EQ(VfsCreate(S, "b.txt", 0644, O_WRONLY | O_CREAT | O_EXCL, N), 0);   // a new name: made
    if (N) VfsRelease(N);
    CHECK(fs::exists(t / "wl/b.txt"));
}

// The rest of what WinFsp leaves to us, as for a create: a folder, a link or a hard link is made only in a folder that
// is there and over no name, a lower layer's included — a mkdir under a deleted folder made the folder appear again.
// A hard link is a name change (an open between resolving and taking its marker looks again). Teeth: any of the checks
// dropped from mkdir, symlink or link; link without BeginNameChange.
TEST(a_folder_or_link_is_made_only_in_a_folder_that_is_there_and_over_no_name) {
    TmpDir t;
    writeFile(t / "host/a.txt", "package");
    writeFile(t / "host/gone/inside.txt", "package");
    Spec sp; sp.readOnly = false; sp.writelayer = t.str("wl"); sp.layers = { dirLayer(t.str("host")) };
    VfsState S; std::string err; CHECK(S.Init(sp, err));
    CHECK_EQ(VfsUnlink(S, "gone/inside.txt"), 0);
    CHECK_EQ(VfsRmdir(S, "gone"), 0);
    for (const std::string V : { "gone/sub", "nodir/sub" })
    {
        CHECK_EQ(VfsMkdir(S, V, 0755), -ENOENT);
        CHECK_EQ(VfsSymlink(S, "a.txt", V), -ENOENT);
        CHECK_EQ(VfsLink(S, "a.txt", V), -ENOENT);
    }
    CHECK(!fs::exists(t / "wl/gone"));
    CHECK(!fs::exists(t / "wl/nodir"));
    VfsAttr A;
    CHECK_EQ(VfsGetattr(S, "gone", A), -ENOENT);
    CHECK_EQ(VfsMkdir(S, "a.txt/sub", 0755), -ENOTDIR);
    CHECK_EQ(VfsMkdir(S, "a.txt", 0755), -EEXIST);
    CHECK_EQ(VfsSymlink(S, "x", "a.txt"), -EEXIST);
    CHECK(!fs::exists(t / "wl/a.txt"));
    CHECK_EQ(VfsGetattr(S, "a.txt", A), 0);
    CHECK(!A.isDir);
    CHECK_EQ(A.size, (uint64_t)7);
    CHECK_EQ(VfsMkdir(S, "made", 0755), 0);
    const unsigned long long Before = S.detaches.load();
    CHECK_EQ(VfsLink(S, "a.txt", "made/b.txt"), 0);
    CHECK(S.detaches.load() > Before);
    CHECK(fs::exists(t / "wl/made/b.txt"));
}

// Two mounts of one writelayer (a launch's host mount, --uncached, and the sandbox's): what the other deletes from the
// lower layers, or makes again over a deletion, the uncached one sees at its next look — in the writelayer and in a kept
// folder, by name and under a deleted or made-again folder. Teeth: the uncached state answering from the masks it
// seeded at Init (every check below reads the other's change through them).
TEST(an_uncached_state_reads_the_markers_another_state_writes) {
    TmpDir t;
    for (const char *F : { "host/a.txt", "host/Saves/shipped.sav", "host/Config/c.ini", "host/Kept/k.cfg", "host/Kept/sub/x.ini" })
        writeFile(t / F, "package");
    fs::create_directories(t / "keep");
    Spec sp; sp.readOnly = false; sp.writelayer = t.str("wl");
    sp.layers = { dirLayer(t.str("host")), dirLayer(t.str("keep"), "Kept", true) };
    VfsState Host, Game; std::string err;
    Host.uncached = true;
    CHECK(Host.Init(sp, err));
    CHECK_EQ(VfsUnlink(Host, "Saves/shipped.sav"), 0);
    CHECK_EQ(VfsRmdir(Host, "Saves"), 0);
    CHECK(Game.Init(sp, err));
    VfsAttr A;
    CHECK_EQ(VfsGetattr(Game, "Saves", A), -ENOENT);
    CHECK_EQ(VfsMkdir(Game, "Saves", 0755), 0);
    CHECK_EQ(VfsUnlink(Game, "a.txt"), 0);
    CHECK_EQ(VfsUnlink(Game, "Config/c.ini"), 0);
    CHECK_EQ(VfsRmdir(Game, "Config"), 0);
    CHECK_EQ(VfsUnlink(Game, "Kept/k.cfg"), 0);
    CHECK_EQ(VfsUnlink(Game, "Kept/sub/x.ini"), 0);
    CHECK_EQ(VfsRmdir(Game, "Kept/sub"), 0);
    CHECK_EQ(VfsMkdir(Game, "Kept/sub", 0755), 0);
    CHECK_EQ(VfsGetattr(Host, "Saves", A), 0);
    CHECK(A.isDir);
    CHECK_EQ(VfsGetattr(Host, "Saves/shipped.sav", A), -ENOENT);   // under a folder made again
    for (const char *V : { "a.txt", "Config", "Config/c.ini", "Kept/k.cfg", "Kept/sub/x.ini" })
        CHECK_EQ(VfsGetattr(Host, V, A), -ENOENT);
    std::vector<std::string> Saves, Sub;
    CHECK_EQ(VfsReaddir(Host, "Saves", [&](const std::string &N) { Saves.push_back(N); }), 0);
    CHECK_EQ(VfsReaddir(Host, "Kept/sub", [&](const std::string &N) { Sub.push_back(N); }), 0);
    CHECK(Saves.empty());
    CHECK(Sub.empty());
    //And back: what the other made, it deletes again; the uncached state sees the shipped name gone, not back.
    CHECK_EQ(VfsRmdir(Game, "Saves"), 0);
    CHECK_EQ(VfsGetattr(Host, "Saves", A), -ENOENT);
    CHECK_EQ(VfsGetattr(Host, "Saves/shipped.sav", A), -ENOENT);
}

// `touch` sets now (UTIME_NOW), a time left alone stays (UTIME_OMIT), and nanoseconds are kept. Teeth: seconds only
// with nsec 0 (touch → 1970, the omitted time reset to 1970).
TEST(utimens_keeps_now_omit_and_nanoseconds) {
    TmpDir t;
    Spec sp; sp.readOnly = false; sp.writelayer = t.str("wl"); sp.layers = {};
    VfsState S; std::string err; CHECK(S.Init(sp, err));
    OpenFile *N = nullptr;
    CHECK_EQ(VfsCreate(S, "f.dat", 0644, O_WRONLY | O_TRUNC, N), 0);
    if (N) VfsRelease(N);
    const std::string Host = t.str("wl") + "/f.dat";
    struct stat St{};
    CHECK_EQ(VfsUtimens(S, "f.dat", { 1600000000, 123456789 }, { 1650000000, 987654321 }), 0);
    CHECK_EQ(::stat(Host.c_str(), &St), 0);
    CHECK_EQ((long long)St.st_mtim.tv_sec, 1650000000LL);
    CHECK_EQ((long long)St.st_mtim.tv_nsec, 987654321LL);
    CHECK_EQ(VfsUtimens(S, "f.dat", { 0, HostIO::TimeOmit }, { 0, HostIO::TimeNow }), 0);   // touch -m
    CHECK_EQ(::stat(Host.c_str(), &St), 0);
    CHECK((long long)St.st_mtim.tv_sec > 1700000000LL);                                    // now, not 1970
    CHECK_EQ((long long)St.st_atim.tv_sec, 1600000000LL);                                   // left alone
}

// A folder renamed while a lazy handle under it has not written yet: its first write lands in the moved file, a file
// made at the old place is left alone. Teeth: a folder rename that does not copy its files up before moving them.
TEST(a_lazy_writer_under_a_renamed_folder_writes_the_moved_file) {
    TmpDir t;
    writeFile(t / "host/D/x.dat", "old-x");
    Spec sp; sp.readOnly = false; sp.writelayer = t.str("wl"); sp.layers = { dirLayer(t.str("host")) };
    VfsState S; std::string err; CHECK(S.Init(sp, err));
    OpenFile *A = nullptr;
    CHECK_EQ(VfsOpen(S, "D/x.dat", O_RDWR, A), 0);
    if (!A) return;
    CHECK_EQ(VfsRename(S, "D", "E"), 0);
    CHECK_EQ(VfsMkdir(S, "D", 0755), 0);
    OpenFile *N = nullptr;
    CHECK_EQ(VfsCreate(S, "D/x.dat", 0644, O_WRONLY | O_TRUNC, N), 0);
    CHECK_EQ(VfsWrite(S, N, "NEW-x", 5, 0), (ssize_t)5);
    VfsRelease(N);
    CHECK_EQ(VfsWrite(S, A, "Z", 1, 0), (ssize_t)1);
    VfsRelease(A);
    auto Read = [&](const char *P) {
        OpenFile *H = nullptr; char b[16] = {0};
        if (VfsOpen(S, P, O_RDONLY, H) != 0) return std::string("(none)");
        const ssize_t n = VfsRead(H, b, sizeof b, 0); VfsRelease(H);
        return std::string(b, n > 0 ? (size_t)n : 0);
    };
    CHECK_EQ(Read("E/x.dat"), std::string("Zld-x"));
    CHECK_EQ(Read("D/x.dat"), std::string("NEW-x"));
}

// A copy-up is written under a name no listing shows and renamed to its own when whole; one a crash left behind in a
// kept writelayer is removed at the next mount, never shown and never taken for a deletion marker. Teeth: write the
// copy in place (a crash leaves a cut-short file under the file's name); keep leftovers.
TEST(a_copy_up_cut_short_is_never_the_file) {
    TmpDir t;
    writeFile(t / "host/d/big.dat", std::string(32 << 20, 'b'));
    writeFile(t / "wl/d/.wh..vgfs-copy.7", "half");
    Spec sp; sp.readOnly = false; sp.writelayer = t.str("wl"); sp.layers = { dirLayer(t.str("host")) };
    VfsState S; std::string err; CHECK(S.Init(sp, err));
    CHECK(!fs::exists(t / "wl/d/.wh..vgfs-copy.7"));
    VfsAttr a;
    CHECK_EQ(VfsGetattr(S, "d/.vgfs-copy.7", a), -ENOENT);
    CHECK(!readdirNames(S, "d").count(".wh..vgfs-copy.7"));
    // While a copy is written, the file's own name in the writelayer is not there: a reader resolving it meanwhile
    // reads the lower file, never a part of the copy.
    std::atomic<bool> Done{false}, SawPart{false};
    std::thread Watch([&] {
        while (!Done) {
            std::error_code ec;
            const auto n = fs::file_size(t / "wl/d/big.dat", ec);
            if (!ec && n != (uintmax_t)(32 << 20)) SawPart = true;
        }
    });
    OpenFile *W = nullptr;
    CHECK_EQ(VfsOpen(S, "d/big.dat", O_RDWR, W), 0);
    CHECK_EQ(VfsWrite(S, W, "X", 1, 0), (ssize_t)1);
    Done = true; Watch.join();
    CHECK(!SawPart.load());
    CHECK_EQ(fs::file_size(t / "wl/d/big.dat"), (uintmax_t)(32 << 20));
    VfsRelease(W);
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

// A delta whose tables name sizes the file cannot hold (corrupt, or crafted) is refused with a reason — never an
// allocation of what it says (tens of GB: the mount helper aborted). Teeth: allocate the table as named.
TEST(a_delta_naming_impossible_sizes_is_refused) {
    std::string base(4096, 'A');
    std::string tgt = base; tgt[100] = 'B';
    auto delta = vgdelta::GenerateDelta((const uint8_t *)base.data(), base.size(), (const uint8_t *)tgt.data(), tgt.size());
    CHECK(!delta.empty());
    auto baseSrc = std::make_shared<MemByteSource>(std::vector<uint8_t>(base.begin(), base.end()));
    //The segment table's compressed length (u64 at 44) said to be 2^40 bytes.
    std::vector<uint8_t> Bad = delta;
    const uint64_t Huge = 1ull << 40;
    std::memcpy(Bad.data() + 44, &Huge, 8);
    std::string derr;
    auto ds = vgdelta::DeltaByteSource::Create(std::make_shared<MemByteSource>(Bad), baseSrc, derr, false);
    CHECK(ds == nullptr);
    CHECK(derr.find("larger than the file") != std::string::npos);
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
    CHECK(spec("[]").first);                          // an empty list: a delta over nothing (its own bytes)
    CHECK(spec("null").first);                        // null: it named no base (the plan reports it)
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

// A delta built over a single file — a disc image, the extracted files rebuilt from it — reads that file's own bytes as
// its base (the image is stored as it was dumped, no zip around it). Where the delta is mounted it hides the image (the
// files replace it there); at another place the image stays; read only for its bytes, it shows nowhere. A spec may name
// a file's CID and mark it bytes-only. Teeth: only a zip or a delta carries a CID (the delta cannot rebuild); a file
// named as a base left showing where the delta mounts.
TEST(a_delta_over_a_disc_image_file_rebuilds_from_its_bytes) {
    TmpDir t;
    std::string iso(300000, '\0');
    std::mt19937 rng(7);
    for (char &c : iso) c = char(rng());
    fs::create_directories(t / "disc");
    { std::ofstream(t / "disc/game.iso", std::ios::binary) << iso; }
    writeStoreZip(t / "files.zip", { { "default.xbe", "XBE-HEADER", false }, { "data/a.bin", iso.substr(4096, 100000), false } });
    writeDelta(t / "files.vgdelta", iso, t / "files.zip");
    auto File = [&](const std::string &target, bool bytesOnly) {
        LayerSpec L; L.type = LayerType::File; L.source = t.str("disc/game.iso"); L.cid = L.source; L.target = target; L.bytesOnly = bytesOnly;
        return L;
    };
    auto Read = [](VfsState &S, const std::string &P) {
        OpenFile *H = nullptr; if (VfsOpen(S, P, O_RDONLY, H) != 0 || !H) return std::string("(none)");
        std::string Out(200000, '\0'); const ssize_t n = VfsRead(H, Out.data(), Out.size(), 0); VfsRelease(H);
        Out.resize(n > 0 ? (size_t)n : 0); return Out;
    };
    VfsAttr a;
    {   // at the same place: the files, not the image
        Spec sp; sp.readOnly = true; sp.layers = { File("game", false), deltaLayer(t.str("files.vgdelta"), "game", { t.str("disc/game.iso") }) };
        VfsState S; std::string err; CHECK(S.Init(sp, err));
        CHECK_EQ(Read(S, "game/default.xbe"), std::string("XBE-HEADER"));
        CHECK(Read(S, "game/data/a.bin") == iso.substr(4096, 100000));
        CHECK_EQ(VfsGetattr(S, "game/game.iso", a), -ENOENT);
        CHECK(PlanTree(sp).problems.empty());
    }
    {   // elsewhere: the image stays where it is
        Spec sp; sp.readOnly = true; sp.layers = { File("disc", false), deltaLayer(t.str("files.vgdelta"), "game", { t.str("disc/game.iso") }) };
        VfsState S; std::string err; CHECK(S.Init(sp, err));
        CHECK_EQ(Read(S, "game/default.xbe"), std::string("XBE-HEADER"));
        CHECK_EQ(VfsGetattr(S, "disc/game.iso", a), 0);
        CHECK_EQ(a.size, (uint64_t)iso.size());
    }
    {   // placed by a submount (a TAKE renaming it): hidden inside the delta's place, shown by its new name outside
        LayerSpec In = File("", false); In.submounts = { { "game.iso", "game/renamed.iso" } };
        LayerSpec Out = File("", false); Out.submounts = { { "game.iso", "other/renamed.iso" } };
        Spec sp; sp.readOnly = true; sp.layers = { In, Out, deltaLayer(t.str("files.vgdelta"), "game", { t.str("disc/game.iso") }) };
        VfsState S; std::string err; CHECK(S.Init(sp, err));
        CHECK_EQ(Read(S, "game/default.xbe"), std::string("XBE-HEADER"));
        CHECK_EQ(VfsGetattr(S, "game/renamed.iso", a), -ENOENT);
        CHECK_EQ(VfsGetattr(S, "other/renamed.iso", a), 0);
        CHECK_EQ(a.size, (uint64_t)iso.size());
        CHECK(Read(S, "other/renamed.iso").substr(0, 1000) == iso.substr(0, 1000));
        CHECK(readdirNames(S, "other").count("renamed.iso"));
        CHECK_EQ(VfsGetattr(S, "game.iso", a), -ENOENT);            // only where its submounts place it
    }
    {   // only its bytes: nowhere in the tree
        Spec sp; sp.readOnly = true; sp.layers = { File("game", true), deltaLayer(t.str("files.vgdelta"), "game", { t.str("disc/game.iso") }) };
        VfsState S; std::string err; CHECK(S.Init(sp, err));
        CHECK_EQ(Read(S, "game/default.xbe"), std::string("XBE-HEADER"));
        CHECK_EQ(VfsGetattr(S, "game/game.iso", a), -ENOENT);
    }
    // The spec says it: a file's cid, bytes-only.
    Spec parsed; std::string err;
    CHECK(ParseSpecText(R"({"mountpoint":"/m","readonly":true,"layers":[{"type":"file","source":"/x.iso","target":"g","cid":"Qmx","bytesOnly":true},)"
                        R"({"type":"delta","source":"/d.vgdelta","target":"g","bases":["Qmx"]}]})", parsed, err));
    CHECK(err.empty());
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

// A delta over several bases reads each where it lies (never joined in memory) and is, byte for byte, the delta over
// them joined: windows and matches that cross from one base into the next included. Teeth: drop a window across parts;
// stop a match at a part's end.
TEST(a_delta_over_several_bases_is_the_delta_over_them_joined) {
    std::mt19937 r(31); std::vector<uint8_t> a(70000), b(1000), c(90000), t;
    for (auto *v : {&a, &b, &c}) for (auto &x : *v) x = (uint8_t)r();
    std::vector<uint8_t> joined = a; joined.insert(joined.end(), b.begin(), b.end()); joined.insert(joined.end(), c.begin(), c.end());
    // the target: runs from each base, and runs crossing a|b and b|c, with literals between
    t.insert(t.end(), joined.begin() + 69000, joined.begin() + 72000);          // across a|b|c (b is 1000 bytes)
    for (int i = 0; i < 500; ++i) t.push_back((uint8_t)r());
    t.insert(t.end(), joined.begin() + 100, joined.begin() + 30000);
    t.insert(t.end(), joined.begin() + 80000, joined.begin() + 160000);
    TmpDir d; std::string e1, e2;
    CHECK(vgdelta::GenerateDeltaToFile(joined.data(), joined.size(), t.data(), t.size(), d.str("one.vgdelta"), e1));
    CHECK(vgdelta::GenerateDeltaToFile({ {a.data(), a.size()}, {b.data(), b.size()}, {c.data(), c.size()} }, t.data(), t.size(), d.str("parts.vgdelta"), e2));
    CHECK(slurpFile(d / "one.vgdelta") == slurpFile(d / "parts.vgdelta"));
    CHECK(slurpFile(d / "one.vgdelta").size() < t.size() / 10);             // it did match (the runs, the crossings)
}

// A delta over NOTHING ("bases": []) is a file stored compressed: it mounts its own bytes, zstd blocks read at random;
// a delta that named no base ("bases": null) is reported and left out. Teeth: refuse empty bases; read null as empty.
TEST(a_delta_over_nothing_is_its_own_bytes_and_one_naming_none_is_left_out) {
    TmpDir t;
    std::string game(300000, 'g'); for (size_t i = 0; i < game.size(); ++i) game[i] = char('a' + ((i / 3) * 7 + i % 11) % 26);
    writeStoreZip(t / "v1.zip", { { "game.exe", game, false } });
    const auto Dl = vgdelta::GenerateDelta(reinterpret_cast<const uint8_t *>(""), 0, (const uint8_t *)slurpFile(t / "v1.zip").data(), slurpFile(t / "v1.zip").size());
    CHECK(!Dl.empty() && Dl.size() < slurpFile(t / "v1.zip").size());     // compressed
    { std::ofstream o(t / "v1.vgdelta", std::ios::binary); o.write((const char *)Dl.data(), (std::streamsize)Dl.size()); }
    { std::ofstream o(t / "junk.vgdelta", std::ios::binary); o << "x"; }
    LayerSpec Own = deltaLayer(t.str("v1.vgdelta"), "g", {}); Own.basesNamed = true;
    LayerSpec None = deltaLayer(t.str("junk.vgdelta"), "n", {}); None.basesNamed = false;
    Spec sp; sp.readOnly = true; sp.layers = { Own, None };
    const TreePlan P = PlanTree(sp);
    CHECK(!P.broken[0] && P.broken[1]);
    CHECK(P.problems.size() == 1 && P.problems[0].find("names no base") != std::string::npos);
    VfsState S; std::string err;
    CHECK(S.Init(sp, err));
    OpenFile *F = nullptr;
    CHECK_EQ(VfsOpen(S, "g/game.exe", 0, F), 0);
    std::string got(game.size(), 0);
    CHECK_EQ(F ? VfsRead(F, got.data(), got.size(), 0) : -1, (ssize_t)game.size());
    if (F) VfsRelease(F);
    CHECK(got == game);
    VfsAttr at;
    CHECK(VfsGetattr(S, "n", at) != 0);
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
    {   // a single file placed by a submount (a TAKE renaming it) collides by case where it lands, by its new name — not
        // at its target by the name its source has — at each place a submount puts it. Teeth: name the file at
        // target/its source's name; use only its first mount.
        const std::vector<std::string> Za = { "DATA/GAME.ISO", "Other/Game.iso" };
        const EntriesFn Ff = [&](size_t I) -> const std::vector<std::string> * { return I == 0 ? &Za : nullptr; };
        auto KeysOf = [&](std::vector<std::pair<std::string, std::string>> Subs) {
            LayerSpec F; F.type = LayerType::File; F.source = "/disc/game [1234].iso"; F.target = "x"; F.submounts = std::move(Subs);
            Spec Fs; Fs.readOnly = true;
            Fs.layers = { zipLayer("/a.zip"), F };
            std::set<std::string> Keys;
            for (const auto &Cc : CaseConflicts(Fs, PlanTree(Fs), Ff)) Keys.insert(Cc.key);
            return Keys;
        };
        CHECK(KeysOf({ { "game [1234].iso", "Data/Game.iso" } }).count("data"));                 // DATA against Data
        CHECK(KeysOf({ { "game [1234].iso", "DATA/Game.iso" } }).count("data/game.iso"));         // GAME.ISO against Game.iso
        CHECK(KeysOf({ { "game [1234].iso", "elsewhere/a.iso" }, { "game [1234].iso", "other/game.iso" } }).count("other"));
        CHECK(KeysOf({}).empty());                                                                  // whole, at x/: nothing
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

// Counts what is read of a source and records what is asked for ahead (prefetch), passing both through.
struct CountingSource : ByteSource {
    std::shared_ptr<ByteSource> inner;
    std::atomic<int> reads{0};
    std::vector<std::pair<uint64_t, uint64_t>> asked;   // prefetch (off, n), in order
    std::vector<std::string> order;                     // "p" a prefetch, "r" a read
    std::mutex mu;
    std::function<bool(uint64_t)> failAt;               // a read at this offset fails (once the function says so)
    explicit CountingSource(std::shared_ptr<ByteSource> s) : inner(std::move(s)) {}
    ssize_t pread(void *buf, size_t n, uint64_t off) override {
        { std::lock_guard<std::mutex> g(mu); order.push_back("r"); }
        if (failAt && failAt(off)) return -EIO;
        ++reads; return inner->pread(buf, n, off);
    }
    void prefetch(uint64_t off, uint64_t n) override {
        std::lock_guard<std::mutex> g(mu); asked.push_back({ off, n }); order.push_back("p");
    }
    uint64_t size() const override { return inner->size(); }
};

static std::shared_ptr<ByteSource> fileSource(const fs::path &p) {
    std::ifstream f(p, std::ios::binary);
    std::vector<uint8_t> b((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    return std::make_shared<MemByteSource>(std::move(b));
}

// Indexing an archive reads its central directory and nothing per member: where a member's bytes start is read from
// its local header when it is first opened, once. On a disk that seeks a read per member was minutes for a runner's
// thousands. Teeth: read each local header while indexing (reads grow with the members); forget the offset (a
// second open reads the header again).
TEST(an_archive_is_indexed_without_reading_its_members) {
    TmpDir t;
    std::vector<std::tuple<std::string, std::string, bool>> few, many;
    for (int i = 0; i < 4; ++i) few.push_back({ "f" + std::to_string(i) + ".txt", "x" + std::to_string(i), false });
    for (int i = 0; i < 400; ++i) many.push_back({ "m" + std::to_string(i) + ".txt", "y" + std::to_string(i), false });
    writeStoreZip(t / "few.zip", few);
    writeStoreZip(t / "many.zip", many);
    auto fewSrc = std::make_shared<CountingSource>(fileSource(t / "few.zip"));
    auto manySrc = std::make_shared<CountingSource>(fileSource(t / "many.zip"));
    auto F = BuildZipIndex(fewSrc, "few.zip");
    auto M = BuildZipIndex(manySrc, "many.zip");
    CHECK(F && M);
    if (!F || !M) return;
    CHECK_EQ(M->byName.size(), (size_t)400);
    CHECK(manySrc->reads.load() <= fewSrc->reads.load() + 4);   // the directory is bigger, not read member by member
    const ZipEntry &E = M->byName.at("m123.txt");
    ZipReader R;
    const int before = manySrc->reads.load();
    CHECK_EQ(OpenZipEntry(*M, E, R), 0);
    char buf[16] = {0};
    CHECK_EQ(ReadZipEntry(R, buf, sizeof buf, 0), 4);
    CHECK_EQ(std::string(buf, 4), std::string("y123"));
    const int opened = manySrc->reads.load();
    CHECK(opened > before);
    ZipReader R2;
    CHECK_EQ(OpenZipEntry(*M, E, R2), 0);
    CHECK_EQ(manySrc->reads.load(), opened);                    // its header is known now
}

// A member whose local header is not one (a damaged archive) is still listed, and refuses to open: its bytes are not
// served from a guessed place. Teeth: serve it at the central directory's offset (reads the header as content).
TEST(a_member_whose_local_header_is_damaged_does_not_open) {
    TmpDir t;
    writeStoreZip(t / "a.zip", { { "ok.txt", "fine", false }, { "bad.txt", "broken", false } });
    auto Z0 = BuildZipIndex(fileSource(t / "a.zip"), "a.zip");
    CHECK(Z0);
    if (!Z0) return;
    std::ifstream f(t / "a.zip", std::ios::binary);
    std::vector<uint8_t> b((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    b[Z0->byName.at("bad.txt").localHeader] = 'X';            // "PK\3\4" no more
    auto Z = BuildZipIndex(std::make_shared<MemByteSource>(b), "a.zip");
    CHECK(Z && Z->byName.count("bad.txt"));
    if (!Z) return;
    ZipReader R;
    CHECK_EQ(OpenZipEntry(*Z, Z->byName.at("bad.txt"), R), -EIO);
    CHECK_EQ(ZipDataOffset(*Z, Z->byName.at("bad.txt")), UINT64_MAX);
    CHECK_EQ(OpenZipEntry(*Z, Z->byName.at("ok.txt"), R), 0);
}

// A stored member read by handing over its archive's file (the splice path, VfsReadFrom) is handed at its own bytes:
// the member's data offset plus the read's, cut at the member's end. Teeth: hand the read's offset alone; do not cut
// at the member's end (the next member's header is read as content).
TEST(a_stored_member_is_handed_over_at_its_own_bytes) {
    TmpDir t;
    writeStoreZip(t / "a.zip", { { "first.txt", "AAAAAAAA", false }, { "m.txt", "0123456789", false }, { "z.txt", "ZZZ", false } });
    Spec sp; sp.readOnly = true; sp.layers = { zipLayer(t.str("a.zip")) };
    VfsState S; std::string err; CHECK(S.Init(sp, err));
    OpenFile *H = nullptr;
    CHECK_EQ(VfsOpen(S, "m.txt", O_RDONLY, H), 0);
    if (!H) return;
    int fd = -1; uint64_t pos = 0; size_t len = 0;
    CHECK(VfsReadFrom(H, 4, 3, fd, pos, len));
    char b[16] = {0};
    CHECK_EQ(len, (size_t)4);
    CHECK_EQ(pread(fd, b, len, (off_t)pos), (ssize_t)4);
    CHECK_EQ(std::string(b, 4), std::string("3456"));
    CHECK(VfsReadFrom(H, 16, 8, fd, pos, len));                      // past the end: only what is left
    CHECK_EQ(len, (size_t)2);
    CHECK_EQ(pread(fd, b, len, (off_t)pos), (ssize_t)2);
    CHECK_EQ(std::string(b, 2), std::string("89"));
    VfsRelease(H);
}

// An archive whose end record counts fewer members than its directory holds is not indexed from that count: the walk
// served two of three and c.txt was missing, unseen (libzip refuses the archive). Teeth: trust the count.
TEST(an_archive_counting_fewer_members_than_it_holds_is_not_walked_short) {
    TmpDir t;
    writeStoreZip(t / "a.zip", { { "a.txt", "a", false }, { "b.txt", "b", false }, { "c.txt", "c", false } });
    std::ifstream f(t / "a.zip", std::ios::binary);
    std::vector<uint8_t> b((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    size_t eocd = b.size() - 22;
    while (eocd > 0 && !(b[eocd] == 'P' && b[eocd + 1] == 'K' && b[eocd + 2] == 5 && b[eocd + 3] == 6)) --eocd;
    b[eocd + 8] = 2; b[eocd + 9] = 0; b[eocd + 10] = 2; b[eocd + 11] = 0;   // this disk's count and the total
    MemByteSource M(b);
    int Walked = 0;
    CHECK(!zipscan::WalkCentralDirFull(M, [&](const zipscan::CdEntry &) { ++Walked; return true; }));
    auto Z = BuildZipIndex(std::make_shared<MemByteSource>(b), "a.zip");
    CHECK(!Z || Z->byName.count("c.txt"));                     // all of it, or none (refused, said so)
}

// A link is worked out once: a prefix's links are looked up over and over, and each lookup read the target again. One
// whose bytes did not read is tried again next time, not taken for a link that leads nowhere. Teeth: resolve every
// time (reads grow per lookup); remember a failed read as "no file" (the second lookup stays null).
TEST(an_archive_link_is_resolved_once_and_a_failed_read_again) {
    TmpDir t;
    writeStoreZip(t / "a.zip", { { "lib/real.dll", "MZcontent", false }, { "pfx/sys/real.dll", "../../lib/real.dll", true } });
    auto Src = std::make_shared<CountingSource>(fileSource(t / "a.zip"));
    auto Z = BuildZipIndex(Src, "a.zip");
    CHECK(Z);
    if (!Z) return;
    const ZipEntry &L = Z->byName.at("pfx/sys/real.dll");
    bool fail = true;
    const uint64_t at = L.localHeader;
    Src->failAt = [&](uint64_t off) { return fail && off >= at && off < at + 128; };
    CHECK(ResolveZipSymlink(*Z, L) == nullptr);                 // the link did not read
    fail = false;
    const ZipEntry *T = ResolveZipSymlink(*Z, L);
    CHECK(T && T->name == "lib/real.dll");
    const int after = Src->reads.load();
    for (int i = 0; i < 5; ++i) CHECK(ResolveZipSymlink(*Z, L) == T);
    CHECK_EQ(Src->reads.load(), after);
}

// A delta's view of a file is short runs from all over its base and blocks of its delta: a read across them asks for
// every one first, then reads (a disk serves the queue in one sweep — measured ten times faster than one after
// another); opening a small file in such a view asks for all of it. Teeth: drop the prefetch from pread (the first
// thing the base sees is a read), or from the open; ask on every open (a plain archive's file is asked for too).
TEST(a_read_through_a_delta_asks_for_its_runs_before_reading_them) {
    std::string base(1 << 16, 0);
    for (size_t i = 0; i < base.size(); ++i) base[i] = (char)((i * 2654435761u) >> 13);
    std::string tgt;
    for (int k = 0; k < 16; ++k) {                              // runs of the base far apart, between new bytes
        tgt += base.substr((size_t)((k * 37) % 61) * 1000, 900);
        tgt += std::string(300, (char)('a' + k));
    }
    auto delta = vgdelta::GenerateDelta((const uint8_t *)base.data(), base.size(), (const uint8_t *)tgt.data(), tgt.size(), 4096);
    auto Base = std::make_shared<CountingSource>(std::make_shared<MemByteSource>(std::vector<uint8_t>(base.begin(), base.end())));
    auto File = std::make_shared<CountingSource>(std::make_shared<MemByteSource>(delta));
    std::string err;
    auto D = vgdelta::DeltaByteSource::Create(File, Base, err, false);
    CHECK(D != nullptr);
    if (!D) return;
    Base->order.clear(); File->order.clear(); Base->asked.clear(); File->asked.clear();
    std::vector<uint8_t> out(tgt.size());
    CHECK(D->preadAll(out.data(), out.size(), 0));
    CHECK(std::memcmp(out.data(), tgt.data(), tgt.size()) == 0);
    CHECK(!Base->order.empty() && Base->order.front() == "p");
    CHECK(Base->asked.size() >= 8);                             // the runs, each where it is in the base
    CHECK(!File->order.empty() && File->order.front() == "p");  // and the delta's blocks
    //Opening a small file inside the view asks for the whole of it at once; one in a plain archive (one run, which the
    //host reads ahead itself) is not asked for.
    struct Rec : ByteSource {
        std::vector<std::pair<uint64_t, uint64_t>> asked; std::shared_ptr<ByteSource> in; bool scat = true;
        ssize_t pread(void *b, size_t n, uint64_t o) override { return in->pread(b, n, o); }
        void prefetch(uint64_t o, uint64_t n) override { asked.push_back({ o, n }); }
        bool scattered() const override { return scat; }
        uint64_t size() const override { return in->size(); }
    };
    TmpDir t;
    writeStoreZip(t / "z.zip", { { "a.dll", std::string(5000, 'q'), false } });
    auto R = std::make_shared<Rec>(); R->in = fileSource(t / "z.zip");
    auto Z = BuildZipIndex(R, "z.zip");
    CHECK(Z);
    if (!Z) return;
    R->asked.clear();
    ZipReader Zr;
    CHECK_EQ(OpenZipEntry(*Z, Z->byName.at("a.dll"), Zr), 0);
    CHECK_EQ(R->asked.size(), (size_t)1);
    if (!R->asked.empty()) { CHECK_EQ(R->asked[0].first, Zr.dataOffset); CHECK_EQ(R->asked[0].second, (uint64_t)5000); }
    R->scat = false;
    CHECK_EQ(OpenZipEntry(*Z, Z->byName.at("a.dll"), Zr), 0);
    CHECK_EQ(R->asked.size(), (size_t)1);
}

// The decompressed blocks of a delta are kept while they are used: reading a file again does not read its delta again.
// They go with the delta file's view. Teeth: keep nothing (the second read reads the delta again); drop nothing when the
// view goes (the cache still holds its bytes).
TEST(delta_blocks_are_kept_while_used_and_go_with_their_view) {
    auto make = [](char seed) {
        std::string base(1 << 15, seed), tgt;
        for (size_t i = 0; i < 100000; ++i) tgt += (char)(seed + (i * 7919) % 251);
        return std::make_pair(base, tgt);
    };
    auto [b1, t1] = make('a');
    auto [b2, t2] = make('k');
    auto d1 = vgdelta::GenerateDelta((const uint8_t *)b1.data(), b1.size(), (const uint8_t *)t1.data(), t1.size(), 4096);
    auto d2 = vgdelta::GenerateDelta((const uint8_t *)b2.data(), b2.size(), (const uint8_t *)t2.data(), t2.size(), 4096);
    std::string err;
    const size_t heldBefore = vgdelta::CachedBlockBytes();
    {
        auto File = std::make_shared<CountingSource>(std::make_shared<MemByteSource>(d1));
        auto D = vgdelta::DeltaByteSource::Create(File, std::make_shared<MemByteSource>(std::vector<uint8_t>(b1.begin(), b1.end())), err, false);
        CHECK(D != nullptr);
        if (!D) return;
        std::vector<uint8_t> out(t1.size());
        CHECK(D->preadAll(out.data(), out.size(), 0));
        const int once = File->reads.load();
        CHECK(D->preadAll(out.data(), out.size(), 0));
        CHECK_EQ(File->reads.load(), once);
        CHECK(std::memcmp(out.data(), t1.data(), t1.size()) == 0);
        CHECK(vgdelta::CachedBlockBytes() > heldBefore);
    }
    CHECK_EQ(vgdelta::CachedBlockBytes(), heldBefore);
    auto D2 = vgdelta::DeltaByteSource::Create(std::make_shared<MemByteSource>(d2),
                                               std::make_shared<MemByteSource>(std::vector<uint8_t>(b2.begin(), b2.end())), err, false);
    CHECK(D2 != nullptr);
    if (!D2) return;
    std::vector<uint8_t> out(t2.size());
    CHECK(D2->preadAll(out.data(), out.size(), 0));
    CHECK(std::memcmp(out.data(), t2.data(), t2.size()) == 0);
}

// Views of one chain share the delta files' blocks: a version read after the one beneath it reads none of that one's
// delta again. Teeth: keep blocks per view (the upper view reads the lower delta's blocks again).
TEST(views_of_one_chain_share_their_delta_blocks) {
    std::string base(1 << 14, 'b'), v1, v2;
    for (size_t i = 0; i < 60000; ++i) v1 += (char)((i * 7919) % 251);
    v2 = v1; v2.replace(30000, 500, std::string(500, '!'));
    auto d1 = vgdelta::GenerateDelta((const uint8_t *)base.data(), base.size(), (const uint8_t *)v1.data(), v1.size(), 4096);
    auto d2 = vgdelta::GenerateDelta((const uint8_t *)v1.data(), v1.size(), (const uint8_t *)v2.data(), v2.size(), 4096);
    auto F1 = std::make_shared<CountingSource>(std::make_shared<MemByteSource>(d1));
    std::string err;
    auto V1 = vgdelta::DeltaByteSource::Create(F1, std::make_shared<MemByteSource>(std::vector<uint8_t>(base.begin(), base.end())), err, false);
    CHECK(V1 != nullptr);
    if (!V1) return;
    auto V2 = vgdelta::DeltaByteSource::Create(std::make_shared<MemByteSource>(d2), V1, err, false);
    CHECK(V2 != nullptr);
    if (!V2) return;
    std::vector<uint8_t> out(v1.size());
    CHECK(V1->preadAll(out.data(), out.size(), 0));
    const int read1 = F1->reads.load();
    CHECK(V2->preadAll(out.data(), out.size(), 0));
    CHECK(std::memcmp(out.data(), v2.data(), v2.size()) == 0);
    CHECK_EQ(F1->reads.load(), read1);
}

// The cache keeps no more than its budget, whatever is read: the least recently used blocks go first. Teeth: never
// evict (the bytes held grow with what was read).
TEST(the_block_cache_keeps_within_its_budget) {
    vgdelta::SetCachedBlockBudget(32u << 20);                       // a budget this test can fill quickly
    struct Restore { ~Restore() { vgdelta::SetCachedBlockBudget(0); } } restore;   // the default again after
    const size_t Block = 1u << 20, Blocks = vgdelta::CachedBlockBudget() / Block + 8;
    std::string tgt(Blocks * Block, '\0');
    for (size_t b = 0; b < Blocks; ++b)
        for (size_t i = 0; i < Block; i += 4) { const uint32_t v = (uint32_t)(b * 2654435761u + 1); std::memcpy(&tgt[b * Block + i], &v, 4); }
    std::string base(4096, '\0');
    auto d = vgdelta::GenerateDelta((const uint8_t *)base.data(), base.size(), (const uint8_t *)tgt.data(), tgt.size(), (uint32_t)Block);
    std::string err;
    auto D = vgdelta::DeltaByteSource::Create(std::make_shared<MemByteSource>(d), std::make_shared<MemByteSource>(std::vector<uint8_t>(base.begin(), base.end())), err, false);
    CHECK(D != nullptr);
    if (!D) return;
    std::vector<uint8_t> out(Block);
    bool same = true;
    for (size_t b = 0; b < Blocks; ++b) {
        CHECK(D->preadAll(out.data(), Block, b * Block));
        same = same && std::memcmp(out.data(), &tgt[b * Block], Block) == 0;
    }
    CHECK(same);
    CHECK(vgdelta::CachedBlockBytes() <= vgdelta::CachedBlockBudget());
    CHECK(vgdelta::CachedBlockBytes() >= vgdelta::CachedBlockBudget() - Block);
}

// The budget is the machine's to set: a 32nd of its memory, never under 128 MiB nor over 1 GiB (a fixed 128 MiB thrashed
// on a large game's update on any machine). Teeth: a fixed budget (the bounds or the scale broken).
TEST(the_block_budget_follows_the_machines_memory) {
    const size_t B = vgdelta::DefaultCachedBlockBudget();
    CHECK(B >= (128u << 20) && B <= (1u << 30));
    const long Pages = sysconf(_SC_PHYS_PAGES), Page = sysconf(_SC_PAGE_SIZE);
    const uint64_t Ram = (uint64_t)Pages * (uint64_t)Page;
    CHECK_EQ((uint64_t)B, std::clamp<uint64_t>(Ram / 32, 128ull << 20, 1ull << 30));
    ::setenv("VGFS_BLOCK_CACHE_MB", "300", 1);
    CHECK_EQ(vgdelta::DefaultCachedBlockBudget(), (size_t)300 << 20);
    vgdelta::ShareCachedBlockBudget(2);                              // one told how much to keep keeps it whole
    CHECK_EQ(vgdelta::CachedBlockBudget(), (size_t)300 << 20);
    ::unsetenv("VGFS_BLOCK_CACHE_MB");
    vgdelta::SetCachedBlockBudget(0);
}

// The mounts of one launch (a runner build, the game) share one budget: each took the machine's 32nd, so a launch held
// twice it. A spec that says how many mounts its launch makes gets its share; one that says nothing, all of it.
// Teeth: ignore launchMounts (each mount takes the whole budget).
TEST(the_mounts_of_a_launch_share_one_block_budget) {
    const fs::path t = fs::temp_directory_path() / ("vgfs_share_" + std::to_string(::getpid()) + ".json");
    { std::ofstream(t) << "{\"mountpoint\":\"/x\",\"readonly\":true,\"launchMounts\":2,\"layers\":[]}"; }
    Spec sp; std::string err;
    CHECK(ParseSpec(t.string(), sp, err));
    CHECK_EQ(sp.launchMounts, 2);
    vgdelta::ShareCachedBlockBudget(sp.launchMounts);
    CHECK_EQ(vgdelta::CachedBlockBudget(), std::max<size_t>(vgdelta::DefaultCachedBlockBudget() / 2, 64u << 20));
    { std::ofstream(t) << "{\"mountpoint\":\"/x\",\"readonly\":true,\"layers\":[]}"; }
    Spec one; CHECK(ParseSpec(t.string(), one, err));
    CHECK_EQ(one.launchMounts, 1);
    vgdelta::SetCachedBlockBudget(0);
    fs::remove(t);
}

// Readers of the same block at the same time decompress it once: the others wait for it (FUSE serves reads at once,
// and neighbouring files share blocks). Teeth: no flight (each reader decompresses it again).
TEST(a_block_read_at_once_is_decompressed_once) {
    std::string base(4096, '\0'), tgt;
    for (size_t i = 0; i < 300000; ++i) tgt += (char)((i * 131 + i / 977) % 251);
    auto d = vgdelta::GenerateDelta((const uint8_t *)base.data(), base.size(), (const uint8_t *)tgt.data(), tgt.size(), 1u << 18);
    std::string err;
    auto D = vgdelta::DeltaByteSource::Create(std::make_shared<MemByteSource>(d), std::make_shared<MemByteSource>(std::vector<uint8_t>(base.begin(), base.end())), err, false);
    CHECK(D != nullptr);
    if (!D) return;
    vgdelta::DebugSlowDecompress(200);
    const long long Before = vgdelta::DebugDecompressions();
    std::vector<std::thread> T;
    std::atomic<int> Ok{ 0 };
    for (int I = 0; I < 6; ++I)
        T.emplace_back([&, I] {
            std::vector<uint8_t> out(1000);
            if (D->preadAll(out.data(), out.size(), 1000 * (uint64_t)I) && std::memcmp(out.data(), &tgt[1000 * (size_t)I], out.size()) == 0) ++Ok;
        });
    for (auto &X : T) X.join();
    vgdelta::DebugSlowDecompress(0);
    CHECK_EQ(Ok.load(), 6);
    CHECK_EQ(vgdelta::DebugDecompressions() - Before, 1LL);
}

// A file prefetched whole when opened is not prefetched again, read by read: each read went over every run again.
// A range outside it is. Teeth: drop the memo (a scan per read).
TEST(a_range_prefetched_is_not_prefetched_again) {
    std::string base(1 << 20, '\0');
    for (size_t i = 0; i < base.size(); ++i) base[i] = (char)(i * 7);
    std::string tgt;
    for (size_t i = 0; i < 200; ++i) { tgt += base.substr((i * 4099) % (base.size() - 3000), 3000); tgt += std::string(17, (char)i); }
    auto d = vgdelta::GenerateDelta((const uint8_t *)base.data(), base.size(), (const uint8_t *)tgt.data(), tgt.size(), 1u << 16);
    std::string err;
    auto D = vgdelta::DeltaByteSource::Create(std::make_shared<MemByteSource>(d), std::make_shared<MemByteSource>(std::vector<uint8_t>(base.begin(), base.end())), err, false);
    CHECK(D != nullptr);
    if (!D) return;
    const long long Before = vgdelta::DebugPrefetchScans();
    D->prefetch(0, 200000);
    std::vector<uint8_t> out(9000);
    for (uint64_t At = 0; At + out.size() < 200000; At += 9000) CHECK(D->preadAll(out.data(), out.size(), At));
    CHECK_EQ(vgdelta::DebugPrefetchScans() - Before, 1LL);
    CHECK(D->preadAll(out.data(), out.size(), 300000));               // outside it: asked for
    CHECK_EQ(vgdelta::DebugPrefetchScans() - Before, 2LL);
}

// A zip written byte by byte: each member {raw name, flags, made-by, external attributes, method, extra field, data}.
struct RawMember { std::string name; uint16_t flags = 0, madeBy = 0x031E, method = 0; uint32_t ext = 0100644u << 16; std::string extra, data; };
static void Put16(std::string &o, uint16_t v) { o += (char)(v & 0xFF); o += (char)(v >> 8); }
static void Put32(std::string &o, uint32_t v) { Put16(o, (uint16_t)(v & 0xFFFF)); Put16(o, (uint16_t)(v >> 16)); }
static uint32_t TestCrc(const std::string &S) {
    uint32_t C = 0xFFFFFFFFu;
    for (unsigned char B : S) { C ^= B; for (int K = 0; K < 8; ++K) C = (C >> 1) ^ (0xEDB88320u & (0u - (C & 1u))); }
    return ~C;
}
static void writeRawZip(const fs::path &p, const std::vector<RawMember> &ms) {
    std::string out, cd;
    for (const RawMember &m : ms) {
        const uint32_t lh = (uint32_t)out.size(), crc = TestCrc(m.data);
        Put32(out, 0x04034b50); Put16(out, 20); Put16(out, m.flags); Put16(out, m.method); Put16(out, 0x6000); Put16(out, 0x5A21);
        Put32(out, crc); Put32(out, (uint32_t)m.data.size()); Put32(out, (uint32_t)m.data.size());
        Put16(out, (uint16_t)m.name.size()); Put16(out, 0); out += m.name; out += m.data;
        Put32(cd, 0x02014b50); Put16(cd, m.madeBy); Put16(cd, 20); Put16(cd, m.flags); Put16(cd, m.method); Put16(cd, 0x6000); Put16(cd, 0x5A21);
        Put32(cd, crc); Put32(cd, (uint32_t)m.data.size()); Put32(cd, (uint32_t)m.data.size());
        Put16(cd, (uint16_t)m.name.size()); Put16(cd, (uint16_t)m.extra.size()); Put16(cd, 0); Put16(cd, 0); Put16(cd, 0);
        Put32(cd, m.ext); Put32(cd, lh); cd += m.name; cd += m.extra;
    }
    const uint32_t cdOff = (uint32_t)out.size();
    out += cd;
    Put32(out, 0x06054b50); Put16(out, 0); Put16(out, 0); Put16(out, (uint16_t)ms.size()); Put16(out, (uint16_t)ms.size());
    Put32(out, (uint32_t)cd.size()); Put32(out, cdOff); Put16(out, 0);
    writeFile(p, out);
}

// Two indexes of one archive, entry for entry.
static void sameIndex(const ZipIndex &A, const ZipIndex &B, const std::string &What) {
    CHECK_EQ(A.byName.size(), B.byName.size());
    for (const auto &[N, E] : A.byName) {
        const auto It = B.byName.find(N);
        CHECK(It != B.byName.end());
        if (It == B.byName.end()) { std::cerr << "    " << What << ": not in the other index: " << N << "\n"; continue; }
        const ZipEntry &F = It->second;
        //What libzip's index serves zero-copy, this one serves the same way. It serves more: libzip's looked the offset
        //up by the stored name, which a CP437 or Unicode-path name never matched — such a member was never served.
        const bool Same = E.index == F.index && E.size == F.size && E.mtime == F.mtime && E.isDir == F.isDir
                       && E.symlink == F.symlink && (!F.stored || (E.stored && E.localHeader == F.localHeader));
        CHECK(Same);
        if (!Same) std::cerr << "    " << What << ": " << N << " differs (mtime " << E.mtime << "/" << F.mtime << ")\n";
    }
    CHECK(A.dirChildren == B.dirChildren);
}

// The index a mount builds from its own walk of the central directory is libzip's, entry for entry: names (UTF-8
// flagged, UTF-8 unflagged, CP437, an Info-ZIP Unicode path), times (DOS, an extended timestamp), links, folders,
// what is served zero-copy (stored and not encrypted). VGFS_ZIP_SAMPLE=a.zip:b.zip compares real archives too.
// Teeth: name a CP437 member by its raw bytes; ignore the extended timestamp; serve an encrypted member.
TEST(the_index_from_the_directory_walk_is_libzips) {
    TmpDir t;
    std::string Ut; Put16(Ut, 0x5455); Put16(Ut, 5); Ut += (char)1; Put32(Ut, 1700000000u);
    std::string Up; { const std::string Raw = "x\x81.txt", U = "x\xE2\x82\xAC.txt"; /* not what CP437 makes of it (xü) */ Put16(Up, 0x7075); Put16(Up, (uint16_t)(5 + U.size())); Up += (char)1; Put32(Up, TestCrc(Raw)); Up += U; }
    writeRawZip(t / "raw.zip", {
        { "ascii.txt", 0, 0x031E, 0, 0100644u << 16, "", "plain" },
        { "caf\x82.txt", 0, 0x0014, 0, 0, "", "cp437" },
        { "na\xC3\xAFve.txt", 0x800, 0x031E, 0, 0100644u << 16, "", "utf8 flagged" },
        { "unflagged \xC3\xA9.txt", 0, 0x031E, 0, 0100644u << 16, "", "utf8 not flagged" },
        { "x\x81.txt", 0, 0x031E, 0, 0100644u << 16, Up, "unicode path" },
        { "stamped.txt", 0, 0x031E, 0, 0100644u << 16, Ut, "ut" },
        { "dir/", 0, 0x031E, 0, 040755u << 16, "", "" },
        { "dir/link", 0, 0x031E, 0, 0120777u << 16, "", "../ascii.txt" },
        { "dir/deflated.bin", 0, 0x031E, 8, 0100644u << 16, "", "notreally" },
        { "secret.bin", 1, 0x031E, 0, 0100644u << 16, "", "encrypted" },
    });
    auto Src = fileSource(t / "raw.zip");
    auto A = BuildZipIndex(Src, "raw.zip"), B = BuildZipIndexLibzip(Src, "raw.zip");
    CHECK(A && B);
    if (A && B) sameIndex(*A, *B, "raw.zip");
    if (A) {
        CHECK(A->byName.count("caf\xC3\xA9.txt") == 1);                     // CP437 0x82 = é
        CHECK(A->byName.count("x\xE2\x82\xAC.txt") == 1);                   // the Unicode path's name (x€), not CP437's
        CHECK(A->byName.count("secret.bin") && !A->byName.at("secret.bin").stored);
        for (const auto &[N, Want] : std::vector<std::pair<std::string, std::string>>{ { "caf\xC3\xA9.txt", "cp437" }, { "x\xE2\x82\xAC.txt", "unicode path" } }) {
            const auto It = A->byName.find(N);
            if (It == A->byName.end()) continue;
            ZipReader R; char buf[32] = {0};
            CHECK_EQ(OpenZipEntry(*A, It->second, R), 0);                    // served: its bytes read
            const int got = ReadZipEntry(R, buf, sizeof buf, 0);
            CHECK_EQ(std::string(buf, got > 0 ? (size_t)got : 0), Want);
        }
    }
    writeStoreZip(t / "store.zip", { { "a/b/c.txt", "c", false }, { "d/", "", false }, { "e.txt", "e", false } });
    auto S2 = fileSource(t / "store.zip");
    auto C = BuildZipIndex(S2, "store.zip"), D = BuildZipIndexLibzip(S2, "store.zip");
    CHECK(C && D);
    if (C && D) sameIndex(*C, *D, "store.zip");
    if (const char *Sample = std::getenv("VGFS_ZIP_SAMPLE"))
        for (std::string Rest = Sample; !Rest.empty();) {
            const size_t Cut = Rest.find(':');
            const std::string P = Rest.substr(0, Cut);
            Rest = Cut == std::string::npos ? "" : Rest.substr(Cut + 1);
            auto Real = fileSource(P);
            auto X = BuildZipIndex(Real, P), Y = BuildZipIndexLibzip(Real, P);
            CHECK(X && Y);
            if (X && Y) sameIndex(*X, *Y, P);
            std::cerr << "    compared " << (X ? X->byName.size() : 0) << " entries of " << P << "\n";
        }
}

// A chain whose later delta takes back what an earlier one put in reads as the base again — and its flat map is one
// run over the base, not the pieces the composition cut it into (the map grew with every level, a pread per piece).
// Teeth: no joining (two runs); join across a gap (the bytes differ).
TEST(a_chains_flat_map_joins_runs_that_continue_each_other) {
    std::string b0(200000, '\0');
    std::mt19937 Rng(42);                                              // no run of it repeats elsewhere
    for (char &C : b0) C = (char)(Rng() & 0xFF);
    std::string ins(5000, 'Q');
    const std::string t1 = b0.substr(0, 90000) + ins + b0.substr(90000);
    auto d1 = vgdelta::GenerateDelta((const uint8_t *)b0.data(), b0.size(), (const uint8_t *)t1.data(), t1.size(), 4096);
    auto d2 = vgdelta::GenerateDelta((const uint8_t *)t1.data(), t1.size(), (const uint8_t *)b0.data(), b0.size(), 4096);
    std::string err;
    auto V1 = vgdelta::DeltaByteSource::Create(std::make_shared<MemByteSource>(d1), std::make_shared<MemByteSource>(std::vector<uint8_t>(b0.begin(), b0.end())), err, false);
    CHECK(V1 != nullptr);
    if (!V1) return;
    auto V2 = vgdelta::DeltaByteSource::Create(std::make_shared<MemByteSource>(d2), V1, err, false);
    CHECK(V2 != nullptr);
    if (!V2) return;
    if (std::getenv("VGFS_SHOW_RUNS"))
        for (const auto &R : V2->flatRuns()) std::cerr << "    run kind " << (int)R.kind << " len " << R.len << " src " << R.srcOff << " add " << R.addSrc << "\n";
    CHECK(!V2->runsLeftUnjoined());
    CHECK_EQ(V2->runs(), (size_t)1);                               // the base again, whole
    std::vector<uint8_t> out(b0.size());
    CHECK(V2->preadAll(out.data(), out.size(), 0));
    CHECK(std::memcmp(out.data(), b0.data(), b0.size()) == 0);
}

// A central directory longer than the window it is read through: every record found, one straddling the window's end
// included, and members at its far end served. Teeth: refill the window at the wrong place, or only when a record
// starts past it (a straddling record reads past the window).
TEST(a_central_directory_longer_than_one_read_is_walked_whole) {
    TmpDir t;
    std::vector<std::tuple<std::string, std::string, bool>> es;
    for (int i = 0; i < 30000; ++i) {
        char n[48]; std::snprintf(n, sizeof n, "data/sub%02d/entry_%05d.txt", i % 37, i);
        es.push_back({ n, std::to_string(i), false });
    }
    writeStoreZip(t / "big.zip", es);
    auto Src = fileSource(t / "big.zip");
    const auto Offs = zipscan::CentralDirOffsets(*Src);
    CHECK_EQ(Offs.size(), (size_t)30000);
    auto Z = BuildZipIndex(Src, "big.zip");
    CHECK(Z);
    if (!Z) return;
    for (int i : { 0, 15000, 16131, 29999 }) {
        char n[48]; std::snprintf(n, sizeof n, "data/sub%02d/entry_%05d.txt", i % 37, i);
        const auto It = Z->byName.find(n);
        CHECK(It != Z->byName.end());
        if (It == Z->byName.end()) continue;
        ZipReader R; char buf[16] = {0};
        CHECK_EQ(OpenZipEntry(*Z, It->second, R), 0);
        const int got = ReadZipEntry(R, buf, sizeof buf, 0);
        CHECK_EQ(std::string(buf, got > 0 ? (size_t)got : 0), std::to_string(i));
    }
}

// Destroyed at exit after everything main makes, as the mount's own static state is: a view still holding cached
// blocks then drops them into a cache that must still be there. Teeth: the cache as an ordinary static (destroyed
// first; the drop is a use after free and the run ends in a crash).
static std::shared_ptr<ByteSource> g_ViewPastExit;
TEST(a_view_held_past_main_ends_cleanly) {
    std::string base(4096, 'z'), tgt;
    for (size_t i = 0; i < 20000; ++i) tgt += (char)((i * 31) % 253);
    auto d = vgdelta::GenerateDelta((const uint8_t *)base.data(), base.size(), (const uint8_t *)tgt.data(), tgt.size(), 4096);
    std::string err;
    auto D = vgdelta::DeltaByteSource::Create(std::make_shared<MemByteSource>(d), std::make_shared<MemByteSource>(std::vector<uint8_t>(base.begin(), base.end())), err, false);
    CHECK(D != nullptr);
    if (!D) return;
    std::vector<uint8_t> out(tgt.size());
    CHECK(D->preadAll(out.data(), out.size(), 0));
    CHECK(vgdelta::CachedBlockBytes() > 0);
    g_ViewPastExit = D;
}

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
    GuardTestProcess();
    //VGFS_TEST_FILTER=a,b,c runs only the tests whose names contain one of them (a mutation run's quick pass).
    std::vector<std::string> only; size_t ran = 0;
    if (const char *f = std::getenv("VGFS_TEST_FILTER")) { std::string F = f; for (size_t a = 0, b; a <= F.size(); a = b + 1) { b = F.find(',', a); if (b == std::string::npos) b = F.size(); if (b > a) only.push_back(F.substr(a, b - a)); } }
    for (auto &[name, fn] : g_tests) {
        if (!only.empty() && std::none_of(only.begin(), only.end(), [&](const std::string &o) { return std::string(name).find(o) != std::string::npos; })) continue;
        std::cerr << "[ RUN ] " << name << "\n";
        fn(); ++ran;
    }
    if (!only.empty()) std::cerr << "(filter: " << ran << " of " << g_tests.size() << " tests)\n";
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

// The same in the writelayer: a create, mkdir, symlink or rename the host refuses leaves a deleted lower name deleted.
// Teeth: the deletion marker dropped before the host op (the package's old file shows again).
TEST(a_refused_make_in_the_writelayer_leaves_the_deleted_name_deleted) {
    if (::geteuid() == 0) return;
    TmpDir t;
    writeFile(t / "host/old.txt", "old");
    writeFile(t / "host/olddir/x.txt", "x");
    writeFile(t / "host/src.txt", "s");
    Spec sp; sp.readOnly = false; sp.writelayer = t.str("wl"); sp.layers = { dirLayer(t.str("host")) };
    VfsState S; std::string err; CHECK(S.Init(sp, err));
    CHECK_EQ(VfsUnlink(S, "old.txt"), 0);
    CHECK_EQ(VfsUnlink(S, "olddir/x.txt"), 0);
    CHECK_EQ(VfsRmdir(S, "olddir"), 0);
    OpenFile *Cp = nullptr;
    CHECK_EQ(VfsOpen(S, "src.txt", O_RDWR, Cp), 0);   // copied up before the folder is locked
    if (Cp) { CHECK_EQ(VfsWrite(S, Cp, "S", 1, 0), (ssize_t)1); VfsRelease(Cp); }
    fs::permissions(t / "wl", fs::perms::owner_read | fs::perms::owner_exec);
    OpenFile *of = nullptr;
    CHECK(VfsCreate(S, "old.txt", 0644, O_WRONLY | O_TRUNC, of) < 0);
    CHECK(VfsMkdir(S, "olddir", 0755) < 0);
    CHECK(VfsSymlink(S, "x", "old.txt") < 0);
    CHECK(VfsRename(S, "src.txt", "old.txt") < 0);
    fs::permissions(t / "wl", fs::perms::owner_all);
    VfsAttr a;
    CHECK_EQ(VfsGetattr(S, "old.txt", a), -ENOENT);
    CHECK_EQ(VfsGetattr(S, "olddir", a), -ENOENT);
}

// A rename into a kept folder the host refuses leaves the user's deletions there as they were: the markers the move
// would have replaced are put back, on disk too (the next launch sees them). Teeth: no put-back of kept markers (the
// package's deleted file shows again, for good).
TEST(a_refused_rename_into_a_kept_folder_keeps_what_the_user_deleted) {
    if (::geteuid() == 0) return;
    TmpDir t; Spec sp = keptOverLower(t, "cfg");
    {
        VfsState S; std::string err; CHECK(S.Init(sp, err));
        CHECK_EQ(VfsUnlink(S, "cfg/sub/x.txt"), 0);                 // cfg/sub: empty now, a marker inside it
        CHECK_EQ(VfsMkdir(S, "cfg/new", 0755), 0);
        fs::permissions(t / "durable", fs::perms::owner_read | fs::perms::owner_exec);   // no rename in the kept root
        CHECK(VfsRename(S, "cfg/new", "cfg/sub") < 0);
        fs::permissions(t / "durable", fs::perms::owner_all);
        VfsAttr a;
        CHECK_EQ(VfsGetattr(S, "cfg/sub/x.txt", a), -ENOENT);
    }
    VfsState R; std::string err; CHECK(R.Init(sp, err));
    VfsAttr a;
    CHECK_EQ(VfsGetattr(R, "cfg/sub/x.txt", a), -ENOENT);
}

// A crafted zip member named through ".." is left out: it neither lists nor lands outside the writelayer when its
// folder is copied up (a rename). A "." part is nothing and '\\' a separator, as the app reads names ("./Docs/" is
// Docs, a Windows-made "Bin\\x.exe" is Bin/x.exe). Teeth: index names as they are (".." a child of d: the copy-up
// writes outside; "./Docs" and "Bin\\x.exe" served under names nothing looks for).
TEST(a_zip_member_named_through_dotdot_is_left_out) {
    TmpDir t;
    writeStoreZip(t / "pkg.zip", {{"d/ok.txt", "ok", false}, {"d/../../escaped.txt", "out", false}, {"d/./dot.txt", "dot", false},
                                  {"./Docs/", "", true}, {"Bin\\x.exe", "exe", false}, {"a..b.txt", "dots", false},
                                  {"Saves\\", "", false}});   // a Windows-made folder entry: a folder, not a file
    Spec sp; sp.readOnly = false; sp.writelayer = t.str("wl"); sp.layers = { zipLayer(t.str("pkg.zip")) };
    VfsState S; std::string err; CHECK(S.Init(sp, err));
    CHECK(readdirNames(S, "d") == (std::set<std::string>{"ok.txt", "dot.txt"}));
    CHECK(readdirNames(S, "") == (std::set<std::string>{"d", "Docs", "Bin", "a..b.txt", "Saves"}));
    VfsAttr Sv; CHECK_EQ(VfsGetattr(S, "Saves", Sv), 0); CHECK(Sv.isDir);
    CHECK(readdirNames(S, "Bin") == (std::set<std::string>{"x.exe"}));
    CHECK_EQ(VfsRename(S, "d", "e"), 0);
    CHECK(!fs::exists(t / "escaped.txt"));
    CHECK(!fs::exists(t / "wl" / ".." / "escaped.txt"));
    CHECK(readdirNames(S, "e") == (std::set<std::string>{"ok.txt", "dot.txt"}));
}

// A delta whose header names a block size past 64 MiB, or a block whose frame lies past the end of the file, is
// refused: the per-block bound is measured against the header's block size. Teeth: no bound on it (a crafted header
// lifts the per-block bound; a read allocated up to 4 GiB).
TEST(a_delta_with_a_crafted_block_size_is_refused) {
    std::string base(4096, 'A');
    std::string tgt = base; tgt.insert(100, std::string(3000, 'Q'));
    auto delta = vgdelta::GenerateDelta((const uint8_t *)base.data(), base.size(), (const uint8_t *)tgt.data(), tgt.size());
    CHECK(!delta.empty());
    auto baseSrc = std::make_shared<MemByteSource>(std::vector<uint8_t>(base.begin(), base.end()));
    std::vector<uint8_t> Bad = delta;
    const uint32_t Huge = 0xFFFFFFFFu;
    std::memcpy(Bad.data() + 8, &Huge, 4);   // the header's block size
    std::string derr;
    CHECK(vgdelta::DeltaByteSource::Create(std::make_shared<MemByteSource>(Bad), baseSrc, derr, false) == nullptr);
    CHECK(derr.find("block size") != std::string::npos);
    //...and the writer makes none: a delta that would not mount is no delta. (Teeth: the writer's cap gone.)
    CHECK(vgdelta::GenerateDelta((const uint8_t *)base.data(), base.size(), (const uint8_t *)tgt.data(), tgt.size(), 128u << 20).empty());
    std::vector<uint8_t> Cut(delta.begin(), delta.end() - 8);   // the last block's frame cut short
    derr.clear();
    CHECK(vgdelta::DeltaByteSource::Create(std::make_shared<MemByteSource>(Cut), baseSrc, derr, false) == nullptr);
    CHECK(derr.find("past the end") != std::string::npos);
}

// An rmdir the host refuses leaves what was deleted inside the folder deleted: the markers it swept to remove it are
// put back (disk and mask). Teeth: no put-back (the deleted file shows again, for good).
TEST(a_refused_rmdir_keeps_the_deletions_inside_it) {
    if (::geteuid() == 0) return;
    TmpDir t;
    writeFile(t / "host/d/x.txt", "package x");
    Spec sp; sp.readOnly = false; sp.writelayer = t.str("wl"); sp.layers = { dirLayer(t.str("host")) };
    {
        VfsState S; std::string err; CHECK(S.Init(sp, err));
        CHECK_EQ(VfsUnlink(S, "d/x.txt"), 0);                        // wl/d/.wh.x.txt
        fs::permissions(t / "wl", fs::perms::owner_read | fs::perms::owner_exec);   // d cannot come off wl
        CHECK(VfsRmdir(S, "d") < 0);
        fs::permissions(t / "wl", fs::perms::owner_all);
        VfsAttr a;
        CHECK_EQ(VfsGetattr(S, "d/x.txt", a), -ENOENT);
    }
    VfsState R; std::string err; CHECK(R.Init(sp, err));
    VfsAttr a;
    CHECK_EQ(VfsGetattr(R, "d/x.txt", a), -ENOENT);
}

// A deletion the writelayer cannot record fails, and the file stays — this session and the next (the marker was
// taken for written: the file was gone until a relaunch brought it back). Teeth: mask the name though its marker was
// not written (unlink says 0, the file is hidden now and back after a remount).
TEST(a_deletion_the_writelayer_cannot_record_fails) {
    if (::geteuid() == 0) return;
    TmpDir t;
    writeFile(t / "host/save.dat", "package save");
    Spec sp; sp.readOnly = false; sp.writelayer = t.str("wl"); sp.layers = { dirLayer(t.str("host")) };
    VfsState S; std::string err; CHECK(S.Init(sp, err));
    fs::create_directories(t / "wl");
    fs::permissions(t / "wl", fs::perms::owner_read | fs::perms::owner_exec);
    CHECK(VfsUnlink(S, "save.dat") < 0);
    fs::permissions(t / "wl", fs::perms::owner_all);
    VfsAttr a;
    CHECK_EQ(VfsGetattr(S, "save.dat", a), 0);
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

// ================================================================ the deflate layer: shipped bytes from content + decisions
// A raw deflate stream as zlib makes it, with every knob the developer's tool might have turned.
static std::vector<uint8_t> rawDeflate(const std::vector<uint8_t> &in, int level, int wbits, int mem, int strategy) {
    z_stream z{}; if (deflateInit2(&z, level, Z_DEFLATED, -wbits, mem, strategy) != Z_OK) return {};
    std::vector<uint8_t> out(deflateBound(&z, (uLong)in.size()) + 64);
    z.next_in = const_cast<Bytef *>(in.data()); z.avail_in = (uInt)in.size(); z.next_out = out.data(); z.avail_out = (uInt)out.size();
    deflate(&z, Z_FINISH); out.resize(z.total_out); deflateEnd(&z); return out;
}
// Content of several kinds: game text (repetitive words), noise, runs of one byte, and the three mixed.
static std::vector<uint8_t> sampleContent(int kind, size_t n, uint32_t seed) {
    std::mt19937 r(seed); std::vector<uint8_t> v; v.reserve(n);
    static const char *words[] = {"Unit", "Hero", "Footman", "Damage", "Armor", "=", "\r\n", "Speed", "Range", "Cooldown", "0.75", "Human", "[", "]"};
    while (v.size() < n) {
        const int k = kind == 3 ? (int)(r() % 3) : kind;
        if (k == 0) { const char *w = words[r() % 14]; while (*w && v.size() < n) v.push_back((uint8_t)*w++); }
        else if (k == 1) v.push_back((uint8_t)r());
        else { const uint8_t c = (uint8_t)r(); for (int i = 0, m = (int)(r() % 300); i < m && v.size() < n; ++i) v.push_back(c); }
    }
    return v;
}
// Every byte, read in uneven pieces, then random ranges of every size — against the stream itself.
static bool readsBack(ByteSource &s, const std::vector<uint8_t> &want, uint32_t seed, int randomReads = 200) {
    if (s.size() != want.size()) return false;
    std::vector<uint8_t> got(want.size());
    for (size_t o = 0, step = 1; o < want.size(); o += step, step = step * 3 % 9973 + 1)
        if (!s.preadAll(got.data() + o, std::min(step, want.size() - o), o)) return false;
    if (got != want) return false;
    std::mt19937 r(seed);
    for (int i = 0; i < randomReads && !want.empty(); ++i) {
        const size_t a = r() % want.size(), n = 1 + r() % std::min<size_t>(want.size() - a, i % 3 ? 70000 : 9);
        std::vector<uint8_t> b(n);
        if (!s.preadAll(b.data(), n, a) || std::memcmp(b.data(), want.data() + a, n)) return false;
    }
    return true;
}
static std::shared_ptr<deflatelayer::DeflateByteSource> deflateSource(const std::vector<uint8_t> &stream, std::vector<uint8_t> *contentOut = nullptr) {
    std::vector<uint8_t> dec, content; std::string err;
    if (!deflatelayer::DeflateDecisions(stream.data(), stream.size(), dec, content, err)) { std::cerr << "  decisions: " << err << "\n"; return nullptr; }
    if (contentOut) *contentOut = content;
    return deflatelayer::DeflateByteSource::Create(std::make_shared<MemByteSource>(dec), std::make_shared<MemByteSource>(content), stream.size(), err);
}

// Whatever the encoder's settings (stored, fixed and dynamic blocks, every level, strategy and window), the stream reads
// back from its content and decisions, every byte, at any offset — and the content is what the stream decodes to.
TEST(a_deflate_stream_rebuilds_from_its_content_at_every_setting) {
    const int strategies[] = {Z_DEFAULT_STRATEGY, Z_FILTERED, Z_HUFFMAN_ONLY, Z_RLE, Z_FIXED};
    int cases = 0;
    for (int kind = 0; kind < 4; ++kind) {
        const auto in = sampleContent(kind, kind == 1 ? 70000 : 150000, (uint32_t)kind + 7);
        for (int level = 0; level <= 9; ++level)
            for (int st : strategies)
                for (int wbits : {9, 12, 15}) {
                    if ((level + wbits + st) % 3 && level != 0 && level != 9) continue;   // a spread, not the full product
                    const auto stream = rawDeflate(in, level, wbits, (level % 9) + 1, st);
                    std::vector<uint8_t> content; auto s = deflateSource(stream, &content);
                    CHECK(s != nullptr);
                    if (!s) continue;
                    CHECK(content == in);
                    CHECK(readsBack(*s, stream, (uint32_t)(level * 31 + wbits), 60));
                    ++cases;
                }
    }
    CHECK(cases > 100);
}

// The smallest streams: nothing, one byte, two — each a block or two of a few bits.
TEST(an_empty_or_tiny_deflate_stream_rebuilds) {
    for (size_t n : {0, 1, 2, 3}) for (int level : {0, 1, 9}) {
        const auto in = sampleContent(0, n, 1); const auto stream = rawDeflate(in, level, 15, 8, Z_DEFAULT_STRATEGY);
        std::vector<uint8_t> content; auto s = deflateSource(stream, &content);
        CHECK(s != nullptr); CHECK(content == in); if (s) CHECK(readsBack(*s, stream, 3));
    }
}

// Megabytes over many blocks: reads that start anywhere, cross block boundaries, and read one byte at a time near them.
TEST(a_multi_block_deflate_stream_reads_anywhere) {
    // memLevel 1: a small symbol buffer, so the encoder ends a block every few hundred symbols — hundreds of blocks
    const auto in = sampleContent(3, 3 << 20, 11); const auto stream = rawDeflate(in, 6, 15, 1, Z_DEFAULT_STRATEGY);
    auto s = deflateSource(stream);
    CHECK(s != nullptr); if (!s) return;
    CHECK(s->blocks() > 100);
    CHECK(readsBack(*s, stream, 99, 2000));
    std::mt19937 r(5);
    for (int i = 0; i < 300; ++i) {                          // single bytes, all over
        const size_t a = r() % stream.size(); uint8_t b = 0;
        CHECK(s->pread(&b, 1, a) == 1); CHECK(b == stream[a]);
    }
    uint8_t b = 0; CHECK(s->pread(&b, 1, stream.size()) == 0);   // at the end: nothing, not an error
    std::vector<uint8_t> tail(100);                          // a read running past the end gets what is there
    CHECK(s->pread(tail.data(), tail.size(), stream.size() - 10) == 10);
    CHECK(std::memcmp(tail.data(), stream.data() + stream.size() - 10, 10) == 0);
}

// One byte read at every offset of a stream of many small blocks: a read's first bit lands, somewhere, on every kind of
// item boundary there is — inside a literal run, on a match, on an end-of-block code, on a block's first bit.
TEST(a_deflate_stream_reads_one_byte_at_every_offset) {
    for (int strategy : {Z_DEFAULT_STRATEGY, Z_FIXED}) {
        const auto in = sampleContent(3, 120000, 21); const auto stream = rawDeflate(in, 6, 15, 1, strategy);
        auto s = deflateSource(stream); CHECK(s != nullptr); if (!s) continue;
        CHECK(s->blocks() > 20);
        size_t wrong = 0;
        for (size_t a = 0; a < stream.size(); ++a) { uint8_t b = 0; if (s->pread(&b, 1, a) != 1 || b != stream[a]) ++wrong; }
        CHECK_EQ(wrong, (size_t)0);
    }
}

// Deflate's bits as a hand-written stream: values LSB first, Huffman codes most significant bit first.
struct DeflateBits {
    std::vector<uint8_t> out; int n = 0;
    void put(uint32_t v, int bits) { for (int i = 0; i < bits; ++i, ++n) { if (!(n & 7)) out.push_back(0); out.back() |= (uint8_t)(((v >> i) & 1) << (n & 7)); } }
    void code(uint32_t c, int bits) { for (int i = bits - 1; i >= 0; --i) put((c >> i) & 1, 1); }
};

// Code tables deflate cannot have and symbols it does not define are refused with what is wrong with them, never decoded
// into something: a literal/length table that over-subscribes its code space, the fixed table's length codes 286 and 287.
TEST(a_deflate_stream_with_an_impossible_code_is_refused) {
    std::vector<uint8_t> dec, content; std::string err;
    {   // a dynamic block whose literal/length lengths give three codes of one bit
        DeflateBits w; w.put(1, 1); w.put(2, 2); w.put(0, 5); w.put(0, 5); w.put(14, 4);  // final, dynamic, 257 + 1 codes, 18 cl lengths
        // code-length code: symbol 0 one bit ("0"), symbols 1 and 2 two bits ("10", "11") — complete
        const int clorder[18] = {16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1};
        for (int sym : clorder) w.put(sym == 0 ? 1 : sym == 1 || sym == 2 ? 2 : 0, 3);
        auto len1 = [&] { w.code(2, 2); }; auto len0 = [&] { w.code(0, 1); };
        len1(); len1(); for (int k = 2; k < 256; ++k) len0(); len1();                  // literals 0, 1 and end of block: 1 bit each
        len1();                                                                          // the one distance code
        w.put(0, 16);
        CHECK(!deflatelayer::DeflateDecisions(w.out.data(), w.out.size(), dec, content, err));
        CHECK(err == "a block whose code lengths over-subscribe");
    }
    for (uint32_t sym : {286u, 287u}) {   // a fixed block whose first symbol is a length code deflate leaves undefined
        DeflateBits w; w.put(1, 1); w.put(1, 2); w.code(0xC0 + (sym - 280), 8); w.put(0, 16);
        CHECK(!deflatelayer::DeflateDecisions(w.out.data(), w.out.size(), dec, content, err));
        CHECK(err == "a length symbol deflate does not define");
    }
}

// The decisions never carry the content: a stream of nothing but literals (noise, Huffman only) records only how many
// there are, never the bytes themselves.
TEST(deflate_decisions_carry_no_content) {
    const auto in = sampleContent(1, 400000, 2); const auto stream = rawDeflate(in, 6, 15, 8, Z_HUFFMAN_ONLY);
    std::vector<uint8_t> dec, content; std::string err;
    CHECK(deflatelayer::DeflateDecisions(stream.data(), stream.size(), dec, content, err));
    CHECK(content == in);
    CHECK(dec.size() < content.size() / 100);
}

// Many threads reading one source at once all get the stream's bytes.
TEST(a_deflate_source_reads_from_many_threads_at_once) {
    const auto in = sampleContent(3, 1 << 20, 4); const auto stream = rawDeflate(in, 6, 15, 8, Z_DEFAULT_STRATEGY);
    auto s = deflateSource(stream); CHECK(s != nullptr); if (!s) return;
    std::atomic<int> bad{0}; std::vector<std::thread> th;
    for (int t = 0; t < 8; ++t) th.emplace_back([&, t] {
        std::mt19937 r((uint32_t)t); std::vector<uint8_t> b(65536);
        for (int i = 0; i < 150; ++i) { const size_t a = r() % stream.size(), n = 1 + r() % std::min<size_t>(65536, stream.size() - a);
            if (!s->preadAll(b.data(), n, a) || std::memcmp(b.data(), stream.data() + a, n)) ++bad; }
    });
    for (auto &x : th) x.join();
    CHECK_EQ(bad.load(), 0);
}

// What is not exactly one whole raw deflate stream is refused, never split wrong: cut short, followed by more bytes,
// a reserved block type, a stored block whose lengths disagree.
TEST(a_broken_deflate_stream_is_refused) {
    const auto in = sampleContent(0, 50000, 8); const auto stream = rawDeflate(in, 6, 15, 8, Z_DEFAULT_STRATEGY);
    std::vector<uint8_t> dec, content; std::string err;
    auto cut = stream; cut.resize(cut.size() - 3);
    CHECK(!deflatelayer::DeflateDecisions(cut.data(), cut.size(), dec, content, err));
    auto more = stream; more.push_back(0);
    CHECK(!deflatelayer::DeflateDecisions(more.data(), more.size(), dec, content, err));
    CHECK(err == "bytes after the final block");
    auto reserved = stream; reserved[0] = (uint8_t)((reserved[0] & ~6) | 6);
    CHECK(!deflatelayer::DeflateDecisions(reserved.data(), reserved.size(), dec, content, err));
    auto stored = rawDeflate(in, 0, 15, 8, Z_DEFAULT_STRATEGY); stored[3] ^= 1;   // LEN's complement no longer matches
    CHECK(!deflatelayer::DeflateDecisions(stored.data(), stored.size(), dec, content, err));
}

// A record and content that do not belong together are refused at creation: content of the wrong size, a record cut
// short, a stream size the record cannot fill.
TEST(a_deflate_source_refuses_a_record_that_does_not_fit) {
    const auto in = sampleContent(0, 60000, 9); const auto stream = rawDeflate(in, 6, 15, 8, Z_DEFAULT_STRATEGY);
    std::vector<uint8_t> dec, content; std::string err;
    CHECK(deflatelayer::DeflateDecisions(stream.data(), stream.size(), dec, content, err));
    auto shortContent = content; shortContent.pop_back();
    CHECK(!deflatelayer::DeflateByteSource::Create(std::make_shared<MemByteSource>(dec), std::make_shared<MemByteSource>(shortContent), stream.size(), err));
    auto cutRecord = dec; cutRecord.resize(cutRecord.size() / 2);
    CHECK(!deflatelayer::DeflateByteSource::Create(std::make_shared<MemByteSource>(cutRecord), std::make_shared<MemByteSource>(content), stream.size(), err));
    CHECK(!deflatelayer::DeflateByteSource::Create(std::make_shared<MemByteSource>(dec), std::make_shared<MemByteSource>(content), 1, err));
    for (uint8_t type : {3, 0xFF}) {                         // a block type deflate does not have
        auto badType = dec; badType[0] = type;
        CHECK(!deflatelayer::DeflateByteSource::Create(std::make_shared<MemByteSource>(badType), std::make_shared<MemByteSource>(content), stream.size(), err));
    }
    CHECK(deflatelayer::DeflateByteSource::Create(std::make_shared<MemByteSource>(dec), std::make_shared<MemByteSource>(content), stream.size(), err) != nullptr);
}

// ================================================================ the coding algebra: shipped bytes from content + decisions + a DESCRIPTION
static std::vector<uint8_t> lzmaAlone(const std::vector<uint8_t> &in, uint32_t preset, uint32_t lc, uint32_t lp, uint32_t pb) {
    lzma_options_lzma o; lzma_lzma_preset(&o, preset); o.lc = lc; o.lp = lp; o.pb = pb;
    lzma_stream z = LZMA_STREAM_INIT; if (lzma_alone_encoder(&z, &o) != LZMA_OK) return {};
    std::vector<uint8_t> out(in.size() + in.size() / 2 + 65536); z.next_in = in.data(); z.avail_in = in.size(); z.next_out = out.data(); z.avail_out = out.size();
    const lzma_ret r = lzma_code(&z, LZMA_FINISH); out.resize(z.total_out); lzma_end(&z); return r == LZMA_STREAM_END ? out : std::vector<uint8_t>{};
}
static std::vector<uint8_t> lz4Block(const std::vector<uint8_t> &in, int level) {
    std::vector<uint8_t> out((size_t)LZ4_compressBound((int)in.size()) + 16);
    const int n = level ? LZ4_compress_HC((const char *)in.data(), (char *)out.data(), (int)in.size(), (int)out.size(), level)
                        : LZ4_compress_default((const char *)in.data(), (char *)out.data(), (int)in.size(), (int)out.size());
    out.resize((size_t)std::max(n, 0)); return out;
}
static coding::Description lzmaFor(const std::vector<uint8_t> &alone) {
    const uint8_t pr = alone[0]; const uint32_t dict = alone[1] | alone[2] << 8 | alone[3] << 16 | (uint32_t)alone[4] << 24;
    return coding::LzmaDescription(pr % 9, (pr / 9) % 5, pr / 45, dict, true);
}
// Mint a shipped stream, then serve it from description + record + content: every byte, every random range.
static std::shared_ptr<coding::CodedByteSource> codedSource(const coding::Description &d, const uint8_t *s, size_t n, const std::vector<uint8_t> &want,
                                                            uint64_t spacing, std::vector<uint8_t> *recordOut = nullptr) {
    std::vector<uint8_t> content, record; std::string err;
    if (!coding::Mint(d, s, n, want.size(), want.size(), spacing, content, record, err)) { std::cerr << "  mint: " << err << "\n"; return nullptr; }
    if (content != want) { std::cerr << "  mint: the content differs\n"; return nullptr; }
    if (recordOut) *recordOut = record;
    auto src = coding::CodedByteSource::Create(std::make_shared<MemByteSource>(coding::Serialize(d)), std::make_shared<MemByteSource>(record),
                                               std::make_shared<MemByteSource>(content), n, err);
    if (!src) std::cerr << "  create: " << err << "\n";
    return src;
}

// A description is data: it serializes and parses back to the same bytes, for every format this repository writes.
TEST(a_coding_description_survives_serialization) {
    for (const coding::Description &d : {coding::LzmaDescription(3, 0, 2, 1u << 20, true), coding::LzmaDescription(0, 2, 0, 4096, false),
                                         coding::DeflateDescription(), coding::Lz4BlockDescription()}) {
        const auto bytes = coding::Serialize(d); coding::Description back; std::string err;
        CHECK(coding::Parse(bytes.data(), bytes.size(), back, err));
        CHECK(coding::Serialize(back) == bytes);
        CHECK(back.name == d.name);
    }
}

// LZMA streams from liblzma at several presets and literal/position settings decode to their content and are served
// back exactly, from checkpoints, anywhere.
TEST(lzma_streams_are_served_from_content_and_decisions) {
    int cases = 0;
    for (int kind = 0; kind < 4; ++kind) {
        const auto in = sampleContent(kind, kind == 1 ? 40000 : 120000, (uint32_t)kind + 3);
        for (uint32_t preset : {0u, 6u, 9u | LZMA_PRESET_EXTREME}) for (auto lcp : {std::array<uint32_t, 3>{3, 0, 2}, std::array<uint32_t, 3>{0, 2, 0}, std::array<uint32_t, 3>{4, 0, 1}}) {
            if ((kind + (int)lcp[0] + (int)(preset & 0xF)) % 2 && preset != 6) continue;
            const auto alone = lzmaAlone(in, preset, lcp[0], lcp[1], lcp[2]); CHECK(alone.size() > 13); if (alone.size() <= 13) continue;
            auto src = codedSource(lzmaFor(alone), alone.data() + 13, alone.size() - 13, in, std::max<uint64_t>(256, (alone.size() - 13) / 8));
            CHECK(src != nullptr); if (!src) continue;
            CHECK(src->checkpoints() >= 4);                                  // random reads start from checkpoints, not only the start
            std::vector<uint8_t> shipped(alone.begin() + 13, alone.end());
            CHECK(readsBack(*src, shipped, (uint32_t)(kind * 7 + preset), 40));
            ++cases;
        }
    }
    CHECK(cases >= 12);
}

// The same engine, a different description: deflate (dynamic, fixed and stored blocks, its header included) and LZ4
// blocks, from the reference encoders, at many settings.
TEST(deflate_and_lz4_streams_are_served_through_their_descriptions) {
    const auto deflate = coding::DeflateDescription(), lz4 = coding::Lz4BlockDescription();
    int cases = 0;
    for (int kind = 0; kind < 4; ++kind) {
        const auto in = sampleContent(kind, 90000, (uint32_t)kind + 11);
        for (int level : {0, 1, 6, 9}) for (int st : {Z_DEFAULT_STRATEGY, Z_FIXED, Z_HUFFMAN_ONLY}) {
            const auto stream = rawDeflate(in, level, 15, level ? 8 : 1, st);
            auto src = codedSource(deflate, stream.data(), stream.size(), in, std::max<uint64_t>(256, stream.size() / 6)); CHECK(src != nullptr); if (!src) continue;
            CHECK(src->checkpoints() >= (level ? 3u : 2u));                   // a stored block is one byte run: a checkpoint per block
            CHECK(readsBack(*src, stream, (uint32_t)(level * 5 + st), 30)); ++cases;
        }
        for (int level : {0, 3, 9, 12}) {
            const auto blk = lz4Block(in, level);
            auto src = codedSource(lz4, blk.data(), blk.size(), in, 4096); CHECK(src != nullptr); if (!src) continue;
            CHECK(readsBack(*src, blk, (uint32_t)level, 30)); ++cases;
        }
    }
    {   // deflate's one non-canonical spelling, made on purpose: a copy of 258 written as code 284 + extra 31
        std::vector<uint8_t> w; uint64_t acc = 0; int nb = 0;
        auto put = [&](uint32_t v, int n) { acc |= (uint64_t)v << nb; nb += n; while (nb >= 8) { w.push_back((uint8_t)acc); acc >>= 8; nb -= 8; } };
        auto huff = [&](uint32_t c, int n) { for (int i = n - 1; i >= 0; --i) put((c >> i) & 1, 1); };
        put(1, 1); put(1, 2);                                              // final, fixed
        huff(0x30 + 'a', 8);                                               // the literal 'a'
        huff(0xC0 + (284 - 280), 8); put(31, 5); huff(0, 5);              // 284 + 31 = 258, distance code 0 = 1
        huff(0, 7); if (nb) put(0, 8 - nb);                                // end of block, pad
        const std::vector<uint8_t> want(259, 'a');
        auto src = codedSource(deflate, w.data(), w.size(), want, 4096); CHECK(src != nullptr); if (src) CHECK(readsBack(*src, w, 3, 5));
    }
    for (size_t n : {0, 1, 5, 13}) {                                       // the smallest LZ4 blocks: literals only
        const auto in = sampleContent(0, n, 2); const auto blk = lz4Block(in, 0);
        auto src = codedSource(lz4, blk.data(), blk.size(), in, 4096); CHECK(src != nullptr); if (src) CHECK(readsBack(*src, blk, 1, 5));
    }
    CHECK_EQ(cases, 64);
}

// A stream its format forbids is refused at mint, never split wrong: cut short, followed by more bytes, bits flipped
// where zlib refuses too.
TEST(a_broken_stream_is_refused_by_its_description) {
    const auto in = sampleContent(3, 60000, 5);
    std::vector<uint8_t> content, record; std::string err;
    const auto deflate = coding::DeflateDescription();
    const auto stream = rawDeflate(in, 6, 15, 8, Z_DEFAULT_STRATEGY);
    auto cut = stream; cut.resize(cut.size() - 3);
    CHECK(!coding::Mint(deflate, cut.data(), cut.size(), 0, 1 << 20, 4096, content, record, err));
    auto more = stream; more.push_back(0);
    CHECK(!coding::Mint(deflate, more.data(), more.size(), 0, 1 << 20, 4096, content, record, err));
    int agree = 0, tried = 0;
    for (int k = 0; k < 60; ++k) {
        auto b = stream; b[(size_t)k * 977 % b.size()] ^= (uint8_t)(1u << (k % 8));
        uint8_t sink[1 << 17]; z_stream z{}; inflateInit2(&z, -15); z.next_in = b.data(); z.avail_in = (uInt)b.size();
        int r = Z_OK; while (r == Z_OK) { z.next_out = sink; z.avail_out = sizeof sink; r = inflate(&z, Z_NO_FLUSH); if (r == Z_BUF_ERROR && z.avail_in) r = Z_OK; }
        const bool zok = r == Z_STREAM_END && z.avail_in == 0; inflateEnd(&z);
        const bool ours = coding::Mint(deflate, b.data(), b.size(), 0, 1 << 20, 4096, content, record, err);
        ++tried; agree += ours == zok;
    }
    CHECK_EQ(agree, tried);
    const auto alone = lzmaAlone(in, 6, 3, 0, 2);
    CHECK(!coding::Mint(lzmaFor(alone), alone.data() + 13, alone.size() - 13 - 9, in.size(), in.size(), 4096, content, record, err));
}

// Descriptions come from peers: anything that is not a valid description is refused at parse, and a valid one that
// misbehaves (loops without progress, reads past its tables or slots) is refused when it runs - never obeyed.
TEST(a_hostile_description_is_refused) {
    std::string err; coding::Description d; int ran = 0;
    const auto sample = rawDeflate(sampleContent(3, 20000, 4), 6, 15, 8, Z_DEFAULT_STRATEGY);
    std::mt19937 r(9);
    // noise, and real descriptions with their text broken where it means something: a number changed, a line dropped
    // or doubled, two lines swapped (what a hostile peer would send is text that still reads)
    const auto deflateText = coding::Serialize(coding::DeflateDescription());
    const auto textOf = nlohmann::ordered_json::parse(deflateText.begin(), deflateText.end());
    for (int i = 0; i < 300; ++i) {
        std::vector<uint8_t> b;
        if (i % 3 == 0) { b.resize(64 + r() % 512); for (auto &x : b) x = (uint8_t)r(); }
        else {
            auto j = textOf; auto &code = j["CODE"];
            for (int k = 0; k < 3; ++k) {
                const size_t at = r() % code.size(); std::string line = code[at].get<std::string>();
                switch (r() % 4) {
                    case 0: { std::vector<size_t> nums;
                              for (size_t q = 0; q < line.size(); ++q) { if (isdigit((unsigned char)line[q]) && (q == 0 || !isalnum((unsigned char)line[q - 1]))) nums.push_back(q); }
                              if (nums.empty()) break;
                              const size_t q = nums[r() % nums.size()]; size_t e = q;
                              while (e < line.size() && isalnum((unsigned char)line[e])) ++e;
                              const uint32_t pick[] = {0, 1, 2, 7, 255, 65535, 0xFFFFFFFFu, (uint32_t)r()}; line = line.substr(0, q) + std::to_string(pick[r() % 8]) + line.substr(e);
                              code[at] = line; break; }
                    case 1: code.erase(at); break;
                    case 2: code.insert(code.begin() + (long)at, line); break;
                    default: { const size_t o = r() % code.size(); std::swap(code[at], code[o]); break; }
                }
            }
            const std::string t = j.dump(); b.assign(t.begin(), t.end());
        }
        if (coding::Parse(b.data(), b.size(), d, err) && i % 3) {        // what still parses must RUN safely on a real stream
            std::vector<uint8_t> c2, r2; coding::Mint(d, sample.data(), sample.size(), 0, 1 << 18, 256, c2, r2, err); ++ran; }
    }
    CHECK(ran > 50);
    auto base = [] { coding::Description x; x.name = "t"; x.ex = {coding::Ex{coding::EX_CONST, 0, 0, 0}}; return x; };
    coding::Description fwd = base(); fwd.ex.push_back(coding::Ex{coding::EX_ADD, 2, 0, 0}); fwd.ex.push_back(coding::Ex{coding::EX_CONST, 0, 0, 1});
    fwd.ops = {coding::Op{coding::OP_END}};
    auto bytes = coding::Serialize(fwd); CHECK(!coding::Parse(bytes.data(), bytes.size(), d, err));
    coding::Description newer = base(); newer.isa = coding::kIsa + 1; newer.ops = {coding::Op{coding::OP_END}};
    bytes = coding::Serialize(newer); CHECK(!coding::Parse(bytes.data(), bytes.size(), d, err));
    coding::Description wild = base(); coding::Op j; j.op = coding::OP_JMP; j.target = 5; wild.ops = {j};
    bytes = coding::Serialize(wild); CHECK(!coding::Parse(bytes.data(), bytes.size(), d, err));
    const uint8_t one[1] = {0}; std::vector<uint8_t> content, record;
    coding::Description spin = base(); coding::Op self; self.op = coding::OP_JMP; self.target = 0; spin.ops = {self}; spin.coder = coding::kBits;
    bytes = coding::Serialize(spin); CHECK(coding::Parse(bytes.data(), bytes.size(), d, err));
    CHECK(!coding::Mint(d, one, 1, 0, 16, 4096, content, record, err)); CHECK(err.find("progress") != std::string::npos);
    coding::Description tab = base(); tab.coder = coding::kBits; tab.tables = {{7}}; tab.ex.push_back(coding::Ex{coding::EX_CONST, 0, 0, 99}); tab.ex.push_back(coding::Ex{coding::EX_TABLE, 1, 0, 0});
    coding::Op set; set.op = coding::OP_SET; set.tgt = 1; set.v = 2; tab.ops = {set, coding::Op{coding::OP_END}};
    bytes = coding::Serialize(tab); CHECK(coding::Parse(bytes.data(), bytes.size(), d, err));
    CHECK(!coding::Mint(d, one, 1, 0, 16, 4096, content, record, err)); CHECK(err.find("table") != std::string::npos);
    coding::Description slot = base(); slot.nslots = 10; slot.ex.push_back(coding::Ex{coding::EX_CONST, 0, 0, 999999});
    coding::Op bit; bit.op = coding::OP_BIT; bit.x = 1; slot.ops = {bit, coding::Op{coding::OP_END}};
    bytes = coding::Serialize(slot); CHECK(coding::Parse(bytes.data(), bytes.size(), d, err));
    CHECK(!coding::Mint(d, one, 1, 0, 16, 4096, content, record, err)); CHECK(err.find("slot") != std::string::npos);
}

// A record that does not belong is refused at creation; one source serves many threads at once.
TEST(a_coded_source_refuses_a_bad_record_and_reads_from_many_threads) {
    const auto in = sampleContent(3, 200000, 8); const auto alone = lzmaAlone(in, 6, 3, 0, 2);
    std::vector<uint8_t> record; const auto d = lzmaFor(alone);
    auto src = codedSource(d, alone.data() + 13, alone.size() - 13, in, 16384, &record); CHECK(src != nullptr); if (!src) return;
    std::string err; auto desc = std::make_shared<MemByteSource>(coding::Serialize(d)); auto content = std::make_shared<MemByteSource>(in);
    auto cutRec = record; cutRec.resize(cutRec.size() - 10);
    CHECK(!coding::CodedByteSource::Create(desc, std::make_shared<MemByteSource>(cutRec), content, alone.size() - 13, err));
    auto badRec = record; badRec[0] = 'X';
    CHECK(!coding::CodedByteSource::Create(desc, std::make_shared<MemByteSource>(badRec), content, alone.size() - 13, err));
    std::vector<uint8_t> shipped(alone.begin() + 13, alone.end());
    std::atomic<int> bad{0}; std::vector<std::thread> th;
    for (int t = 0; t < 8; ++t) th.emplace_back([&, t] { std::mt19937 rr((uint32_t)t); std::vector<uint8_t> b(32768);
        for (int i = 0; i < 25; ++i) { const size_t a = rr() % shipped.size(), n = 1 + rr() % std::min<size_t>(32768, shipped.size() - a);
            if (!src->preadAll(b.data(), n, a) || memcmp(b.data(), shipped.data() + a, n)) ++bad; } });
    for (auto &x : th) x.join();
    CHECK_EQ(bad.load(), 0);
}

// The validator's edges, one by one: what is one past an end is refused; what runs past slots or arrays is refused when
// it runs; a description that loses what it decodes is refused by the mint's code-back check.
TEST(a_description_is_checked_at_every_edge) {
    std::string err; coding::Description d; const uint8_t one[1] = {1}; std::vector<uint8_t> content, record;
    auto base = [] { coding::Description x; x.name = "edge"; x.coder = coding::kBits; x.ex = {coding::Ex{coding::EX_CONST, 0, 0, 0}}; return x; };
    auto parses = [&](const coding::Description &x) { const auto b = coding::Serialize(x); return coding::Parse(b.data(), b.size(), d, err); };
    coding::Op end; end.op = coding::OP_END;
    { auto x = base(); x.ex.push_back(coding::Ex{coding::EX_ADD, 1, 0, 0}); x.ops = {end}; CHECK(!parses(x)); }            // refers to itself
    { auto x = base(); x.ex.push_back(coding::Ex{coding::EX_ADD, 0, 0, 0}); x.ops = {end}; CHECK(parses(x)); }             // refers back: fine
    { auto x = base(); coding::Op j; j.op = coding::OP_JMP; j.target = 1; x.ops = {j}; CHECK(!parses(x)); }               // one past the last op
    { auto x = base(); coding::Op j; j.op = coding::OP_JMP; j.target = 0; x.ops = {j}; CHECK(parses(x)); }
    { auto x = base(); x.nslots = 64; coding::Op t; t.op = coding::OP_TREE; t.nb = 25; x.ops = {t, end}; CHECK(!parses(x)); }         // a tree too deep
    { auto x = base(); x.nslots = 64; coding::Op t; t.op = coding::OP_TREE; t.nb = 24; x.ops = {t, end}; CHECK(parses(x)); }
    { auto x = base(); coding::Op h; h.op = coding::OP_HPUSH; h.tgt = 60; h.nb = 5; x.ops = {h, end}; CHECK(!parses(x)); }             // history past the registers
    { auto x = base(); coding::Op h; h.op = coding::OP_HPUSH; h.tgt = 60; h.nb = 4; x.ops = {h, end}; CHECK(parses(x)); }
    { auto x = base(); x.coder = coding::kRange; x.nslots = 20; coding::Op t; t.op = coding::OP_TREE; t.nb = 5; x.ops = {t, end};       // a tree past its slots
      CHECK(parses(x)); CHECK(!coding::Mint(d, one, 1, 0, 16, 4096, content, record, err)); CHECK(err.find("out of range") != std::string::npos); }
    { auto x = base(); x.arrays = {{1, 2}}; x.ex.push_back(coding::Ex{coding::EX_CONST, 0, 0, 2}); x.ex.push_back(coding::Ex{coding::EX_ARR, 1, 0, 0});  // past an array
      coding::Op set; set.op = coding::OP_SET; set.tgt = 1; set.v = 2; x.ops = {set, end};
      CHECK(parses(x)); CHECK(!coding::Mint(d, one, 1, 0, 16, 4096, content, record, err)); CHECK(err.find("array") != std::string::npos); }
    { auto x = base(); x.tables = {{7}}; x.ex.push_back(coding::Ex{coding::EX_CONST, 0, 0, 1}); x.ex.push_back(coding::Ex{coding::EX_TABLE, 1, 0, 0});   // one past a table
      coding::Op set; set.op = coding::OP_SET; set.tgt = 1; set.v = 2; x.ops = {set, end};
      CHECK(parses(x)); CHECK(!coding::Mint(d, one, 1, 0, 16, 4096, content, record, err)); CHECK(err.find("table") != std::string::npos); }
    { auto x = base(); x.ex.push_back(coding::Ex{coding::EX_CONST, 0, 0, 1});                                              // a copy of distance 0
      coding::Op lit; lit.op = coding::OP_OUTLIT; lit.v = 0; coding::Op cp; cp.op = coding::OP_OUTCOPY; cp.x = 1; cp.v = 0; x.ops = {lit, cp, end};
      CHECK(parses(x)); CHECK(!coding::Mint(d, one, 1, 0, 16, 4096, content, record, err)); CHECK(err.find("before the start") != std::string::npos); }
    { auto x = base(); x.ex.push_back(coding::Ex{coding::EX_CONST, 0, 0, 8});                                              // a decision only DECODE records
      coding::Op raw; raw.op = coding::OP_RAW; raw.flags = coding::kFree; raw.tgt = 1; raw.x = 1; coding::Op dec; dec.op = coding::OP_DEC; dec.tgt = 1; dec.modes = coding::kDecode;
      x.ops = {raw, dec, end};
      CHECK(parses(x)); CHECK(!coding::Mint(d, one, 1, 0, 16, 4096, content, record, err)); CHECK(err.find("left over") != std::string::npos); }
    { auto x = base(); x.ex.push_back(coding::Ex{coding::EX_CONST, 0, 0, 8});                                              // decodes a byte, codes back 0
      coding::Op raw; raw.op = coding::OP_RAW; raw.tgt = 1; raw.x = 1; raw.v = 0; x.ops = {raw, end};
      CHECK(parses(x)); CHECK(!coding::Mint(d, one, 1, 0, 16, 4096, content, record, err)); CHECK(err.find("code back") != std::string::npos); }
}

// Records come from peers too. A record whose checkpoints are damaged (carry counts, probabilities, cursors, lengths:
// payloads decompressed, broken, recompressed) is refused or read, never crashes or hangs a reader; a description built
// to make its compiled form explode is refused; content over 4 GiB is refused before anything is allocated.
TEST(a_hostile_record_or_oversized_description_is_refused) {
    const auto in = sampleContent(1, 60000, 12); const auto alone = lzmaAlone(in, 6, 3, 0, 2); const auto d = lzmaFor(alone);
    std::vector<uint8_t> record; auto src = codedSource(d, alone.data() + 13, alone.size() - 13, in, 2048, &record); CHECK(src != nullptr); if (!src) return;
    // the record's index: magic, shipped size, total, count, then (out, dec, length) per checkpoint, then the payloads
    auto var = [](const std::vector<uint8_t> &b, size_t &at) { uint64_t v = 0; for (int sh = 0;; sh += 7) { const uint8_t x = b[at++]; v |= (uint64_t)(x & 0x7F) << sh; if (!(x & 0x80)) return v; } };
    auto put = [](std::vector<uint8_t> &o, uint64_t v) { while (v >= 0x80) { o.push_back((uint8_t)(v | 0x80)); v >>= 7; } o.push_back((uint8_t)v); };
    size_t at = 4; const uint64_t shippedN = var(record, at), total = var(record, at), nck = var(record, at);
    std::vector<uint64_t> outs, decs, lens; for (uint64_t k = 0; k < nck; ++k) { outs.push_back(var(record, at)); decs.push_back(var(record, at)); lens.push_back(var(record, at)); }
    std::vector<std::vector<uint8_t>> pay; for (uint64_t k = 0; k < nck; ++k) { pay.emplace_back(record.begin() + (long)at, record.begin() + (long)(at + lens[k])); at += lens[k]; }
    CHECK(nck > 3);
    std::mt19937 r(31); std::string err; int refused = 0, served = 0;
    for (int i = 0; i < 120; ++i) {
        auto pays = pay; const size_t k = 1 + r() % (nck - 1);
        std::vector<uint8_t> raw(ZSTD_getFrameContentSize(pays[k].data(), pays[k].size())); ZSTD_decompress(raw.data(), raw.size(), pays[k].data(), pays[k].size());
        const int how = i % 3;
        if (how == 0) for (int j = 0; j < 3; ++j) raw[r() % std::min<size_t>(raw.size(), 400)] ^= (uint8_t)(1u << (r() % 8));      // registers, coder, cursor
        else if (how == 1) raw[r() % raw.size()] = 0xFF;                                                                           // anywhere
        else { size_t s2 = 0; while (raw[s2] & 0x80) ++s2; ++s2; for (int j = 0; j < 12; ++j) raw[s2 + (size_t)(r() % 64)] = 0xFF; }  // the carry, the pc
        std::vector<uint8_t> z(ZSTD_compressBound(raw.size())); z.resize(ZSTD_compress(z.data(), z.size(), raw.data(), raw.size(), 3)); pays[k] = z;
        std::vector<uint8_t> rec = {'V', 'G', 'C', 'R'}; put(rec, shippedN); put(rec, total); put(rec, nck);
        for (uint64_t j = 0; j < nck; ++j) { put(rec, outs[j]); put(rec, decs[j]); put(rec, pays[j].size()); }
        for (auto &q : pays) rec.insert(rec.end(), q.begin(), q.end());
        auto s2 = coding::CodedByteSource::Create(std::make_shared<MemByteSource>(coding::Serialize(d)), std::make_shared<MemByteSource>(rec),
                                                  std::make_shared<MemByteSource>(in), alone.size() - 13, err);
        if (!s2) { ++refused; continue; }
        std::vector<uint8_t> b(4096); const size_t off = std::min<size_t>(outs[k] + 10, alone.size() - 13 - 1);
        if (s2->pread(b.data(), std::min<size_t>(4096, alone.size() - 13 - off), off) < 0) ++refused; else ++served;
    }
    CHECK(refused + served == 120); CHECK(refused > 0);
    {   // the first checkpoint must be the stream's start
        std::vector<uint8_t> rec = {'V', 'G', 'C', 'R'}; put(rec, shippedN); put(rec, total); put(rec, nck);
        for (uint64_t j = 0; j < nck; ++j) { put(rec, j ? outs[j] : 1); put(rec, decs[j]); put(rec, pay[j].size()); }
        for (auto &q : pay) rec.insert(rec.end(), q.begin(), q.end());
        CHECK(!coding::CodedByteSource::Create(std::make_shared<MemByteSource>(coding::Serialize(d)), std::make_shared<MemByteSource>(rec),
                                               std::make_shared<MemByteSource>(in), alone.size() - 13, err)); }
    // an expression chain every op needs: its compiled form would be quadratic
    coding::Description bomb; bomb.name = "bomb"; bomb.coder = coding::kBits; bomb.ex.push_back(coding::Ex{coding::EX_REG, 0, 0, 1});
    for (uint16_t i = 1; i < 60000; ++i) bomb.ex.push_back(coding::Ex{coding::EX_ADD, (uint16_t)(i - 1), 0, 0});
    for (uint16_t i = 0; i < 60000; i += 2) { coding::Op o; o.op = coding::OP_SET; o.tgt = 2; o.v = i; bomb.ops.push_back(o); }
    coding::Op e; e.op = coding::OP_END; bomb.ops.push_back(e);
    // as text it cannot even be said (its values nest past what a description may; printed, it would take gigabytes),
    // and held in memory it is refused when it runs
    CHECK(coding::Serialize(bomb).empty()); std::string why; CHECK(coding::Validate(bomb, why));
    const auto t0 = std::chrono::steady_clock::now(); std::vector<uint8_t> c, rr; const uint8_t one[1] = {0};
    CHECK(!coding::Mint(bomb, one, 1, 0, 16, 4096, c, rr, err)); CHECK(err.find("complex") != std::string::npos);
    CHECK(std::chrono::steady_clock::now() - t0 < std::chrono::seconds(30));                     // (sanitizer builds run slow)
    CHECK(!coding::Mint(coding::DeflateDescription(), one, 1, 0, (size_t)5 << 30, 4096, c, rr, err)); CHECK(err.find("4 GiB") != std::string::npos);
}

// A coded stream MOUNTS: its content is any layer carrying bytes (here a bytes-only file, named by CID), its record and
// description are files; it appears as one file at its name, serves the shipped bytes exactly, hides nothing, and a
// spec that names a content no layer carries is planned as broken, not mounted wrong.
// ---- BSA 105 (Skyrim Special Edition), from its description: an archive made here, member by member
struct BsaMember { std::string name; std::vector<uint8_t> data; bool flip = false; int frameFlags = 0; };
// frameFlags: 1 = block checksums, 2 = content checksum, 4 = content size, 8 = linked blocks, 16 = 64 KiB blocks,
// 32 = a dictionary id in the frame header
static std::vector<uint8_t> lz4Frame(const std::vector<uint8_t> &in, int ff) {
    LZ4F_preferences_t p{}; p.frameInfo.blockSizeID = ff & 16 ? LZ4F_max64KB : LZ4F_max4MB;
    p.frameInfo.blockMode = ff & 8 ? LZ4F_blockLinked : LZ4F_blockIndependent;
    p.frameInfo.contentChecksumFlag = ff & 2 ? LZ4F_contentChecksumEnabled : LZ4F_noContentChecksum;
    p.frameInfo.blockChecksumFlag = ff & 1 ? LZ4F_blockChecksumEnabled : LZ4F_noBlockChecksum;
    p.frameInfo.contentSize = ff & 4 ? in.size() : 0; p.compressionLevel = ff & 8 ? 9 : 0;
    p.frameInfo.dictID = ff & 32 ? 0x5EED1234u : 0;
    std::vector<uint8_t> out(LZ4F_compressFrameBound(in.size(), &p));
    const size_t n = LZ4F_compressFrame(out.data(), out.size(), in.data(), in.size(), &p);
    out.resize(LZ4F_isError(n) ? 0 : n); return out;
}
static std::vector<uint8_t> familyFrame(const std::vector<uint8_t> &in, uint32_t attempts, int bd);
// Returns the archive; `content` gets what the description must decode it to (header region, then each member's bytes).
static std::vector<uint8_t> makeBsa(const std::vector<std::pair<std::string, std::vector<BsaMember>>> &folders, uint32_t flags,
                                    std::vector<uint8_t> &content, bool shuffle = false) {
    auto u32 = [](std::vector<uint8_t> &v, uint32_t x) { for (int i = 0; i < 4; ++i) v.push_back((uint8_t)(x >> 8 * i)); };
    auto u64 = [&](std::vector<uint8_t> &v, uint64_t x) { u32(v, (uint32_t)x); u32(v, (uint32_t)(x >> 32)); };
    uint32_t nfiles = 0, tfn = 0, tfin = 0;
    for (auto &f : folders) { nfiles += (uint32_t)f.second.size(); tfn += (uint32_t)f.first.size() + 1; for (auto &m : f.second) tfin += (uint32_t)m.name.size() + 1; }
    std::vector<uint8_t> h; u32(h, 0x00415342); u32(h, 105); u32(h, 36); u32(h, flags);
    u32(h, (uint32_t)folders.size()); u32(h, nfiles); u32(h, tfn); u32(h, tfin); u32(h, 0);
    const uint32_t region = 36 + (uint32_t)folders.size() * 24 + (flags & 1 ? tfn + (uint32_t)folders.size() : 0) + nfiles * 16 + (flags & 2 ? tfin : 0);
    // member bytes, in data order
    std::vector<std::vector<uint8_t>> stored, decoded;
    for (auto &f : folders) for (auto &m : f.second) {
        const bool comp = ((flags >> 2) & 1) ^ m.flip;
        std::vector<uint8_t> s, d;
        if (flags & 0x100) { const std::string full = f.first + "\\" + m.name; s.push_back((uint8_t)full.size()); s.insert(s.end(), full.begin(), full.end()); d = s; }
        if (comp) { u32(s, (uint32_t)m.data.size());
            const auto fr = m.frameFlags & 64 ? familyFrame(m.data, 512, 0x40) : m.frameFlags & 128 ? familyFrame(m.data, 512, 0x70) : lz4Frame(m.data, m.frameFlags);
            s.insert(s.end(), fr.begin(), fr.end()); }
        else s.insert(s.end(), m.data.begin(), m.data.end());
        d.insert(d.end(), m.data.begin(), m.data.end());
        stored.push_back(s); decoded.push_back(d);
    }
    //shuffle: the members stored in the reverse of the order the records list them (data order != record order)
    std::vector<size_t> order(stored.size()); for (size_t i = 0; i < order.size(); ++i) order[i] = shuffle ? order.size() - 1 - i : i;
    std::vector<uint32_t> at(stored.size()); uint32_t o = region; for (size_t i : order) { at[i] = o; o += (uint32_t)stored[i].size(); }
    size_t k = 0; uint32_t recOff = 36 + (uint32_t)folders.size() * 24;
    std::vector<uint8_t> recs;
    for (auto &f : folders) {
        u64(h, 0x1234 + k); u32(h, (uint32_t)f.second.size()); u32(h, 0); u64(h, recOff + tfin + (uint32_t)recs.size());
        if (flags & 1) { recs.push_back((uint8_t)(f.first.size() + 1)); recs.insert(recs.end(), f.first.begin(), f.first.end()); recs.push_back(0); }
        for (auto &m : f.second) { u64(recs, 0x9876 + k); u32(recs, (uint32_t)stored[k].size() | (m.flip ? 1u << 30 : 0)); u32(recs, at[k]); ++k; }
    }
    h.insert(h.end(), recs.begin(), recs.end());
    if (flags & 2) for (auto &f : folders) for (auto &m : f.second) { h.insert(h.end(), m.name.begin(), m.name.end()); h.push_back(0); }
    content = h; std::vector<uint8_t> bsa = h;
    for (size_t i : order) { bsa.insert(bsa.end(), stored[i].begin(), stored[i].end()); content.insert(content.end(), decoded[i].begin(), decoded[i].end()); }
    return bsa;
}

// Skyrim SE's archives decode to their header region and every member's bytes, and are coded back bit-exact from
// those and the decisions: compressed and stored members (bit 30 flips one), every LZ4 frame option, embedded names.
TEST(a_bsa_archive_is_served_through_its_description) {
    const auto bsaD = coding::BsaDescription();
    {   const auto bytes = coding::Serialize(bsaD); coding::Description back; std::string err;
        CHECK(coding::Parse(bytes.data(), bytes.size(), back, err)); CHECK(coding::Serialize(back) == bytes); }
    int cases = 0;
    for (uint32_t flags : {0x7u, 0x3u, 0x107u}) {
        std::vector<std::pair<std::string, std::vector<BsaMember>>> f = {
            {"textures\\armor", {{"iron.dds", sampleContent(0, 70000, 3), false, 0}, {"steel.dds", sampleContent(1, 300000, 4), false, 1 | 2 | 4},
                                 {"glass.dds", sampleContent(2, 5000, 5), true, 0}}},
            {"meshes", {{"a.nif", sampleContent(3, 140000, 6), false, 8 | 16}, {"empty.nif", {}, false, 0}, {"b.nif", sampleContent(0, 90000, 7), false, 16 | 1}, {"c.nif", sampleContent(2, 20000, 8), false, 32 | 4}}}};
        std::vector<uint8_t> want; const auto bsa = makeBsa(f, flags, want);
        auto src = codedSource(bsaD, bsa.data(), bsa.size(), want, 4096);
        CHECK(src != nullptr); if (!src) continue;
        CHECK(src->checkpoints() >= (flags & 4 ? 12u : 4u));                  // members (and LZ4 sequences) are checkpoints
        CHECK(coding::SuggestedSpacing(bsaD, bsa.size()) >= 4096);            // static coder: cheap checkpoints, but not per byte
        CHECK(readsBack(*src, bsa, flags, 60)); ++cases;
        // the streaming mint into a caller's buffer gives the same content and a record that serves the same bytes
        std::vector<uint8_t> buf(want.size() + 64), rec; size_t len = 0; std::string err;
        CHECK(coding::MintInto(bsaD, bsa.data(), bsa.size(), 0, buf.data(), buf.size(), 4096, len, rec, err));
        CHECK(len == want.size() && std::equal(want.begin(), want.end(), buf.begin()));
        std::vector<uint8_t> small(want.size() / 2);                          // too small a buffer is refused, never overrun
        CHECK(!coding::MintInto(bsaD, bsa.data(), bsa.size(), 0, small.data(), small.size(), 4096, len, rec, err));
    }
    CHECK(cases == 3);
    {   // members stored in another order than the records list them (Skyrim SE's 2021 Misc.bsa) decode in data order and
        // code back; a record pointing where no member starts, and a wrong magic, are refused
        std::vector<std::pair<std::string, std::vector<BsaMember>>> f = {{"x", {{"1", sampleContent(0, 3000, 1)}, {"2", sampleContent(1, 5000, 2)}, {"3", sampleContent(2, 2000, 3)}}}};
        std::vector<uint8_t> want, content, record; std::string err;
        auto bsa = makeBsa(f, 0x7, want, true);
        CHECK(coding::Mint(bsaD, bsa.data(), bsa.size(), 0, want.size() * 2, 4096, content, record, err));
        CHECK(content == want);                                           // the header region, then the members in data order
        auto src = codedSource(bsaD, bsa.data(), bsa.size(), content, 256);
        CHECK(src != nullptr && readsBack(*src, bsa, 9, 30));
        bsa = makeBsa(f, 0x7, want);
        const size_t Rec1 = 36 + 24 + 1 + 2 + 16 + 12;                        // the second file record's offset field
        bsa[Rec1] += 1;
        CHECK(!coding::Mint(bsaD, bsa.data(), bsa.size(), 0, want.size() * 2, 4096, content, record, err));
        bsa = makeBsa(f, 0x7, want); bsa[2] = 'X';
        CHECK(!coding::Mint(bsaD, bsa.data(), bsa.size(), 0, want.size() * 2, 4096, content, record, err));
        bsa = makeBsa(f, 0x7, want); bsa[4] = 104;                            // version 104 (Oldrim) is another description
        CHECK(!coding::Mint(bsaD, bsa.data(), bsa.size(), 0, want.size() * 2, 4096, content, record, err));
    }
}

// An LZ4 frame as Bethesda's packer makes them, from the family itself (independent blocks of BlockMax, no checksums):
// every sequence is the family's, so a predicted record holds flags only
static std::vector<uint8_t> familyFrame(const std::vector<uint8_t> &in, uint32_t attempts, int bd) {
    const size_t bmax = (size_t)1 << (2 * ((bd >> 4) & 7) + 8);
    std::vector<uint8_t> f = {0x04, 0x22, 0x4D, 0x18, 0x60, (uint8_t)bd, 0x73};
    coding::Lz4hcParser P; std::vector<coding::Lz4Seq> seqs;
    auto len = [](std::vector<uint8_t> &o, size_t n) { for (; n >= 255; n -= 255) o.push_back(255); o.push_back((uint8_t)n); };
    for (size_t o = 0; o < in.size(); o += bmax) {
        const size_t n = std::min(bmax, in.size() - o); { uint64_t st = 0; P.parse(in.data() + o, n, attempts, seqs, st); }
        std::vector<uint8_t> b;
        for (const auto &q : seqs) {
            const size_t ml = q.ml ? q.ml - 4 : 0;
            b.push_back((uint8_t)((std::min<size_t>(q.lit, 15) << 4) | (q.ml ? std::min<size_t>(ml, 15) : 0)));
            if (q.lit >= 15) len(b, q.lit - 15);
            b.insert(b.end(), in.begin() + (long)(o + q.anchor), in.begin() + (long)(o + q.anchor + q.lit));
            if (!q.ml) break;
            b.push_back((uint8_t)q.off); b.push_back((uint8_t)(q.off >> 8));
            if (ml >= 15) len(b, ml - 15);
        }
        for (int i = 0; i < 4; ++i) f.push_back((uint8_t)(b.size() >> 8 * i));
        f.insert(f.end(), b.begin(), b.end());
    }
    for (int i = 0; i < 4; ++i) f.push_back(0);
    return f;
}

// The family (ISA 5): a BSA whose frames Bethesda's packer made mints a PREDICTED record that holds only flags, far smaller
// than the plain one, and serves the same bytes; EXPAND gives exactly the plain mint's record; a predicted record passed
// off as plain is refused; frames from another encoder still mint (their sequences are corrections). Teeth: predict nothing
// (records stay plain-sized); expand without the plain mint (records differ); ignore the flag.
TEST(a_bsa_family_predicts_its_frames) {
    const uint32_t att = 512;                                             // a cheap family keeps the test fast; the knob is data
    const auto famD = coding::BsaDescription(att), plainD = coding::BsaDescription(0);
    CHECK(coding::UsesPrediction(famD)); CHECK(!coding::UsesPrediction(plainD)); CHECK(famD.isa == 5 && plainD.isa == 4);
    // the archive: members whose frames come from the family (64 KiB and 4 MiB blocks), with liblz4's members beside them
    const auto m1 = sampleContent(0, 200000, 41), m2 = sampleContent(3, 90000, 42), m3 = sampleContent(1, 150000, 43);
    std::vector<uint8_t> want;
    // a and b: the family's own frames (frameFlags 64: 64 KiB blocks, 128: 4 MiB); c: liblz4's, checksummed
    std::vector<uint8_t> content, recQ, recP; std::string err;
    const auto bsa = makeBsa({{"t", {{"a.dds", m1, false, 64}, {"b.dds", m2, false, 128}, {"c.nif", m3, false, 1 | 4}}}}, 0x7, want);
    CHECK(coding::Mint(famD, bsa.data(), bsa.size(), 0, want.size() * 2, 4096, content, recQ, err)); CHECK(content == want);
    CHECK(coding::Mint(famD, bsa.data(), bsa.size(), 0, want.size() * 2, 4096, content, recP, err, false));
    CHECK(recQ.size() >= 4 && recQ[3] == 'Q' && recP[3] == 'R');
    CHECK(recQ.size() * 20 < recP.size());                               // flags, not tokens (1.6 KB against 60 KB)
    auto mk = [&](const coding::Description &d, const std::vector<uint8_t> &rec) {
        return coding::CodedByteSource::Create(std::make_shared<MemByteSource>(coding::Serialize(d)), std::make_shared<MemByteSource>(rec),
                                               std::make_shared<MemByteSource>(content), bsa.size(), err); };
    auto q = mk(famD, recQ), p = mk(famD, recP);
    CHECK(q && p); if (!q || !p) return;
    CHECK(q->predicted() && !p->predicted());
    CHECK(readsBack(*q, bsa, 51, 40)); CHECK(readsBack(*p, bsa, 52, 40));
    // expand: the predicted record's plain twin is the plain mint's record, byte for byte
    std::vector<uint8_t> sb(bsa.size()), cb(content.size()), plain;
    CHECK(coding::ExpandInto(std::make_shared<MemByteSource>(coding::Serialize(famD)), std::make_shared<MemByteSource>(recQ), std::make_shared<MemByteSource>(content),
                             sb.data(), sb.size(), cb.data(), cb.size(), 4096, plain, err));
    CHECK(plain == recP);
    // a predicted record passed off as plain: its flags name predictions a plain run does not make
    auto fake = recQ; fake[3] = 'R';
    auto bad = mk(famD, fake);                                           // (refused at its index, or on the first read)
    if (bad) { std::vector<uint8_t> all(bsa.size()); CHECK(!bad->preadAll(all.data(), all.size(), 0)); }
    // the family's knob is part of the description: another one predicts other tokens, and a record served under it is
    // refused segment by segment (each carries its bytes' hash), never other bytes, and never expanded into a twin
    // (adversary 2026-11-27: on sparse noise, 512 vs 500 attempts served 5,810 other bytes). Teeth: skip the hash.
    {
        std::vector<uint8_t> noise(400000); std::mt19937 rr(77);
        for (auto &x : noise) x = (rr() % 7) ? 0 : (uint8_t)(1 + rr() % 3);
        std::vector<uint8_t> w2; const auto nb = makeBsa({{"n", {{"noise.dds", noise, false, 64}}}}, 0x7, w2);
        std::vector<uint8_t> c2, q2;
        CHECK(coding::Mint(famD, nb.data(), nb.size(), 0, w2.size() * 2, 4096, c2, q2, err));
        auto under = coding::CodedByteSource::Create(std::make_shared<MemByteSource>(coding::Serialize(coding::BsaDescription(500))),
                                                     std::make_shared<MemByteSource>(q2), std::make_shared<MemByteSource>(c2), nb.size(), err);
        CHECK(under != nullptr);
        if (under) { std::vector<uint8_t> all(nb.size()); CHECK(!under->preadAll(all.data(), all.size(), 0)); }
        std::vector<uint8_t> sb2(nb.size()), cb2(c2.size()), pl2;
        CHECK(!coding::ExpandInto(std::make_shared<MemByteSource>(coding::Serialize(coding::BsaDescription(500))), std::make_shared<MemByteSource>(q2),
                                  std::make_shared<MemByteSource>(c2), sb2.data(), sb2.size(), cb2.data(), cb2.size(), 4096, pl2, err));
        auto right = coding::CodedByteSource::Create(std::make_shared<MemByteSource>(coding::Serialize(famD)), std::make_shared<MemByteSource>(q2),
                                                     std::make_shared<MemByteSource>(c2), nb.size(), err);
        CHECK(right && readsBack(*right, nb, 53, 20));
    }
}

// The family parses as lz4 1.7 did (the parse verified against Skyrim SE's archives: Meshes1 3000/3000 blocks): its
// output over a fixed set of inputs is pinned, and today's liblz4 at level 9 (the same parser, later revised) agrees on
// most of them. Teeth: any change to the parse (the lookahead, a correction, the window, the chain) moves the digest.
static std::vector<uint8_t> familyBlock(const std::vector<uint8_t> &in, uint32_t att) {
    coding::Lz4hcParser P; std::vector<coding::Lz4Seq> seqs; uint64_t st = 0; P.parse(in.data(), in.size(), att, seqs, st); std::vector<uint8_t> b;
    auto len = [](std::vector<uint8_t> &o, size_t n) { for (; n >= 255; n -= 255) o.push_back(255); o.push_back((uint8_t)n); };
    for (const auto &q : seqs) { const size_t ml = q.ml ? q.ml - 4 : 0;
        b.push_back((uint8_t)((std::min<size_t>(q.lit, 15) << 4) | (q.ml ? std::min<size_t>(ml, 15) : 0)));
        if (q.lit >= 15) len(b, q.lit - 15);
        b.insert(b.end(), in.begin() + (long)q.anchor, in.begin() + (long)(q.anchor + q.lit));
        if (!q.ml) break;
        b.push_back((uint8_t)q.off); b.push_back((uint8_t)(q.off >> 8)); if (ml >= 15) len(b, ml - 15); }
    return b;
}
TEST(the_lz4_family_parses_as_lz4_1_7_did) {
    int same = 0, all = 0; uint64_t h = 1469598103934665603ull; bool decodes = true;
    for (int kind : {0, 1, 2, 3}) for (uint32_t seed = 1; seed <= 25; ++seed) for (size_t n : {13ul, 100ul, 5000ul, 60000ul, 65536ul}) {
        const auto in = sampleContent(kind, n, seed);
        const auto ours = familyBlock(in, 256);
        std::vector<uint8_t> t((size_t)LZ4_compressBound((int)n));
        t.resize((size_t)LZ4_compress_HC((const char *)in.data(), (char *)t.data(), (int)n, (int)t.size(), 9));
        ++all; if (t == ours) ++same;
        std::vector<uint8_t> back(n + 16);                                // and it is a valid LZ4 block of the input
        decodes = decodes && LZ4_decompress_safe((const char *)ours.data(), (char *)back.data(), (int)ours.size(), (int)back.size()) == (int)n
                          && std::equal(in.begin(), in.end(), back.begin());
        for (uint8_t c : ours) { h ^= c; h *= 1099511628211ull; } h ^= ours.size(); h *= 1099511628211ull;
    }
    CHECK(decodes);
    CHECK_EQ(h, 4403846504761238684ull);
    {   // the window's far end: a run whose only earlier copy lies 65,000 bytes back is found there
        std::vector<uint8_t> in(80000); std::mt19937 r(123); for (auto &x : in) x = (uint8_t)r();
        std::copy(in.begin() + 1000, in.begin() + 1400, in.begin() + 66000);
        coding::Lz4hcParser P; std::vector<coding::Lz4Seq> q; uint64_t st = 0;
        CHECK(P.parse(in.data(), in.size(), 256, q, st));
        bool far = false; for (const auto &x : q) far = far || (x.ml >= 300 && x.off == 65000);
        CHECK(far);
    }
    CHECK(same >= 350 && same < all);                                    // 357/500: the revisions show, rarely
}

// A description asking for parse after parse of big blocks (a new one each time: the cache holds what it has parsed) while
// making no progress is refused by the work budget, and quickly.
TEST(a_description_that_parses_without_progress_is_refused) {
    coding::Description d; d.name = "parse bomb"; d.isa = 5; d.coder = coding::kBits;
    auto ex = [&](uint8_t op, uint16_t a, uint16_t b, uint32_t imm) { d.ex.push_back(coding::Ex{op, a, b, imm}); return (uint16_t)(d.ex.size() - 1); };
    const uint16_t c0 = ex(coding::EX_CONST, 0, 0, 0), c1 = ex(coding::EX_CONST, 0, 0, 1), big = ex(coding::EX_CONST, 0, 0, 4u << 20);
    const uint16_t cnt = ex(coding::EX_REG, 0, 0, 20), dec = ex(coding::EX_SUB, cnt, c1, 0), lim = ex(coding::EX_CONST, 0, 0, 200);
    auto op = [&](uint8_t o, uint8_t tgt, uint16_t x, uint16_t v, uint16_t m, uint32_t imm, uint8_t nb = 0, uint16_t target = 0) {
        coding::Op p; p.op = o; p.tgt = tgt; p.x = x; p.v = v; p.m = m; p.imm = imm; p.nb = nb; p.target = target; d.ops.push_back(p); };
    op(coding::OP_SET, 20, c0, lim, c0, 0);                                           // 0: 200 rounds
    op(coding::OP_PREDICT, 30, c0, cnt, big, 1, coding::kFamilyLz4hc);             // 1: the block [round, 4 MiB): a new one each round
    op(coding::OP_PREDICT, 30, c0, cnt, big, 1, coding::kFamilyLz4hc);             // 2: (the same: the cache holds it)
    op(coding::OP_SET, 20, c0, dec, c0, 0);                                           // 3
    op(coding::OP_JZ, 0, c0, cnt, c0, 0, 0, 6);                                       // 4: done
    op(coding::OP_JMP, 0, c0, c0, c0, 0, 0, 1);                                       // 5
    op(coding::OP_BYTERUN, 0, big, c0, c0, 0);                                        // 6: then the stream, as it is
    op(coding::OP_END, 0, c0, c0, c0, 0);
    const auto bytes = coding::Serialize(d); coding::Description back; std::string err;
    CHECK(coding::Parse(bytes.data(), bytes.size(), back, err));
    std::vector<uint8_t> shipped(4u << 20); std::mt19937 rr(9); for (auto &x : shipped) x = (uint8_t)rr();   // every position searched
    std::vector<uint8_t> content, rec;
    const auto t0 = std::chrono::steady_clock::now();
    CHECK(!coding::Mint(back, shipped.data(), shipped.size(), shipped.size(), shipped.size(), 1u << 20, content, rec, err));
    if (err.find("parses without making progress") == std::string::npos) std::fprintf(stderr, "  parse bomb: %s\n", err.c_str());
    CHECK(err.find("parses without making progress") != std::string::npos);
    CHECK(std::chrono::steady_clock::now() - t0 < std::chrono::seconds(60));
    // the same program minted plain never parses: it is only a byte run
    CHECK(coding::Mint(back, shipped.data(), shipped.size(), shipped.size(), shipped.size(), 1u << 20, content, rec, err, false));
}

// Content built to make the family's parse crawl (two symbols at random: every chain is long) is refused by the parse's
// WORK budget, in seconds, where the parse itself would take minutes (adversary 2026-11-27: 18 s a 4 MiB block at 65536
// attempts). Teeth: budget bytes, not steps.
TEST(a_parse_that_would_crawl_is_refused_by_its_work) {
    coding::Description d; d.name = "crawl"; d.isa = 5; d.coder = coding::kBits;
    auto ex = [&](uint8_t op, uint32_t imm) { d.ex.push_back(coding::Ex{op, 0, 0, imm}); return (uint16_t)(d.ex.size() - 1); };
    const uint16_t c0 = ex(coding::EX_CONST, 0), big = ex(coding::EX_CONST, 4u << 20);
    auto op = [&](uint8_t o, uint8_t tgt, uint16_t x, uint16_t v, uint16_t m, uint32_t imm, uint8_t nb = 0) {
        coding::Op p; p.op = o; p.tgt = tgt; p.x = x; p.v = v; p.m = m; p.imm = imm; p.nb = nb; d.ops.push_back(p); };
    op(coding::OP_PREDICT, 30, c0, c0, big, coding::kLz4hcMaxAttempts, coding::kFamilyLz4hc);   // (a mint's second pass has the content)
    op(coding::OP_BYTERUN, 0, big, c0, c0, 0);
    op(coding::OP_END, 0, c0, c0, c0, 0);
    std::vector<uint8_t> shipped(4u << 20); std::mt19937 r(5); for (auto &x : shipped) x = (uint8_t)(r() & 1);
    std::vector<uint8_t> content, rec; std::string err;
    const auto t0 = std::chrono::steady_clock::now();
    CHECK(!coding::Mint(d, shipped.data(), shipped.size(), shipped.size(), shipped.size(), 1u << 20, content, rec, err));
    CHECK(err.find("parses without making progress") != std::string::npos);
    CHECK(std::chrono::steady_clock::now() - t0 < std::chrono::seconds(30));
}

// Whatever the mint accepts, every reader can read: the mint codes back as a reader restored at each checkpoint runs
// (its own parse budget, no parse at hand), so a slow block after much easy content is refused at mint, never minted
// into a record no reader can read (adversary 2026-11-27: minted, then EIO). Teeth: one budget for the whole mint.
TEST(a_record_the_mint_accepts_every_reader_can_read) {
    std::vector<uint8_t> easy(20u << 20), slow(4u << 20); std::mt19937 r(11);
    for (auto &x : easy) x = (uint8_t)r();
    for (auto &x : slow) x = (uint8_t)(r() & 1);
    std::vector<uint8_t> want; const auto bsa = makeBsa({{"t", {{"easy.dds", easy}, {"slow.dds", slow}}}}, 0x7, want);
    const auto famD = coding::BsaDescription(32768);
    std::vector<uint8_t> content, rec; std::string err;
    const bool minted = coding::Mint(famD, bsa.data(), bsa.size(), 0, want.size() + 4096, 1u << 20, content, rec, err);
    if (minted) {
        auto src = coding::CodedByteSource::Create(std::make_shared<MemByteSource>(coding::Serialize(famD)), std::make_shared<MemByteSource>(rec),
                                                   std::make_shared<MemByteSource>(content), bsa.size(), err);
        CHECK(src != nullptr);
        std::vector<uint8_t> all(bsa.size());
        CHECK(src && src->preadAll(all.data(), all.size(), 0) && all == bsa);
    } else CHECK(err.find("parses without making progress") != std::string::npos);
    // the same archive minted plain always mints and reads (the fallback for such a stream)
    CHECK(coding::Mint(famD, bsa.data(), bsa.size(), 0, want.size() + 4096, 1u << 20, content, rec, err, false));
}

// A mount reads a predicted record for as long as it lives: re-reading (segments decoded again, parses evicted) never runs
// the stream's parse budget out (adversary 2026-11-27: the 4th full read of one source failed). Teeth: charge every
// parse, not every distinct block.
TEST(a_predicted_record_reads_again_and_again) {
    std::vector<uint8_t> data(4u << 20); std::mt19937 r(13); for (auto &x : data) x = (uint8_t)(r() & 3);
    std::vector<BsaMember> ms;
    for (int i = 0; i < 16; ++i) ms.push_back({ "m" + std::to_string(i) + ".dds", std::vector<uint8_t>(data.begin() + i * (256 << 10), data.begin() + (i + 1) * (256 << 10)), false, 64 });
    std::vector<uint8_t> want; const auto bsa = makeBsa({{"t", ms}}, 0x7, want);
    const auto famD = coding::BsaDescription(512);
    std::vector<uint8_t> content, rec; std::string err;
    CHECK(coding::Mint(famD, bsa.data(), bsa.size(), 0, want.size() + 4096, 8u << 10, content, rec, err));
    auto src = coding::CodedByteSource::Create(std::make_shared<MemByteSource>(coding::Serialize(famD)), std::make_shared<MemByteSource>(rec),
                                               std::make_shared<MemByteSource>(content), bsa.size(), err);
    CHECK(src != nullptr); if (!src) return;
    CHECK(src->checkpoints() > 40);                                      // more segments than the cache keeps: decoded again each pass
    std::vector<uint8_t> all(bsa.size()); int good = 0;
    for (int pass = 0; pass < 8; ++pass) if (src->preadAll(all.data(), all.size(), 0) && all == bsa) ++good;
    CHECK_EQ(good, 8);
}

// The parser's work budget is exact: a parse stops at MaxSteps (never far past it), and Steps carries on across calls.
TEST(the_family_parse_stops_at_its_budget) {
    std::vector<uint8_t> s(1u << 20); std::mt19937 r(3); for (auto &x : s) x = (uint8_t)(r() & 1);
    coding::Lz4hcParser P; std::vector<coding::Lz4Seq> q; uint64_t st = 0;
    CHECK(!P.parse(s.data(), s.size(), 65536, q, st, 100000));
    CHECK(st > 100000 && st <= 100000 + 8);                              // (each search on the way out adds one)
    uint64_t st2 = 5; CHECK(P.parse(s.data(), 4096, 16, q, st2)); CHECK(st2 > 5);
}

// A predicted record over content that is not its own (one byte of a member changed) is refused by that segment's hash,
// never served with the byte changed; a record claiming a stream far bigger than its content is refused by ExpandInto
// itself. Teeth: skip the hash; drop the bound.
TEST(a_predicted_record_refuses_content_not_its_own) {
    const auto famD = coding::BsaDescription(512);
    std::vector<uint8_t> want; const auto bsa = makeBsa({{"t", {{"a.dds", sampleContent(0, 300000, 61), false, 64}}}}, 0x7, want);
    std::vector<uint8_t> content, rec; std::string err;
    CHECK(coding::Mint(famD, bsa.data(), bsa.size(), 0, want.size() + 4096, 4096, content, rec, err));
    auto other = content; other[other.size() - 5000] ^= 0x20;            // a member's byte (a literal or a copied one)
    auto src = coding::CodedByteSource::Create(std::make_shared<MemByteSource>(coding::Serialize(famD)), std::make_shared<MemByteSource>(rec),
                                               std::make_shared<MemByteSource>(other), bsa.size(), err);
    CHECK(src != nullptr);
    if (src) { std::vector<uint8_t> all(bsa.size()); CHECK(!src->preadAll(all.data(), all.size(), 0)); }
    // a record whose shipped size says 16x its content
    auto big = rec; std::vector<uint8_t> h = {'V', 'G', 'C', 'Q'}; size_t at = 4; while (big[at] & 0x80) ++at; ++at;
    for (uint64_t v = (uint64_t)content.size() * 16; ; v >>= 7) { if (v < 0x80) { h.push_back((uint8_t)v); break; } h.push_back((uint8_t)(v | 0x80)); }
    h.insert(h.end(), big.begin() + (long)at, big.end());
    std::vector<uint8_t> sb(content.size() * 16 + 16), cb(content.size()), plain;
    CHECK(!coding::ExpandInto(std::make_shared<MemByteSource>(coding::Serialize(famD)), std::make_shared<MemByteSource>(h), std::make_shared<MemByteSource>(content),
                              sb.data(), sb.size(), cb.data(), cb.size(), 4096, plain, err));
    if (err.find("far bigger") == std::string::npos) std::fprintf(stderr, "  expand: %s\n", err.c_str());
    CHECK(err.find("far bigger") != std::string::npos);
}

// PREDICT is ISA 5 and bounded: an ISA-4 description naming it, a family the reader lacks, and a knob past the limit are
// refused.
TEST(a_predict_op_is_checked) {
    auto d = coding::BsaDescription(512); std::string err; coding::Description back;
    auto bytes = coding::Serialize(d); CHECK(coding::Parse(bytes.data(), bytes.size(), back, err));
    auto with = [&](auto edit) { auto e = d; edit(e); const auto b = coding::Serialize(e); coding::Description x; return coding::Parse(b.data(), b.size(), x, err); };
    size_t at = 0; for (; at < d.ops.size(); ++at) if (d.ops[at].op == coding::OP_PREDICT) break;
    CHECK(at < d.ops.size());
    CHECK(!with([](coding::Description &e) { e.isa = 4; }));
    CHECK(!with([&](coding::Description &e) { e.ops[at].nb = 2; }));
    CHECK(!with([&](coding::Description &e) { e.ops[at].imm = coding::kLz4hcMaxAttempts + 1; }));
    CHECK(!with([&](coding::Description &e) { e.ops[at].imm = 0; }));
    CHECK(with([&](coding::Description &e) { e.ops[at].imm = coding::kLz4hcMaxAttempts; }));
}

// Under a slow content read (a busy disk) and read-ahead far past the segment cache, readers on many threads still get
// every byte: a segment decoded for a reader is never evicted before it is taken, and one gone anyway is decoded again
// (Packagizer 2026-11-27: `coding verify` of a 1.8 GB BSA failed once with "read failed" under HDD load). Teeth: let
// await return when its segment is gone (EIO); evict a segment a reader waits for.
struct SlowSource : ByteSource {
    std::shared_ptr<ByteSource> In;
    explicit SlowSource(std::shared_ptr<ByteSource> S) : In(std::move(S)) {}
    ssize_t pread(void *b, size_t n, uint64_t o) override { std::this_thread::sleep_for(std::chrono::microseconds(300)); return In->pread(b, n, o); }
    uint64_t size() const override { return In->size(); }
};
TEST(a_coded_stream_reads_whole_under_slow_content_and_deep_read_ahead) {
    const auto in = sampleContent(3, 1500000, 21);
    std::vector<uint8_t> stream;                                          // stored deflate blocks of 8000 bytes
    std::vector<uint8_t> s2;
    for (size_t o = 0; o < in.size(); o += 8000) {
        const size_t n = std::min<size_t>(8000, in.size() - o);
        s2.push_back(o + n == in.size() ? 1 : 0);
        s2.push_back((uint8_t)n); s2.push_back((uint8_t)(n >> 8)); s2.push_back((uint8_t)~n); s2.push_back((uint8_t)(~n >> 8));
        s2.insert(s2.end(), in.begin() + (long)o, in.begin() + (long)(o + n));
    }
    stream = s2;
    const auto d = coding::DeflateDescription();
    std::vector<uint8_t> content, record; std::string err;
    CHECK(coding::Mint(d, stream.data(), stream.size(), in.size(), in.size(), 256, content, record, err));
    auto src = coding::CodedByteSource::Create(std::make_shared<MemByteSource>(coding::Serialize(d)), std::make_shared<MemByteSource>(record),
                                               std::make_shared<SlowSource>(std::make_shared<MemByteSource>(content)), stream.size(), err);
    CHECK(src != nullptr); if (!src) return;
    CHECK(src->checkpoints() > 60);                                          // far more segments than the cache keeps
    std::atomic<int> bad{0};
    std::vector<std::thread> T;
    for (int t = 0; t < 6; ++t)
        T.emplace_back([&, t] {
            std::vector<uint8_t> b(9000);
            for (uint64_t o = (uint64_t)t * 3000; o < stream.size(); o += b.size()) {
                const size_t n = (size_t)std::min<uint64_t>(b.size(), stream.size() - o);
                src->prefetch(o + n, 8u << 20);                              // read-ahead far past the cache
                if (!src->preadAll(b.data(), n, o) || memcmp(b.data(), stream.data() + o, n)) { ++bad; return; }
            }
        });
    for (auto &x : T) x.join();
    CHECK_EQ(bad.load(), 0);
}

// The two interleavings behind that failure, forced (Packagizer 2026-11-27): (1) a reader waiting on a segment a pool worker
// decodes wakes to find it gone — it decodes it again, never EIO; (2) a segment a reader waits for is never evicted,
// however many segments read-ahead decodes meanwhile. Teeth: return from await when the segment is gone; let eviction
// pick a waited-for segment.
struct GateSource : ByteSource {
    std::shared_ptr<ByteSource> In; uint64_t From = 0, To = 0;
    std::mutex M; std::condition_variable Cv; bool Open = true, Entered = false;
    ssize_t pread(void *b, size_t n, uint64_t o) override {
        if (o < To && o + n > From) {
            std::unique_lock<std::mutex> l(M);
            if (!Open) { Entered = true; Cv.notify_all(); Cv.wait(l, [this] { return Open; }); }
        }
        return In->pread(b, n, o);
    }
    uint64_t size() const override { return In->size(); }
};
TEST(a_reader_never_loses_the_segment_it_waits_for) {
    const auto in = sampleContent(0, 1000000, 22);
    const auto stream = rawDeflate(in, 6, 15, 8, Z_DEFAULT_STRATEGY);     // literals: decoding a segment reads the content
    const auto d = coding::DeflateDescription();
    std::vector<uint8_t> content, record; std::string err;
    CHECK(coding::Mint(d, stream.data(), stream.size(), in.size(), in.size(), 2048, content, record, err));
    auto gate = std::make_shared<GateSource>(); gate->In = std::make_shared<MemByteSource>(content);
    auto src = coding::CodedByteSource::Create(std::make_shared<MemByteSource>(coding::Serialize(d)), std::make_shared<MemByteSource>(record), gate, stream.size(), err);
    CHECK(src != nullptr); if (!src) return;
    CHECK(src->checkpoints() > 60);
    // (1) a worker decodes the segment at half the stream and blocks reading its content; a reader waits on it; it is dropped as the
    //     reader wakes: the reader must decode it again and get its bytes
    const uint64_t At = stream.size() / 2;
    gate->From = 0; gate->To = UINT64_MAX;                                 // every content read blocks while closed
    { std::lock_guard<std::mutex> l(gate->M); gate->Open = false; gate->Entered = false; }
    src->prefetch(At, 1);                                                 // a pool worker takes it
    { std::unique_lock<std::mutex> l(gate->M); gate->Cv.wait_for(l, std::chrono::seconds(10), [&] { return gate->Entered; }); }
    CHECK(gate->Entered);
    src->debugDropOnNextWake();
    std::vector<uint8_t> got(4096); bool ok = false;
    std::thread reader([&] { ok = src->preadAll(got.data(), got.size(), At); });
    std::this_thread::sleep_for(std::chrono::milliseconds(200));           // the reader is waiting on the worker now
    { std::lock_guard<std::mutex> l(gate->M); gate->Open = true; } gate->Cv.notify_all();
    reader.join();
    CHECK(ok);
    CHECK(memcmp(got.data(), stream.data() + At, got.size()) == 0);
    // (2) a segment held by a waiting reader survives read-ahead decoding far more segments than the cache keeps
    std::vector<uint8_t> one(1);
    CHECK(src->preadAll(one.data(), 1, 0));                               // segment 0 decoded
    src->debugHoldWaiter(0, true);
    std::vector<uint8_t> b(64 << 10);
    for (uint64_t o = stream.size() / 8; o < stream.size(); o += b.size()) {   // every later segment, read and decoded
        const size_t n = (size_t)std::min<uint64_t>(b.size(), stream.size() - o);
        src->prefetch(o + n, 1u << 20);
        CHECK(src->preadAll(b.data(), n, o));
    }
    CHECK(src->debugCached(0));
    src->debugHoldWaiter(0, false);
}

// ISA 4: a description using STREAMPOS is refused by a parser that claims an older instruction set.
// 22.16: a description is DATA in a node — readable text. A hand-written one runs; every built one reads back to what
// it was (the same text, the same records); the names an author gave survive a round trip; a node holding one reads as
// it; and text that is not a description is refused, saying where. Teeth: drop a name; misread a mode; accept a table
// by number; let labels repeat; let values nest without bound.
TEST(a_description_is_readable_text_in_a_node) {
    std::string err;
    const std::string copy = R"J({
  "NAME": "a file as it is",
  "ISA": 4,
  "CODER": "BITS",
  "REGISTERS": { "left": 1 },
  "ENTRY": "@start",
  "CODE": [
    "# every byte through, then the end",
    "@start",
    "decode: set left (shr (inleft) 3)",
    "code: set left (xleft)",
    "byterun left",
    "end"
  ]
})J";
    coding::Description d; coding::TextNames names;
    CHECK(coding::Read(copy, d, err, &names));
    if (!err.empty()) std::cerr << "  read: " << err << "\n";
    std::vector<uint8_t> shipped(5000); for (size_t i = 0; i < shipped.size(); ++i) shipped[i] = (uint8_t)(i * 31 + (i >> 4));
    std::vector<uint8_t> content, rec;
    CHECK(coding::Mint(d, shipped.data(), shipped.size(), 0, 1 << 16, 1024, content, rec, err));
    CHECK(content == shipped);
    CHECK(d.ops.size() == 4 && d.ops[0].modes == coding::kDecode && d.ops[1].modes == coding::kCode);
    std::string back; CHECK(coding::Print(d, back, err, &names));
    CHECK(back.find("\"left\": 1") != std::string::npos && back.find("byterun left") != std::string::npos && back.find("@start") != std::string::npos);
    coding::Description d2; CHECK(coding::Read(back, d2, err)); CHECK(coding::Serialize(d2) == coding::Serialize(d));
    // a node holding it
    const std::string node = std::string(R"J({"LABEL": "copy v1", "DESCRIPTION": )J") + copy + R"J(, "LAYERS": []})J";
    CHECK(coding::Read(node, d2, err)); CHECK(coding::Serialize(d2) == coding::Serialize(d));
    // ...but only a node is unwrapped: a description that merely holds a DESCRIPTION key is no description
    CHECK(!coding::Read(std::string(R"J({"DESCRIPTION": )J") + copy + R"J(, "junk": 1})J", d2, err));
    // every built description: printed, read, printed again is the same text, and mints the same record
    const auto sample = rawDeflate(sampleContent(5, 30000, 3), 6, 15, 8, Z_DEFAULT_STRATEGY);
    for (const coding::Description &b : {coding::DeflateDescription(), coding::DeflateDescription(6 | 8 << 8 | 15 << 16), coding::InnoDescription(),
                                         coding::Lz4BlockDescription(), coding::BsaDescription(), coding::BsaDescription(0),
                                         coding::LzmaDescription(3, 0, 2, 1u << 20, true)}) {
        const auto t1 = coding::Serialize(b); coding::Description r1;
        CHECK(!t1.empty() && coding::Parse(t1.data(), t1.size(), r1, err));
        CHECK(coding::Serialize(r1) == t1);
        if (b.name.rfind("deflate", 0) == 0) {
            std::vector<uint8_t> c1, q1, c2, q2;
            CHECK(coding::Mint(b, sample.data(), sample.size(), 0, 1 << 20, 4096, c1, q1, err));
            CHECK(coding::Mint(r1, sample.data(), sample.size(), 0, 1 << 20, 4096, c2, q2, err));
            CHECK(c1 == c2 && q1 == q2 && !q1.empty());
        }
    }
    // refused, and why
    const auto refuses = [&](const std::string &patch, const std::string &from, const std::string &to, const char *why) {
        std::string t = patch.empty() ? copy : patch; const size_t at = t.find(from);
        if (at == std::string::npos) { CHECK(!"the test's text moved"); return; }
        t.replace(at, from.size(), to); coding::Description x;
        const bool ok = coding::Read(t, x, err);
        CHECK(!ok); CHECK(err.find(why) != std::string::npos);
        if (ok || err.find(why) == std::string::npos) std::cerr << "  expected '" << why << "', got '" << err << "'\n";
    };
    refuses("", "\"ISA\": 4,", "\"ISA\": 4, \"COLOUR\": 1,", "unknown description field");
    refuses("", "\"byterun left\"", "\"bytesrun left\"", "no such instruction");
    refuses("", "\"byterun left\"", "\"byterun lft\"", "not a value");
    refuses("", "\"byterun left\"", "\"byterun left 3\"", "more than byterun takes");
    refuses("", "\"end\"", "\"jmp @nowhere\"", "no instruction at label @nowhere");
    refuses("", "\"end\"", "\"@start\", \"end\"", "label @start twice");
    refuses("", "\"decode: set", "\"decodes: set", "no such mode");
    refuses("", "\"ENTRY\": \"@start\"", "\"ENTRY\": \"@later\"", "no instruction at @later");
    refuses("", "\"left\": 1", "\"and\": 1", "not a register name");
    refuses("", "\"left\": 1", "\"left\": 64", "names no register");
    refuses("", "(shr (inleft) 3)", "(shr (inleft))", "an unexpected )");
    refuses("", "(shr (inleft) 3)", "(shr (inleft) 3 4)", "takes 2 values");
    refuses("", "(xleft)", "(table t0 0)", "no such table");
    std::string deep = "0"; for (int i = 0; i < 300; ++i) deep = "(add " + deep + " 1)";
    refuses("", "(xleft)", deep, "nested too deep");
    // ISA 6: integers as containers store them, read in place (the content so far: the bytes this run has made)
    const std::string ints = R"J({"NAME": "ints", "ISA": 6, "CODER": "BITS", "ENTRY": "@s", "CODE": ["@s", "byterun 8",
        "assert (eq (u32 0) 0x5D3E1F00)", "assert (eq (u16 2) 0x5D3E)", "assert (eq (u16be 1) 0x1F3E)", "assert (eq (u32be 0) 0x001F3E5D)",
        "decode: set r1 (shr (inleft) 3)", "code: set r1 (xleft)", "byterun r1", "end"]})J";
    err.clear(); CHECK(coding::Read(ints, d, err));
    if (!err.empty()) std::cerr << "  ints: " << err << "\n";
    CHECK(coding::Mint(d, shipped.data(), shipped.size(), 0, 1 << 16, 1024, content, rec, err));
    if (!err.empty()) std::cerr << "  ints mint: " << err << "\n";
    CHECK(content == shipped);
    refuses(ints, "\"ISA\": 6", "\"ISA\": 5", "newer than the instruction set");
    {   std::string wrong = ints; wrong.replace(wrong.find("(u16 2) 0x5D3E"), 14, "(u16 2) 0x5D3F");   // a wrong value: refused at mint
        coding::Description w; CHECK(coding::Read(wrong, w, err)); std::vector<uint8_t> c3, r3;
        CHECK(!coding::Mint(w, shipped.data(), shipped.size(), 0, 1 << 16, 1024, c3, r3, err)); }
    // a read across the place: DECODE has only the bytes before it (the rest read as 0), CODE the whole content
    // (shipped[6..9] = 186, 217, 248, 23: (u32 6) at place 8 reads 186, 217, then 0, 0 in DECODE)
    const std::string across = R"J({"NAME": "across", "ISA": 6, "CODER": "BITS", "ENTRY": "@s", "CODE": ["@s", "byterun 8",
        "decode: assert (eq (u32 6) 0xD9BA)", "code: assert (eq (u32 6) 0x17F8D9BA)",
        "decode: set r1 (shr (inleft) 3)", "code: set r1 (xleft)", "byterun r1", "end"]})J";
    err.clear(); CHECK(coding::Read(across, d, err));
    CHECK(coding::Mint(d, shipped.data(), shipped.size(), 0, 1 << 16, 1024, content, rec, err));
    if (!err.empty()) std::cerr << "  across: " << err << "\n";
    // arrays and tables are numbered by NAME: the text's key order changes nothing (a mount reads the description back
    // from its spec with sorted keys; records hold arrays by number). Teeth: number them in text order.
    {   const std::string a = R"J({"NAME": "x", "ISA": 4, "CODER": "BITS", "ARRAYS": {"zk": {"SIZE": 1, "INIT": [90]}, "ak": {"SIZE": 1, "INIT": [3]}},
            "TABLES": {"zt": [5], "at": [6]}, "ENTRY": "@s", "CODE": ["@s", "@loop", "mark", "decode: set r1 (shr (inleft) 3)", "code: set r1 (xleft)",
            "jz r1 @done", "raw 8 (xor (byte r0) (and (arr zk 0) 255)) r2", "outlit (xor r2 (and (arr zk 0) 255))",
            "sta zk 0 (add (arr zk 0) (table zt 0))", "sta ak 0 (add (arr ak 0) (table at 0))", "jmp @loop", "@done", "end"]})J";
        std::string b = a;
        b.replace(b.find(R"J("zk": {"SIZE": 1, "INIT": [90]}, "ak": {"SIZE": 1, "INIT": [3]})J"), 63, R"J("ak": {"SIZE": 1, "INIT": [3]}, "zk": {"SIZE": 1, "INIT": [90]})J");
        b.replace(b.find(R"J("zt": [5], "at": [6])J"), 20, R"J("at": [6], "zt": [5])J");
        coding::Description da, db; CHECK(coding::Read(a, da, err)); CHECK(coding::Read(b, db, err));
        CHECK(coding::Serialize(da) == coding::Serialize(db));
        std::vector<uint8_t> ca, ra; CHECK(coding::Mint(da, shipped.data(), 4096, 4096, 4096, 256, ca, ra, err, false));
        auto src = coding::CodedByteSource::Create(std::make_shared<MemByteSource>(coding::Serialize(db)), std::make_shared<MemByteSource>(ra),
                                                   std::make_shared<MemByteSource>(ca), 4096, err);
        std::vector<uint8_t> got(4096); CHECK(src && src->preadAll(got.data(), got.size(), 0));
        CHECK(std::equal(got.begin(), got.end(), shipped.begin()));
    }
    // a zlib family asked about 300 streams, the newest always first in the cache's order: the cache stays bounded and
    // never frees what it hands out (a use-after-free once). Teeth: evict the entry just made.
    {   const std::string many = R"J({"NAME": "zlib entries, lowest first", "ISA": 5, "CODER": "BITS", "ENTRY": "@s",
            "CODE": ["@s", "decode: set r1 (shr (inleft) 3)", "code: set r1 (xleft)", "byterun r1", "set r2 300", "@loop",
            "predict zlib 0xF0806 r10 r2 r2 r0", "jz r2 @done", "set r2 (sub r2 1)", "jmp @loop", "@done", "end"]})J";
        coding::Description dz; CHECK(coding::Read(many, dz, err));
        std::vector<uint8_t> cz, rz; coding::Mint(dz, shipped.data(), shipped.size(), 0, 1 << 16, 1024, cz, rz, err);
    }
    // tables, arrays and codes by name only (an object's keys may come back in another order)
    const std::string withTable = R"J({"NAME": "t", "ISA": 4, "CODER": "BITS", "TABLES": {"b": [7], "a": [9]}, "ENTRY": "@s",
        "CODE": ["@s", "set r1 (table a 0)", "assert (eq r1 9)", "end"]})J";
    CHECK(coding::Read(withTable, d, err));
    refuses(withTable, "(table a 0)", "(table 1 0)", "no such table");
}

// A zlib-family record of a stream with more tokens than a parse keeps behind it, read back through segments decoding
// in parallel (as a mount's read-ahead and an expansion do): every segment reads. Once one parse was shared by all of a
// stream's segments; dragged back and forth between them it re-parsed from the stream's start until refused, so the
// mint passed and the reader failed. Teeth: share one parser between machines again.
TEST(a_zlib_family_record_reads_through_parallel_segments) {
    std::vector<uint8_t> in(6u << 20); std::mt19937 r(5);
    for (size_t i = 0; i < in.size(); i += 4) { in[i] = 'a'; in[i + 1] = 'b'; in[i + 2] = 'c'; in[i + 3] = (uint8_t)r(); }
    const auto shipped = rawDeflate(in, 6, 15, 8, Z_DEFAULT_STRATEGY);
    const auto d = coding::DeflateDescription(6 | 8 << 8 | 15 << 16);
    std::vector<uint8_t> content, rec; std::string err;
    CHECK(coding::Mint(d, shipped.data(), shipped.size(), in.size(), in.size(), 512u << 10, content, rec, err));
    if (!err.empty()) std::cerr << "  mint: " << err << "\n";
    CHECK(content == in && rec.size() > 3 && rec[3] == 'Q');
    auto src = coding::CodedByteSource::Create(std::make_shared<MemByteSource>(coding::Serialize(d)), std::make_shared<MemByteSource>(rec),
                                               std::make_shared<MemByteSource>(content), shipped.size(), err);
    CHECK(src != nullptr);
    if (!src) return;
    CHECK(src->checkpoints() > 4);
    // from the back first (each segment restored on its own), then front to back with read-ahead
    std::vector<uint8_t> got(shipped.size());
    for (size_t k = src->checkpoints(); k-- > 0;) {
        const uint64_t a = shipped.size() * k / src->checkpoints(); const size_t n = (size_t)std::min<uint64_t>(4096, shipped.size() - a);
        CHECK(src->preadAll(got.data() + a, n, a));
    }
    CHECK(src->preadAll(got.data(), got.size(), 0));
    CHECK(got == shipped);
}

// ISA 7, for LZX (CAB) and its kin: the BITS16M coder (bits MSB-first from 16-bit little-endian words, counted from where
// the bits begin), RAWBYTES, a HUFFRUN bounded by a count (no end symbol), DIV and MOD, codes of up to 1024 symbols and
// 16 bits. Streams are written here by an independent LZX-style bit writer; each description decodes its stream, codes
// it back, and a reader restored at checkpoints (mid-word ones included) reads it back. Teeth: a word's bytes swapped;
// bits LSB-first; words counted from the stream's start; restores limited to 7 pending bits; the run's end symbol
// written when the count ran out; any ISA 7 piece let through under ISA 6; a division by zero let through.
TEST(the_bits16m_coder_reads_lzx_order) {
    struct W16 { std::vector<uint8_t> o; uint32_t acc = 0; int n = 0;
        void bits(uint32_t v, int k) { for (int i = k - 1; i >= 0; --i) { acc = (acc << 1) | ((v >> i) & 1); if (++n == 16) { o.push_back((uint8_t)acc); o.push_back((uint8_t)(acc >> 8)); acc = 0; n = 0; } } }
        void align(uint32_t fill = 0) { if (n) bits(fill ? 0xFFFF : 0, 16 - n); }
        void byte(uint8_t b) { o.push_back(b); } };
    std::string err;
    // mint, then read back through a reader restored at every checkpoint (segments of `spacing` shipped bytes)
    const auto roundTrip = [&](const coding::Description &d, const std::vector<uint8_t> &s, uint64_t spacing, std::vector<uint8_t> &content) {
        std::vector<uint8_t> rec; err.clear();
        if (!coding::Mint(d, s.data(), s.size(), 0, 1 << 16, spacing, content, rec, err)) { std::cerr << "  mint: " << err << "\n"; return false; }
        auto src = coding::CodedByteSource::Create(std::make_shared<MemByteSource>(coding::Serialize(d)), std::make_shared<MemByteSource>(rec),
                                                   std::make_shared<MemByteSource>(content), s.size(), err);
        if (!src) { std::cerr << "  reader: " << err << "\n"; return false; }
        std::vector<uint8_t> got(s.size());
        for (size_t k = src->checkpoints(); k-- > 0;) {                    // each segment alone, from the back
            const uint64_t at = s.size() * k / src->checkpoints(); if (!src->preadAll(got.data() + at, std::min<size_t>(3, s.size() - at), at)) return false; }
        if (!src->preadAll(got.data(), got.size(), 0) || got != s) { std::cerr << "  read back differs\n"; return false; }
        if (src->checkpoints() < 2) { std::cerr << "  only " << src->checkpoints() << " checkpoint(s)\n"; return false; }
        return true;
    };
    // canonical code for lengths 1,2,3,3: 0, 10, 110, 111
    const uint32_t code[4] = {0, 2, 6, 7}; const int clen[4] = {1, 2, 3, 3};
    const std::string text = R"J({"NAME": "lzx-ish", "ISA": 7, "CODER": "BITS16M", "ARRAYS": {"lens": {"SIZE": 4, "INIT": [1, 2, 3, 3]}},
      "HUFFS": ["h"], "REGISTERS": {"place": 0, "count": 1, "run": 2, "term": 3, "pad": 4, "q": 5, "padb": 6, "tail": 7, "i": 8, "c": 9, "z": 10}, "ENTRY": "@s",
      "CODE": ["@s", "build h lens 0 4", "raw free 16 count", "set i 0",
        "@lit", "mark", "jz (lt i count) @run", "huff h (byte place) c", "outlit c", "set i (add i 1)", "jmp @lit",
        "@run", "mark", "raw free 16 count",
        "huffrun h count run term 4 count",
        "decode: assert (eq term 0xFFFFFFFF)", "assert (eq run count)",
        "mark", "raw free (and (sub 16 (bitpos)) 15) pad",
        "rawbytes free 4 q", "assert (eq q 0x11223344)",
        "byterun 3",
        "rawbytes free 1 padb",
        "mark", "raw free 7 tail", "raw free (and (sub 16 (bitpos)) 15) z", "flush", "end"]})J";
    coding::Description d; CHECK(coding::Read(text, d, err));
    if (!err.empty()) std::cerr << "  read: " << err << "\n";
    // three streams: zero pads; ones pads; a run that ends on a word boundary (no pad bits at all)
    for (const auto &[pad, runLen] : std::vector<std::pair<uint32_t, int>>{{0, 700}, {1, 700}, {0, 0}}) {
        std::vector<uint8_t> lits, run; std::mt19937 r(3); for (int i = 0; i < 300; ++i) lits.push_back((uint8_t)(r() % 4));
        W16 w; w.bits((uint32_t)lits.size(), 16);
        for (uint8_t c : lits) w.bits(code[c], clen[c]);
        int n = runLen;
        if (!n) {                                                          // as many as make the run end word-aligned
            int bits = w.n + 16; std::mt19937 r2(4);
            while (true) { const uint8_t c = (uint8_t)(r2() % 4); run.push_back(c); bits += clen[c]; if (run.size() > 50 && bits % 16 == 0) break; }
            n = (int)run.size();
        } else { std::mt19937 r2(4); for (int i = 0; i < n; ++i) run.push_back((uint8_t)(r2() % 4)); }
        w.bits((uint32_t)n, 16); for (uint8_t c : run) w.bits(code[c], clen[c]);
        w.align(pad); for (uint8_t bt : {0x44, 0x33, 0x22, 0x11}) w.byte(bt);
        for (uint8_t bt : {'x', 'y', 'z'}) w.byte(bt);
        w.byte(0); w.bits(0x55, 7); w.align(pad);
        std::vector<uint8_t> content;
        const bool ok = roundTrip(d, w.o, 16, content); CHECK(ok);
        if (!ok) std::cerr << "  (stream: pad " << pad << ", run " << runLen << ")\n";
        std::vector<uint8_t> want = lits; want.insert(want.end(), run.begin(), run.end()); want.insert(want.end(), {'x', 'y', 'z'});
        CHECK(content == want);
    }
    std::string printed; CHECK(coding::Print(d, printed, err)); coding::Description back; CHECK(coding::Read(printed, back, err));
    CHECK(coding::Serialize(back) == coding::Serialize(d));
    // a bitstream that begins at an odd byte (a CAB's LZX data starts wherever its block does)
    {   W16 w2; for (uint8_t bt : {'h', 'd', 'r'}) w2.byte(bt);
        W16 bits2; bits2.bits(0xABC, 12); bits2.bits(0x5, 4); bits2.bits(0x1234, 16); bits2.align();
        w2.o.insert(w2.o.end(), bits2.o.begin(), bits2.o.end());
        const std::string t2 = R"J({"NAME": "odd start", "ISA": 7, "CODER": "BITS16M", "ENTRY": "@s", "CODE": ["@s", "byterun 3",
            "mark", "raw free 12 r1", "assert (eq r1 0xABC)", "mark", "raw free 4 r2", "assert (eq r2 5)", "raw free 16 r3", "assert (eq r3 0x1234)", "flush", "end"]})J";
        coding::Description d2; CHECK(coding::Read(t2, d2, err)); std::vector<uint8_t> c2;
        CHECK(roundTrip(d2, w2.o, 1, c2)); }
    // bytes in the middle of a word are refused (a description that lost its alignment pad)
    {   std::string t3 = text; t3.replace(t3.find("\"raw free (and (sub 16 (bitpos)) 15) pad\","), 42, "");
        coding::Description d3; CHECK(coding::Read(t3, d3, err));
        W16 w; w.bits(1, 16); w.bits(0, 1); w.bits(1, 16); w.bits(0, 1); w.align(); for (int k = 0; k < 8; ++k) w.byte(0x11);
        std::vector<uint8_t> c3, r3; CHECK(!coding::Mint(d3, w.o.data(), w.o.size(), 0, 4096, 1 << 20, c3, r3, err));
        CHECK(err.find("decode: bytes off a byte boundary") != std::string::npos); }
    // LZX's codes: up to 1024 symbols, lengths up to 16. A complete code of lengths 1..15, 16, 16 on symbols 640..656 of
    // a 700-symbol code: its symbols 656 (sixteen 1s) and 640 (one 0) read and written back
    {   W16 w3; w3.bits(0xFFFF, 16); w3.bits(0x0, 1); w3.align();
        std::string init; for (int k = 0; k < 640; ++k) init += "0, ";
        for (int l = 1; l <= 15; ++l) { init += std::to_string(l) + ", "; }
        init += "16, 16";
        const std::string t4 = std::string(R"J({"NAME": "long codes", "ISA": 7, "CODER": "BITS16M", "ARRAYS": {"lens": {"SIZE": 700, "INIT": [)J") + init +
            R"J(]}}, "HUFFS": ["g"], "ENTRY": "@s", "CODE": ["@s", "build g lens 0 700", "huff free g r1", "assert (eq r1 656)",
            "huff free g r2", "assert (eq r2 640)", "raw free (and (sub 16 (bitpos)) 15) r3", "flush", "end"]})J";
        coding::Description d4; err.clear(); CHECK(coding::Read(t4, d4, err)); std::vector<uint8_t> c4, r4;
        CHECK(coding::Mint(d4, w3.o.data(), w3.o.size(), 0, 64, 1 << 20, c4, r4, err));
        if (!err.empty()) std::cerr << "  long codes: " << err << "\n";
        // the same code under ISA 6 (with the BITS coder): refused, it is ISA 7's
        const std::string from4 = "\"ISA\": 7, \"CODER\": \"BITS16M\"";
        std::string t4b = t4; t4b.replace(t4b.find(from4), from4.size(), "\"ISA\": 6, \"CODER\": \"BITS\"");
        coding::Description d4b; CHECK(coding::Read(t4b, d4b, err));
        CHECK(!coding::Mint(d4b, w3.o.data(), w3.o.size(), 0, 64, 1 << 20, c4, r4, err)); }
    // a bound of 0 is a run of no literals (not "no bound": the next bits are not read as literals)
    {   W16 w5; w5.bits(0, 16);
        const std::string t5 = R"J({"NAME": "bound 0", "ISA": 7, "CODER": "BITS16M", "ARRAYS": {"lens": {"SIZE": 4, "INIT": [1, 2, 3, 3]}}, "HUFFS": ["h"],
            "ENTRY": "@s", "CODE": ["@s", "build h lens 0 4", "huffrun h 0 r2 r3 4 0", "assert (eq r2 0)", "raw free 16 r4", "flush", "end"]})J";
        coding::Description d5; CHECK(coding::Read(t5, d5, err)); std::vector<uint8_t> c5, r5;
        CHECK(coding::Mint(d5, w5.o.data(), w5.o.size(), 0, 64, 1 << 20, c5, r5, err)); CHECK(c5.empty()); }
    // each code limit of ISA 7 alone, on a valid LSB-first stream: more than 320 symbols; a 16-bit length
    for (const std::string &init : {std::string("1, 1"), std::string("1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 16")}) {
        const bool many = init == "1, 1"; const std::string size = many ? "321" : "17";
        for (const char *isa : {"6", "7"}) {
            const std::string t6 = std::string(R"J({"NAME": "limits", "ISA": )J") + isa + R"J(, "CODER": "BITS", "ARRAYS": {"lens": {"SIZE": )J" + size +
                R"J(, "INIT": [)J" + init + R"J(]}}, "HUFFS": ["h"], "ENTRY": "@s", "CODE": ["@s", "build h lens 0 )J" + size +
                R"J(", "huff free h r1", "raw free 7 r2", "end"]})J";
            coding::Description d6; CHECK(coding::Read(t6, d6, err)); const uint8_t one[1] = {0}; std::vector<uint8_t> c6, r6;
            const bool ok = coding::Mint(d6, one, 1, 0, 16, 1 << 20, c6, r6, err);
            CHECK(ok == (std::string(isa) == "7"));
            if (ok != (std::string(isa) == "7")) std::cerr << "  limits (" << (many ? "symbols" : "length") << ", ISA " << isa << "): " << err << "\n";
        }
    }
    // a division by zero refuses the run, a constant divisor and a register one alike
    for (const char *e : {"(div 100 r9)", "(mod 100 r9)", "(div r1 0)", "(mod r1 0)"}) {
        const std::string t5 = std::string(R"J({"NAME": "div", "ISA": 7, "CODER": "BITS", "ENTRY": "@s", "CODE": ["@s", "raw free 8 r1", "set r2 )J") + e + R"J(", "end"]})J";
        coding::Description d5; CHECK(coding::Read(t5, d5, err)); std::vector<uint8_t> c5, r5; const uint8_t one[1] = {7};
        CHECK(!coding::Mint(d5, one, 1, 0, 16, 1 << 20, c5, r5, err)); CHECK(err.find("division by zero") != std::string::npos); }
    // each of ISA 7's pieces under ISA 6: refused at read
    for (const char *piece : {"\"rawbytes free 1 r1\"", "\"set r1 (div 7 2)\"", "\"set r1 (mod 7 2)\"", "\"huffrun h 4 r1 r2 4 r3\""}) {
        const std::string t6 = std::string(R"J({"NAME": "old", "ISA": 6, "CODER": "BITS", "ARRAYS": {"lens": {"SIZE": 4, "INIT": [1, 2, 3, 3]}},
            "HUFFS": ["h"], "ENTRY": "@s", "CODE": ["@s", "build h lens 0 4", )J") + piece + R"J(, "end"]})J";
        coding::Description d6; CHECK(!coding::Read(t6, d6, err));
        std::string t7 = t6; t7.replace(t7.find("\"ISA\": 6"), 8, "\"ISA\": 7"); CHECK(coding::Read(t7, d6, err)); }
    {   coding::Description d8; CHECK(!coding::Read(R"J({"NAME": "c", "ISA": 6, "CODER": "BITS16M", "ENTRY": "@s", "CODE": ["@s", "end"]})J", d8, err)); }
    // RAWBYTES in the LSB-first coder: bytes at a byte boundary, little-endian
    {   const std::string lsb = R"J({"NAME": "lsb", "ISA": 7, "CODER": "BITS", "ENTRY": "@s", "CODE": ["@s", "raw free 8 r1",
            "rawbytes free 2 r2", "assert (eq r2 0xBEEF)", "raw free 3 r3", "flush", "end"]})J";
        coding::Description d9; CHECK(coding::Read(lsb, d9, err));
        const std::vector<uint8_t> s9 = {0x7A, 0xEF, 0xBE, 0x05}; std::vector<uint8_t> c9, r9;
        CHECK(coding::Mint(d9, s9.data(), s9.size(), 0, 64, 1 << 20, c9, r9, err)); }
}

// ISA 8: a translated view (LZX's E8). A toy LZ format: frame 0 stored, every later frame a COPY of the one before, all
// as the encoder saw them (translated, "W"); the content must be the real bytes ("C" = the E8 inverse, frame by frame,
// with each frame's own stream position), so copies read W while the content holds C. Checked against an inverse written
// here, coded back, and read back through a reader restored at each frame. Teeth: copies reading the real bytes; the
// content left translated; the code reading the content untranslated; checkpoints without the frame table; the last 10
// bytes or the 4 after an E8 translated.
TEST(an_e8_view_keeps_the_real_bytes_while_the_code_sees_the_encoders) {
    const uint32_t fs = 100000, F = 64, K = 6;
    std::vector<uint8_t> w0(F); std::mt19937 r(11); for (auto &x : w0) x = (uint8_t)(r() % 200);   // (no stray E8 bytes)
    auto put = [&](uint32_t at, int32_t v) { w0[at] = 0xE8; for (int k = 0; k < 4; ++k) w0[at + 1 + k] = (uint8_t)((uint32_t)v >> (8 * k)); };
    put(3, 70000); put(8, -10); put(20, 232); put(40, -300000); put(45, 777); put(56, 1234);   // in range, negative, an E8 in an operand, out of range, past the mid-frame checkpoint, the last 10 bytes
    std::vector<uint8_t> shipped = {(uint8_t)fs, (uint8_t)(fs >> 8), (uint8_t)(fs >> 16), (uint8_t)(fs >> 24)};
    shipped.insert(shipped.end(), w0.begin(), w0.end());
    for (uint32_t k = 1; k < K; ++k) shipped.push_back(1);                    // "the frame before, again"
    // the real bytes, by an inverse written here
    auto inverse = [&](std::vector<uint8_t> b, uint32_t cur) {
        for (uint32_t i = 0; i + 10 < b.size(); ++i) {
            if (b[i] != 0xE8) continue;
            const int64_t pos = cur + i; const int32_t a = (int32_t)(b[i + 1] | b[i + 2] << 8 | b[i + 3] << 16 | (uint32_t)b[i + 4] << 24);
            if (a >= -pos && a < (int64_t)fs) { const int32_t rel = a >= 0 ? (int32_t)(a - pos) : (int32_t)(a + (int64_t)fs); for (int k = 0; k < 4; ++k) b[i + 1 + k] = (uint8_t)((uint32_t)rel >> (8 * k)); }
            i += 4;
        }
        return b; };
    std::vector<uint8_t> want; for (uint32_t k = 0; k < K; ++k) { const auto c = inverse(w0, k * F); want.insert(want.end(), c.begin(), c.end()); }
    CHECK(want != std::vector<uint8_t>(want.size(), 0) && !std::equal(w0.begin(), w0.end(), want.begin()));   // (it does translate)
    // (a WINDOW of 4 frames: checkpoints carry several frames as a run, and the oldest leave; NEAREST looks across frames)
    const auto text = [&](const char *translated) { return std::string(R"J({"NAME": "e8 toy", "ISA": 8, "CODER": "BITS", "WINDOW": 256,
        "REGISTERS": {"place": 0, "fs": 1, "i": 2, "f": 3, "pd": 4},
        "ENTRY": "@s", "CODE": ["@s", "rawbytes free 4 fs", "set i 0",
          "@frame", "mark", "jz (lt i 6) @done", "e8frame place 64 (mul i 64) fs", "jz i @first",
          "raw free 8 f", "assert (eq f 1)", "mark", "nearest pd 64 0 256", "decode: assert (or (eq pd 0xFFFFFFFF) (eq pd 64))", "code: assert (eq pd 64)",
          "outcopy 64 64", "jmp @fe",
          "@first", "byterun 32", "mark", "byterun 32",
          "@fe", "e8end )J") + translated + R"J(", "set i (add i 1)", "jmp @frame",
          "@done", "end"]})J"; };
    std::string err; coding::Description d; CHECK(coding::Read(text("1"), d, err));
    if (!err.empty()) std::cerr << "  read: " << err << "\n";
    std::vector<uint8_t> content, rec;
    CHECK(coding::Mint(d, shipped.data(), shipped.size(), 0, 4096, 1, content, rec, err));
    if (!err.empty()) std::cerr << "  mint: " << err << "\n";
    CHECK(content == want);
    auto src = coding::CodedByteSource::Create(std::make_shared<MemByteSource>(coding::Serialize(d)), std::make_shared<MemByteSource>(rec),
                                               std::make_shared<MemByteSource>(content), shipped.size(), err);
    CHECK(src != nullptr);
    if (src) {
        CHECK(src->checkpoints() >= K);
        std::vector<uint8_t> got(shipped.size());
        for (size_t k = src->checkpoints(); k-- > 0;) {                      // each frame's segment alone, from the back
            const uint64_t at = shipped.size() * k / src->checkpoints(); CHECK(src->preadAll(got.data() + at, std::min<size_t>(5, shipped.size() - at), at)); }
        CHECK(src->preadAll(got.data(), got.size(), 0)); CHECK(got == shipped);
    }
    // frames left untranslated: the content is what the stream holds
    coding::Description d0; CHECK(coding::Read(text("0"), d0, err)); std::vector<uint8_t> c0, r0;
    CHECK(coding::Mint(d0, shipped.data(), shipped.size(), 0, 4096, 1, c0, r0, err));
    std::vector<uint8_t> plain; for (uint32_t k = 0; k < K; ++k) plain.insert(plain.end(), w0.begin(), w0.end());
    CHECK(c0 == plain);
    // under ISA 7: refused at read
    std::string t7 = text("1"); t7.replace(t7.find("\"ISA\": 8"), 8, "\"ISA\": 7"); CHECK(!coding::Read(t7, d0, err));
    // what is refused: frames out of order, overlapping, past the content, of no size or over 1 MiB, an end without a
    // frame, a frame never ended, a filesize past 2^31, NEAREST reaching past the WINDOW, a family through a view
    for (const char *body : {"\"e8frame 32 16 0 fs\", \"e8end 1\", \"e8frame 0 16 0 fs\", \"e8end 1\"",
                             "\"e8frame 0 32 0 fs\", \"e8frame 16 16 0 fs\", \"e8end 1\"",
                             "\"e8frame 60 100 0 fs\", \"e8end 1\"", "\"e8frame 0 0 0 fs\", \"e8end 1\"", "\"e8frame 0 2000000 0 fs\", \"e8end 1\"",
                             "\"e8end 1\"", "\"e8frame 0 16 0 fs\"", "\"set fs 0x80000000\", \"e8frame 0 16 0 fs\", \"e8end 1\"",
                             "\"nearest r5 4 0 300\""}) {
        const std::string th = std::string(R"J({"NAME": "hostile", "ISA": 8, "CODER": "BITS", "WINDOW": 256, "REGISTERS": {"place": 0, "fs": 1},
            "ENTRY": "@s", "CODE": ["@s", "rawbytes free 4 fs", "byterun 64", "set place 0", )J") + body + R"J(, "end"]})J";
        coding::Description dh; CHECK(coding::Read(th, dh, err)); std::vector<uint8_t> ch, rh;
        std::vector<uint8_t> sh = {(uint8_t)fs, (uint8_t)(fs >> 8), (uint8_t)(fs >> 16), 0}; sh.insert(sh.end(), w0.begin(), w0.end());
        const bool ok = coding::Mint(dh, sh.data(), sh.size(), 0, 64, 1 << 20, ch, rh, err);
        CHECK(!ok); if (ok) std::cerr << "  not refused: " << body << "\n"; }
    {   coding::Description dp;
        CHECK(!coding::Read(R"J({"NAME": "fam", "ISA": 8, "CODER": "BITS", "REGISTERS": {"fs": 1}, "ENTRY": "@s", "CODE": ["@s",
            "predict zlib 0x0F0806 r10 0 0 1", "e8frame 0 16 0 fs", "e8end 1", "end"]})J", dp, err)); }
    // a WINDOW over 32 MiB with E8 frames or NEAREST: refused at read (NEAREST's index and the frame table are sized by it)
    {   coding::Description dw;
        CHECK(!coding::Read(R"J({"NAME": "huge", "ISA": 8, "CODER": "BITS", "WINDOW": 4294967295, "ENTRY": "@s", "CODE": ["@s",
            "nearest r5 3 0 4294967280", "end"]})J", dw, err)); }
    // a frame read just after a newer frame's registration dropped it from the window (WINDOW 0): read as it is, never
    // from a translation the drop freed (ASan: a use-after-free once)
    {   const std::string tu = R"J({"NAME": "dropped", "ISA": 8, "CODER": "BITS", "REGISTERS": {"place": 0, "fs": 1, "x": 2},
            "ENTRY": "@s", "CODE": ["@s", "rawbytes free 4 fs", "e8frame place 32 0 fs", "byterun 32", "e8end 1",
            "e8frame place 32 32 fs", "set x (byte 7)", "byterun 32", "e8end 1", "end"]})J";
        coding::Description du; CHECK(coding::Read(tu, du, err)); std::vector<uint8_t> cu, ru;
        std::vector<uint8_t> su = {(uint8_t)fs, (uint8_t)(fs >> 8), (uint8_t)(fs >> 16), 0}; su.insert(su.end(), w0.begin(), w0.end());
        coding::Mint(du, su.data(), su.size(), 0, 64, 1, cu, ru, err); }
    // BITS16M (LZX's coder): a stored block of an ODD length inside a translated frame, then its pad byte — the encoder's
    // bytes go out as they are, never packed into words (the AoK 1999 cab's last block)
    {   std::vector<uint8_t> w(33); for (size_t k = 0; k < w.size(); ++k) w[k] = (uint8_t)(k * 7 % 200);
        w[4] = 0xE8; w[5] = 0x10; w[6] = 0x27; w[7] = 0; w[8] = 0;              // a call to 10000: in range
        std::vector<uint8_t> s2 = {(uint8_t)fs, (uint8_t)(fs >> 8), (uint8_t)(fs >> 16), (uint8_t)(fs >> 24)};
        s2.insert(s2.end(), w.begin(), w.end()); s2.push_back(0);
        const std::string t2 = R"J({"NAME": "odd stored block", "ISA": 8, "CODER": "BITS16M", "REGISTERS": {"place": 0, "fs": 1, "pad": 2},
            "ENTRY": "@s", "CODE": ["@s", "rawbytes free 4 fs", "e8frame place 33 0 fs", "byterun 33", "rawbytes free 1 pad", "e8end 1", "end"]})J";
        coding::Description d2; err.clear(); CHECK(coding::Read(t2, d2, err)); std::vector<uint8_t> c2, r2;
        CHECK(coding::Mint(d2, s2.data(), s2.size(), 0, 64, 1 << 20, c2, r2, err));
        if (!err.empty()) std::cerr << "  odd stored: " << err << "\n";
        CHECK(c2 == inverse(w, 0) && c2 != w); }
}

// ISA 8's NEAREST: an LZ format storing every copy's distance explicitly, its encoder taking the nearest distance that
// reaches the length (as match finders hand them out) except now and then. The description stores a flag where NEAREST
// says the same, the distance where not: the predicted record is far smaller than the plain one, the content right, and
// a reader restored at every token reads it back. Teeth: NEAREST answering a farther distance, a shorter match, or a
// distance from before the stream; the predicted record no smaller than the plain one.
TEST(nearest_predicts_an_lz_formats_distances) {
    std::mt19937 r(21); std::vector<uint8_t> content, shipped = {0, 0};
    struct T { bool copy; uint8_t lit; uint32_t len, dist; }; std::vector<T> toks;
    auto naive = [&](size_t at, uint32_t len) -> uint32_t {               // the nearest d whose copy reproduces len bytes
        for (uint32_t d = 1; d <= at && d <= 65535; ++d) { uint32_t k = 0; while (k < len && content[at - d + k] == content[at + k]) ++k; if (k == len) return d; }
        return 0; };
    // literals, and copies of earlier stretches (the encoder knows the content it is about to write)
    while (content.size() < 20000) {
        if (content.size() < 64 || r() % 3 == 0) { const uint8_t c = (uint8_t)(r() % 64); content.push_back(c); toks.push_back({false, c, 0, 0}); continue; }
        const uint32_t len = 3 + r() % 30, from = (uint32_t)(r() % (content.size() - 1)); const uint32_t dist = (uint32_t)content.size() - from;
        for (uint32_t k = 0; k < len; ++k) content.push_back(content[content.size() - dist]);
        const uint32_t nd = naive(content.size() - len, len);
        const bool farther = r() % 10 == 0 && nd != dist;                  // now and then the encoder does not take the nearest
        toks.push_back({true, 0, len, farther ? dist : nd});
    }
    for (const T &t : toks) {
        if (!t.copy) { shipped.push_back(0); shipped.push_back(t.lit); }
        else { shipped.push_back(1); shipped.push_back((uint8_t)t.len); shipped.push_back((uint8_t)t.dist); shipped.push_back((uint8_t)(t.dist >> 8)); } }
    shipped[0] = (uint8_t)toks.size(); shipped[1] = (uint8_t)(toks.size() >> 8);
    const std::string text = R"J({"NAME": "lz with explicit distances", "ISA": 8, "CODER": "BITS", "WINDOW": 65536,
      "REGISTERS": {"place": 0, "cnt": 1, "i": 2, "k": 3, "c": 4, "len": 5, "pd": 6, "dist": 7, "f": 8}, "ENTRY": "@s",
      "CODE": ["@s", "raw free 16 cnt", "set i 0",
        "@t", "mark", "jz (lt i cnt) @end", "set i (add i 1)", "raw free 8 k", "jz k @lit",
        "raw free 8 len", "nearest pd len 0 65535",
        "decode: raw 16 0 dist", "decode: set f (ne dist pd)", "dec f", "jz f @pred", "dec dist", "jmp @emit",
        "@pred", "code: set dist pd",
        "@emit", "code: raw 16 dist dist", "outcopy len dist", "jmp @t",
        "@lit", "raw 8 (byte place) c", "outlit c", "jmp @t",
        "@end", "end"]})J";
    std::string err; coding::Description d; CHECK(coding::Read(text, d, err));
    if (!err.empty()) std::cerr << "  read: " << err << "\n";
    std::vector<uint8_t> c1, rq, c2, rp;
    CHECK(coding::Mint(d, shipped.data(), shipped.size(), 0, 1 << 16, 64, c1, rq, err));
    if (!err.empty()) std::cerr << "  mint: " << err << "\n";
    CHECK(coding::Mint(d, shipped.data(), shipped.size(), 0, 1 << 16, 64, c2, rp, err, false));
    CHECK(c1 == content && c2 == content);
    CHECK(rq.size() > 3 && rq[3] == 'Q' && rp[3] == 'R');
    CHECK(rq.size() * 10 < rp.size() * 9);                                // the distances, mostly flags now (a token's other
    if (rq.size() * 10 >= rp.size() * 9) std::cerr << "  predicted " << rq.size() << " vs plain " << rp.size() << "\n";
    auto src = coding::CodedByteSource::Create(std::make_shared<MemByteSource>(coding::Serialize(d)), std::make_shared<MemByteSource>(rq),
                                               std::make_shared<MemByteSource>(c1), shipped.size(), err);
    CHECK(src != nullptr);
    if (src) {
        std::vector<uint8_t> got(shipped.size());
        for (size_t k = src->checkpoints(); k-- > 0;) { const uint64_t at = shipped.size() * k / src->checkpoints(); CHECK(src->preadAll(got.data() + at, std::min<size_t>(4, shipped.size() - at), at)); }
        CHECK(src->preadAll(got.data(), got.size(), 0)); CHECK(got == shipped);
    }
    std::string t7 = text; t7.replace(t7.find("\"ISA\": 8"), 8, "\"ISA\": 7"); CHECK(!coding::Read(t7, d, err));
    // exactly what it answers: an encoder that ALWAYS takes the nearest (within 300 bytes, else a farther one), and a
    // description asserting, when NEAREST answers, that it is the encoder's distance and within the bound
    {   std::vector<uint8_t> s2 = {0, 0}; size_t n2 = 0;
        for (const T &t : toks) {
            const size_t at = [&] { size_t a = 0; for (size_t q = 0; q < (size_t)(&t - &toks[0]); ++q) a += toks[q].copy ? toks[q].len : 1; return a; }();
            if (!t.copy) { s2.push_back(0); s2.push_back(t.lit); ++n2; continue; }
            const uint32_t nd = naive(at, t.len);
            s2.push_back(1); s2.push_back((uint8_t)t.len); s2.push_back((uint8_t)nd); s2.push_back((uint8_t)(nd >> 8)); ++n2;
            if (n2 > 400) break; }
        s2[0] = (uint8_t)n2; s2[1] = (uint8_t)(n2 >> 8);
        std::string t2 = text;
        t2.replace(t2.find("\"nearest pd len 0 65535\""), 24, "\"nearest pd len 0 300\", \"decode: assert (or (eq pd 0xFFFFFFFF) (ge 300 pd))\"");
        t2.replace(t2.find("\"decode: set f (ne dist pd)\""), 28,
                   "\"decode: assert (or (eq pd 0xFFFFFFFF) (eq dist pd))\", \"decode: set f (ne dist pd)\"");
        coding::Description d2; err.clear(); CHECK(coding::Read(t2, d2, err)); std::vector<uint8_t> c3, r3;
        CHECK(coding::Mint(d2, s2.data(), s2.size(), 0, 1 << 16, 64, c3, r3, err));
        if (!err.empty()) std::cerr << "  exact nearest: " << err << "\n"; }
}

namespace lzxcab {
// The cabinet MAKECAB 1.00 made of two generated files (LZX 21, FolderSizeThreshold=0: a folder each, setID 0x6BF), rebuilt
// here through the family's compressor: its FNV-64 is that of MAKECAB's own (Wine, sandboxed, 2026-11-27).
constexpr uint64_t kMakecabFnv = 0x6e3133c0867753f2ull;
std::vector<std::vector<uint8_t>> files() {
    uint64_t s = 7; auto next = [&] { s = (s * 1103515245ull + 12345) & 0x7FFFFFFF; return (uint32_t)s; };
    std::vector<uint8_t> f0;
    auto le = [&](int32_t v) { for (int k = 0; k < 4; ++k) f0.push_back((uint8_t)((uint32_t)v >> (8 * k))); };
    while (f0.size() < 40000) {
        const uint32_t r = next();
        switch (r % 5) {
        case 0: f0.insert(f0.end(), {0x55, 0x8B, 0xEC, 0xE8}); le((int32_t)((r >> 8) % 6000) - 3000); f0.insert(f0.end(), {0x83, 0xC4, 0x04}); break;
        case 1: { const int32_t back = -(int32_t)(f0.size() % 4096); f0.push_back(0xE8); le(back); f0.insert(f0.end(), {0x5D, 0xC3}); break; }
        case 2: { const std::string t = "mov eax, [ebp+" + std::to_string((r >> 4) % 64) + "]\n"; f0.insert(f0.end(), t.begin(), t.end()); break; }
        case 3: for (int sh : {3, 7, 11, 15}) f0.push_back((uint8_t)(r >> sh)); break;
        default: f0.insert(f0.end(), (r >> 5) % 9 + 1, 0x90);
        }
    }
    f0.resize(40000);
    static const char *W[] = {"the", "of", "and", "to", "in", "is", "was", "for", "on", "that", "with", "as", "by", "at", "from",
                              "his", "her", "an", "which", "or", "were", "are", "be", "this"};
    std::string f1;
    for (int i = 0; i < 1100; ++i) { if (i) f1 += ' '; f1 += W[next() % 24]; }
    if (f1.size() > 6000) f1.resize(6000);
    return {f0, std::vector<uint8_t>(f1.begin(), f1.end())};
}
uint32_t checksum(const uint8_t *p, size_t n, uint32_t c) {
    for (size_t k = 0; k + 4 <= n; k += 4) c ^= (uint32_t)p[k] | (uint32_t)p[k + 1] << 8 | (uint32_t)p[k + 2] << 16 | (uint32_t)p[k + 3] << 24;
    uint32_t u = 0; const uint8_t *t = p + (n & ~(size_t)3);
    switch (n & 3) { case 3: u |= (uint32_t)*t++ << 16; [[fallthrough]]; case 2: u |= (uint32_t)*t++ << 8; [[fallthrough]]; case 1: u |= *t; }
    return c ^ u;
}
// the cabinet: file i in folder of[i] (consecutive; none given: a folder each), folder j compressed with E8 file size e8[j]
// (MAKECAB: always 12,000,000), window 2^wbits, second partition `second`
std::vector<uint8_t> make(const std::vector<std::vector<uint8_t>> &fs, const std::vector<uint32_t> &e8, std::vector<uint64_t> *steps = nullptr,
                          uint32_t second = 0x10000, uint32_t wbits = 21, std::vector<size_t> of = {}, uint16_t setid = 0x6BF,
                          std::vector<uint32_t> wb = {}) {
    const char *names[] = {"code.bin", "words.txt", "more.bin"};
    if (of.empty()) for (size_t i = 0; i < fs.size(); ++i) of.push_back(i);
    const size_t nf = of.back() + 1;
    if (wb.empty()) wb.assign(nf, wbits);   // (a folder of another window: a context of its own, as MAKECAB makes it)
    std::vector<std::vector<uint8_t>> in(nf); std::vector<uint32_t> uoff(fs.size());
    for (size_t i = 0; i < fs.size(); ++i) { uoff[i] = (uint32_t)in[of[i]].size(); in[of[i]].insert(in[of[i]].end(), fs[i].begin(), fs[i].end()); }
    std::vector<std::vector<std::vector<uint8_t>>> frames(nf); std::vector<std::vector<uint32_t>> unc(nf);
    LzxMakecab *m = LzxMakecabNew(wb[0], second); if (!m) return {};
    struct A { std::vector<std::vector<uint8_t>> *f; std::vector<uint32_t> *u; };
    auto sink = [](void *a, const uint8_t *p, uint32_t n, uint32_t un) { auto *x = (A *)a; x->f->emplace_back(p, p + n); x->u->push_back(un); return 0; };
    for (size_t i = 0; i < nf; ++i) {
        if (i && wb[i] != wb[i - 1]) { if (LzxMakecabNextFolderWindow(m, wb[i], second) != LZXMK_OK) { LzxMakecabFree(m); return {}; } }
        else if (i && LzxMakecabNextFolder(m) != LZXMK_OK) { LzxMakecabFree(m); return {}; }
        A a{&frames[i], &unc[i]};
        for (size_t o = 0; o < in[i].size(); o += 32768)
            if (LzxMakecabCompress(m, in[i].data() + o, (uint32_t)std::min<size_t>(32768, in[i].size() - o), e8[i], 1, sink, &a) != LZXMK_OK) { LzxMakecabFree(m); return {}; }
        if (LzxMakecabFlush(m, sink, &a) != LZXMK_OK) { LzxMakecabFree(m); return {}; }
        if (steps) steps->push_back(LzxMakecabSteps(m));   // (the match finder's work so far)
    }
    LzxMakecabFree(m);
    std::vector<uint8_t> o;
    auto u16 = [&](uint32_t v) { o.push_back((uint8_t)v); o.push_back((uint8_t)(v >> 8)); };
    auto u32 = [&](uint32_t v) { u16(v & 0xFFFF); u16(v >> 16); };
    const uint32_t coffFiles = 36 + 8 * (uint32_t)nf;
    uint32_t at = coffFiles; for (size_t i = 0; i < fs.size(); ++i) at += 17 + (uint32_t)strlen(names[i]);
    o.insert(o.end(), {'M', 'S', 'C', 'F'}); u32(0); u32(0); u32(0); u32(coffFiles); u32(0); o.push_back(3); o.push_back(1);
    u16((uint32_t)nf); u16((uint32_t)fs.size()); u16(0); u16(setid); u16(0);
    for (size_t i = 0; i < nf; ++i) {
        u32(at); u16((uint32_t)frames[i].size()); u16(0x0003 | wb[i] << 8);
        for (const auto &f : frames[i]) at += 8 + (uint32_t)f.size();
    }
    for (size_t i = 0; i < fs.size(); ++i) { u32((uint32_t)fs[i].size()); u32(uoff[i]); u16((uint32_t)of[i]); u16(0x5D7B); u16(0x9F4B); u16(0x20);
        o.insert(o.end(), names[i], names[i] + strlen(names[i]) + 1); }
    for (size_t i = 0; i < nf; ++i)
        for (size_t k = 0; k < frames[i].size(); ++k) {
            const auto &f = frames[i][k]; uint8_t h[4] = {(uint8_t)f.size(), (uint8_t)(f.size() >> 8), (uint8_t)unc[i][k], (uint8_t)(unc[i][k] >> 8)};
            u32(checksum(h, 4, checksum(f.data(), f.size(), 0))); o.insert(o.end(), h, h + 4); o.insert(o.end(), f.begin(), f.end());
        }
    o[8] = (uint8_t)o.size(); o[9] = (uint8_t)(o.size() >> 8); o[10] = (uint8_t)(o.size() >> 16); o[11] = (uint8_t)(o.size() >> 24);
    return o;
}
uint64_t fnv(const std::vector<uint8_t> &b) { uint64_t h = 1469598103934665603ull; for (uint8_t x : b) { h ^= x; h *= 1099511628211ull; } return h; }
std::string description() { std::ifstream f(VGFS_TEST_DATA "/cab_lzx_family.json"); return std::string(std::istreambuf_iterator<char>(f), {}); }
uint64_t decisions(const std::vector<uint8_t> &rec) {            // the record's header: magic, shipped size, decisions
    size_t at = 4; uint64_t v = 0;
    for (int f = 0; f < 2; ++f) { v = 0; for (int sh = 0; at < rec.size(); sh += 7) { const uint8_t b = rec[at++]; v |= (uint64_t)(b & 0x7F) << sh; if (!(b & 0x80)) break; } }
    return v; }
}  // namespace lzxcab

TEST(the_lzx_family_makes_makecabs_folders) {
    const auto fs = lzxcab::files();
    std::vector<uint64_t> steps; const auto cab = lzxcab::make(fs, {12000000, 12000000}, &steps);
    CHECK_EQ(steps.size(), (size_t)2);
    CHECK(steps.size() == 2 && steps[0] == 748420 && steps[1] == 812898);   // the match finder's work, pinned (its bound counts it)
    CHECK_EQ(cab.size(), (size_t)12253);
    CHECK_EQ(lzxcab::fnv(cab), lzxcab::kMakecabFnv);                    // the compressor IS MAKECAB's, byte for byte
    const std::string text = lzxcab::description();
    coding::Description d; std::string err; CHECK(coding::Read(text, d, err));
    if (!err.empty()) std::cerr << "  read: " << err << "\n";
    std::vector<uint8_t> c1, rq, c2, rp;
    CHECK(coding::Mint(d, cab.data(), cab.size(), 0, 1 << 20, 2048, c1, rq, err));
    if (!err.empty()) std::cerr << "  mint: " << err << "\n";
    CHECK(coding::Mint(d, cab.data(), cab.size(), 0, 1 << 20, 2048, c2, rp, err, false));
    // the content: the header and file table as they are, then each folder's real bytes (the installed files)
    CHECK_EQ(c1.size(), (size_t)(103 + 40000 + 4209)); CHECK(c1 == c2);
    CHECK(c1.size() == 44312 && std::equal(fs[0].begin(), fs[0].end(), c1.begin() + 103) && std::equal(fs[1].begin(), fs[1].end(), c1.begin() + 40103));
    // the family's record: a decision per folder (it is the family's) and each block's checksum, nothing else
    CHECK(rq.size() > 3 && rq[3] == 'Q' && rp.size() > 3 && rp[3] == 'R');
    CHECK_EQ(lzxcab::decisions(rq), (uint64_t)5);
    CHECK(rq.size() < 400 && rp.size() > 8000);
    if (rq.size() >= 400) std::cerr << "  predicted " << rq.size() << " vs plain " << rp.size() << "\n";
    // read back segment by segment, each from a reader that has nothing yet (restored inside a folder the family makes)
    for (int pass = 0; pass < 2; ++pass) {
        auto src = coding::CodedByteSource::Create(std::make_shared<MemByteSource>(coding::Serialize(d)), std::make_shared<MemByteSource>(rq),
                                                   std::make_shared<MemByteSource>(c1), cab.size(), err);
        CHECK(src != nullptr); if (!src) break;
        CHECK(src->checkpoints() >= 3);
        std::vector<uint8_t> got(cab.size());
        if (pass == 0) CHECK(src->preadAll(got.data(), got.size(), 0));
        else for (size_t k = src->checkpoints(); k-- > 0;) {
            auto one = coding::CodedByteSource::Create(std::make_shared<MemByteSource>(coding::Serialize(d)), std::make_shared<MemByteSource>(rq),
                                                       std::make_shared<MemByteSource>(c1), cab.size(), err);
            const uint64_t at = cab.size() * (2 * k + 1) / (2 * src->checkpoints());
            const size_t n = (size_t)std::min<uint64_t>(700, cab.size() - at);
            CHECK(one && one->preadAll(got.data() + at, n, at));
            CHECK(std::equal(got.begin() + (long)at, got.begin() + (long)(at + n), cab.begin() + (long)at)); }
        if (pass == 0) CHECK(got == cab);
    }
    // a checkpoint naming a folder the content cannot hold (a peer's record): refused, never a folder-sized allocation
    {   auto put = [](std::vector<uint8_t> &o, uint64_t x) { while (x >= 0x80) { o.push_back((uint8_t)(x | 0x80)); x >>= 7; } o.push_back((uint8_t)x); };
        struct Rv { const std::vector<uint8_t> &p; size_t at = 0;
                    uint64_t var() { uint64_t x = 0; for (int sh = 0; at < p.size(); sh += 7) { const uint8_t b = p[at++]; x |= (uint64_t)(b & 0x7F) << sh; if (!(b & 0x80)) break; } return x; } };
        Rv r{rq}; r.at = 4; const uint64_t N = r.var(), total = r.var(), nck = r.var();
        struct Ck { uint64_t out, dec, len, hash; }; std::vector<Ck> cks;
        for (uint64_t k = 0; k < nck; ++k) { Ck c; c.out = r.var(); c.dec = r.var(); c.len = r.var(); c.hash = r.var(); cks.push_back(c); }
        std::vector<std::vector<uint8_t>> pay; size_t at = r.at;
        for (const auto &c : cks) { pay.emplace_back(rq.begin() + (long)at, rq.begin() + (long)(at + c.len)); at += c.len; }
        auto tail = [&](uint64_t a, uint64_t n) { std::vector<uint8_t> t; put(t, 1); put(t, a); put(t, n); put(t, 12000000); put(t, 533); put(t, 1); put(t, 1); return t; };
        const auto honest = tail(103, 40000);
        int target = -1; std::vector<uint8_t> raw; uint64_t sn = 0; size_t s0 = 0;
        for (size_t k = 0; k < pay.size() && target < 0; ++k) {             // the checkpoint inside folder 0
            raw.assign((size_t)ZSTD_getFrameContentSize(pay[k].data(), pay[k].size()), 0);
            raw.resize(ZSTD_decompress(raw.data(), raw.size(), pay[k].data(), pay[k].size()));
            Rv q{raw}; sn = q.var(); s0 = q.at;
            if (sn >= honest.size() && memcmp(raw.data() + s0 + sn - honest.size(), honest.data(), honest.size()) == 0) target = (int)k; }
        CHECK(target > 0);
        const std::pair<uint64_t, uint64_t> cases[] = {{103, 40000}, {1ull << 63, (1ull << 63) + 5}, {103, (1ull << 40) + 5}, {0xFFFFFFFFull, 2}, {103, 0xFFFFFFFFull}};
        for (const auto &[ca, cn] : cases) {
            if (target <= 0) break;
            std::vector<uint8_t> snap(raw.begin() + (long)s0, raw.begin() + (long)(s0 + sn - honest.size())); const auto t = tail(ca, cn); snap.insert(snap.end(), t.begin(), t.end());
            std::vector<uint8_t> nr; put(nr, snap.size()); nr.insert(nr.end(), snap.begin(), snap.end()); nr.insert(nr.end(), raw.begin() + (long)(s0 + sn), raw.end());
            std::vector<uint8_t> z(ZSTD_compressBound(nr.size())); z.resize(ZSTD_compress(z.data(), z.size(), nr.data(), nr.size(), 3));
            auto pp = pay; auto cc = cks; pp[(size_t)target] = z; cc[(size_t)target].len = z.size();
            std::vector<uint8_t> rec = {'V', 'G', 'C', 'Q'}; put(rec, N); put(rec, total); put(rec, nck);
            for (const auto &c : cc) { put(rec, c.out); put(rec, c.dec); put(rec, c.len); put(rec, c.hash); }
            for (const auto &q : pp) rec.insert(rec.end(), q.begin(), q.end());
            auto src = coding::CodedByteSource::Create(std::make_shared<MemByteSource>(coding::Serialize(d)), std::make_shared<MemByteSource>(rec),
                                                       std::make_shared<MemByteSource>(c1), cab.size(), err);
            CHECK(src != nullptr); if (!src) continue;
            std::vector<uint8_t> got(700);
            CHECK_EQ(src->preadAll(got.data(), got.size(), cks[(size_t)target].out + 10), ca == 103 && cn == 40000); }
        //the same record as a PLAIN one (no segment hashes): a plain record never takes the family's frames
        std::vector<uint8_t> plain = {'V', 'G', 'C', 'R'}; put(plain, N); put(plain, total); put(plain, nck);
        for (const auto &c : cks) { put(plain, c.out); put(plain, c.dec); put(plain, c.len); }
        for (const auto &q : pay) plain.insert(plain.end(), q.begin(), q.end());
        auto ps = coding::CodedByteSource::Create(std::make_shared<MemByteSource>(coding::Serialize(d)), std::make_shared<MemByteSource>(plain),
                                                  std::make_shared<MemByteSource>(c1), cab.size(), err);
        CHECK(ps != nullptr);
        if (ps) { std::vector<uint8_t> got(cab.size()); CHECK(!ps->preadAll(got.data(), got.size(), 0)); } }
    // frames kept past the bound are dropped, and made again when asked for: from the stream's start, paid once (the
    // budget that read it once reads it again)
    {   auto src = coding::CodedByteSource::Create(std::make_shared<MemByteSource>(coding::Serialize(d)), std::make_shared<MemByteSource>(rq),
                                                   std::make_shared<MemByteSource>(c1), cab.size(), err);
        CHECK(src != nullptr);
        if (src && steps.size() == 2) {
            src->debugLzxKept(1); src->debugStreamBudget(steps[1] + 100);
            std::vector<uint8_t> got(cab.size());
            CHECK(src->preadAll(got.data() + 12000, cab.size() - 12000, 12000));   // folder 1 (folder 0 made on the way, dropped)
            CHECK(src->preadAll(got.data(), 12000, 0));                          // folder 0 again: made again, unpaid
            CHECK(got == cab);
            } }
    // two readers of one source at once, each in another folder (the family's lock, its frames shared)
    {   auto src = coding::CodedByteSource::Create(std::make_shared<MemByteSource>(coding::Serialize(d)), std::make_shared<MemByteSource>(rq),
                                                   std::make_shared<MemByteSource>(c1), cab.size(), err);
        CHECK(src != nullptr);
        if (src) { std::vector<uint8_t> g1(cab.size()), g2(cab.size()); bool o1 = false, o2 = false;
            std::thread t1([&] { o1 = src->preadAll(g1.data() + 11600, cab.size() - 11600, 11600); });
            std::thread t2([&] { o2 = src->preadAll(g2.data(), 11000, 0); });
            t1.join(); t2.join();
            CHECK(o1 && o2 && std::equal(g1.begin() + 11600, g1.end(), cab.begin() + 11600) && std::equal(g2.begin(), g2.begin() + 11000, cab.begin())); } }
    // the family's work is the stream's account: a reader with too little left refuses the folder, it never runs unbounded
    //(too little for folder 0; enough for folder 0 and half of folder 1, which then is refused; enough)
    for (int b = 0; b < 3 && steps.size() == 2; ++b) {
        const uint64_t budget = b == 0 ? 4000 : b == 1 ? steps[0] + (steps[1] - steps[0]) / 2 : 50000000;
        auto src = coding::CodedByteSource::Create(std::make_shared<MemByteSource>(coding::Serialize(d)), std::make_shared<MemByteSource>(rq),
                                                   std::make_shared<MemByteSource>(c1), cab.size(), err);
        CHECK(src != nullptr); if (!src) break;
        src->debugStreamBudget(budget);
        std::vector<uint8_t> got(cab.size());
        CHECK_EQ(src->preadAll(got.data(), 9000, 0), b > 0);             // folder 0's first block
        CHECK_EQ(src->preadAll(got.data() + 12000, cab.size() - 12000, 12000), b > 1);   // folder 1's
        if (b > 1) { CHECK(src->preadAll(got.data(), got.size(), 0)); CHECK(got == cab); } }
    // a folder the family does not make (another E8 size): that folder alone keeps its decisions, the stream still codes back
    {   const auto cab2 = lzxcab::make(fs, {12000000, 11000000});
        std::vector<uint8_t> c3, r3, c4, r4;
        CHECK(coding::Mint(d, cab2.data(), cab2.size(), 0, 1 << 20, 2048, c3, r3, err));
        CHECK(coding::Mint(d, cab2.data(), cab2.size(), 0, 1 << 20, 2048, c4, r4, err, false));
        CHECK(c3 == c1 && cab2 != cab);
        CHECK(lzxcab::decisions(r3) > 5 && lzxcab::decisions(r3) < lzxcab::decisions(r4));
        CHECK(r3.size() > 400 && r3.size() < r4.size()); }
    // the compressor's match finder is bounded (its trees have no depth limit of their own): past its steps it stops
    {   LzxMakecab *m = LzxMakecabNew(21, 0x10000); CHECK(m != nullptr);
        auto none = [](void *, const uint8_t *, uint32_t, uint32_t) { return 0; };
        LzxMakecabLimit(m, 1000);
        CHECK_EQ(LzxMakecabCompress(m, fs[0].data(), 32768, 12000000, 1, none, nullptr), (int)LZXMK_OVER);
        CHECK_EQ(LzxMakecabSteps(m), (uint64_t)1001);
        CHECK_EQ(LzxMakecabCompress(m, fs[0].data(), 32768, 12000000, 1, none, nullptr), (int)LZXMK_ERROR);   // (spent)
        LzxMakecabFree(m);
        m = LzxMakecabNew(21, 0x10000);
        CHECK_EQ(LzxMakecabCompress(m, fs[0].data(), 32768, 12000000, 1, none, nullptr), (int)LZXMK_OK);
        CHECK_EQ(LzxMakecabSteps(m), (uint64_t)298670);                 // every tree step counted, pinned
        LzxMakecabFree(m); }
    // a frame the family does not make, though its folder decodes alike: a padding bit of its last 16-bit word set (the
    // frame differs from MAKECAB's in its last bytes only)
    {   const size_t end = cab.size();                                    // folder 1's only frame ends the cabinet
        bool found = false;
        for (int bit = 0; bit < 16 && !found; ++bit) {
            auto cab3 = cab; cab3[end - 2 + bit / 8] ^= (uint8_t)(1u << (bit % 8));
            std::vector<uint8_t> c5, r5, c6, r6; std::string e5;
            if (!coding::Mint(d, cab3.data(), cab3.size(), 0, 1 << 20, 2048, c6, r6, e5, false) || c6 != c1) continue;   // not a padding bit
            found = true; e5.clear();
            CHECK(coding::Mint(d, cab3.data(), cab3.size(), 0, 1 << 20, 2048, c5, r5, e5));
            if (!e5.empty()) std::cerr << "  padding: " << e5 << "\n";
            CHECK(c5 == c1 && lzxcab::decisions(r5) > 5 && lzxcab::decisions(r5) < lzxcab::decisions(r6)); }
        CHECK(found); }
    // the engine, not the description, has the last word: a description calling every folder the family's mints plain
    // where the family is not at hand (a plain mint), and a closed folder has no frames
    {   std::string tl = text; const std::string e = "\"lzxend (and ok (eq rem 0))\",";
        CHECK(tl.find(e) != std::string::npos);
        tl.replace(tl.find(e), e.size(), "\"lzxend 1\",");
        coding::Description dl; CHECK(coding::Read(tl, dl, err));
        std::vector<uint8_t> c11, r11; err.clear();
        CHECK(coding::Mint(dl, cab.data(), cab.size(), 0, 1 << 20, 2048, c11, r11, err, false));
        if (!err.empty()) std::cerr << "  claims all: " << err << "\n";
        CHECK(c11 == c1 && r11.size() > 3 && r11[3] == 'R' && lzxcab::decisions(r11) == lzxcab::decisions(rp));
        std::string ta = text;
        ta.replace(ta.find(e), e.size(), e + " \"decode: lzxsize 0 t\", \"decode: assert (eq t 0xFFFFFFFF)\",");
        coding::Description da; CHECK(coding::Read(ta, da, err));
        std::vector<uint8_t> c12, r12; err.clear();
        CHECK(coding::Mint(da, cab.data(), cab.size(), 0, 1 << 20, 2048, c12, r12, err));
        if (!err.empty()) std::cerr << "  closed: " << err << "\n";
        CHECK_EQ(lzxcab::decisions(r12), (uint64_t)5); }
    // CODE never takes the family's frames for a folder that is not its (here: folder 1 of cab2, coded as it decodes, and a
    // description asking for the family's frame there anyway)
    {   std::string tc = text; const std::string at = "\"@cfnf\",";
        CHECK(tc.find(at) != std::string::npos);
        tc.replace(tc.find(at), at.size(), at + " \"code: lzxemit 0 e\",");
        coding::Description dc; CHECK(coding::Read(tc, dc, err));
        const auto cab2 = lzxcab::make(fs, {12000000, 11000000});
        std::vector<uint8_t> c7, r7; err.clear();
        CHECK(!coding::Mint(dc, cab2.data(), cab2.size(), 0, 1 << 20, 2048, c7, r7, err));
        CHECK(err.find("not the family's") != std::string::npos);
        if (err.find("not the family's") == std::string::npos) std::cerr << "  emit outside: " << err << "\n"; }
    // folders past the window and MAKECAB's second partition (32 KiB + 64 KiB: the window slides): the knob's window and
    // partition are the ones the compressor runs with
    {   std::vector<uint8_t> big; for (int k = 0; k < 4; ++k) { big.insert(big.end(), fs[0].begin(), fs[0].end()); big[big.size() - 1 - (size_t)k * 977] ^= 0x5A; }
        const std::vector<std::vector<uint8_t>> three = {fs[0], fs[1], big};
        //MAKECAB's own (CompressionMemory=15; it put words.txt and more.bin in one folder): its window slides
        std::vector<uint64_t> ss; const auto slide = lzxcab::make(three, {12000000, 12000000}, &ss, 0x10000, 15, {0, 1, 1}, 0x9D9);
        CHECK(ss.size() == 2 && ss[0] == 746040 && ss[1] == 3396319);   // (the slides' copying counted too)
        CHECK_EQ(slide.size(), (size_t)56656); CHECK_EQ(lzxcab::fnv(slide), (uint64_t)0xccf1d370595df203ull);
        //and with folders of two windows (CompressionMemory 21, then 16): the second folder's knob is its own
        std::vector<uint64_t> ms; const auto mixed = lzxcab::make(three, {12000000, 12000000}, &ms, 0x10000, 21, {0, 1, 1}, 0x9D9, {21, 16});
        CHECK(ms.size() == 2 && ms[0] == 748420 && ms[1] == 4001477);   // (the count carried across the change of window)
        CHECK_EQ(mixed.size(), (size_t)39536); CHECK_EQ(lzxcab::fnv(mixed), (uint64_t)0xc294e6b0aefe72ddull);
        {   std::vector<uint8_t> c10, r10; err.clear();
            CHECK(coding::Mint(d, mixed.data(), mixed.size(), 0, 1 << 22, 8192, c10, r10, err));
            if (!err.empty()) std::cerr << "  mixed: " << err << "\n";
            CHECK_EQ(lzxcab::decisions(r10), (uint64_t)(1 + 2 + 1 + 6)); }
        {   std::vector<uint8_t> c9, r9; err.clear();
            CHECK(coding::Mint(d, slide.data(), slide.size(), 0, 1 << 22, 8192, c9, r9, err));
            if (!err.empty()) std::cerr << "  slide: " << err << "\n";
            CHECK_EQ(lzxcab::decisions(r9), (uint64_t)(1 + 2 + 1 + 6)); }
        const auto cab4 = lzxcab::make(three, {12000000, 12000000, 12000000}, nullptr, 0x10000, 15);
        CHECK(cab4 != lzxcab::make(three, {12000000, 12000000, 12000000}, nullptr, 0x20000, 15));   // (the partition matters here)
        CHECK(cab4 != lzxcab::make(three, {12000000, 12000000, 12000000}, nullptr, 0x10000, 16));   // (and the window)
        std::vector<uint8_t> c8, r8; err.clear();
        CHECK(coding::Mint(d, cab4.data(), cab4.size(), 0, 1 << 22, 8192, c8, r8, err));
        if (!err.empty()) std::cerr << "  big: " << err << "\n";
        CHECK_EQ(lzxcab::decisions(r8), (uint64_t)(5 + 1 + 5)); }        // folder 2: 160000 bytes, 5 blocks
    // the family's ops need ISA 9, a window of 15..21 and a second partition of 1..32 frames
    std::string t8 = text; t8.replace(t8.find("\"ISA\": 9"), 8, "\"ISA\": 8"); CHECK(!coding::Read(t8, d, err)); CHECK(err.find("newer") != std::string::npos);
    std::string tk = text; tk.replace(tk.find(" 12000000 533 r"), 15, " 12000000 534 r"); CHECK(!coding::Read(tk, d, err));
    std::string tz = text; tz.replace(tz.find(" 12000000 533 r"), 15, " 12000000 21 r"); CHECK(!coding::Read(tz, d, err));
}

TEST(a_description_newer_than_its_isa_is_refused) {
    auto d = coding::BsaDescription(0); auto bytes = coding::Serialize(d);
    coding::Description back; std::string err;
    CHECK(coding::Parse(bytes.data(), bytes.size(), back, err));
    // claim ISA 3
    std::string t(bytes.begin(), bytes.end()); const size_t at = t.find("\"ISA\": 4,");
    CHECK(at != std::string::npos);
    if (at != std::string::npos) t[at + 7] = '3';
    CHECK(!coding::Read(t, back, err)); CHECK(err.find("newer") != std::string::npos);
}

TEST(a_coded_stream_mounts_as_a_file) {
    TmpDir t;
    const auto in = sampleContent(3, 150000, 21); const auto alone = lzmaAlone(in, 6, 3, 0, 2); const auto d = lzmaFor(alone);
    std::vector<uint8_t> content, record; std::string err;
    CHECK(coding::Mint(d, alone.data() + 13, alone.size() - 13, in.size(), in.size(), 4096, content, record, err));
    const auto desc = coding::Serialize(d);
    auto put = [&](const std::string &n, const std::vector<uint8_t> &b) { std::ofstream(t / n, std::ios::binary).write((const char *)b.data(), (std::streamsize)b.size()); };
    put("content.bin", content); put("stream.vgcr", record);
    const std::string spec = std::string(R"({"mountpoint":"/m","readonly":true,"layers":[)")
        + R"({"type":"file","source":")" + t.str("content.bin") + R"(","target":"","cid":"bafycontent","bytesOnly":true},)"
        + R"({"type":"coded","source":")" + t.str("stream.vgcr") + R"(","description":)" + std::string(desc.begin(), desc.end())
        + R"(,"descriptionCid":"bafydesc","bases":["bafycontent"],"name":"data/level1.bundle","target":"game","cid":"bafystream"}]})";
    Spec sp; CHECK(ParseSpecText(spec, sp, err)); CHECK(sp.layers.size() == 2 && sp.layers[1].type == LayerType::Coded);
    VfsState S; CHECK(S.Init(sp, err));
    VfsAttr a; CHECK_EQ(VfsGetattr(S, "game/data/level1.bundle", a), 0); CHECK_EQ(a.size, (uint64_t)(alone.size() - 13));
    CHECK_EQ(VfsGetattr(S, "content.bin", a), -ENOENT);                  // the content is bytes only
    OpenFile *H = nullptr; CHECK_EQ(VfsOpen(S, "game/data/level1.bundle", O_RDONLY, H), 0);
    if (H) {
        std::vector<uint8_t> got(alone.size() - 13); size_t o = 0;
        while (o < got.size()) { const ssize_t n = VfsRead(H, (char *)got.data() + o, std::min<size_t>(65536, got.size() - o), (off_t)o); if (n <= 0) break; o += (size_t)n; }
        CHECK(o == got.size() && std::equal(got.begin(), got.end(), alone.begin() + 13));
        const size_t at = got.size() / 3; std::vector<uint8_t> mid(std::min<size_t>(1500, got.size() - at));     // back to the middle, after the end
        CHECK_EQ(VfsRead(H, (char *)mid.data(), mid.size(), (off_t)at), (ssize_t)mid.size());
        CHECK(std::equal(mid.begin(), mid.end(), alone.begin() + 13 + (long)at));
        CHECK(got.size() > 3000);
        VfsRelease(H);
    }
    // the content named by a CID no layer carries: planned broken, nothing served
    Spec bad; CHECK(ParseSpecText(spec.substr(0, spec.find("bafycontent")) + "bafynothing" + spec.substr(spec.find("bafycontent") + 11), bad, err));
    CHECK(!PlanTree(bad).problems.empty());
    VfsState B; CHECK(B.Init(bad, err)); CHECK_EQ(VfsGetattr(B, "game/data/level1.bundle", a), -ENOENT);
    // a coded layer must name exactly one content, a description and a name
    CHECK(!ParseSpecText(R"({"mountpoint":"/m","layers":[{"type":"coded","source":"/r","bases":["a","b"],"description":"/d","name":"x"}]})", bad, err));
    CHECK(!ParseSpecText(R"({"mountpoint":"/m","layers":[{"type":"coded","source":"/r","bases":["a"],"name":"x"}]})", bad, err));
    // the description is the node's text, carried whole, with that node's CID: a path to a file is not one
    CHECK(!ParseSpecText(R"({"mountpoint":"/m","layers":[{"type":"coded","source":"/r","bases":["a"],"description":"/d","descriptionCid":"q","name":"x"}]})", bad, err));
    CHECK(!ParseSpecText(R"({"mountpoint":"/m","layers":[{"type":"coded","source":"/r","bases":["a"],"description":{"NAME":"d"},"name":"x"}]})", bad, err));
    CHECK(!ParseSpecText(R"({"mountpoint":"/m","layers":[{"type":"zip","source":"/r","name":"x"}]})", bad, err));
}

// What the engine refuses on its own, whatever the description says: an over-subscribed Huffman code (three codes of one
// bit), and the range coder's carry, which only a long stream exercises.
TEST(the_engine_refuses_bad_codes_and_carries_correctly) {
    DeflateBits w; w.put(1, 1); w.put(2, 2); w.put(0, 5); w.put(0, 5); w.put(14, 4);
    const int clorder[18] = {16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1};
    for (int sym : clorder) w.put(sym == 0 ? 1 : sym == 1 || sym == 2 ? 2 : 0, 3);
    auto len1 = [&] { w.code(2, 2); }; auto len0 = [&] { w.code(0, 1); };
    len1(); len1(); for (int k = 2; k < 256; ++k) len0(); len1(); len1(); w.put(0, 16);
    std::vector<uint8_t> content, record; std::string err;
    CHECK(!coding::Mint(coding::DeflateDescription(), w.out.data(), w.out.size(), 0, 1 << 16, 4096, content, record, err));
    CHECK(err.find("over-subscribed") != std::string::npos);
    const auto in = sampleContent(1, 3 << 20, 77); const auto alone = lzmaAlone(in, 0, 3, 0, 2);
    auto src = codedSource(lzmaFor(alone), alone.data() + 13, alone.size() - 13, in, 1 << 20);
    CHECK(src != nullptr);
    if (src) { std::vector<uint8_t> shipped(alone.begin() + 13, alone.end()); CHECK(readsBack(*src, shipped, 5, 10)); }
}

// The sequential cursor serves only what it holds: reads ending at every byte just past what a paused run produced.
TEST(a_coded_source_cursor_never_serves_past_what_it_holds) {
    const auto in = sampleContent(1, 50000, 3); const auto alone = lzmaAlone(in, 6, 3, 0, 2);
    auto src = codedSource(lzmaFor(alone), alone.data() + 13, alone.size() - 13, in, 4096); CHECK(src != nullptr); if (!src) return;
    std::vector<uint8_t> shipped(alone.begin() + 13, alone.end()), b(4096); size_t wrong = 0;
    CHECK(src->preadAll(b.data(), 100, 0));
    for (size_t e = 101; e < 2500; ++e) { const size_t n = e - 50; if (!src->preadAll(b.data(), n, 50) || memcmp(b.data(), shipped.data() + 50, n)) ++wrong; }
    CHECK_EQ(wrong, (size_t)0);
}

// Checkpoints and records forged on purpose, field by field: a carry count no stream could hold, a probability that is
// none, an index length past any record — refused, never run; and a description using an op newer than the
// instruction set it names is refused.
TEST(a_forged_checkpoint_or_record_field_is_refused) {
    const auto in = sampleContent(1, 60000, 13); const auto alone = lzmaAlone(in, 6, 3, 0, 2); const auto d = lzmaFor(alone);
    std::vector<uint8_t> record; auto src = codedSource(d, alone.data() + 13, alone.size() - 13, in, 2048, &record); CHECK(src != nullptr); if (!src) return;
    auto var = [](const std::vector<uint8_t> &b, size_t &at) { uint64_t v = 0; for (int sh = 0;; sh += 7) { const uint8_t x = b[at++]; v |= (uint64_t)(x & 0x7F) << sh; if (!(x & 0x80)) return v; } };
    auto put = [](std::vector<uint8_t> &o, uint64_t v) { while (v >= 0x80) { o.push_back((uint8_t)(v | 0x80)); v >>= 7; } o.push_back((uint8_t)v); };
    size_t at = 4; const uint64_t shippedN = var(record, at), total = var(record, at), nck = var(record, at);
    std::vector<uint64_t> outs, decs, lens; for (uint64_t k = 0; k < nck; ++k) { outs.push_back(var(record, at)); decs.push_back(var(record, at)); lens.push_back(var(record, at)); }
    std::vector<std::vector<uint8_t>> pay; for (uint64_t k = 0; k < nck; ++k) { pay.emplace_back(record.begin() + (long)at, record.begin() + (long)(at + lens[k])); at += lens[k]; }
    auto assemble = [&](const std::vector<std::vector<uint8_t>> &ps, uint64_t badLen) {
        std::vector<uint8_t> rec = {'V', 'G', 'C', 'R'}; put(rec, shippedN); put(rec, total); put(rec, nck);
        for (uint64_t j = 0; j < nck; ++j) { put(rec, outs[j]); put(rec, decs[j]); put(rec, j == 1 && badLen ? badLen : ps[j].size()); }
        for (auto &q : ps) rec.insert(rec.end(), q.begin(), q.end());
        return rec; };
    std::string err; auto desc = std::make_shared<MemByteSource>(coding::Serialize(d)); auto content = std::make_shared<MemByteSource>(in);
    CHECK(!coding::CodedByteSource::Create(desc, std::make_shared<MemByteSource>(assemble(pay, 1ull << 62)), content, 0, err));   // a length past any record
    {   // two lengths that wrap: each past any record, their sum the record's own (a total check alone would pass it)
        std::vector<uint8_t> rec = {'V', 'G', 'C', 'R'}; put(rec, shippedN); put(rec, total); put(rec, nck);
        for (uint64_t j = 0; j < nck; ++j) { put(rec, outs[j]); put(rec, decs[j]); put(rec, pay[j].size() + (j == 1 || j == 2 ? 1ull << 63 : 0)); }
        for (auto &q : pay) rec.insert(rec.end(), q.begin(), q.end());
        CHECK(nck > 2); CHECK(!coding::CodedByteSource::Create(desc, std::make_shared<MemByteSource>(rec), content, 0, err));
    }
    // rewrite checkpoint 1's snapshot: pc, stack, 64 registers, low, range, cache, CARRY COUNT, ..., the first slot
    auto forged = [&](int what) {
        std::vector<uint8_t> raw(ZSTD_getFrameContentSize(pay[1].data(), pay[1].size())); ZSTD_decompress(raw.data(), raw.size(), pay[1].data(), pay[1].size());
        size_t q = 0; const uint64_t sn = var(raw, q); const size_t s0 = q; std::vector<uint8_t> snap;
        auto copyVar = [&](uint64_t replace, bool doIt) { const uint64_t v = var(raw, q); put(snap, doIt ? replace : v); };
        copyVar(0, false); const uint64_t ns = var(raw, q); put(snap, ns); for (uint64_t i = 0; i < ns; ++i) copyVar(0, false);
        for (int i = 0; i < 64; ++i) copyVar(0, false);
        copyVar(0, false); copyVar(0, false); snap.push_back(raw[q++]);   // low, range, cache
        copyVar(1ull << 40, what == 0);                                     // the carry count
        copyVar(0, false); copyVar(0, false);                               // acc, bn
        copyVar(what == 1 ? 0 : 4096, what >= 1);                           // the first slot: 0, or past 2047
        snap.insert(snap.end(), raw.begin() + (long)q, raw.begin() + (long)(s0 + sn));
        std::vector<uint8_t> np; put(np, snap.size()); np.insert(np.end(), snap.begin(), snap.end()); np.insert(np.end(), raw.begin() + (long)(s0 + sn), raw.end());
        std::vector<uint8_t> z(ZSTD_compressBound(np.size())); z.resize(ZSTD_compress(z.data(), z.size(), np.data(), np.size(), 3));
        auto ps = pay; ps[1] = z; return assemble(ps, 0); };
    for (int what = 0; what < 3; ++what) {
        auto s2 = coding::CodedByteSource::Create(desc, std::make_shared<MemByteSource>(forged(what)), content, 0, err);
        CHECK(s2 != nullptr); if (!s2) continue;
        std::vector<uint8_t> b(256); const auto t0 = std::chrono::steady_clock::now();
        CHECK(s2->pread(b.data(), b.size(), outs[1] + 1) < 0);              // random read from the forged checkpoint: refused
        CHECK(std::chrono::steady_clock::now() - t0 < std::chrono::seconds(5));
    }
    coding::Description old = coding::DeflateDescription(); old.isa = 2;    // uses ISA 3's runs
    const auto ob = coding::Serialize(old); coding::Description back; CHECK(!coding::Parse(ob.data(), ob.size(), back, err));
}

// THE TARGET: read through an arbitrary number of layers, each a different encoding. Twenty-one layers cycling LZ4 ->
// deflate -> LZMA, each layer's shipped stream the next one's content; the top is served through every layer below it,
// as stacked sources and as a mount (coded layers chained by CID), front to back, anywhere, and from many threads.
// A tiny description assembler for the compiler's own tests (the real formats' assembler is not part of the reader).
struct MiniAsm {
    coding::Description d;
    uint16_t e(uint8_t op, uint16_t a, uint16_t b, uint32_t imm) { d.ex.push_back(coding::Ex{op, a, b, imm}); return (uint16_t)(d.ex.size() - 1); }
    uint16_t C(uint32_t v) { return e(coding::EX_CONST, 0, 0, v); }
    uint16_t R(int r) { return e(coding::EX_REG, 0, 0, (uint32_t)r); }
    uint16_t X(uint8_t op, uint16_t a, uint16_t b) { return e(op, a, b, 0); }
    uint16_t op(uint8_t o, uint8_t flags, uint8_t tgt, uint16_t x, uint16_t v, uint16_t target = 0) {
        coding::Op p; p.op = o; p.flags = flags; p.tgt = tgt; p.x = x; p.v = v; p.m = C(0); p.target = target; d.ops.push_back(p); return (uint16_t)(d.ops.size() - 1);
    }
};
// 16 raw bits per step; every content byte is an expression of them, so DECODE writes what the compiled form computes.
static bool mintRaw(const std::function<uint16_t(MiniAsm &)> &expr, const std::vector<uint8_t> &shipped, size_t n, std::vector<uint8_t> &content, std::string &err) {
    MiniAsm a; a.d.coder = coding::kBits; a.d.name = "raw-expr";
    std::vector<uint32_t> tbl = {10, 20, 30, 40}; a.d.tables.push_back(tbl);
    a.op(coding::OP_SET, 0, 2, a.C(0), a.C(0));
    const uint16_t loop = a.op(coding::OP_RAW, coding::kFree, 1, a.C(16), a.C(0));
    a.op(coding::OP_OUTLIT, 0, 0, a.C(0), expr(a));
    a.op(coding::OP_SET, 0, 2, a.C(0), a.X(coding::EX_ADD, a.R(2), a.C(1)));
    a.op(coding::OP_JZ, 0, 0, a.C(0), a.X(coding::EX_EQ, a.R(2), a.C((uint32_t)n)), loop);
    a.op(coding::OP_FLUSH, 0, 0, a.C(0), a.C(0)); a.op(coding::OP_END, 0, 0, a.C(0), a.C(0));
    std::vector<uint8_t> rec;
    return coding::Mint(a.d, shipped.data(), shipped.size(), n, n, 4096, content, rec, err);
}
// The compiler folds expressions into affine forms and fuses op patterns; each fold must mean exactly what it folds.
TEST(the_compiled_forms_mean_what_they_fold) {
    std::string err; std::vector<uint8_t> c;
    // (x & 0xFF) >> 4: the mask shifts with the value (a value with bits 8..11 set shows a mask left in place)
    const std::vector<uint16_t> xs = {0x0ABC, 0x0F0F, 0xFFFF, 0x1234, 0x00F0};
    std::vector<uint8_t> sh; for (uint16_t x : xs) { sh.push_back((uint8_t)x); sh.push_back((uint8_t)(x >> 8)); }
    CHECK(mintRaw([](MiniAsm &a) { return a.X(coding::EX_SHR, a.X(coding::EX_AND, a.R(1), a.C(0xFF)), a.C(4)); }, sh, xs.size(), c, err));
    for (size_t i = 0; i < xs.size() && i < c.size(); ++i) CHECK_EQ((int)c[i], (int)((xs[i] & 0xFF) >> 4));
    // a table term in a sum: the last entry reads, one past it is refused
    std::vector<uint8_t> in = {3, 0, 1, 0};
    CHECK(mintRaw([](MiniAsm &a) { return a.X(coding::EX_ADD, a.e(coding::EX_TABLE, a.R(1), 0, 0), a.R(2)); }, in, 2, c, err));
    if (c.size() == 2) { CHECK_EQ((int)c[0], 40); CHECK_EQ((int)c[1], 21); }
    in = {4, 0, 1, 0};
    CHECK(!mintRaw([](MiniAsm &a) { return a.X(coding::EX_ADD, a.e(coding::EX_TABLE, a.R(1), 0, 0), a.R(2)); }, in, 2, c, err));
    CHECK(err.find("table read out of range") != std::string::npos);
    // a refusal pending when the program returns (a table read out of range, then RET at the top) refuses the stream
    {
        MiniAsm q; q.d.coder = coding::kBits; q.d.name = "ret-refusal"; q.d.tables.push_back({10, 20, 30, 40});
        q.op(coding::OP_RAW, coding::kFree, 1, q.C(8), q.C(0));
        q.op(coding::OP_OUTLIT, 0, 0, q.C(0), q.X(coding::EX_ADD, q.e(coding::EX_TABLE, q.R(1), 0, 0), q.R(2)));
        q.op(coding::OP_RET, 0, 0, q.C(0), q.C(0));
        std::vector<uint8_t> rec, one = {2}, bad = {4};
        CHECK(coding::Mint(q.d, one.data(), one.size(), 1, 1, 4096, c, rec, err)); CHECK(c.size() == 1 && c[0] == 30);
        CHECK(!coding::Mint(q.d, bad.data(), bad.size(), 1, 1, 4096, c, rec, err));
    }
    // compute-a-bit + code-it + branch, with a jump landing on the BIT from another path: the fused form must not swallow
    // the landing. The stream is range-coded here by a reference encoder, bit by bit through the one slot.
    MiniAsm a; a.d.coder = coding::kRange; a.d.nslots = 1; a.d.name = "fusion-landing";
    const int N = 40; std::mt19937 r(7); std::vector<uint8_t> bits(N); for (auto &b : bits) b = (uint8_t)(r() & 1);
    const uint16_t bitOfContent = a.X(coding::EX_AND, a.e(coding::EX_BYTE, a.R(0), 0, 0), a.C(1));
    a.op(coding::OP_SET, 0, 2, a.C(0), a.C(0));                                                   // 0: i = 0
    const uint16_t loop = a.op(coding::OP_JZ, 0, 0, a.C(0), a.X(coding::EX_AND, a.R(2), a.C(1)), 0);   // 1: even i -> 4
    a.op(coding::OP_SET, 0, 1, a.C(0), bitOfContent);                                            // 2: odd: compute the bit ...
    a.op(coding::OP_JMP, 0, 0, a.C(0), a.C(0), 5);                                               // 3: ... and land on the BIT
    a.op(coding::OP_SET, 0, 1, a.C(0), bitOfContent);                                            // 4: even: compute,
    a.op(coding::OP_BIT, 0, 1, a.C(0), a.R(1));                                                  // 5: code it,
    a.op(coding::OP_JZ, 0, 0, a.C(0), a.R(1), 9);                                                // 6: branch on it
    a.op(coding::OP_OUTLIT, 0, 0, a.C(0), a.C(1));                                               // 7
    a.op(coding::OP_JMP, 0, 0, a.C(0), a.C(0), 10);                                              // 8
    a.op(coding::OP_OUTLIT, 0, 0, a.C(0), a.C(0));                                               // 9
    a.op(coding::OP_SET, 0, 2, a.C(0), a.X(coding::EX_ADD, a.R(2), a.C(1)));                    // 10: i += 1
    a.op(coding::OP_JZ, 0, 0, a.C(0), a.X(coding::EX_EQ, a.R(2), a.C(N)), loop);                 // 11
    a.op(coding::OP_FLUSH, 0, 0, a.C(0), a.C(0)); a.op(coding::OP_END, 0, 0, a.C(0), a.C(0));
    a.d.ops[loop].target = 4;
    struct { uint64_t low = 0; uint32_t range = 0xFFFFFFFFu; uint8_t cache = 0; uint64_t cs = 1; std::vector<uint8_t> o;
        void shift() { if ((uint32_t)low < 0xFF000000u || (low >> 32) != 0) { uint8_t t = cache; do { o.push_back((uint8_t)(t + (uint8_t)(low >> 32))); t = 0xFF; } while (--cs); cache = (uint8_t)((uint32_t)low >> 24); } cs++; low = (uint32_t)low << 8; }
        void bit(uint16_t &p, int b) { const uint32_t bound = (range >> 11) * p; if (!b) { range = bound; p = (uint16_t)(p + ((2048 - p) >> 5)); } else { low += bound; range -= bound; p = (uint16_t)(p - (p >> 5)); } while (range < (1u << 24)) { range <<= 8; shift(); } }
    } enc;
    uint16_t prob = 1024; for (uint8_t b : bits) enc.bit(prob, b); for (int i = 0; i < 5; ++i) enc.shift();
    std::vector<uint8_t> rec;
    CHECK(coding::Mint(a.d, enc.o.data(), enc.o.size(), N, N, 4096, c, rec, err));
    CHECK(c == bits);
}

// Axiom 10 (Demand): bytes a layer only COPIES (LZ4 literals, stored blocks) are handed down as ranges, never generated
// again by each layer, and a layer asks the one below for about what it needs: in big windows (not one read per
// literal), and nothing behind its segment unless its format reads there.
struct ByteCountingSource : ByteSource {
    std::shared_ptr<ByteSource> inner; std::atomic<uint64_t> bytes{0}, reads{0};
    explicit ByteCountingSource(std::shared_ptr<ByteSource> s) : inner(std::move(s)) {}
    ssize_t pread(void *buf, size_t n, uint64_t off) override { ++reads; const ssize_t r = inner->pread(buf, n, off); if (r > 0) bytes += (uint64_t)r; return r; }
    uint64_t size() const override { return inner->size(); }
};
TEST(copy_runs_are_handed_down_through_every_layer) {
    auto content = sampleContent(1, 400000, 51); { const auto text = sampleContent(0, 200000, 52); content.insert(content.end(), text.begin(), text.end()); }
    // LZ4 over noise then game text, LZ4 over that (incompressible: long literal runs), deflate STORED, LZ4 fast on top
    std::vector<std::vector<uint8_t>> S = {content}; std::vector<coding::Description> D; std::vector<std::vector<uint8_t>> R;
    std::string err;
    for (int k = 0; k < 4; ++k) {
        const auto &in = S.back();
        std::vector<uint8_t> out = k == 2 ? rawDeflate(in, 0, 15, 8, Z_DEFAULT_STRATEGY) : lz4Block(in, k == 3 ? 0 : 9);
        const coding::Description d = k == 2 ? coding::DeflateDescription() : coding::Lz4BlockDescription();
        std::vector<uint8_t> c, rec;
        CHECK(coding::Mint(d, out.data(), out.size(), in.size(), in.size(), coding::SuggestedSpacing(d, out.size()), c, rec, err));
        CHECK(c == in);
        S.push_back(out); D.push_back(d); R.push_back(rec);
    }
    auto stack = [&](std::shared_ptr<ByteCountingSource> &bottom, std::vector<std::shared_ptr<coding::CodedByteSource>> &L) {
        bottom = std::make_shared<ByteCountingSource>(std::make_shared<MemByteSource>(content));
        std::shared_ptr<ByteSource> src = bottom; L.clear();
        for (int k = 0; k < 4; ++k) {
            auto c = coding::CodedByteSource::Create(std::make_shared<MemByteSource>(coding::Serialize(D[(size_t)k])), std::make_shared<MemByteSource>(R[(size_t)k]), src, 0, err);
            CHECK(c != nullptr); if (!c) return false; L.push_back(c); src = c;
        }
        return true;
    };
    std::shared_ptr<ByteCountingSource> bottom; std::vector<std::shared_ptr<coding::CodedByteSource>> L;
    if (!stack(bottom, L)) return;
    CHECK(readsBack(*L[3], S[4], 91, 60));
    // a fresh stack read front to back, as a game loads it
    if (!stack(bottom, L)) return;
    std::vector<uint8_t> got(S[4].size());
    for (size_t o = 0; o < got.size(); o += 65536) CHECK(L[3]->preadAll(got.data() + o, std::min<size_t>(65536, got.size() - o), o));
    CHECK(got == S[4]);
    std::cerr << "  generated: " << L[0]->bytesGenerated() << "/" << S[1].size() << " " << L[1]->bytesGenerated() << "/" << S[2].size() << " "
              << L[2]->bytesGenerated() << "/" << S[3].size() << " " << L[3]->bytesGenerated() << "/" << S[4].size()
              << "; content read " << bottom->bytes.load() << "/" << content.size() << " in " << bottom->reads.load() << " reads; decoded";
    for (auto &c : L) std::cerr << " " << c->segmentsDecoded() << "/" << c->checkpoints();
    std::cerr << "\n";
    // copied bytes are handed down, not generated: the layers over noise generate only their framing
    CHECK(L[0]->bytesGenerated() * 100 <= S[1].size() * 15);   // LZ4 over noise + text: the text's framing and short literals
    CHECK(L[1]->bytesGenerated() * 100 <= S[2].size() * 5);    // LZ4 over LZ4
    CHECK(L[2]->bytesGenerated() * 100 <= S[3].size() * 1);    // stored blocks: their headers
    CHECK(L[3]->bytesGenerated() * 100 <= S[4].size() * 2);
    // the content is read about once, in few big reads: short literals slide a window instead of a read each, nothing
    // behind a segment is fetched for formats that never look back, and a long run leaves no burst of tiny segments
    CHECK(bottom->bytes.load() * 2 <= content.size() * 3);
    CHECK(bottom->reads.load() <= 64);
    CHECK(L[0]->checkpoints() <= 12);
    for (auto &c : L) CHECK_EQ(c->segmentsDecoded(), (uint64_t)c->checkpoints());   // each segment decoded once
    // a read the layer below refuses is refused above it, copy run or not (never served as whatever the buffer held)
    {
        auto nz = sampleContent(1, 300000, 81); const auto sh = lz4Block(nz, 9); const auto dz = coding::Lz4BlockDescription(); std::vector<uint8_t> cz, rz;
        CHECK(coding::Mint(dz, sh.data(), sh.size(), nz.size(), nz.size(), coding::SuggestedSpacing(dz, sh.size()), cz, rz, err));
        auto failing = std::make_shared<CountingSource>(std::make_shared<MemByteSource>(nz));
        failing->failAt = [](uint64_t off) { return off >= 150000 && off < 160000; };
        auto top = coding::CodedByteSource::Create(std::make_shared<MemByteSource>(coding::Serialize(dz)), std::make_shared<MemByteSource>(rz), failing, 0, err);
        CHECK(top != nullptr);
        if (top) { std::vector<uint8_t> b(4096);
            CHECK(top->preadAll(b.data(), b.size(), 1000) && !memcmp(b.data(), sh.data() + 1000, b.size()));
            CHECK(!top->preadAll(b.data(), b.size(), 152000)); }
    }
    // short literals far apart (text between long noise runs, which are handed down): each text block starts a small
    // window of its own instead of fetching the noise again that the copy runs already handed down
    std::vector<uint8_t> sparse;
    for (int k = 0; k < 8; ++k) { const auto nz = sampleContent(1, 100000, 60 + k), tx = sampleContent(0, 3000, 70 + k); sparse.insert(sparse.end(), nz.begin(), nz.end()); sparse.insert(sparse.end(), tx.begin(), tx.end()); }
    const auto sz = lz4Block(sparse, 9); const auto d1 = coding::Lz4BlockDescription(); std::vector<uint8_t> c1, r1;
    CHECK(coding::Mint(d1, sz.data(), sz.size(), sparse.size(), sparse.size(), 4u << 20, c1, r1, err));   // one segment: the jumps fall inside one window
    auto sb = std::make_shared<ByteCountingSource>(std::make_shared<MemByteSource>(sparse));
    auto s1 = coding::CodedByteSource::Create(std::make_shared<MemByteSource>(coding::Serialize(d1)), std::make_shared<MemByteSource>(r1), sb, 0, err);
    CHECK(s1 != nullptr);
    if (s1) { std::vector<uint8_t> g(sz.size());
        for (size_t o = 0; o < g.size(); o += 65536) CHECK(s1->preadAll(g.data() + o, std::min<size_t>(65536, g.size() - o), o));
        CHECK(g == sz);
        std::cerr << "  sparse: content read " << sb->bytes.load() << "/" << sparse.size() << " in " << sb->reads.load() << " reads\n";
        CHECK(sb->bytes.load() * 10 <= sparse.size() * 13); }
}
TEST(a_deep_stack_of_mixed_encodings_reads_through_every_layer) {
    const int depth = 21;
    std::vector<std::vector<uint8_t>> S = {sampleContent(3, 300000, 41)};      // S[0] the content, S[k] layer k's stream
    std::vector<coding::Description> D; std::vector<std::vector<uint8_t>> rec;
    std::string err;
    for (int k = 1; k <= depth; ++k) {
        const auto &in = S.back(); std::vector<uint8_t> out; coding::Description d; size_t skip = 0;
        if (k % 3 == 1) { out = lz4Block(in, 9); d = coding::Lz4BlockDescription(); }
        else if (k % 3 == 2) { out = rawDeflate(in, 6, 15, 8, Z_DEFAULT_STRATEGY); d = coding::DeflateDescription(); }
        else { out = lzmaAlone(in, 1, 3, 0, 2); d = lzmaFor(out); skip = 13; }
        std::vector<uint8_t> shipped(out.begin() + (long)skip, out.end()), content, record;
        CHECK(coding::Mint(d, shipped.data(), shipped.size(), in.size(), in.size(), coding::SuggestedSpacing(d), content, record, err));
        CHECK(content == in);
        S.push_back(shipped); D.push_back(d); rec.push_back(record);
    }
    // as stacked sources
    std::shared_ptr<ByteSource> src = std::make_shared<MemByteSource>(S[0]);
    for (int k = 1; k <= depth; ++k) {
        auto c = coding::CodedByteSource::Create(std::make_shared<MemByteSource>(coding::Serialize(D[(size_t)k - 1])), std::make_shared<MemByteSource>(rec[(size_t)k - 1]), src, 0, err);
        CHECK(c != nullptr); if (!c) return; src = c;
    }
    CHECK(readsBack(*src, S[depth], 77, 30));
    std::atomic<int> bad{0}; std::vector<std::thread> th;
    for (int t = 0; t < 8; ++t) th.emplace_back([&, t] { std::mt19937 rr((uint32_t)t); std::vector<uint8_t> b(16384);
        for (int i = 0; i < 12; ++i) { const size_t a = rr() % S[depth].size(), n = 1 + rr() % std::min<size_t>(16384, S[depth].size() - a);
            if (!src->preadAll(b.data(), n, a) || memcmp(b.data(), S[depth].data() + a, n)) ++bad; } });
    for (auto &x : th) x.join();
    CHECK_EQ(bad.load(), 0);
    // as a mount: the content a bytes-only file, every layer a coded layer naming the one below by CID, the top surfacing
    TmpDir t;
    auto put = [&](const std::string &n, const std::vector<uint8_t> &b) { std::ofstream(t / n, std::ios::binary).write((const char *)b.data(), (std::streamsize)b.size()); };
    put("c0.bin", S[0]);
    std::string layers = R"({"type":"file","source":")" + t.str("c0.bin") + R"(","target":"","cid":"c0","bytesOnly":true})";
    for (int k = 1; k <= depth; ++k) {
        put("r" + std::to_string(k), rec[(size_t)k - 1]); const auto dk = coding::Serialize(D[(size_t)k - 1]);
        layers += R"(,{"type":"coded","source":")" + t.str("r" + std::to_string(k)) + R"(","description":)" + std::string(dk.begin(), dk.end())
                + R"(,"descriptionCid":"desc)" + std::to_string(k) + R"(","bases":["c)" + std::to_string(k - 1) + R"("],"name":"top.bin","target":"","cid":"c)" + std::to_string(k) + R"(")" + (k < depth ? R"(,"bytesOnly":true)" : "") + "}";
    }
    Spec sp; CHECK(ParseSpecText(R"({"mountpoint":"/m","readonly":true,"layers":[)" + layers + "]}", sp, err));
    CHECK(PlanTree(sp).problems.empty());
    VfsState V; CHECK(V.Init(sp, err));
    VfsAttr a; CHECK_EQ(VfsGetattr(V, "top.bin", a), 0); CHECK_EQ(a.size, (uint64_t)S[depth].size());
    OpenFile *H = nullptr; CHECK_EQ(VfsOpen(V, "top.bin", O_RDONLY, H), 0);
    if (H) { std::vector<uint8_t> got(S[depth].size()); size_t o = 0;
        while (o < got.size()) { const ssize_t n = VfsRead(H, (char *)got.data() + o, std::min<size_t>(131072, got.size() - o), (off_t)o); if (n <= 0) break; o += (size_t)n; }
        CHECK(o == got.size() && got == S[depth]); VfsRelease(H); }
}
