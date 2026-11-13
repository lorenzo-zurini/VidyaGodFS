#include "overlay.h"
#include "treeplan.h"
#include "vgdelta.h"
#include "hostio.h"     // all host filesystem I/O goes through the backend-neutral shim

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <cstring>
#include <cerrno>
#include <unordered_map>
#include <unordered_set>
#include <fcntl.h>      // O_RDONLY / O_CREAT / O_WRONLY / O_TRUNC flag constants (passed to HostIO::Open)
#include <iostream>

namespace fs = std::filesystem;
static constexpr uint64_t kIndexPrefetch = 1ull << 20;   // what a mount reads first of each archive, asked for at once

// ---- small path helpers --------------------------------------------------

// Symlink abolition containment: a followed DATA-layer symlink must resolve to a real path that stays
// INSIDE the layer's source root. A zip layer already rejects absolute targets; a dir layer's host symlink
// could point at an absolute path (`-> /etc/passwd`) or `../..`-escape the source, which would make the FS
// serve an arbitrary host file. Returns true iff the followed `host` path is contained in `layerSource`.
static bool SymlinkContained(const std::string &host, const std::string &layerSource)
{
    std::error_code ec;
    std::filesystem::path resolved = std::filesystem::weakly_canonical(host, ec);
    if (ec) return false;
    std::filesystem::path rootc = std::filesystem::weakly_canonical(layerSource, ec);
    if (ec) return false;
    // Lexical prefix check on canonical paths (both absolute, no symlinks remaining).
    auto rit = rootc.begin(), rend = rootc.end();
    auto pit = resolved.begin(), pend = resolved.end();
    for (; rit != rend; ++rit, ++pit)
        if (pit == pend || *pit != *rit) return false;
    return true;   // resolved == rootc or a descendant
}

static std::string ParentVRel(const std::string &vrel)
{
    size_t s = vrel.find_last_of('/');
    return (s == std::string::npos) ? std::string() : vrel.substr(0, s);
}

static std::string BaseName(const std::string &p)
{
    size_t s = p.find_last_of('/');
    return (s == std::string::npos) ? p : p.substr(s + 1);
}

std::string WLPath(const VfsState &S, const std::string &vrel)
{
    return vrel.empty() ? S.writelayer : (S.writelayer + "/" + vrel);
}

// ---- VfsState init -------------------------------------------------------

//Adds every directory strictly above `leaf` to implicitDirs.
static void AddAncestors(std::set<std::string> &dst, const std::string &leaf)
{
    std::string cur = ParentVRel(leaf);
    while (!cur.empty()) { dst.insert(cur); cur = ParentVRel(cur); }
}


static void SeedMasksFromWritelayer(VfsState &S);   // defined with the mask machinery below
static void SeedKeptMasks(Layer &L);                 // likewise, for each kept folder

bool VfsState::Init(const Spec &S, std::string &Err)
{
    writelayer = S.writelayer;
    readOnly   = S.readOnly;
    uid        = S.uid;
    gid        = S.gid;

    std::error_code ec;
    if (!writelayer.empty()) fs::create_directories(writelayer, ec);
    // Persisted writelayers carry `.wh.*` markers from earlier sessions — rebuild the in-memory masks
    // from disk so deletions keep masking across remounts.
    SeedMasksFromWritelayer(*this);

    int prio = 0;
    //What the layers make of the tree (treeplan.h): where each appears, which file each base CID is, what each delta
    //hides. Then the bytes of each layer that surfaces, built on demand — a delta over its bases' bytes, released as
    //soon as no surfacing layer or unbuilt delta needs them. A delta that turns out not to rebuild hides nothing: the
    //plan is made again with it broken, so what it would have hidden surfaces — and again, while that finds more.
    TreePlan P = PlanTree(S);
    for (const std::string &Why : P.problems) std::cerr << "[vidyagodfs] " << Why << " — it is left out\n";
    //What indexing reads first, asked for at once: an archive's central directory at its end, a delta's header and
    //segment table at its start. The disk serves them in one sweep, where layer after layer each waited for its seeks.
    for (size_t I = 0; I < S.layers.size(); ++I)
    {
        const LayerSpec &LS = S.layers[I];
        const bool Zip = LS.type == LayerType::Zip && !P.whole[I], Delta = LS.type == LayerType::Delta && !P.broken[I];
        if (!Zip && !Delta) continue;
        HostIO::Fd Fd = HostIO::Open(LS.source, O_RDONLY);
        if (Fd < 0) continue;
        HostIO::Stat St;
        if (HostIO::Fstat(Fd, St) == 0)
        {
            const uint64_t Len = St.size < kIndexPrefetch ? St.size : kIndexPrefetch;
            HostIO::Prefetch(Fd, Zip ? St.size - Len : 0, Len);
        }
        HostIO::Close(Fd);
    }
    std::vector<std::shared_ptr<ZipIndex>> Index(S.layers.size());
    std::vector<bool> Failed(S.layers.size(), false);
    //Each round surfaces what the failures so far stopped hiding, and may find a failure beneath them (a delta whose own
    //file is gone is found to fail before anything beneath it is tried): re-planned until a round finds none. At most
    //one round per delta, plus the last.
    for (;;)
    {
        std::vector<bool> Keep(S.layers.size());
        for (size_t I = 0; I < S.layers.size(); ++I) Keep[I] = !P.whole[I];
        LayerBytes Bytes(S, P, Keep);
        bool NewFailure = false;
        for (size_t I = 0; I < S.layers.size(); ++I)
        {
            const LayerSpec &LS = S.layers[I];
            if ((LS.type != LayerType::Zip && LS.type != LayerType::Delta) || P.whole[I] || Index[I] || Failed[I]) continue;
            if (LS.type == LayerType::Delta && P.broken[I]) continue;
            std::string Why;
            std::shared_ptr<ByteSource> Src = Bytes.Get(I, &Why);
            if (!Src)
            {
                std::cerr << "[vidyagodfs] skipping layer " << LS.source << ": " << Why << "\n";
                if (Bytes.Failed(I)) { Failed[I] = true; NewFailure = true; }
                continue;
            }
            Index[I] = BuildZipIndex(Src, LS.source);
            if (!Index[I]) std::cerr << "[vidyagodfs] skipping unreadable zip layer: " << LS.source << "\n";
        }
        for (size_t I = 0; I < S.layers.size(); ++I)          // a delta read only as a base can fail too
            if (Bytes.Failed(I) && !Failed[I]) { Failed[I] = true; NewFailure = true; }
        if (!NewFailure) break;
        P = PlanTree(S, Failed);                              // what the failed deltas hid surfaces
    }

    for (size_t gi = 0; gi < S.layers.size(); ++gi)
    {
        const LayerSpec &LS = S.layers[gi];
        const bool Archive = LS.type == LayerType::Zip || LS.type == LayerType::Delta;
        if (Archive && (P.whole[gi] || !Index[gi])) continue;   // a byte input only, or nothing to serve
        for (const auto &[sub, tgt] : P.mounts[gi])
        {
            Layer L;
            L.type = Archive ? LayerType::Zip : LS.type;      // delta-backed → a zip layer
            L.source = LS.source;
            L.target = tgt;
            L.subpath = sub;
            L.rw = LS.rw;
            L.zip = Archive ? Index[gi] : nullptr;
            L.priority = prio++;
            L.maskedUnder = P.maskedUnder[gi];
            if (LS.type == LayerType::File)
            {
                L.fileBase  = BaseName(LS.source);
                L.fileVPath = L.target.empty() ? L.fileBase : (L.target + "/" + L.fileBase);
            }
            layers.push_back(std::move(L));
        }
    }
    //Structural dirs come from what is visible: a base hidden whole by its delta implies none of its own.
    for (const Layer &L : layers)
    {
        if (LayerMasked(L, L.type == LayerType::File ? L.fileVPath : L.target)) continue;
        if (L.type == LayerType::File) AddAncestors(implicitDirs, L.fileVPath);   // includes the containing target dir
        else AddAncestors(implicitDirs, L.target.empty() ? std::string("\x01") : L.target);   // target itself is real via the layer
    }
    implicitDirs.erase("\x01");
    implicitDirs.erase("");
    for (Layer &L : layers)
        if (L.type == LayerType::Dir && L.rw) SeedKeptMasks(L);
    caseInsensitive = S.caseInsensitive;
    if (caseInsensitive)
    {
        //Lowest layer first, first spelling kept: the base layer's case wins, as the packaging-time case resolver
        //(FixCaseConflicts) already makes every layer spell a shared name.
        //A base hidden under its delta spells nothing: the delta's own names are the ones that resolve.
        const Layer *Of = nullptr;
        auto Add = [&](const std::string &V) { if (!V.empty() && !LayerMasked(*Of, V)) canonCase.try_emplace(FoldCase(V), V); };
        for (const Layer &L : layers)
        {
            Of = &L;
            if (L.type == LayerType::File) { Add(L.fileVPath); continue; }
            Add(L.target);
            if (L.type != LayerType::Zip || !L.zip) continue;
            auto AddZip = [&](const std::string &Rel) {
                std::string Under = Rel;
                if (!L.subpath.empty())
                {
                    if (Rel != L.subpath && Rel.rfind(L.subpath + "/", 0) != 0) return;
                    Under = Rel.size() > L.subpath.size() ? Rel.substr(L.subpath.size() + 1) : std::string();
                }
                Add(L.target.empty() ? Under : (Under.empty() ? L.target : L.target + "/" + Under));
            };
            for (const auto &[Name, E] : L.zip->byName) AddZip(Name);
            for (const auto &[Dir, Kids] : L.zip->dirChildren) AddZip(Dir);
        }
        for (const std::string &D : implicitDirs) canonCase.try_emplace(FoldCase(D), D);
    }
    return true;
    (void)Err;
}

std::mutex &VfsState::CopyUpLock(const std::string &vrel)
{
    return copyUpShards[std::hash<std::string>{}(vrel) % kCopyUpShards];
}

// ---- coverage / relative path --------------------------------------------

bool LayerCovers(const Layer &L, const std::string &vrel)
{
    if (L.type == LayerType::File) return vrel == L.fileVPath;
    if (L.target.empty()) return true;
    return vrel == L.target || vrel.rfind(L.target + "/", 0) == 0;
}


bool LayerMasked(const Layer &L, const std::string &vrel)
{
    for (const std::string &M : L.maskedUnder)
        if (Within(vrel, M)) return true;
    return false;
}

std::string RelUnder(const Layer &L, const std::string &vrel)
{
    if (L.target.empty()) return vrel;
    if (vrel == L.target) return "";
    return vrel.substr(L.target.size() + 1);
}

//The source/zip-side relative path for vrel: the path under target (RelUnder), prefixed by the layer's
//subpath. With subpath set, the layer exposes source/subpath at target (subpath="" → whole source).
std::string SourceRel(const Layer &L, const std::string &vrel)
{
    std::string rel = RelUnder(L, vrel);
    if (L.subpath.empty()) return rel;
    if (rel.empty())       return L.subpath;
    return L.subpath + "/" + rel;
}

// ---- whiteouts + opaque dirs ---------------------------------------------
// The masks live TWICE: as `.wh.*` files in the writelayer (durable truth, survives remounts of persisted
// writelayers) and as immutable in-memory sets swapped copy-on-write (what the hot Resolve path reads —
// pure lock-free lookups, zero host syscalls per path/ancestor). Every mutation writes disk first, then
// swaps the set, so a reader that observes the new set finds the marker already durable.

using MaskSet = std::set<std::string>;
using MaskPtr = std::shared_ptr<const MaskSet>;

static MaskPtr LoadMask(const std::atomic<MaskPtr> &a)
{
    return a.load(std::memory_order_acquire);
}

//Clone-modify-swap under maskWriteMtx. `mut` edits the writable clone.
static void MutateMask(VfsState &S, std::atomic<MaskPtr> &a, const std::function<void(MaskSet &)> &mut)
{
    std::lock_guard<std::mutex> g(S.maskWriteMtx);
    MaskPtr cur = a.load(std::memory_order_acquire);
    auto next = std::make_shared<MaskSet>(cur ? *cur : MaskSet{});
    mut(*next);
    a.store(std::move(next), std::memory_order_release);
}

std::string WhiteoutPath(const VfsState &S, const std::string &vrel)
{
    return WLPath(S, ParentVRel(vrel)) + "/.wh." + BaseName(vrel);
}

bool IsWhiteouted(const VfsState &S, const std::string &vrel)
{
    if (S.writelayer.empty() || vrel.empty()) return false;
    MaskPtr m = LoadMask(S.whiteoutSet);
    return m && m->count(vrel) != 0;
}

void CreateWhiteout(VfsState &S, const std::string &vrel)
{
    if (S.writelayer.empty()) return;
    std::error_code ec;
    fs::create_directories(WLPath(S, ParentVRel(vrel)), ec);
    HostIO::Fd fd = HostIO::Open(WhiteoutPath(S, vrel), O_CREAT | O_WRONLY, 0644);
    if (fd >= 0) HostIO::Close(fd);
    MutateMask(S, S.whiteoutSet, [&](MaskSet &m) { m.insert(vrel); });
}

void RemoveWhiteout(VfsState &S, const std::string &vrel)
{
    if (S.writelayer.empty()) return;
    HostIO::Unlink(WhiteoutPath(S, vrel));
    MutateMask(S, S.whiteoutSet, [&](MaskSet &m) { m.erase(vrel); });
}

static std::string OpaqueMarker(const VfsState &S, const std::string &vrel)
{
    return WLPath(S, vrel) + "/.wh..wh..opq";
}

void MarkOpaque(VfsState &S, const std::string &vrel)
{
    if (S.writelayer.empty()) return;
    HostIO::Fd fd = HostIO::Open(OpaqueMarker(S, vrel), O_CREAT | O_WRONLY, 0644);
    if (fd >= 0) HostIO::Close(fd);
    MutateMask(S, S.opaqueSet, [&](MaskSet &m) { m.insert(vrel); });
}

void UnmarkOpaque(VfsState &S, const std::string &vrel)
{
    if (S.writelayer.empty()) return;
    // Disk marker removal is the caller's business (the rmdir sweep already unlinks it); just drop the mask.
    MutateMask(S, S.opaqueSet, [&](MaskSet &m) { m.erase(vrel); });
}

void RenameMaskPrefix(VfsState &S, const std::string &oldv, const std::string &newv)
{
    if (S.writelayer.empty() || oldv == newv) return;
    auto rewrite = [&](MaskSet &m) {
        MaskSet moved;
        std::string pfx = oldv + "/";
        for (auto it = m.begin(); it != m.end();)
        {
            if (*it == oldv || it->rfind(pfx, 0) == 0)
            {
                moved.insert(*it == oldv ? newv : newv + "/" + it->substr(pfx.size()));
                it = m.erase(it);
            }
            else ++it;
        }
        m.merge(moved);
    };
    MutateMask(S, S.whiteoutSet, rewrite);
    MutateMask(S, S.opaqueSet, rewrite);
}

//True if any ANCESTOR directory of vrel is whiteouted (deleted) — a deleted directory masks its entire
//subtree, not just its own name. Empty-set fast path; pure in-memory lookups.
bool IsUnderWhiteout(const VfsState &S, const std::string &vrel)
{
    if (S.writelayer.empty()) return false;
    MaskPtr m = LoadMask(S.whiteoutSet);
    if (!m || m->empty()) return false;
    for (std::string cur = ParentVRel(vrel); !cur.empty(); cur = ParentVRel(cur))
        if (m->count(cur) != 0) return true;
    return false;
}

//True if any ancestor directory of vrel (including the root) is opaque — meaning the lower layers are
//masked here. Empty-set fast path; pure in-memory lookups.
bool IsUnderOpaque(const VfsState &S, const std::string &vrel)
{
    if (S.writelayer.empty()) return false;
    MaskPtr m = LoadMask(S.opaqueSet);
    if (!m || m->empty()) return false;
    for (std::string cur = ParentVRel(vrel); !cur.empty(); cur = ParentVRel(cur))
        if (m->count(cur) != 0) return true;
    return m->count(std::string{}) != 0; // root opaque masks everything
}

//Init-time seeding: rebuild both masks from the persisted writelayer's `.wh.*` markers so masks survive
//remounts (persist keeps writelayers). One bounded walk of what the guest actually wrote.
static void SeedMasksFromWritelayer(VfsState &S)
{
    if (S.writelayer.empty()) return;
    auto wh  = std::make_shared<MaskSet>();
    auto opq = std::make_shared<MaskSet>();
    std::function<void(const std::string &)> walk = [&](const std::string &vdir) {
        std::string host = WLPath(S, vdir);
        HostIO::ReadDir(host, [&](const std::string &n) {
            std::string childV = vdir.empty() ? n : vdir + "/" + n;
            if (n == ".wh..wh..opq") { opq->insert(vdir); return; }
            if (n.rfind(".wh.", 0) == 0) { wh->insert(vdir.empty() ? n.substr(4) : vdir + "/" + n.substr(4)); return; }
            HostIO::Stat st;
            if (HostIO::Lstat(host + "/" + n, st) == 0 && st.isDir) walk(childV);
        });
    };
    walk("");
    S.whiteoutSet.store(std::move(wh), std::memory_order_release);
    S.opaqueSet.store(std::move(opq), std::memory_order_release);
}

// ---- case ----------------------------------------------------------------

std::string FoldCase(std::string S)
{
    for (char &C : S) if (C >= 'A' && C <= 'Z') C = static_cast<char>(C - 'A' + 'a');
    return S;
}

std::string CanonicalCase(const VfsState &S, const std::string &vrel)
{
    if (!S.caseInsensitive || S.canonCase.empty() || vrel.empty()) return vrel;
    const std::string F = FoldCase(vrel);
    size_t Cut = F.size();
    while (true)
    {
        const auto It = S.canonCase.find(F.substr(0, Cut));
        if (It != S.canonCase.end()) return It->second + vrel.substr(Cut);   // ASCII folding keeps every length
        const size_t Slash = F.rfind('/', Cut - 1);
        if (Slash == std::string::npos || Slash == 0) return vrel;
        Cut = Slash;
    }
}

// ---- resolution ----------------------------------------------------------

ResolveResult Resolve(VfsState &S, const std::string &vrel)
{
    ResolveResult R;

    if (!S.writelayer.empty())
    {
        if (IsWhiteouted(S, vrel)) return R; // deleted → None
        std::string wp = WLPath(S, vrel);
        HostIO::Stat st;
        if (HostIO::Lstat(wp, st) == 0) { R.kind = HitKind::WriteLayer; R.hostPath = wp; return R; }
        // Not in the writelayer, but masked by an opaque ancestor OR under a deleted (whiteouted) directory
        // → the lower layers don't show here (recreating an ancestor removes its whiteout, so no conflict).
        if (IsUnderOpaque(S, vrel) || IsUnderWhiteout(S, vrel)) return R;
    }

    // Highest priority first.
    for (auto it = S.layers.rbegin(); it != S.layers.rend(); ++it)
    {
        const Layer &L = *it;
        if (!LayerCovers(L, vrel) || LayerMasked(L, vrel)) continue;

        if (L.type == LayerType::Dir)
        {
            std::string rel = SourceRel(L, vrel);
            std::string host = rel.empty() ? L.source : (L.source + "/" + rel);
            HostIO::Stat st;
            if (HostIO::Lstat(host, st) == 0)
            {
                // Symlink abolition: a DATA layer never serves a link. Followable on the host (the layer
                // source tree is complete there) → serve as the target; dangling → this layer doesn't have
                // the path (fall through to lower layers). rw (passthrough) layers are EXEMPT like the
                // writelayer: they hold live guest-written state (persisted user dirs where proton keeps
                // its own user-path links), which must round-trip as authored.
                if (S.flattenSymlinks && !L.rw && st.isSymlink &&
                    (HostIO::StatFollow(host, st) != 0 || !SymlinkContained(host, L.source)))
                    continue;   // dangling OR escapes the layer source → not served by this layer
                R.kind = HitKind::DirLayer; R.hostPath = host; R.layer = &L; R.rwPassthrough = L.rw;
                return R;
            }
            if (L.rw && KeptMasked(L, vrel)) return R;   // deleted in the kept folder: the lower layers don't show
        }
        else if (L.type == LayerType::File)
        {
            HostIO::Stat st;
            if (HostIO::Lstat(L.source, st) == 0)
            {
                if (S.flattenSymlinks && st.isSymlink && HostIO::StatFollow(L.source, st) != 0)
                    continue;
                R.kind = HitKind::FileLayer; R.hostPath = L.source; R.layer = &L;
                return R;
            }
        }
        else // Zip
        {
            std::string rel = SourceRel(L, vrel);
            auto fit = L.zip->byName.find(rel);
            bool isDir = (fit != L.zip->byName.end() && fit->second.isDir) || L.zip->dirChildren.count(rel);
            if (fit != L.zip->byName.end() || isDir)
            {
                const ZipEntry *e = (fit != L.zip->byName.end()) ? &fit->second : nullptr; // null → synthesized dir
                // An archive link that resolves to a FILE inside the archive is served as that file: links
                // authored for the archive's own tree (proton's default_pfx template, drivers/mountmgr.sys ->
                // ../../../../../../lib/wine/...) resolve only there, not where the layer is mounted. Every
                // other link (absolute, out of the archive, to a folder, dangling) is served as the link it
                // is, its target as stored: the kernel resolves it inside the game's own view of the tree,
                // as an installed copy would be resolved (a self-mounting bundle's entrypoint into /nix/store).
                if (S.flattenSymlinks && e && e->symlink)
                {
                    if (const ZipEntry *T = ResolveZipSymlink(*L.zip, *e)) e = T;
                    //A target longer than any path is no link (its size is the archive's claim, read on every
                    //lookup): this layer does not have it.
                    else if (e->size > 4096 || !e->stored) continue;
                }
                R.kind = HitKind::ZipEntry; R.layer = &L; R.zipEntry = e;
                return R;
            }
        }
    }

    if (S.implicitDirs.count(vrel)) { R.kind = HitKind::ImplicitDir; return R; }
    return R;
}

// ---- copy-up -------------------------------------------------------------

bool PassthroughHost(VfsState &S, const std::string &vrel, std::string &HostOut)
{
    for (auto it = S.layers.rbegin(); it != S.layers.rend(); ++it)
    {
        const Layer &L = *it;
        if (L.type == LayerType::Dir && L.rw && LayerCovers(L, vrel))
        {
            std::string rel = SourceRel(L, vrel);
            HostOut = rel.empty() ? L.source : (L.source + "/" + rel);
            return true;
        }
    }
    return false;
}

// ---- deletions under a kept (rw passthrough) folder (see overlay.h) --------
const Layer *KeptLayerFor(const VfsState &S, const std::string &vrel)
{
    for (auto it = S.layers.rbegin(); it != S.layers.rend(); ++it)
        if (it->type == LayerType::Dir && it->rw && LayerCovers(*it, vrel)) return &*it;
    return nullptr;
}

static std::string KeptHost(const Layer &L, const std::string &rel)
{
    return rel.empty() ? L.source : (L.source + "/" + rel);
}

//vrel's marker in kept layer L; empty for the kept folder's own root (a mount point cannot hide itself).
static std::string KeptMarker(const Layer &L, const std::string &rel)
{
    return rel.empty() ? std::string() : KeptHost(L, ParentVRel(rel)) + "/.wh." + BaseName(rel);
}

static int TouchMarker(const std::string &path)
{
    std::error_code ec;
    fs::create_directories(fs::path(path).parent_path(), ec);
    if (ec) return -(ec.value() ? ec.value() : EIO);
    HostIO::Fd fd = HostIO::Open(path, O_CREAT | O_WRONLY, 0644);
    if (fd < 0) return (int)fd;
    HostIO::Close(fd);
    return 0;
}

static bool InMask(const std::atomic<MaskPtr> &a, const std::string &rel)
{
    MaskPtr m = LoadMask(a);
    return m && m->count(rel) != 0;
}

//Init-time: one walk of each kept folder for its markers (the folder holds only what the user's games wrote).
static void SeedKeptMasks(Layer &L)
{
    auto del = std::make_shared<MaskSet>(), opq = std::make_shared<MaskSet>();
    std::function<void(const std::string &)> walk = [&](const std::string &rel) {
        const std::string host = KeptHost(L, rel);
        HostIO::ReadDir(host, [&](const std::string &n) {
            if (n == ".wh..wh..opq") { opq->insert(rel); return; }
            if (n.rfind(".wh.", 0) == 0) { del->insert(rel.empty() ? n.substr(4) : rel + "/" + n.substr(4)); return; }
            HostIO::Stat st;
            if (HostIO::Lstat(host + "/" + n, st) == 0 && st.isDir) walk(rel.empty() ? n : rel + "/" + n);
        });
    };
    walk(L.subpath);
    L.kept = std::make_shared<KeptMasks>();
    L.kept->deleted.store(std::move(del), std::memory_order_release);
    L.kept->opaque.store(std::move(opq), std::memory_order_release);
}

int HideLower(VfsState &S, const std::string &vrel)
{
    if (const Layer *L = KeptLayerFor(S, vrel))
    {
        const std::string rel = SourceRel(*L, vrel);
        if (!rel.empty())
        {
            if (int e = TouchMarker(KeptMarker(*L, rel)); e != 0) return e;
            MutateMask(S, L->kept->deleted, [&](MaskSet &m) { m.insert(rel); });
            return 0;
        }
    }
    CreateWhiteout(S, vrel);
    return 0;
}

int UnhideLower(VfsState &S, const std::string &vrel)
{
    if (const Layer *L = KeptLayerFor(S, vrel))
        if (const std::string rel = SourceRel(*L, vrel); !rel.empty() && InMask(L->kept->deleted, rel))
        {
            if (int e = HostIO::Unlink(KeptMarker(*L, rel)); e != 0 && e != -ENOENT) return e;
            MutateMask(S, L->kept->deleted, [&](MaskSet &m) { m.erase(rel); });
        }
    RemoveWhiteout(S, vrel);
    return 0;
}

bool KeptHidden(const VfsState &S, const std::string &vrel)
{
    const Layer *L = KeptLayerFor(S, vrel);
    return L && InMask(L->kept->deleted, SourceRel(*L, vrel));
}

bool KeptOpaqueDir(const Layer &L, const std::string &vrel)
{
    return L.kept && InMask(L.kept->opaque, SourceRel(L, vrel));
}

bool KeptMasked(const Layer &L, const std::string &vrel)
{
    if (!L.kept) return false;
    MaskPtr del = LoadMask(L.kept->deleted), opq = LoadMask(L.kept->opaque);
    const bool anyDel = del && !del->empty(), anyOpq = opq && !opq->empty();
    if (!anyDel && !anyOpq) return false;
    std::string rel = SourceRel(L, vrel);
    if (rel.empty()) return false;
    if (anyDel && del->count(rel)) return true;
    for (std::string cur = ParentVRel(rel);; cur = ParentVRel(cur))
    {
        if (anyDel && !cur.empty() && del->count(cur)) return true;   // an ancestor deleted here
        if (anyOpq && opq->count(cur)) return true;                   // an ancestor (or the root) made again
        if (cur.empty()) return false;
    }
}

int KeptMarkOpaque(VfsState &S, const std::string &vrel)
{
    const Layer *L = KeptLayerFor(S, vrel);
    if (!L) return -EINVAL;
    const std::string rel = SourceRel(*L, vrel);
    if (int e = TouchMarker(KeptHost(*L, rel) + "/.wh..wh..opq"); e != 0) return e;
    MutateMask(S, L->kept->opaque, [&](MaskSet &m) { m.insert(rel); });
    return 0;
}

static void RewritePrefix(VfsState &S, std::atomic<MaskPtr> &a, const std::string &o, const std::string &n)
{
    MutateMask(S, a, [&](MaskSet &m) {
        MaskSet next;
        for (const std::string &x : m)
            if (x == o) next.insert(n);
            else if (x.rfind(o + "/", 0) == 0) next.insert(n + x.substr(o.size()));
            else next.insert(x);
        m.swap(next);
    });
}

void KeptRenamePrefix(VfsState &S, const std::string &oldv, const std::string &newv)
{
    const Layer *L = KeptLayerFor(S, oldv);
    if (!L || L != KeptLayerFor(S, newv)) return;
    const std::string o = SourceRel(*L, oldv), n = SourceRel(*L, newv);
    RewritePrefix(S, L->kept->deleted, o, n);
    RewritePrefix(S, L->kept->opaque, o, n);
}

void KeptDropMarkersUnder(VfsState &S, const std::string &vrel)
{
    const Layer *L = KeptLayerFor(S, vrel);
    if (!L) return;
    const std::string rel = SourceRel(*L, vrel), host = KeptHost(*L, rel);
    HostIO::ReadDir(host, [&](const std::string &n) { if (n.rfind(".wh.", 0) == 0) HostIO::Unlink(host + "/" + n); });
    auto under = [&](const std::string &x) { return rel.empty() ? !x.empty() && x.find('/') == std::string::npos
                                                                : x.rfind(rel + "/", 0) == 0 && x.find('/', rel.size() + 1) == std::string::npos; };
    MutateMask(S, L->kept->deleted, [&](MaskSet &m) { for (auto it = m.begin(); it != m.end();) it = under(*it) ? m.erase(it) : std::next(it); });
    MutateMask(S, L->kept->opaque, [&](MaskSet &m) { m.erase(rel); });
}

int EnsureWriteParent(VfsState &S, const std::string &vrel)
{
    std::string parent = ParentVRel(vrel);
    std::error_code ec;
    fs::create_directories(WLPath(S, parent), ec);
    return ec ? -EIO : 0;
}

int CopyUp(VfsState &S, const std::string &vrel, const ResolveResult &rr)
{
    if (S.writelayer.empty()) return -EROFS;
    if (rr.kind == HitKind::WriteLayer) return 0;       // already writable
    if (rr.rwPassthrough) return 0;                     // writes pass straight to source

    std::lock_guard<std::mutex> g(S.CopyUpLock(vrel));

    //A path under a KEEP (rw passthrough) subtree must copy up INTO the passthrough source — the durable
    //store — not into the ephemeral writelayer. Without this, modifying a file that exists in a LOWER
    //layer (e.g. a package-seeded config inside a persisted dir) landed in the writelayer and silently
    //vanished at teardown, while newly-created files (VfsCreate → passthrough) persisted — the
    //"seeded config never keeps the game's changes" hole.
    std::string dst;
    const bool ToPassthrough = PassthroughHost(S, vrel, dst);
    if (!ToPassthrough) dst = WLPath(S, vrel);
    HostIO::Stat st;
    if (HostIO::Lstat(dst, st) == 0) return 0;          // another thread already copied it up

    if (ToPassthrough)
    {
        std::error_code Pec;
        fs::create_directories(fs::path(dst).parent_path(), Pec);   // durable parent chain (mirrors EnsureHostParent)
        if (Pec) return -EIO;
    }
    else if (int e = EnsureWriteParent(S, vrel); e != 0) return e;

    // Directory copy-up: just create the dir in the writelayer. Classify with the SAME follow semantics
    // Resolve used to serve this hit: under flatten a data dir-layer symlink to a directory is served as a
    // dir (getattr uses StatFollow), so copy-up must see a dir too — else it would open the link as a file
    // and stream a directory's bytes. rw/writelayer hits keep the link-itself (Lstat) view.
    const bool followSyms = S.flattenSymlinks && !rr.rwPassthrough && rr.kind == HitKind::DirLayer;
    auto dirStat = [&](const std::string &p) {
        return followSyms ? HostIO::StatFollow(p, st) == 0 && st.isDir
                          : HostIO::Lstat(p, st) == 0 && st.isDir;
    };
    bool isDir = (rr.kind == HitKind::ImplicitDir) ||
                 (rr.kind == HitKind::DirLayer && dirStat(rr.hostPath)) ||
                 (rr.kind == HitKind::ZipEntry && (rr.zipEntry == nullptr || rr.zipEntry->isDir));
    if (isDir)
    {
        std::error_code ec;
        fs::create_directories(dst, ec);
        return ec ? -EIO : 0;
    }

    // Symlink copy-up: recreate the link itself; never dereference it into a regular file. An archive link that
    // reaches here is one served as a link (one resolving to a file inside the archive is served as that file).
    // Host-layer links under flattening are followed (the generic file copy-up below copies the TARGET's content).
    if (rr.kind == HitKind::ZipEntry && rr.zipEntry && rr.zipEntry->symlink)
    {
        if (rr.zipEntry->size > 4096) return -ENAMETOOLONG;
        ZipReader zr;
        if (int e = OpenZipEntry(*const_cast<ZipIndex *>(rr.layer->zip.get()), *rr.zipEntry, zr); e != 0) return e;
        std::string tgt(rr.zipEntry->size, '\0');
        int got = ReadZipEntry(zr, tgt.data(), tgt.size(), 0);
        if (got < 0) return got;
        tgt.resize(got);
        return HostIO::Symlink(tgt, dst);
    }
    if (!S.flattenSymlinks)
    {
        if ((rr.kind == HitKind::DirLayer || rr.kind == HitKind::FileLayer) &&
            HostIO::Lstat(rr.hostPath, st) == 0 && st.isSymlink)
        {
            std::string tgt;
            if (int e = HostIO::Readlink(rr.hostPath, tgt); e != 0) return e;
            return HostIO::Symlink(tgt, dst);
        }
    }

    // File copy-up: materialize full content into the writelayer.
    HostIO::Fd out = HostIO::Open(dst, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (out < 0) return out;

    int rc = 0;
    if (rr.kind == HitKind::ZipEntry && rr.zipEntry)
    {
        ZipReader zr;
        rc = OpenZipEntry(*const_cast<ZipIndex *>(rr.layer->zip.get()), *rr.zipEntry, zr);
        if (rc == 0)
        {
            char buf[256 * 1024];
            off_t off = 0;
            for (;;)
            {
                int got = ReadZipEntry(zr, buf, sizeof buf, off);
                if (got < 0) { rc = got; break; }
                if (got == 0) break;
                if (int we = HostIO::FullWrite(out, buf, (size_t)got); we != 0) { rc = we; break; }
                off += got;
            }
        }
        // The mode the entry was served with (getattr: 0555) plus the owner write bit, as for a host file below: a
        // 0644 copy dropped the executable bit, and a patched program (a BinaryPatch on a zipped ELF) no longer ran.
        if (rc == 0) HostIO::Fchmod(out, 0555 | 0200);
    }
    else // DirLayer or FileLayer host file
    {
        HostIO::Fd in = HostIO::Open(rr.hostPath, O_RDONLY);
        if (in < 0) { rc = (int)in; }
        else
        {
            char buf[256 * 1024];
            ssize_t got;
            while ((got = HostIO::Read(in, buf, sizeof buf)) > 0)
                if (int we = HostIO::FullWrite(out, buf, (size_t)got); we != 0) { rc = we; break; }
            if (got < 0 && rc == 0) rc = (int)got;
            HostIO::Close(in);
            // Keep the lower file's mode — but the copy is a COW copy that exists to be WRITTEN: force the owner
            // write bit. A lower layer served from a read-only mount (a runner build mounted `readonly`, every
            // file 0555) otherwise yields an unwritable copy, and the very open(O_WRONLY) that triggered the
            // copy-up fails with EACCES — every in-place edit of a runner-provided file (a wine hive) was lost.
            if (HostIO::Lstat(rr.hostPath, st) == 0) HostIO::Fchmod(out, (st.mode & 0777) | 0200);
        }
    }
    HostIO::Close(out);
    if (rc != 0) HostIO::Unlink(dst);
    return rc;
}
