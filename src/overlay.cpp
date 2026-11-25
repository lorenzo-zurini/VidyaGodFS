#include "overlay.h"

#include <map>
#include "treeplan.h"
#include "vgdelta.h"
#include "hostio.h"     // all host filesystem I/O goes through the backend-neutral shim

#include <algorithm>
#include <filesystem>
#include <map>
#include <fstream>
#include <cstring>
#include <cerrno>
#include <cstdio>
#include <unordered_map>
#include <unordered_set>
#include <fcntl.h>      // O_RDONLY / O_CREAT / O_WRONLY / O_TRUNC flag constants (passed to HostIO::Open)
#include <iostream>

namespace fs = std::filesystem;
static constexpr uint64_t kIndexPrefetch = 1ull << 20;
static std::atomic<long long> g_CaseWalks{ 0 };   // archive members submounts' case names were walked over   // what a mount reads first of each archive, asked for at once

// ---- small path helpers --------------------------------------------------

// Symlink abolition containment: a followed DATA-layer symlink must resolve to a real path that stays
// INSIDE the layer's source root. A zip layer already rejects absolute targets; a dir layer's host symlink
// could point at an absolute path (`-> /etc/passwd`) or `../..`-escape the source, which would make the FS
// serve an arbitrary host file. Returns true iff the followed `host` path is contained in `layerSource`.
//layerCanon is the layer's source resolved once at Init (Layer::sourceCanon): resolving it again at every link met —
//a lookup per path component, through FUSE when the source is another mount — always gave the same answer.
static bool SymlinkContained(const std::string &host, const std::string &layerCanon)
{
    std::error_code ec;
    std::filesystem::path resolved = std::filesystem::weakly_canonical(host, ec);
    if (ec || layerCanon.empty()) return false;
    const std::filesystem::path rootc(layerCanon);
    // Lexical prefix check on canonical paths (both absolute, no symlinks remaining).
    auto rit = rootc.begin(), rend = rootc.end();
    auto pit = resolved.begin(), pend = resolved.end();
    for (; rit != rend; ++rit, ++pit)
        if (pit == pend || *pit != *rit) return false;
    return true;   // resolved == rootc or a descendant
}

//Every path under source/sub (relative to source, folded when case-insensitive), when there are at most kListMax and
//none is a link; else null (Layer::listed).
static constexpr size_t kListMax = 20000;
static std::shared_ptr<const std::unordered_set<std::string>> ListSmallDirLayer(const std::string &source, const std::string &sub, bool fold)
{
    auto Out = std::make_shared<std::unordered_set<std::string>>();
    bool Ok = true;
    //Not listed: a folder it cannot read (taken for empty, its files were never found), a link (what it names may
    //change), and — folded — a name past ASCII (FoldCase folds ASCII alone; the host's own lookup matched the rest).
    std::function<void(const std::string &)> Walk = [&](const std::string &rel) {
        if (!Ok) return;
        const int e = HostIO::ReadDirTyped(rel.empty() ? source : source + "/" + rel, [&](const std::string &n, int isDir) {
            if (!Ok) return;
            const std::string Child = rel.empty() ? n : rel + "/" + n;
            if (isDir == 2) { Ok = false; return; }
            if (isDir < 0)
            {
                HostIO::Stat st;   // only what the listing leaves untyped
                if (HostIO::Lstat(source + "/" + Child, st) != 0 || st.isSymlink) { Ok = false; return; }
                isDir = st.isDir ? 1 : 0;
            }
            if (fold && std::any_of(n.begin(), n.end(), [](char c) { return (unsigned char)c >= 0x80; })) { Ok = false; return; }
            if (Out->size() >= kListMax) { Ok = false; return; }
            Out->insert(fold ? FoldCase(Child) : Child);
            if (isDir == 1) Walk(Child);
        });
        if (e != 0) Ok = false;
    };
    HostIO::Stat st;
    if (!sub.empty() && (HostIO::Lstat(source + "/" + sub, st) != 0 || !st.isDir || st.isSymlink)) return nullptr;
    if (!sub.empty()) Out->insert(fold ? FoldCase(sub) : sub);
    Walk(sub);
    if (!Ok) return nullptr;
    return Out;
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
static void SeedKeptMasks(Layer &L, bool Fold, bool Disk);      // likewise, for each kept folder

static std::string PatchKey(const VfsState &S, const std::string &vrel);

bool VfsState::Init(const Spec &S, std::string &Err)
{
    writelayer = S.writelayer;
    readOnly   = S.readOnly;
    uid        = S.uid;
    gid        = S.gid;
    caseInsensitive = S.caseInsensitive;   // before any mask is seeded: their keys fold with it (MaskKey)

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
            if (LS.type == LayerType::Dir)
            {
                std::error_code Ec;
                const std::filesystem::path C = std::filesystem::weakly_canonical(LS.source, Ec);
                if (!Ec) L.sourceCanon = C.string();
                //Only a layer whose source cannot change while mounted is answered from a listing taken now (a
                //runtime-sourced folder is filled by another mount after this one starts).
                if (!LS.rw && LS.fixed) L.listed = ListSmallDirLayer(LS.source, sub, S.caseInsensitive);
            }
            if (LS.type == LayerType::File)
            {
                //Placed whole: in its target folder, by its own name; through a submount: at the submount's path, by
                //that path's name (a TAKE renaming it).
                L.fileVPath = !sub.empty() ? tgt : L.target.empty() ? BaseName(LS.source) : (L.target + "/" + BaseName(LS.source));
                L.fileBase  = BaseName(L.fileVPath);
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
        if (L.type == LayerType::Dir && L.rw) SeedKeptMasks(L, caseInsensitive, uncached);
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
            if (L.subpath.empty())
            {
                for (const auto &[Name, E] : L.zip->byName) AddZip(Name);
                for (const auto &[Dir, Kids] : L.zip->dirChildren) AddZip(Dir);
                continue;
            }
            //A submount spells only what lies under its subpath: walked from there down the archive's own tree, not
            //found by a look at every member of the archive — once per submount of it.
            AddZip(L.subpath);
            std::function<void(const std::string &)> Walk = [&](const std::string &D) {
                const auto It = L.zip->dirChildren.find(D);
                if (It == L.zip->dirChildren.end()) return;
                for (const std::string &K : It->second) { const std::string C = D + "/" + K; ++g_CaseWalks; AddZip(C); Walk(C); }
            };
            Walk(L.subpath);
        }
        for (const std::string &D : implicitDirs) canonCase.try_emplace(FoldCase(D), D);
    }
    //The byte patches, by the path as the layers spell it: in spec order onto each file's bytes (a later one wins on a
    //byte two cover), then merged into runs.
    {
        //Runs by offset, none touching another: a patch goes into the run that reaches it (grown in place) and takes in
        //every later run it reaches, keeping their bytes past its own.
        std::unordered_map<std::string, std::map<uint64_t, std::vector<uint8_t>>> Runs;
        for (const BytePatch &Patch : S.patches)
        {
            if (Patch.bytes.empty()) continue;
            auto &M = Runs[PatchKey(*this, NormalizeVPath(Patch.path))];
            const uint64_t End = Patch.at + Patch.bytes.size();
            auto Run = M.upper_bound(Patch.at);
            if (Run != M.begin() && std::prev(Run)->first + std::prev(Run)->second.size() >= Patch.at) --Run;
            else Run = M.emplace(Patch.at, std::vector<uint8_t>()).first;
            std::vector<uint8_t> &V = Run->second;
            const uint64_t Base = Run->first;
            if (V.size() < End - Base) V.resize((size_t)(End - Base));
            std::copy(Patch.bytes.begin(), Patch.bytes.end(), V.begin() + (std::ptrdiff_t)(Patch.at - Base));
            for (auto Next = std::next(Run); Next != M.end() && Next->first <= Base + V.size();)
            {
                if (Next->first + Next->second.size() > Base + V.size())
                    V.insert(V.end(), Next->second.begin() + (std::ptrdiff_t)(Base + V.size() - Next->first), Next->second.end());
                Next = M.erase(Next);
            }
        }
        for (auto &[Path, M] : Runs)
        {
            PatchRuns &R = patches[Path];
            for (auto &[At, B] : M) R.push_back(PatchRun{ At, std::move(B) });
        }
    }
    return true;
    (void)Err;
}

//A patch's key: its path, folded where names match whatever their case (a folder layer's names are not in canonCase).
static std::string PatchKey(const VfsState &S, const std::string &vrel) { return S.caseInsensitive ? FoldCase(vrel) : vrel; }

const PatchRuns *PatchesFor(const VfsState &S, const std::string &vrel)
{
    if (S.patches.empty()) return nullptr;
    const auto It = S.patches.find(PatchKey(S, vrel));
    return It == S.patches.end() ? nullptr : &It->second;
}

void OverlayPatches(const PatchRuns *P, void *Buf, size_t N, uint64_t Off)
{
    if (!P || N == 0) return;
    auto *Out = static_cast<uint8_t *>(Buf);
    const uint64_t End = Off + N;
    //The first run that ends after Off.
    auto It = std::upper_bound(P->begin(), P->end(), Off, [](uint64_t O, const PatchRun &R) { return O < R.at + R.bytes.size(); });
    for (; It != P->end() && It->at < End; ++It)
    {
        const uint64_t From = std::max(Off, It->at), To = std::min(End, It->at + It->bytes.size());
        std::memcpy(Out + (From - Off), It->bytes.data() + (From - It->at), (size_t)(To - From));
    }
}

bool PatchesOverlap(const PatchRuns *P, uint64_t Off, size_t N)
{
    if (!P || N == 0) return false;
    const auto It = std::upper_bound(P->begin(), P->end(), Off, [](uint64_t O, const PatchRun &R) { return O < R.at + R.bytes.size(); });
    return It != P->end() && It->at < Off + N;
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
using MaskPtr = std::shared_ptr<const MaskSnap>;

static MaskPtr LoadMask(const std::atomic<MaskPtr> &a)
{
    return a.load(std::memory_order_acquire);
}

//A mask of a whole set (Init's seeding).
static MaskPtr WholeMask(std::shared_ptr<MaskSet> Set)
{
    auto M = std::make_shared<MaskSnap>();
    M->base = std::move(Set);
    return M;
}

std::atomic<long long> g_MaskFolds{ 0 };
long long DebugCaseWalks() { return g_CaseWalks.load(); }
long long DebugMaskFolds() { return g_MaskFolds.load(); }

//One name in (In) or out of the mask: a copy of the changes since the last fold only, the shared set as it is. Under
//maskWriteMtx; readers keep the version they loaded.
static void EditMask(VfsState &S, std::atomic<MaskPtr> &a, const std::string &K, bool In)
{
    std::lock_guard<std::mutex> g(S.maskWriteMtx);
    MaskPtr cur = a.load(std::memory_order_acquire);
    auto next = cur ? std::make_shared<MaskSnap>(*cur) : std::make_shared<MaskSnap>();
    if (In) { if (!next->removed.erase(K) && !next->base->count(K)) next->added.insert(K); }
    else    { if (!next->added.erase(K) && next->base->count(K)) next->removed.insert(K); }
    if (next->added.size() + next->removed.size() > std::max<size_t>(256, next->base->size() / 8))
    {   // folded in: the whole set copied once per an eighth of its size in changes
        auto Whole = std::make_shared<MaskSet>(*next->base);
        for (const auto &R : next->removed) Whole->erase(R);
        Whole->insert(next->added.begin(), next->added.end());
        next = std::make_shared<MaskSnap>();
        next->base = std::move(Whole);
        ++g_MaskFolds;
    }
    a.store(std::move(next), std::memory_order_release);
}

//Clone-modify-swap of the whole set under maskWriteMtx (a rename's rewrite of every name under a folder). `mut`
//edits the writable clone, which becomes the new base.
static void MutateMask(VfsState &S, std::atomic<MaskPtr> &a, const std::function<void(MaskSet &)> &mut)
{
    std::lock_guard<std::mutex> g(S.maskWriteMtx);
    MaskPtr cur = a.load(std::memory_order_acquire);
    auto Whole = std::make_shared<MaskSet>(cur ? *cur->base : MaskSet{});
    if (cur)
    {
        for (const auto &R : cur->removed) Whole->erase(R);
        Whole->insert(cur->added.begin(), cur->added.end());
    }
    mut(*Whole);
    a.store(WholeMask(std::move(Whole)), std::memory_order_release);
}

//A mask's key for vrel: folded where names match whatever their case. The masks hold names as the backend was handed
//them, and CanonicalCase gives one spelling only to the names a layer registered (an archive's, a target's) — a
//folder layer's own files keep the caller's: `del DATA\X.TXT` of Data/x.txt was masked as DATA/X.TXT, and the next
//open of data\x.txt served the deleted file again.
static std::string MaskKey(bool Fold, const std::string &K) { return Fold ? FoldCase(K) : K; }
static std::string MaskKey(const VfsState &S, const std::string &K) { return MaskKey(S.caseInsensitive, K); }

std::string WhiteoutPath(const VfsState &S, const std::string &vrel)
{
    return WLPath(S, ParentVRel(vrel)) + "/.wh." + BaseName(vrel);
}

//A marker on disk. Under uncached the masks are read there, not from the sets: another mount of the writelayer (the
//sandbox's) writes and removes them, and the sets know only this mount's own changes.
static bool MarkerOnDisk(const std::string &P)
{
    HostIO::Stat st;
    return HostIO::Lstat(P, st) == 0;
}

static std::string OpaqueMarker(const VfsState &S, const std::string &vrel)
{
    return WLPath(S, vrel) + "/.wh..wh..opq";
}

bool IsWhiteouted(const VfsState &S, const std::string &vrel)
{
    if (S.writelayer.empty() || vrel.empty()) return false;
    if (S.uncached) return MarkerOnDisk(WhiteoutPath(S, vrel));
    MaskPtr m = LoadMask(S.whiteoutSet);
    return m && m->count(MaskKey(S, vrel)) != 0;
}

//The mask follows the disk: a marker that could not be written (a full disk, no inodes) is not taken for written —
//the deletion fails, and the file is still there this session and the next (it came back after a relaunch).
int CreateWhiteout(VfsState &S, const std::string &vrel)
{
    if (S.writelayer.empty()) return 0;
    std::error_code ec;
    fs::create_directories(WLPath(S, ParentVRel(vrel)), ec);
    HostIO::Fd fd = HostIO::Open(WhiteoutPath(S, vrel), O_CREAT | O_WRONLY, 0644);
    if (fd < 0) return (int)fd;
    HostIO::Close(fd);
    EditMask(S, S.whiteoutSet, MaskKey(S, vrel), true);
    return 0;
}

int RemoveWhiteout(VfsState &S, const std::string &vrel)
{
    if (S.writelayer.empty()) return 0;
    if (int e = HostIO::Unlink(WhiteoutPath(S, vrel)); e != 0 && e != -ENOENT) return e;   // still on disk: still masked
    EditMask(S, S.whiteoutSet, MaskKey(S, vrel), false);
    return 0;
}

int MarkOpaque(VfsState &S, const std::string &vrel)
{
    if (S.writelayer.empty()) return 0;
    HostIO::Fd fd = HostIO::Open(OpaqueMarker(S, vrel), O_CREAT | O_WRONLY, 0644);
    if (fd < 0) return (int)fd;   // not recorded on disk: not in memory either (a remount would disagree)
    HostIO::Close(fd);
    EditMask(S, S.opaqueSet, MaskKey(S, vrel), true);
    return 0;
}

void UnmarkOpaque(VfsState &S, const std::string &vrel)
{
    if (S.writelayer.empty()) return;
    // Disk marker removal is the caller's business (the rmdir sweep already unlinks it); just drop the mask.
    EditMask(S, S.opaqueSet, MaskKey(S, vrel), false);
}

void RenameMaskPrefix(VfsState &S, const std::string &oldName, const std::string &newName)
{
    if (S.writelayer.empty() || oldName == newName) return;
    const std::string oldv = MaskKey(S, oldName), newv = MaskKey(S, newName);
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
    if (S.uncached)
    {
        for (std::string cur = ParentVRel(vrel); !cur.empty(); cur = ParentVRel(cur))
            if (MarkerOnDisk(WhiteoutPath(S, cur))) return true;
        return false;
    }
    MaskPtr m = LoadMask(S.whiteoutSet);
    if (!m || m->empty()) return false;
    for (std::string cur = ParentVRel(MaskKey(S, vrel)); !cur.empty(); cur = ParentVRel(cur))
        if (m->count(cur) != 0) return true;
    return false;
}

//True if any ancestor directory of vrel (including the root) is opaque — meaning the lower layers are
//masked here. Empty-set fast path; pure in-memory lookups.
bool IsUnderOpaque(const VfsState &S, const std::string &vrel)
{
    if (S.writelayer.empty()) return false;
    if (S.uncached)
    {
        for (std::string cur = ParentVRel(vrel);; cur = ParentVRel(cur))
        {
            if (MarkerOnDisk(OpaqueMarker(S, cur))) return true;
            if (cur.empty()) return false;   // the root's, last
        }
    }
    MaskPtr m = LoadMask(S.opaqueSet);
    if (!m || m->empty()) return false;
    for (std::string cur = ParentVRel(MaskKey(S, vrel)); !cur.empty(); cur = ParentVRel(cur))
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
        HostIO::ReadDirTyped(host, [&](const std::string &n, int isDir) {
            std::string childV = vdir.empty() ? n : vdir + "/" + n;
            if (n == ".wh..wh..opq") { opq->insert(MaskKey(S, vdir)); return; }
            if (n.rfind(kCopyTmpPrefix, 0) == 0) { HostIO::Unlink(host + "/" + n); return; }   // a copy cut short
            if (n.rfind(".wh.", 0) == 0) { wh->insert(MaskKey(S, vdir.empty() ? n.substr(4) : vdir + "/" + n.substr(4))); return; }
            HostIO::Stat st;   // the listing's own type: a stat per entry only where it does not say
            if (isDir == 1 || (isDir < 0 && HostIO::Lstat(host + "/" + n, st) == 0 && st.isDir)) walk(childV);
        });
    };
    walk("");
    S.whiteoutSet.store(WholeMask(std::move(wh)), std::memory_order_release);
    S.opaqueSet.store(WholeMask(std::move(opq)), std::memory_order_release);
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
            if (L.listed && !rel.empty() && !L.listed->count(S.caseInsensitive ? FoldCase(rel) : rel)) continue;   // not in it: no stat
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
                    (HostIO::StatFollow(host, st) != 0 || !SymlinkContained(host, L.sourceCanon)))
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

//rel's key in a kept folder's masks (MaskKey: folded on a case-insensitive mount).
static std::string KeptKey(const Layer &L, const std::string &rel) { return MaskKey(L.kept && L.kept->fold, rel); }

static bool InMask(const Layer &L, const std::atomic<MaskPtr> &a, const std::string &rel)
{
    MaskPtr m = LoadMask(a);
    return m && m->count(KeptKey(L, rel)) != 0;
}

//rel deleted in kept folder L / made again over a deleted one there: read from the folder under uncached (KeptMasks::disk).
static bool KeptDeleted(const Layer &L, const std::string &rel)
{
    if (L.kept->disk) return !rel.empty() && MarkerOnDisk(KeptMarker(L, rel));
    return InMask(L, L.kept->deleted, rel);
}
static bool KeptOpaque(const Layer &L, const std::string &rel)
{
    if (L.kept->disk) return MarkerOnDisk(KeptHost(L, rel) + "/.wh..wh..opq");
    return InMask(L, L.kept->opaque, rel);
}

//Init-time: one walk of each kept folder for its markers (the folder holds only what the user's games wrote).
static void SeedKeptMasks(Layer &L, bool Fold, bool Disk)
{
    auto del = std::make_shared<MaskSet>(), opq = std::make_shared<MaskSet>();
    std::function<void(const std::string &)> walk = [&](const std::string &rel) {
        const std::string host = KeptHost(L, rel);
        //The listing's own type: a stat per entry, to learn it, made a mount of a kept folder of 100,000 saves and mods
        //100,000 stats (seconds on cold metadata). Only an entry the listing does not type is stat'd.
        HostIO::ReadDirTyped(host, [&](const std::string &n, int isDir) {
            if (n == ".wh..wh..opq") { opq->insert(MaskKey(Fold, rel)); return; }
            if (n.rfind(kCopyTmpPrefix, 0) == 0) { HostIO::Unlink(host + "/" + n); return; }   // a copy cut short
            if (n.rfind(".wh.", 0) == 0) { del->insert(MaskKey(Fold, rel.empty() ? n.substr(4) : rel + "/" + n.substr(4))); return; }
            HostIO::Stat st;
            if (isDir == 1 || (isDir < 0 && HostIO::Lstat(host + "/" + n, st) == 0 && st.isDir)) walk(rel.empty() ? n : rel + "/" + n);
        });
    };
    walk(L.subpath);
    L.kept = std::make_shared<KeptMasks>();
    L.kept->fold = Fold;
    L.kept->disk = Disk;
    L.kept->deleted.store(WholeMask(std::move(del)), std::memory_order_release);
    L.kept->opaque.store(WholeMask(std::move(opq)), std::memory_order_release);
}

int HideLower(VfsState &S, const std::string &vrel)
{
    if (const Layer *L = KeptLayerFor(S, vrel))
    {
        const std::string rel = SourceRel(*L, vrel);
        if (!rel.empty())
        {
            if (int e = TouchMarker(KeptMarker(*L, rel)); e != 0) return e;
            EditMask(S, L->kept->deleted, KeptKey(*L, rel), true);
            return 0;
        }
    }
    return CreateWhiteout(S, vrel);
}

int UnhideLower(VfsState &S, const std::string &vrel)
{
    if (const Layer *L = KeptLayerFor(S, vrel))
        if (const std::string rel = SourceRel(*L, vrel); !rel.empty() && KeptDeleted(*L, rel))
        {
            if (int e = HostIO::Unlink(KeptMarker(*L, rel)); e != 0 && e != -ENOENT) return e;
            EditMask(S, L->kept->deleted, KeptKey(*L, rel), false);
        }
    return RemoveWhiteout(S, vrel);
}

bool KeptHidden(const VfsState &S, const std::string &vrel)
{
    const Layer *L = KeptLayerFor(S, vrel);
    return L && KeptDeleted(*L, SourceRel(*L, vrel));
}

bool KeptOpaqueDir(const Layer &L, const std::string &vrel)
{
    return L.kept && KeptOpaque(L, SourceRel(L, vrel));
}

bool KeptMasked(const Layer &L, const std::string &vrel)
{
    if (!L.kept) return false;
    if (L.kept->disk)
    {
        const std::string rel = SourceRel(L, vrel);
        if (rel.empty()) return false;
        if (KeptDeleted(L, rel)) return true;
        for (std::string cur = ParentVRel(rel);; cur = ParentVRel(cur))
        {
            if (KeptDeleted(L, cur) || KeptOpaque(L, cur)) return true;
            if (cur.empty()) return false;
        }
    }
    MaskPtr del = LoadMask(L.kept->deleted), opq = LoadMask(L.kept->opaque);
    const bool anyDel = del && !del->empty(), anyOpq = opq && !opq->empty();
    if (!anyDel && !anyOpq) return false;
    std::string rel = KeptKey(L, SourceRel(L, vrel));
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
    EditMask(S, L->kept->opaque, KeptKey(*L, rel), true);
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
    const std::string o = KeptKey(*L, SourceRel(*L, oldv)), n = KeptKey(*L, SourceRel(*L, newv));
    RewritePrefix(S, L->kept->deleted, o, n);
    RewritePrefix(S, L->kept->opaque, o, n);
}

void KeptDropMarkersUnder(VfsState &S, const std::string &vrel)
{
    const Layer *L = KeptLayerFor(S, vrel);
    if (!L) return;
    const std::string host = KeptHost(*L, SourceRel(*L, vrel)), rel = KeptKey(*L, SourceRel(*L, vrel));
    HostIO::ReadDir(host, [&](const std::string &n) { if (n.rfind(".wh.", 0) == 0) HostIO::Unlink(host + "/" + n); });
    auto under = [&](const std::string &x) { return rel.empty() ? !x.empty() && x.find('/') == std::string::npos
                                                                : x.rfind(rel + "/", 0) == 0 && x.find('/', rel.size() + 1) == std::string::npos; };
    MutateMask(S, L->kept->deleted, [&](MaskSet &m) { for (auto it = m.begin(); it != m.end();) it = under(*it) ? m.erase(it) : std::next(it); });
    EditMask(S, L->kept->opaque, rel, false);
}

int EnsureWriteParent(VfsState &S, const std::string &vrel)
{
    std::string parent = ParentVRel(vrel);
    std::error_code ec;
    fs::create_directories(WLPath(S, parent), ec);
    return ec ? -EIO : 0;
}

VfsState::PendingCopy::~PendingCopy()
{
    if (const int Fd = upper.load(); Fd >= 0) HostIO::Close(Fd);
}

std::string VfsState::PendingKey(const std::string &vrel) const
{
    return caseInsensitive ? FoldCase(vrel) : vrel;
}

std::shared_ptr<VfsState::PendingCopy> VfsState::PendingFor(const std::string &vrel, unsigned long long SeenDetaches,
                                                            const std::function<bool()> &StillOpened)
{
    std::lock_guard<std::mutex> g(pendingMu);
    //A name changed (unlinked, renamed over, made again) since the open resolved it, and what it names now is not the
    //file the open has: a marker of its own, off every name.
    if (detaches.load() != SeenDetaches && !StillOpened())
    {
        auto Own = std::make_shared<PendingCopy>();
        Own->detached.store(true);
        return Own;
    }
    const std::string K = PendingKey(vrel);
    auto &W = pendingCopies[K];
    if (auto P = W.lock()) return P;
    auto P = std::make_shared<PendingCopy>();
    W = P;
    //Markers no handle holds any more go now and then — every open of a lower file makes one, so a sweep at each was
    //the square of the open handles.
    if (pendingCopies.size() >= pendingPruneAt)
    {
        for (auto It = pendingCopies.begin(); It != pendingCopies.end();)
            It = It->second.expired() && It->first != K ? pendingCopies.erase(It) : std::next(It);
        pendingPruneAt = std::max<size_t>(64, pendingCopies.size() * 2);
    }
    return P;
}

void VfsState::MarkCopied(const std::string &vrel, HostIO::Fd Fd)
{
    std::lock_guard<std::mutex> g(pendingMu);
    const auto It = pendingCopies.find(PendingKey(vrel));
    const auto P = It == pendingCopies.end() ? nullptr : It->second.lock();
    int Expected = -1;
    if (!P || !P->upper.compare_exchange_strong(Expected, Fd, std::memory_order_acq_rel)) HostIO::Close(Fd);
}

void VfsState::BeginNameChange()
{
    std::lock_guard<std::mutex> g(pendingMu);
    ++nameChanges;
    ++detaches;
}

void VfsState::EndNameChange(const std::vector<std::pair<std::string, bool>> &Detach)
{
    {
        std::lock_guard<std::mutex> g(pendingMu);
        for (const auto &[V, Subtree] : Detach) DetachPendingLocked(V, Subtree);
        --nameChanges;
    }
    nameChangeCv.notify_all();
}

void VfsState::AdoptCopy(const std::string &vrel, const std::string &host)
{
    std::unique_lock<std::mutex> g(pendingMu);
    //A change half done: what host is, is not known yet. Once it is done, a marker its name no longer names is out of
    //the map (DetachPendingLocked): nothing is adopted for it.
    nameChangeCv.wait(g, [&] { return nameChanges == 0; });
    const auto It = pendingCopies.find(PendingKey(vrel));
    const auto P = It == pendingCopies.end() ? nullptr : It->second.lock();
    if (!P || P->upper.load(std::memory_order_acquire) >= 0) return;
    const HostIO::Fd Fd = HostIO::Open(host, O_RDWR);
    if (Fd < 0)
    {
        std::fprintf(stderr, "vidyagodfs: the copy of %s cannot be opened (%d): its handles keep reading below and "
                             "fail to write\n", vrel.c_str(), Fd);
        return;
    }
    P->upper.store(Fd, std::memory_order_release);
}

void VfsState::DetachPendingLocked(const std::string &vrel, bool subtree)
{
    ++detaches;
    const std::string K = PendingKey(vrel);
    const auto Detach = [](std::unordered_map<std::string, std::weak_ptr<PendingCopy>>::iterator It) {
        if (auto P = It->second.lock()) P->detached.store(true, std::memory_order_release);
    };
    if (const auto It = pendingCopies.find(K); It != pendingCopies.end()) { Detach(It); pendingCopies.erase(It); }
    if (!subtree) return;
    const std::string Under = K.empty() ? std::string() : K + "/";
    for (auto It = pendingCopies.begin(); It != pendingCopies.end();)
        if (It->first.compare(0, Under.size(), Under) == 0) { Detach(It); It = pendingCopies.erase(It); }
        else ++It;
}

static int CopyUpImpl(VfsState &S, const std::string &vrel, const ResolveResult &rr, HostIO::Fd &copyFd);

//Every copy-up opens the copy for the handles still reading the path from below (VfsOpen), once.
int CopyUp(VfsState &S, const std::string &vrel, const ResolveResult &rr)
{
    HostIO::Fd copyFd = -1;
    const int rc = CopyUpImpl(S, vrel, rr, copyFd);
    if (rc != 0) return rc;
    if (rr.kind == HitKind::WriteLayer || rr.rwPassthrough) return 0;   // nothing below: nothing was copied
    ++S.copyUps;
    if (copyFd >= 0) S.MarkCopied(vrel, copyFd);   // the copy itself, whatever its name meets from here on
    return 0;
}

static int CopyUpImpl(VfsState &S, const std::string &vrel, const ResolveResult &rr, HostIO::Fd &copyFd)
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

    // File copy-up: materialize full content into the writelayer — under a name no listing shows, renamed to its own
    // when whole: a copy cut short (a full disk, a crash, a kill) is never taken for the file ("already copied" above).
    static std::atomic<unsigned long long> CopySeq{ 0 };
    const std::string tmp = fs::path(dst).parent_path().string() + "/" + kCopyTmpPrefix + std::to_string(++CopySeq);
    HostIO::Fd out = HostIO::Open(tmp, O_CREAT | O_EXCL | O_RDWR | O_TRUNC, 0644);   // kept open: the handles' copy
    if (out < 0) return out;

    int rc = 0;
    const PatchRuns *Patched = PatchesFor(S, vrel);   // a lower file: its patches go into its copy
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
                OverlayPatches(Patched, buf, (size_t)got, (uint64_t)off);   // the copy is the file as it was read
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
            uint64_t at = 0;
            while ((got = HostIO::Read(in, buf, sizeof buf)) > 0)
            {
                OverlayPatches(Patched, buf, (size_t)got, at);
                at += (uint64_t)got;
                if (int we = HostIO::FullWrite(out, buf, (size_t)got); we != 0) { rc = we; break; }
            }
            if (got < 0 && rc == 0) rc = (int)got;
            HostIO::Close(in);
            // Keep the lower file's mode — but the copy is a COW copy that exists to be WRITTEN: force the owner
            // write bit. A lower layer served from a read-only mount (a runner build mounted `readonly`, every
            // file 0555) otherwise yields an unwritable copy, and the very open(O_WRONLY) that triggered the
            // copy-up fails with EACCES — every in-place edit of a runner-provided file (a wine hive) was lost.
            if (HostIO::Lstat(rr.hostPath, st) == 0) HostIO::Fchmod(out, (st.mode & 0777) | 0200);
        }
    }
    if (S.debugHook) S.debugHook("copy-before-rename");
    //Never over a file made at the name while this was copied (a game's save renamed into place): that one is newer.
    //The handles waiting on this copy were taken off the name by that change; they make copies of their own.
    if (rc == 0) rc = HostIO::RenameNoReplace(tmp, dst);
    if (rc == -EEXIST) { HostIO::Unlink(tmp); HostIO::Close(out); return 0; }
    if (rc != 0) { HostIO::Unlink(tmp); HostIO::Close(out); return rc; }
    copyFd = out;
    return 0;
}
