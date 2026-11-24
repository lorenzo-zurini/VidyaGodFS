#ifndef VIDYAGODFS_OVERLAY_H
#define VIDYAGODFS_OVERLAY_H

#include "layerspec.h"
#include "ziplayer.h"
#include "hostio.h"

#include <array>
#include <string>
#include <vector>
#include <set>
#include <memory>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <cstdint>
#include <functional>
#include <unordered_map>
#include <unordered_set>

//A deletion mask as its readers see it: a large set shared by every version of it, and the few changes made since they
//were last folded in. A change copies only those few (folded in once they pass an eighth of the set): copying the
//whole set at every delete made an installer's 10,000 deletes 50 M string copies. Invariant: removed ⊆ *base,
//added ∩ *base = ∅.
struct MaskSnap {
    std::shared_ptr<const std::set<std::string>> base = std::make_shared<const std::set<std::string>>();
    std::set<std::string> added, removed;
    size_t count(const std::string &K) const { return !removed.count(K) && (added.count(K) || base->count(K)) ? 1 : 0; }
    bool   empty() const { return added.empty() && removed.size() == base->size(); }
};

//A kept folder's deletion markers mirrored in memory, like the writelayer's (VfsState::whiteoutSet): the names
//deleted there and the directories made again over deleted ones (opaque), as paths relative to the layer's source
//(SourceRel). Seeded from the folder at Init, swapped copy-on-write under VfsState::maskWriteMtx on every change, so
//lookups through a kept folder never touch the disk for them.
struct KeptMasks {
    std::atomic<std::shared_ptr<const MaskSnap>> deleted;
    std::atomic<std::shared_ptr<const MaskSnap>> opaque;
};

//A resolved layer in the running filesystem.
struct Layer {
    LayerType   type = LayerType::Dir;
    std::string source;      // host path (dir / archive / single file)
    std::string target;      // normalized virtual subtree root ("" == mount root); for File, the containing dir
    std::string subpath;     // path within source exposed at target ("" == whole source). dir/zip only.
    bool        rw = false;  // Dir + rw:true = RW passthrough (writes go straight to source)
    // A delta reconstructs a complete archive OF WHAT IT REPLACES: the base it was diffed against. So it masks that
    // base (a file deleted in the newer version must not leak up from the older one), and nothing else: another
    // depot's archive at the same target shows through it like through any zip. maskedUnder = the virtual subtrees
    // (the mount targets of the deltas built over this layer) where this layer is hidden. A base hidden whole by its
    // delta never surfaces at all; this covers the rest (a base surfacing partly outside the delta).
    std::vector<std::string> maskedUnder;
    int         priority = 0;
    std::shared_ptr<ZipIndex> zip;  // Zip layers only
    std::string fileVPath;   // File layers only: target [+ "/"] + basename(source)
    std::string fileBase;    // File layers only: basename(source)
    std::shared_ptr<KeptMasks> kept;   // rw Dir layers (kept folders) only
    std::string sourceCanon;  // Dir layers: source with every link resolved, worked out once (SymlinkContained)
    //Read-only Dir layers small enough to list at Init (DefaultData, a package's small folders): every path it holds,
    //relative to source (folded, case-insensitive). A name it does not hold is a miss without a stat of the host —
    //DefaultData sits above all content, and every lookup in the mount stat'd it. Null: not listed (large, or holding
    //a link, through which a path cannot be known without the host).
    std::shared_ptr<const std::unordered_set<std::string>> listed;
};

//The whole running filesystem state, built once from a Spec and immutable afterward (lock-free reads),
//except per-path copy-up serialization.
struct VfsState {
    std::string           writelayer;   // empty when readOnly
    bool                  readOnly = false;
    // Symlink flattening (default ON, `-o keep-symlinks` serves every link as authored): an archive link that
    // resolves to a file inside the archive is served as that file (ResolveZipSymlink); any other archive link
    // (absolute, out of the archive, to a folder, dangling) is served as the link it is, as an installed copy
    // would be. A host-layer (dir/file) link is followed on the host or hidden. The WRITELAYER and rw passthrough
    // layers present links as they are: live runtime state written by the guest itself.
    bool                  flattenSymlinks = true;
    uint32_t              uid = 1000;    // forced ownership presented by getattr (POSIX; the WinFsp mount overrides it with the mounting user)
    uint32_t              gid = 1000;
    std::vector<Layer>    layers;        // ascending priority (index 0 lowest)
    std::set<std::string> implicitDirs;  // synthesized structural dirs (target parents)
    // Case-insensitive names (Spec::caseInsensitive): every name the layers know (zip entries and folders, layer
    // targets, structural dirs) by its folded (ASCII-lowercased) path, mapped to the case it has — the lowest layer's
    // when they differ. CanonicalCase maps an incoming path through it. Host-backed names (writelayer, dir layers)
    // need none: the host filesystem (NTFS) already ignores case.
    bool                                         caseInsensitive = false;
    std::unordered_map<std::string, std::string> canonCase;

    // Deletion masks, mirrored in memory: the set of whiteouted names and the set of opaque dirs. Resolve
    // consults ONLY these (pure lock-free set lookups — no host Lstat per path or per ancestor on the hot
    // path). The on-disk `.wh.*` markers remain the durable truth for persisted writelayers: Init re-scans
    // the writelayer into the sets, and every runtime mutation (Create/RemoveWhiteout, MarkOpaque, the
    // rmdir marker sweep, dir renames) updates disk AND swaps the set copy-on-write under maskWriteMtx.
    // Known seam: a guest literally creating a `.wh.foo` file through the mount lands on disk but not in
    // the set, so it masks only from the NEXT mount — no real guest does this.
    std::atomic<std::shared_ptr<const MaskSnap>> whiteoutSet;
    std::atomic<std::shared_ptr<const MaskSnap>> opaqueSet;
    std::mutex                                                maskWriteMtx;   // serializes set writers

    // Fixed shard array of copy-up locks keyed by hash(vrel) % N — avoids the old per-path map that grew
    // unboundedly for the life of the mount. Collisions only serialize unrelated copy-ups (harmless).
    static constexpr size_t                            kCopyUpShards = 256;
    std::array<std::mutex, kCopyUpShards>              copyUpShards;

    bool Init(const Spec &S, std::string &Err);
    std::mutex &CopyUpLock(const std::string &vrel);   // sharded by hash(vrel); see copyUpShards
    //Files opened over a lower copy (VfsOpen: to read, or to read and write with the copy-up waiting for the first
    //change): one marker per path, shared by the path's handles. A copy-up of the path opens the copy once, into the
    //marker (`upper`): every handle reads — and writes — the copy from then on, through a rename, an unlink or a
    //replace of its name (the descriptor follows the file). A name unlinked, renamed or made again takes its marker off
    //(`detached`): a file there later is another file, and a handle detached before any copy writes a copy of its own.
    struct PendingCopy {
        std::atomic<int>  upper{ -1 };        // HostIO::Fd of the copy, opened once
        std::atomic<bool> detached{ false };
        std::mutex        mu;                 // a detached handle's own copy, made once
        PendingCopy() = default;
        PendingCopy(const PendingCopy &) = delete;
        PendingCopy &operator=(const PendingCopy &) = delete;
        ~PendingCopy();
    };
    std::mutex                                                       pendingMu;
    std::unordered_map<std::string, std::weak_ptr<PendingCopy>>      pendingCopies;   // by PendingKey
    size_t                                                           pendingPruneAt = 64;
    std::atomic<unsigned long long>                                  copyUps{ 0 };    // copy-ups made, ever
    //Name changes (unlink, rename, create) begun or done: bumped before the host change (BeginNameChange) and again
    //when its markers come off (DetachPendingLocked). An open that saw none between resolving a name and taking its
    //marker knows the marker's name still names its file.
    std::atomic<unsigned long long>                                  detaches{ 0 };
    std::function<void(const char *)>                                debugHook;   // TEST ONLY: called at named points
    std::string                  PendingKey(const std::string &vrel) const;   // folded on a case-insensitive mount
    //This path's marker, made if none — or, when a name changed since SeenDetaches and StillOpened() says the path no
    //longer names the open's file, a marker of the handle's own, detached.
    std::shared_ptr<PendingCopy> PendingFor(const std::string &vrel, unsigned long long SeenDetaches,
                                            const std::function<bool()> &StillOpened);
    //A copy-up's copy, open (Fd, owned from here): into the path's marker, unless none waits or one is there already.
    void                         MarkCopied(const std::string &vrel, HostIO::Fd Fd);
    //A copy found at host (made before the marker was taken): opened into the path's marker, once no name change is
    //running. Logged when it cannot be opened.
    void                         AdoptCopy(const std::string &vrel, const std::string &host);
    //A name change around its host change (no lock held across it): begun, then ended with the names whose markers come
    //off — every path ends it, a failed change with none. A copy is adopted only while none is running.
    void                         BeginNameChange();
    void                         EndNameChange(const std::vector<std::pair<std::string, bool>> &Detach);
    int                          nameChanges = 0;            // running, under pendingMu
    std::condition_variable      nameChangeCv;
    //The name (and, for a folder, every name under it) names another file from now on: its markers come off (pendingMu
    //held).
    void                         DetachPendingLocked(const std::string &vrel, bool subtree);
};

//A copy-up's file while it is written (CopyUp): a marker's prefix, so no listing shows it and no guest can make one;
//one left by a crash is removed when the folder's markers are read.
inline constexpr const char *kCopyTmpPrefix = ".wh..vgfs-copy.";

enum class HitKind { None, ImplicitDir, WriteLayer, DirLayer, FileLayer, ZipEntry };

struct ResolveResult {
    HitKind          kind = HitKind::None;
    std::string      hostPath;            // WriteLayer / DirLayer / FileLayer real host path
    const Layer *    layer = nullptr;     // matched Dir/File/Zip layer
    const ZipEntry * zipEntry = nullptr;  // ZipEntry hits
    bool             rwPassthrough = false;
};

//Path helpers (vrel = normalized, no leading slash, "" == root).
bool        LayerCovers(const Layer &L, const std::string &vrel);
bool        LayerMasked(const Layer &L, const std::string &vrel);   // vrel lies where a delta built over L hides it
std::string RelUnder(const Layer &L, const std::string &vrel);   // path under target (coverage side)
std::string SourceRel(const Layer &L, const std::string &vrel);  // subpath-prefixed: the source/zip side
std::string WLPath(const VfsState &S, const std::string &vrel);   // writelayer host path for vrel
std::string WhiteoutPath(const VfsState &S, const std::string &vrel);
bool        IsWhiteouted(const VfsState &S, const std::string &vrel);      // in-memory set lookup
bool        IsUnderWhiteout(const VfsState &S, const std::string &vrel);   // any ancestor deleted
void        CreateWhiteout(VfsState &S, const std::string &vrel);          // disk marker + set insert
void        RemoveWhiteout(VfsState &S, const std::string &vrel);          // disk unlink + set erase
// A directory rename relocates the .wh. markers stored inside its writelayer subtree; mirror that in the
// in-memory sets by rewriting every entry under oldv to the newv prefix (both whiteouts and opaque dirs).
void        RenameMaskPrefix(VfsState &S, const std::string &oldv, const std::string &newv);
long long   DebugMaskFolds();
long long   DebugCaseWalks();   // TEST ONLY: archive members a submount's case names were walked over   // TEST ONLY: times a mask's changes were folded into its whole set

void        MarkOpaque(VfsState &S, const std::string &vrel);
void        UnmarkOpaque(VfsState &S, const std::string &vrel);   // mask erase only (caller owns the disk marker)
bool        IsUnderOpaque(const VfsState &S, const std::string &vrel);

//The case the layers spell vrel in: its longest prefix that a layer knows (VfsState::canonCase), in that case, and the
//rest as given (a name being made). vrel itself when the state is case-sensitive. A backend applies it to every path
//it is handed, so everything below sees one spelling per name: a lookup, a copy-up, a deletion marker.
std::string CanonicalCase(const VfsState &S, const std::string &vrel);
std::string FoldCase(std::string S);   // ASCII lowercase: the key CanonicalCase looks a path up by

//Resolve a vrel: whiteout → None; writelayer entry → WriteLayer; covering layer (highest priority
//first) → DirLayer/FileLayer/ZipEntry; structural dir → ImplicitDir; else None.
ResolveResult Resolve(VfsState &S, const std::string &vrel);

//Ensure the writelayer parent directory chain for vrel exists. Returns 0 or -errno.
int EnsureWriteParent(VfsState &S, const std::string &vrel);

//Copy an under-layer file's full content up into the writelayer (idempotent; no-op if already there
//or already a passthrough). rr is the prior Resolve of vrel. Returns 0 or -errno.
int CopyUp(VfsState &S, const std::string &vrel, const ResolveResult &rr);

//If vrel falls within a rw:true dir layer's subtree, sets HostOut to its source host path and returns
//true. Such paths bypass the overlay entirely (read AND all mutations go straight to the durable
//source) — matching the old bindfs-over-union persist-dir behavior. Highest-priority layer wins.
bool PassthroughHost(VfsState &S, const std::string &vrel, std::string &HostOut);

//Deletions under a kept (rw passthrough) folder. The folder is the user's durable upper layer for its subtree,
//so deleting what a LOWER layer provides there must stay deleted on the next launch: the marker lives IN the kept
//folder, overlayfs-style — `.wh.<name>` beside where the name would be, `.wh..wh..opq` inside a directory made
//again over a deleted one (or inside the kept folder's own root when that is removed) — mirrored in Layer::kept.
//Listings never show the markers; Resolve treats them as masks over the LOWER layers only. Elsewhere both fall
//back to the writelayer's (per-session) whiteouts. All return 0 or -errno: a deletion that can't be recorded
//must fail, never report success while the file stays visible.
int  HideLower(VfsState &S, const std::string &vrel);     //vrel was deleted or renamed away: hide its lower copies
int  UnhideLower(VfsState &S, const std::string &vrel);   //vrel was made again: drop its masks (both kinds)
bool KeptHidden(const VfsState &S, const std::string &vrel);   //a kept folder's own marker for vrel (not ancestors)
//True if kept layer L masks vrel for the layers below it: vrel or an ancestor deleted there, or an ancestor (or
//the kept root) made again (opaque). In-memory lookups only.
bool KeptMasked(const Layer &L, const std::string &vrel);
bool KeptOpaqueDir(const Layer &L, const std::string &vrel);   //the kept folder's dir for vrel is opaque
int  KeptMarkOpaque(VfsState &S, const std::string &vrel);     //make it so (its lower contents stay hidden)
//A directory moved within one kept folder takes the markers inside it along: rewrite the in-memory sets.
void KeptRenamePrefix(VfsState &S, const std::string &oldv, const std::string &newv);
//The rmdir sweep: drop the markers inside a kept directory (disk and memory) before it goes.
void KeptDropMarkersUnder(VfsState &S, const std::string &vrel);
//The kept layer serving vrel's passthrough (the same choice as PassthroughHost), or null.
const Layer *KeptLayerFor(const VfsState &S, const std::string &vrel);

#endif // VIDYAGODFS_OVERLAY_H
