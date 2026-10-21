#ifndef VIDYAGODFS_OVERLAY_H
#define VIDYAGODFS_OVERLAY_H

#include "layerspec.h"
#include "ziplayer.h"

#include <array>
#include <string>
#include <vector>
#include <set>
#include <memory>
#include <mutex>
#include <atomic>
#include <cstdint>
#include <functional>

//A kept folder's deletion markers mirrored in memory, like the writelayer's (VfsState::whiteoutSet): the names
//deleted there and the directories made again over deleted ones (opaque), as paths relative to the layer's source
//(SourceRel). Seeded from the folder at Init, swapped copy-on-write under VfsState::maskWriteMtx on every change, so
//lookups through a kept folder never touch the disk for them.
struct KeptMasks {
    std::atomic<std::shared_ptr<const std::set<std::string>>> deleted;
    std::atomic<std::shared_ptr<const std::set<std::string>>> opaque;
};

//A resolved layer in the running filesystem.
struct Layer {
    LayerType   type = LayerType::Dir;
    std::string source;      // host path (dir / archive / single file)
    std::string target;      // normalized virtual subtree root ("" == mount root); for File, the containing dir
    std::string subpath;     // path within source exposed at target ("" == whole source). dir/zip only.
    bool        rw = false;  // Dir + rw:true = RW passthrough (writes go straight to source)
    // A delta-backed zip reconstructs a COMPLETE archive, so it fully masks lower same-target layers (a file
    // deleted in the newer version must not leak up from the base it was diffed against). opaque=true → for
    // this layer's target subtree, only it (and higher-priority layers) contribute; lower layers are hidden.
    bool        opaque = false;
    int         priority = 0;
    std::shared_ptr<ZipIndex> zip;  // Zip layers only
    std::string fileVPath;   // File layers only: target [+ "/"] + basename(source)
    std::string fileBase;    // File layers only: basename(source)
    std::shared_ptr<KeptMasks> kept;   // rw Dir layers (kept folders) only
};

//The whole running filesystem state, built once from a Spec and immutable afterward (lock-free reads),
//except per-path copy-up serialization.
struct VfsState {
    std::string           writelayer;   // empty when readOnly
    bool                  readOnly = false;
    // Symlink abolition (default ON, `-o keep-symlinks` restores the old behavior): DATA layers (zip/delta/
    // dir/file) never serve a symlink — an archive link is chased to its in-archive target file
    // (ResolveZipSymlink) or hidden; a host-layer link is followed on the host or hidden. Only the
    // WRITELAYER still presents symlinks: that's live runtime state written by the guest itself (e.g. wine
    // creating dosdevices/ at boot), on a real filesystem where they belong.
    bool                  flattenSymlinks = true;
    uint32_t              uid = 1000;    // forced ownership presented by getattr (POSIX uid/gid; inert on Windows)
    uint32_t              gid = 1000;
    std::vector<Layer>    layers;        // ascending priority (index 0 lowest)
    std::set<std::string> implicitDirs;  // synthesized structural dirs (target parents)

    // Deletion masks, mirrored in memory: the set of whiteouted names and the set of opaque dirs. Resolve
    // consults ONLY these (pure lock-free set lookups — no host Lstat per path or per ancestor on the hot
    // path). The on-disk `.wh.*` markers remain the durable truth for persisted writelayers: Init re-scans
    // the writelayer into the sets, and every runtime mutation (Create/RemoveWhiteout, MarkOpaque, the
    // rmdir marker sweep, dir renames) updates disk AND swaps the set copy-on-write under maskWriteMtx.
    // Known seam: a guest literally creating a `.wh.foo` file through the mount lands on disk but not in
    // the set, so it masks only from the NEXT mount — no real guest does this.
    std::atomic<std::shared_ptr<const std::set<std::string>>> whiteoutSet;
    std::atomic<std::shared_ptr<const std::set<std::string>>> opaqueSet;
    std::mutex                                                maskWriteMtx;   // serializes set writers

    // Fixed shard array of copy-up locks keyed by hash(vrel) % N — avoids the old per-path map that grew
    // unboundedly for the life of the mount. Collisions only serialize unrelated copy-ups (harmless).
    static constexpr size_t                            kCopyUpShards = 256;
    std::array<std::mutex, kCopyUpShards>              copyUpShards;

    bool Init(const Spec &S, std::string &Err);
    std::mutex &CopyUpLock(const std::string &vrel);   // sharded by hash(vrel); see copyUpShards
};

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

//Opaque directories: a writelayer dir holding a `.wh..wh..opq` marker fully masks the lower layers for
//its whole subtree (used when a lower-backed dir is deleted then recreated — the new one is empty).
bool        IsOpaqueDir(const VfsState &S, const std::string &vrel);
void        MarkOpaque(VfsState &S, const std::string &vrel);
void        UnmarkOpaque(VfsState &S, const std::string &vrel);   // mask erase only (caller owns the disk marker)
bool        IsUnderOpaque(const VfsState &S, const std::string &vrel);

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
