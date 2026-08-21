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

    // Set once any opaque-dir marker (.wh..wh..opq) is seen (created here, or encountered in a readdir).
    // release/acquire so the marker-file creation happens-before a later thread's masking observes the flag.
    // Gates the per-Resolve ancestor-opacity check so the hot path stays free when no opaque dirs exist.
    std::atomic<bool>     hasOpaque{false};
    // Same gate for directory whiteouts: a deleted directory masks its whole subtree, so Resolve must check
    // whether any ANCESTOR is whiteouted. Set on the first CreateWhiteout; skips the ancestor walk otherwise.
    std::atomic<bool>     hasWhiteout{false};

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
bool        IsWhiteouted(const VfsState &S, const std::string &vrel);
bool        IsUnderWhiteout(const VfsState &S, const std::string &vrel);   // any ancestor deleted
void        CreateWhiteout(VfsState &S, const std::string &vrel);          // sets hasWhiteout
void        RemoveWhiteout(const VfsState &S, const std::string &vrel);

//Opaque directories: a writelayer dir holding a `.wh..wh..opq` marker fully masks the lower layers for
//its whole subtree (used when a lower-backed dir is deleted then recreated — the new one is empty).
bool        IsOpaqueDir(const VfsState &S, const std::string &vrel);
void        MarkOpaque(VfsState &S, const std::string &vrel);
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

#endif // VIDYAGODFS_OVERLAY_H
