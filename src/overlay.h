#ifndef VIDYAGODFS_OVERLAY_H
#define VIDYAGODFS_OVERLAY_H

#include "layerspec.h"
#include "ziplayer.h"

#include <string>
#include <vector>
#include <set>
#include <map>
#include <memory>
#include <mutex>
#include <sys/types.h>

//A resolved layer in the running filesystem.
struct Layer {
    LayerType   type = LayerType::Dir;
    std::string source;      // host path (dir / archive / single file)
    std::string target;      // normalized virtual subtree root ("" == mount root); for File, the containing dir
    bool        rw = false;  // Dir + rw:true = RW passthrough (writes go straight to source)
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
    uid_t                 uid = 1000;
    gid_t                 gid = 1000;
    std::vector<Layer>    layers;        // ascending priority (index 0 lowest)
    std::set<std::string> implicitDirs;  // synthesized structural dirs (target parents)

    std::mutex                                         copyUpMapMtx;
    std::map<std::string, std::shared_ptr<std::mutex>> copyUpLocks;

    bool Init(const Spec &S, std::string &Err);
    std::shared_ptr<std::mutex> CopyUpLock(const std::string &vrel);
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
std::string RelUnder(const Layer &L, const std::string &vrel);
std::string WLPath(const VfsState &S, const std::string &vrel);   // writelayer host path for vrel
std::string WhiteoutPath(const VfsState &S, const std::string &vrel);
bool        IsWhiteouted(const VfsState &S, const std::string &vrel);
void        CreateWhiteout(const VfsState &S, const std::string &vrel);
void        RemoveWhiteout(const VfsState &S, const std::string &vrel);

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
