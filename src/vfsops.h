#ifndef VIDYAGODFS_VFSOPS_H
#define VIDYAGODFS_VFSOPS_H

// ---------------------------------------------------------------------------
// VfsOps — the backend-neutral filesystem operations. This is the seam a mount backend
// (FUSE on Linux via fuse_backend.cpp, WinFsp on Windows via winfsp_backend.cpp) drives:
// each op takes a VfsState + a NORMALIZED virtual path (NormalizeVPath output) and neutral
// arguments, performs the union-overlay logic (Resolve/CopyUp/whiteout/…) plus the host
// I/O (through the HostIO shim), and returns neutral results. No fuse_* / FSP_* / struct
// stat types cross this boundary — the backend adapts to/from its own structs.
//
// These bodies were lifted verbatim (behavior-preserving) out of the old fuseops.cpp; the
// FUSE adapter is now a thin translation of fuse_operations ↔ these calls.
// ---------------------------------------------------------------------------

#include "overlay.h"     // VfsState, Resolve/CopyUp/… (neutral core)
#include "ziplayer.h"    // ZipReader
#include "hostio.h"      // HostIO::Fd / StatvfsInfo

#include <string>
#include <functional>
#include <cstdint>
#include <cstddef>
#include <sys/types.h>   // ssize_t

// A per-open handle: a host fd (dir-layer / writelayer / passthrough) OR a zip-entry reader
// (read-only). Neutral — the backend stashes the pointer in its own per-open slot
// (fuse_file_info::fh / a WinFsp file context).
struct OpenFile {
    HostIO::Fd fd  = -1;
    ZipReader *zip = nullptr;
};

// Neutral file attributes (VfsGetattr output). The backend converts to struct stat (FUSE)
// or FSP_FSCTL_FILE_INFO (WinFsp). Type is carried as explicit flags so the neutral layer
// needs no POSIX S_IF* macros; `perms` is the 0777 permission bits.
struct VfsAttr {
    bool     isDir     = false;
    bool     isSymlink = false;
    uint32_t perms     = 0;
    uint64_t size      = 0;
    int64_t  mtime     = 0;   // seconds since epoch
    uint32_t nlink     = 1;
    uint32_t uid       = 0;
    uint32_t gid       = 0;
};

// readdir sink: invoked once per merged child name (the backend fills its own dir buffer).
using DirFiller = std::function<void(const std::string &name)>;

// All paths are normalized vrel ("" == mount root). Return 0 or -errno unless noted.
int     VfsGetattr (VfsState &S, const std::string &vrel, VfsAttr &out);
int     VfsReaddir (VfsState &S, const std::string &vrel, const DirFiller &fill);
int     VfsOpen    (VfsState &S, const std::string &vrel, int flags, OpenFile *&out);          // out=nullptr → dir (no handle), returns 0
int     VfsCreate  (VfsState &S, const std::string &vrel, uint32_t mode, int flags, OpenFile *&out);
ssize_t VfsRead    (OpenFile *of, void *buf, size_t size, uint64_t off);                        // bytes read (>=0) or -errno
ssize_t VfsWrite   (VfsState &S, OpenFile *of, const void *buf, size_t size, uint64_t off);
void    VfsRelease (OpenFile *of);                                                              // closes fd / frees reader / deletes handle
int     VfsMkdir   (VfsState &S, const std::string &vrel, uint32_t mode);
int     VfsUnlink  (VfsState &S, const std::string &vrel);
int     VfsRmdir   (VfsState &S, const std::string &vrel);
int     VfsRename  (VfsState &S, const std::string &vfrom, const std::string &vto);
int     VfsTruncate(VfsState &S, const std::string &vrel, OpenFile *of, uint64_t size);         // of may be null (path form)
int     VfsChmod   (VfsState &S, const std::string &vrel, uint32_t mode);
int     VfsUtimens (VfsState &S, const std::string &vrel, int64_t atimeSec, int64_t mtimeSec);
int     VfsReadlink(VfsState &S, const std::string &vrel, std::string &target);
int     VfsSymlink (VfsState &S, const std::string &target, const std::string &vrel);
int     VfsFsync   (OpenFile *of);
int     VfsStatfs  (VfsState &S, HostIO::StatvfsInfo &out);

#endif // VIDYAGODFS_VFSOPS_H
