// FUSE backend adapter — the Linux mount backend. Translates libfuse's fuse_operations
// callbacks to/from the backend-neutral VfsOps (vfsops.cpp). No filesystem logic lives
// here: it only marshals FUSE argument/struct types (struct stat, fuse_fill_dir_t,
// fuse_file_info::fh) to and from the neutral calls. The Windows build compiles
// winfsp_backend.cpp against the same VfsOps instead of this file.
#include "fuseops.h"
#include "vfsops.h"
#include "layerspec.h"   // NormalizeVPath

#include <string>
#include <algorithm>
#include <cstring>
#include <cstdint>
#include <cerrno>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/statvfs.h>

// The VfsState for this mount is FUSE's private_data (set at fuse_main time).
static VfsState *St() { return static_cast<VfsState *>(fuse_get_context()->private_data); }
static std::string V(const char *path) { return NormalizeVPath(path ? path : ""); }

// Neutral VfsAttr → POSIX struct stat.
static void ToStat(const VfsAttr &a, struct stat *st)
{
    std::memset(st, 0, sizeof *st);
    mode_t type = a.isDir ? S_IFDIR : (a.isSymlink ? S_IFLNK : S_IFREG);
    st->st_mode  = type | (a.perms & 07777);
    st->st_nlink = a.nlink ? a.nlink : 1;
    st->st_size  = (off_t)a.size;
    st->st_mtime = (time_t)a.mtime;
    st->st_uid   = (uid_t)a.uid;
    st->st_gid   = (gid_t)a.gid;
}

static OpenFile *OF(struct fuse_file_info *fi) { return fi ? (OpenFile *)(uintptr_t)fi->fh : nullptr; }

// ---- ops (thin marshalling) ----------------------------------------------

static int op_getattr(const char *path, struct stat *st, struct fuse_file_info *)
{
    VfsAttr a;
    if (int e = VfsGetattr(*St(), V(path), a); e != 0) return e;
    ToStat(a, st);
    return 0;
}

static int op_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t,
                      struct fuse_file_info *, enum fuse_readdir_flags)
{
    filler(buf, ".",  nullptr, 0, (fuse_fill_dir_flags)0);
    filler(buf, "..", nullptr, 0, (fuse_fill_dir_flags)0);
    return VfsReaddir(*St(), V(path),
                      [&](const std::string &n) { filler(buf, n.c_str(), nullptr, 0, (fuse_fill_dir_flags)0); });
}

static int op_open(const char *path, struct fuse_file_info *fi)
{
    OpenFile *of = nullptr;
    if (int e = VfsOpen(*St(), V(path), fi->flags, of); e != 0) return e;
    fi->fh = (uint64_t)(uintptr_t)of;   // null handle for a directory open
    return 0;
}

static int op_create(const char *path, mode_t mode, struct fuse_file_info *fi)
{
    OpenFile *of = nullptr;
    if (int e = VfsCreate(*St(), V(path), mode, fi->flags, of); e != 0) return e;
    fi->fh = (uint64_t)(uintptr_t)of;
    return 0;
}

static int op_read(const char *, char *buf, size_t size, off_t off, struct fuse_file_info *fi)
{
    return (int)VfsRead(OF(fi), buf, size, (uint64_t)off);
}

static int op_write(const char *, const char *buf, size_t size, off_t off, struct fuse_file_info *fi)
{
    return (int)VfsWrite(*St(), OF(fi), buf, size, (uint64_t)off);
}

static int op_release(const char *, struct fuse_file_info *fi)
{
    VfsRelease(OF(fi));
    fi->fh = 0;
    return 0;
}

static int op_mkdir (const char *path, mode_t mode) { return VfsMkdir (*St(), V(path), mode); }
static int op_unlink(const char *path)              { return VfsUnlink(*St(), V(path)); }
static int op_rmdir (const char *path)              { return VfsRmdir (*St(), V(path)); }

static int op_rename(const char *from, const char *to, unsigned int flags)
{
    if (flags) return -EINVAL;   // RENAME_EXCHANGE/NOREPLACE unsupported
    return VfsRename(*St(), V(from), V(to));
}

static int op_truncate(const char *path, off_t size, struct fuse_file_info *fi)
{
    return VfsTruncate(*St(), V(path), (fi && fi->fh) ? OF(fi) : nullptr, (uint64_t)size);
}

static int op_chmod(const char *path, mode_t mode, struct fuse_file_info *) { return VfsChmod(*St(), V(path), mode); }

static int op_chown(const char *, uid_t, gid_t, struct fuse_file_info *)
{
    // Ownership is presented as a fixed uid/gid; record nothing. No-op success so installers
    // that chown don't fail.
    return St()->readOnly ? -EROFS : 0;
}

static int op_utimens(const char *path, const struct timespec tv[2], struct fuse_file_info *)
{
    return VfsUtimens(*St(), V(path), (int64_t)tv[0].tv_sec, (int64_t)tv[1].tv_sec);
}

static int op_readlink(const char *path, char *buf, size_t size)
{
    std::string tgt;
    if (int e = VfsReadlink(*St(), V(path), tgt); e != 0) return e;
    size_t n = std::min(tgt.size(), size ? size - 1 : (size_t)0);
    std::memcpy(buf, tgt.data(), n);
    buf[n] = '\0';
    return 0;
}

static int op_symlink(const char *target, const char *path) { return VfsSymlink(*St(), target, V(path)); }
static int op_flush(const char *, struct fuse_file_info *)   { return 0; }
static int op_fsync(const char *, int, struct fuse_file_info *fi) { return VfsFsync(OF(fi)); }

static int op_statfs(const char *, struct statvfs *stbuf)
{
    HostIO::StatvfsInfo si;
    if (int e = VfsStatfs(*St(), si); e != 0) return e;
    std::memset(stbuf, 0, sizeof *stbuf);
    stbuf->f_bsize   = si.bsize;
    stbuf->f_blocks  = si.blocks;
    stbuf->f_bfree   = si.bfree;
    stbuf->f_bavail  = si.bavail;
    stbuf->f_files   = si.files;
    stbuf->f_ffree   = si.ffree;
    stbuf->f_namemax = si.namemax;
    return 0;
}

const struct fuse_operations *VidyagodfsOps()
{
    static struct fuse_operations ops = {};
    ops.getattr  = op_getattr;
    ops.readlink = op_readlink;
    ops.mkdir    = op_mkdir;
    ops.unlink   = op_unlink;
    ops.rmdir    = op_rmdir;
    ops.symlink  = op_symlink;
    ops.rename   = op_rename;
    ops.chmod    = op_chmod;
    ops.chown    = op_chown;
    ops.truncate = op_truncate;
    ops.open     = op_open;
    ops.read     = op_read;
    ops.write    = op_write;
    ops.statfs   = op_statfs;
    ops.flush    = op_flush;
    ops.release  = op_release;
    ops.fsync    = op_fsync;
    ops.readdir  = op_readdir;
    ops.create   = op_create;
    ops.utimens  = op_utimens;
    return &ops;
}
