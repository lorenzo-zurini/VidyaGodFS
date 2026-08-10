// WinFsp backend adapter — the Windows mount backend. Bootstraps on WinFsp's FUSE-compatibility
// layer (<fuse3/fuse.h>): WinFsp translates its native FSP_FILE_SYSTEM_INTERFACE to these
// fuse3_operations callbacks, so this file is the exact analogue of the Linux fuseops.cpp — it
// only marshals WinFsp's fuse types (struct fuse_stat, fuse3_file_info::fh, fuse3_fill_dir_t) to
// and from the backend-neutral VfsOps (vfsops.cpp). Zero filesystem logic lives here.
//
// WinFsp names its fuse3 structs with a "3" (fuse3_operations / fuse3_file_info / fuse3_context)
// so a program can host both fuse2 and fuse3; we use those real names directly rather than relying
// on the FUSE_USE_VERSION compat renames. A later native FSP_FILE_SYSTEM_INTERFACE adapter can
// replace this file for finer control over Windows semantics (case-sensitivity, reparse symlinks,
// drive-letter mount) — see the port plan §1.
#define FUSE_USE_VERSION 30
#include <fuse3/fuse.h>

#include "vfsops.h"
#include "layerspec.h"   // NormalizeVPath

#include <string>
#include <algorithm>
#include <cstring>
#include <cstdint>
#include <cerrno>

// POSIX file-type bits (WinFsp's fuse layer carries a Unix mode in fuse_stat::st_mode but does not
// define the S_IF* macros on MinGW). Use the standard octal values directly.
static constexpr uint32_t VG_IFDIR = 0040000u;
static constexpr uint32_t VG_IFREG = 0100000u;
static constexpr uint32_t VG_IFLNK = 0120000u;

// The VfsState for this mount is WinFsp-FUSE's private_data (set at fuse_main time).
static VfsState *St() { return static_cast<VfsState *>(fuse3_get_context()->private_data); }
static std::string V(const char *path) { return NormalizeVPath(path ? path : ""); }

// Neutral VfsAttr → WinFsp's POSIX-shaped struct fuse_stat.
static void ToStat(const VfsAttr &a, struct fuse_stat *st)
{
    std::memset(st, 0, sizeof *st);
    uint32_t type = a.isDir ? VG_IFDIR : (a.isSymlink ? VG_IFLNK : VG_IFREG);
    st->st_mode  = type | (a.perms & 07777);
    st->st_nlink = a.nlink ? a.nlink : 1;
    st->st_size  = (fuse_off_t)a.size;
    st->st_uid   = a.uid;
    st->st_gid   = a.gid;
    st->st_atim.tv_sec = (int32_t)a.mtime;
    st->st_mtim.tv_sec = (int32_t)a.mtime;
    st->st_ctim.tv_sec = (int32_t)a.mtime;
    st->st_birthtim.tv_sec = (int32_t)a.mtime;
}

static OpenFile *OF(struct fuse3_file_info *fi) { return fi ? (OpenFile *)(uintptr_t)fi->fh : nullptr; }

// ---- ops (thin marshalling) ----------------------------------------------

static int op_getattr(const char *path, struct fuse_stat *st, struct fuse3_file_info *)
{
    VfsAttr a;
    if (int e = VfsGetattr(*St(), V(path), a); e != 0) return e;
    ToStat(a, st);
    return 0;
}

static int op_readdir(const char *path, void *buf, fuse3_fill_dir_t filler, fuse_off_t,
                      struct fuse3_file_info *, enum fuse3_readdir_flags)
{
    filler(buf, ".",  nullptr, 0, (enum fuse3_fill_dir_flags)0);
    filler(buf, "..", nullptr, 0, (enum fuse3_fill_dir_flags)0);
    return VfsReaddir(*St(), V(path),
                      [&](const std::string &n) { filler(buf, n.c_str(), nullptr, 0, (enum fuse3_fill_dir_flags)0); });
}

static int op_open(const char *path, struct fuse3_file_info *fi)
{
    OpenFile *of = nullptr;
    if (int e = VfsOpen(*St(), V(path), fi->flags, of); e != 0) return e;
    fi->fh = (uint64_t)(uintptr_t)of;   // null handle for a directory open
    return 0;
}

static int op_create(const char *path, fuse_mode_t mode, struct fuse3_file_info *fi)
{
    OpenFile *of = nullptr;
    if (int e = VfsCreate(*St(), V(path), mode, fi->flags, of); e != 0) return e;
    fi->fh = (uint64_t)(uintptr_t)of;
    return 0;
}

static int op_read(const char *, char *buf, size_t size, fuse_off_t off, struct fuse3_file_info *fi)
{
    return (int)VfsRead(OF(fi), buf, size, (uint64_t)off);
}

static int op_write(const char *, const char *buf, size_t size, fuse_off_t off, struct fuse3_file_info *fi)
{
    return (int)VfsWrite(*St(), OF(fi), buf, size, (uint64_t)off);
}

static int op_release(const char *, struct fuse3_file_info *fi)
{
    VfsRelease(OF(fi));
    if (fi) fi->fh = 0;
    return 0;
}

static int op_mkdir (const char *path, fuse_mode_t mode) { return VfsMkdir (*St(), V(path), mode); }
static int op_unlink(const char *path)                   { return VfsUnlink(*St(), V(path)); }
static int op_rmdir (const char *path)                   { return VfsRmdir (*St(), V(path)); }

static int op_rename(const char *from, const char *to, unsigned int flags)
{
    if (flags) return -EINVAL;   // RENAME_EXCHANGE/NOREPLACE unsupported
    return VfsRename(*St(), V(from), V(to));
}

static int op_truncate(const char *path, fuse_off_t size, struct fuse3_file_info *fi)
{
    return VfsTruncate(*St(), V(path), (fi && fi->fh) ? OF(fi) : nullptr, (uint64_t)size);
}

static int op_chmod(const char *path, fuse_mode_t mode, struct fuse3_file_info *) { return VfsChmod(*St(), V(path), mode); }

static int op_chown(const char *, fuse_uid_t, fuse_gid_t, struct fuse3_file_info *)
{
    // Ownership is presented as a fixed uid/gid; record nothing. No-op success (installers that
    // chown must not fail), read-only rejects.
    return St()->readOnly ? -EROFS : 0;
}

static int op_utimens(const char *path, const struct fuse_timespec tv[2], struct fuse3_file_info *)
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
static int op_flush(const char *, struct fuse3_file_info *)  { return 0; }
static int op_fsync(const char *, int, struct fuse3_file_info *fi) { return VfsFsync(OF(fi)); }

static int op_statfs(const char *, struct fuse_statvfs *stbuf)
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

// The fuse3_operations table, driven by WinFsp's FUSE layer. Exposed to mountsession_win.cpp,
// which passes it to fuse_main().
const struct fuse3_operations *VidyagodfsFuse3Ops()
{
    static struct fuse3_operations ops = {};
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
