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
#include <cstdio>
#include <cstdlib>
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

//VGFS_OPLOG=<file>: every getattr this server answers, one line each (tests count what reached the server: the kernel
//answers from its cache what it may).
static FILE *OpLog()
{
    static FILE *F = [] { const char *P = std::getenv("VGFS_OPLOG"); return P && *P ? std::fopen(P, "a") : nullptr; }();
    return F;
}

// ---- ops (thin marshalling) ----------------------------------------------

static int op_getattr(const char *path, struct stat *st, struct fuse_file_info *)
{
    if (FILE *L = OpLog()) { std::fprintf(L, "getattr %s\n", path ? path : ""); std::fflush(L); }
    VfsAttr a;
    if (int e = VfsGetattr(*St(), V(path), a); e != 0) return e;
    ToStat(a, st);
    return 0;
}

static int op_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t,
                      struct fuse_file_info *, enum fuse_readdir_flags flags)
{
    filler(buf, ".",  nullptr, 0, (fuse_fill_dir_flags)0);
    filler(buf, "..", nullptr, 0, (fuse_fill_dir_flags)0);
    //Each entry's attributes are worked out for the listing anyway (its type is in them): asked for a readdirplus,
    //they are handed over whole, and the kernel keeps them — a lookup per entry after a listing (a game's, Wine's
    //case-insensitive search) asked them all again, one by one.
    const auto Plus = (flags & FUSE_READDIR_PLUS) ? FUSE_FILL_DIR_PLUS : (fuse_fill_dir_flags)0;
    return VfsReaddirTyped(*St(), V(path), [&](const std::string &n, const VfsAttr &a) {
        struct stat st; ToStat(a, &st);
        filler(buf, n.c_str(), &st, 0, Plus);
    });
}

static int op_opendir(const char *, struct fuse_file_info *fi)
{
    // Kernel-side directory caching. Without FOPEN_CACHE_DIR every getdents round-trips to
    // userspace and re-merges the whole overlay; keep_cache preserves the cached listing across
    // opendir calls (wine re-opens the directory on every case-insensitive lookup miss, so
    // without it the cache would be dropped before it's ever reused). The kernel invalidates the
    // cache itself on create/unlink/rename through this mount; external writes into passthrough
    // sources can go stale for a bit (a listing, until the kernel drops it; a file's pages: at most a second past its
    // next open, op_init).
    fi->cache_readdir = 1;
    fi->keep_cache    = 1;
    return 0;
}

static void *op_init(struct fuse_conn_info *conn, struct fuse_config *cfg)
{
    //Reads answered with a file (op_read_buf) go to the kernel by splice — when it can (a kernel without it: copied).
    fuse_set_feature_flag(conn, FUSE_CAP_SPLICE_WRITE);
    fuse_set_feature_flag(conn, FUSE_CAP_SPLICE_MOVE);
    // How long the kernel answers lookups, attributes and misses itself. A mount's layers never change under it (an
    // archive, a delta, a package's folder), and a change made through a name the kernel sees and invalidates at that
    // name: a 1 s cache made every path a game touches again a second later a round trip and a resolve over every
    // layer. What the longer cache leaves stale for up to its length: a size or a time looked at through ANOTHER name
    // of a hard-linked file after a write through one (each name is its own node here), and one changed OUTSIDE the
    // mount (a kept folder, by the user).
    cfg->negative_timeout = kNegativeTimeout;
    cfg->attr_timeout     = kAttrTimeout;
    cfg->entry_timeout    = kEntryTimeout;
    // A file's cached pages are checked at each open (auto_cache) against attributes at most a second old — not the
    // attribute cache's ten: a file changed outside the mount, or through another name of it, reads as it is now at
    // its next open, as it did with the one-second cache.
    cfg->ac_attr_timeout_set = 1;
    cfg->ac_attr_timeout     = 1.0;
    return fuse_get_context()->private_data;
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

//A read whose bytes lie in a host file as stored (a plain file; a STORED archive member read straight from its file)
//is answered with that file and offset: the kernel splices them to the reader, where a read into a buffer copied every
//byte twice (into the buffer, then out to the kernel) — a tenth or more of a CPU streaming gigabytes off an SSD.
static int op_read_buf(const char *, struct fuse_bufvec **bufp, size_t size, off_t off, struct fuse_file_info *fi)
{
    int Fd = -1; uint64_t Pos = 0; size_t Len = 0;
    if (off >= 0 && VfsReadFrom(OF(fi), size, (uint64_t)off, Fd, Pos, Len))
    {
        auto *B = static_cast<fuse_bufvec *>(std::malloc(sizeof(fuse_bufvec)));
        if (!B) return -ENOMEM;
        *B = FUSE_BUFVEC_INIT(Len);
        B->buf[0].flags = static_cast<fuse_buf_flags>(FUSE_BUF_IS_FD | FUSE_BUF_FD_SEEK);
        B->buf[0].fd = Fd;
        B->buf[0].pos = (off_t)Pos;
        *bufp = B;
        if (FILE *L = OpLog()) { std::fprintf(L, "read_buf fd\n"); std::fflush(L); }
        return 0;
    }
    auto *B = static_cast<fuse_bufvec *>(std::malloc(sizeof(fuse_bufvec)));
    void *Mem = std::malloc(size ? size : 1);
    if (!B || !Mem) { std::free(B); std::free(Mem); return -ENOMEM; }
    const ssize_t Got = VfsRead(OF(fi), Mem, size, (uint64_t)off);
    if (Got < 0) { std::free(B); std::free(Mem); return (int)Got; }
    *B = FUSE_BUFVEC_INIT((size_t)Got);
    B->buf[0].mem = Mem;
    *bufp = B;
    return 0;
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
static int op_link(const char *from, const char *to) { return VfsLink(*St(), V(from), V(to)); }
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
    ops.link     = op_link;
    ops.rename   = op_rename;
    ops.chmod    = op_chmod;
    ops.chown    = op_chown;
    ops.truncate = op_truncate;
    ops.open     = op_open;
    ops.read     = op_read;
    ops.read_buf = op_read_buf;
    ops.write    = op_write;
    ops.statfs   = op_statfs;
    ops.flush    = op_flush;
    ops.release  = op_release;
    ops.fsync    = op_fsync;
    ops.readdir  = op_readdir;
    ops.opendir  = op_opendir;
    ops.init     = op_init;
    ops.create   = op_create;
    ops.utimens  = op_utimens;
    return &ops;
}
