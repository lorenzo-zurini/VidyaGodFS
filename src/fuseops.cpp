#include "fuseops.h"
#include "overlay.h"
#include "layerspec.h"
#include "ziplayer.h"

#include <string>
#include <set>
#include <filesystem>
#include <cstring>
#include <cerrno>
#include <dirent.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/statvfs.h>

// A per-open handle stashed in fuse_file_info::fh.
struct OpenFile {
    int        fd  = -1;       // host file descriptor (dir-layer / writelayer / passthrough)
    ZipReader *zip = nullptr;  // zip entry reader (read-only)
};

static VfsState *St() { return static_cast<VfsState *>(fuse_get_context()->private_data); }
static std::string V(const char *path) { return NormalizeVPath(path ? path : ""); }

static void ForceOwner(struct stat *st, const VfsState *S) { st->st_uid = S->uid; st->st_gid = S->gid; }

static void FillDirStat(struct stat *st, const VfsState *S, mode_t perm = 0755)
{
    std::memset(st, 0, sizeof *st);
    st->st_mode = S_IFDIR | perm;
    st->st_nlink = 2;
    ForceOwner(st, S);
}

//Path segment of `path` immediately after the directory `v` ("" = root); "" if path isn't under v.
static std::string SegmentAfter(const std::string &v, const std::string &path)
{
    std::string rest;
    if (v.empty()) rest = path;
    else if (path.rfind(v + "/", 0) == 0) rest = path.substr(v.size() + 1);
    else return "";
    if (rest.empty()) return "";
    size_t s = rest.find('/');
    return (s == std::string::npos) ? rest : rest.substr(0, s);
}

//Gathers the merged child names of directory v (excluding . / ..), honoring whiteouts.
static void CollectChildren(VfsState *S, const std::string &v, std::set<std::string> &out)
{
    std::set<std::string> whiteouts;

    if (!S->writelayer.empty())
    {
        if (DIR *d = ::opendir(WLPath(*S, v).c_str()))
        {
            while (dirent *e = ::readdir(d))
            {
                std::string n = e->d_name;
                if (n == "." || n == "..") continue;
                if (n.rfind(".wh.", 0) == 0) { whiteouts.insert(n.substr(4)); continue; }
                out.insert(n);
            }
            ::closedir(d);
        }
    }

    for (const Layer &L : S->layers)
    {
        // Real entries of a covering dir/zip layer.
        if (LayerCovers(L, v))
        {
            if (L.type == LayerType::Dir)
            {
                std::string rel = RelUnder(L, v);
                std::string host = rel.empty() ? L.source : (L.source + "/" + rel);
                if (DIR *d = ::opendir(host.c_str()))
                {
                    while (dirent *e = ::readdir(d))
                    {
                        std::string n = e->d_name;
                        if (n != "." && n != "..") out.insert(n);
                    }
                    ::closedir(d);
                }
            }
            else if (L.type == LayerType::Zip)
            {
                auto it = L.zip->dirChildren.find(RelUnder(L, v));
                if (it != L.zip->dirChildren.end())
                    for (const std::string &c : it->second) out.insert(c);
            }
        }
        // File layer: its basename is a child of its containing dir.
        if (L.type == LayerType::File && SegmentAfter(v, L.fileVPath) == L.fileBase)
            out.insert(L.fileBase);
        // Structural child dir from a deeper layer presence (target / fileVPath).
        const std::string &pp = (L.type == LayerType::File) ? L.fileVPath : L.target;
        if (std::string seg = SegmentAfter(v, pp); !seg.empty()) out.insert(seg);
    }

    // Synthesized structural dirs.
    for (const std::string &d : S->implicitDirs)
        if (std::string seg = SegmentAfter(v, d); !seg.empty()) out.insert(seg);

    for (const std::string &w : whiteouts) out.erase(w);
}

// ---- ops -----------------------------------------------------------------

static int op_getattr(const char *path, struct stat *st, struct fuse_file_info *)
{
    VfsState *S = St();
    std::string v = V(path);
    std::memset(st, 0, sizeof *st);
    if (v.empty()) { FillDirStat(st, S); return 0; }

    ResolveResult rr = Resolve(*S, v);
    switch (rr.kind)
    {
        case HitKind::None: return -ENOENT;
        case HitKind::ImplicitDir: FillDirStat(st, S); return 0;
        case HitKind::WriteLayer:
        case HitKind::DirLayer:
        case HitKind::FileLayer:
            if (::lstat(rr.hostPath.c_str(), st) != 0) return -errno;
            ForceOwner(st, S);
            return 0;
        case HitKind::ZipEntry:
            if (rr.zipEntry == nullptr || rr.zipEntry->isDir) { FillDirStat(st, S, 0555); return 0; }
            st->st_mode = S_IFREG | 0555;
            st->st_nlink = 1;
            st->st_size = (off_t)rr.zipEntry->size;
            st->st_mtime = rr.zipEntry->mtime;
            ForceOwner(st, S);
            return 0;
    }
    return -ENOENT;
}

static int op_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t,
                      struct fuse_file_info *, enum fuse_readdir_flags)
{
    VfsState *S = St();
    std::string v = V(path);
    filler(buf, ".", nullptr, 0, (fuse_fill_dir_flags)0);
    filler(buf, "..", nullptr, 0, (fuse_fill_dir_flags)0);

    std::set<std::string> names;
    CollectChildren(S, v, names);
    for (const std::string &n : names) filler(buf, n.c_str(), nullptr, 0, (fuse_fill_dir_flags)0);
    return 0;
}

static int op_open(const char *path, struct fuse_file_info *fi)
{
    VfsState *S = St();
    std::string v = V(path);
    ResolveResult rr = Resolve(*S, v);
    if (rr.kind == HitKind::None) return -ENOENT;

    const bool wantWrite = (fi->flags & (O_WRONLY | O_RDWR)) || (fi->flags & O_TRUNC);

    // Directory opens (rare) — no handle; reads won't follow.
    bool isDir = (rr.kind == HitKind::ImplicitDir) ||
                 (rr.kind == HitKind::ZipEntry && (rr.zipEntry == nullptr || rr.zipEntry->isDir));
    if (!isDir && (rr.kind == HitKind::WriteLayer || rr.kind == HitKind::DirLayer || rr.kind == HitKind::FileLayer))
    {
        struct stat st; if (::lstat(rr.hostPath.c_str(), &st) == 0 && S_ISDIR(st.st_mode)) isDir = true;
    }
    if (isDir) { if (wantWrite) return -EISDIR; fi->fh = 0; return 0; }

    if (wantWrite && S->readOnly) return -EROFS;

    // Read-only zip entry: serve from a materialized reader.
    if (!wantWrite && rr.kind == HitKind::ZipEntry && rr.zipEntry)
    {
        auto *zr = new ZipReader;
        int e = OpenZipEntry(*const_cast<ZipIndex *>(rr.layer->zip.get()), *rr.zipEntry, *zr);
        if (e != 0) { delete zr; return e; }
        auto *of = new OpenFile; of->zip = zr; fi->fh = (uint64_t)(uintptr_t)of;
        return 0;
    }

    // Host-backed open. Write intent copies up first (unless passthrough/already writable).
    std::string host;
    if (wantWrite)
    {
        if (!rr.rwPassthrough && rr.kind != HitKind::WriteLayer)
            if (int e = CopyUp(*S, v, rr); e != 0) return e;
        host = rr.rwPassthrough ? rr.hostPath : WLPath(*S, v);
    }
    else
    {
        host = rr.hostPath; // writelayer copy or under-layer original
    }

    int fd = ::open(host.c_str(), fi->flags);
    if (fd < 0) return -errno;
    auto *of = new OpenFile; of->fd = fd; fi->fh = (uint64_t)(uintptr_t)of;
    return 0;
}

//Ensures the host parent directory of `host` exists (used for passthrough writes into the source).
static int EnsureHostParent(const std::string &host)
{
    size_t s = host.find_last_of('/');
    if (s == std::string::npos) return 0;
    std::error_code ec;
    std::filesystem::create_directories(host.substr(0, s), ec);
    return ec ? -EIO : 0;
}

static int op_create(const char *path, mode_t mode, struct fuse_file_info *fi)
{
    VfsState *S = St();
    if (S->readOnly) return -EROFS;
    std::string v = V(path);

    std::string host;
    if (PassthroughHost(*S, v, host)) { EnsureHostParent(host); }   // straight to the durable source
    else { RemoveWhiteout(*S, v); if (int e = EnsureWriteParent(*S, v); e != 0) return e; host = WLPath(*S, v); }

    int fd = ::open(host.c_str(), (fi->flags | O_CREAT) & ~O_NOFOLLOW, mode);
    if (fd < 0) return -errno;
    auto *of = new OpenFile; of->fd = fd; fi->fh = (uint64_t)(uintptr_t)of;
    return 0;
}

static int op_read(const char *, char *buf, size_t size, off_t off, struct fuse_file_info *fi)
{
    auto *of = (OpenFile *)(uintptr_t)fi->fh;
    if (!of) return -EBADF;
    if (of->zip) return ReadZipEntry(*of->zip, buf, size, off);
    if (of->fd >= 0) { ssize_t r = ::pread(of->fd, buf, size, off); return r < 0 ? -errno : (int)r; }
    return -EBADF;
}

static int op_write(const char *, const char *buf, size_t size, off_t off, struct fuse_file_info *fi)
{
    if (St()->readOnly) return -EROFS;
    auto *of = (OpenFile *)(uintptr_t)fi->fh;
    if (!of || of->fd < 0) return -EBADF;
    ssize_t w = ::pwrite(of->fd, buf, size, off);
    return w < 0 ? -errno : (int)w;
}

static int op_release(const char *, struct fuse_file_info *fi)
{
    auto *of = (OpenFile *)(uintptr_t)fi->fh;
    if (of) { if (of->fd >= 0) ::close(of->fd); delete of->zip; delete of; }
    fi->fh = 0;
    return 0;
}

static int op_mkdir(const char *path, mode_t mode)
{
    VfsState *S = St();
    if (S->readOnly) return -EROFS;
    std::string v = V(path);
    std::string host;
    if (PassthroughHost(*S, v, host)) { EnsureHostParent(host); return ::mkdir(host.c_str(), mode) == 0 ? 0 : -errno; }
    RemoveWhiteout(*S, v);
    if (int e = EnsureWriteParent(*S, v); e != 0) return e;
    if (::mkdir(WLPath(*S, v).c_str(), mode) != 0) return -errno;
    return 0;
}

static int op_unlink(const char *path)
{
    VfsState *S = St();
    if (S->readOnly) return -EROFS;
    std::string v = V(path);
    std::string host;
    if (PassthroughHost(*S, v, host)) return ::unlink(host.c_str()) == 0 ? 0 : -errno; // straight to source
    if (!S->writelayer.empty()) ::unlink(WLPath(*S, v).c_str());
    if (Resolve(*S, v).kind != HitKind::None) CreateWhiteout(*S, v); // still visible below → hide it
    return 0;
}

static int op_rmdir(const char *path)
{
    VfsState *S = St();
    if (S->readOnly) return -EROFS;
    std::string v = V(path);
    std::set<std::string> children;
    CollectChildren(S, v, children);
    if (!children.empty()) return -ENOTEMPTY;
    std::string host;
    if (PassthroughHost(*S, v, host)) return ::rmdir(host.c_str()) == 0 ? 0 : -errno;
    if (!S->writelayer.empty()) ::rmdir(WLPath(*S, v).c_str());
    if (Resolve(*S, v).kind != HitKind::None) CreateWhiteout(*S, v);
    return 0;
}

static int op_rename(const char *from, const char *to, unsigned int flags)
{
    VfsState *S = St();
    if (S->readOnly) return -EROFS;
    if (flags) return -EINVAL; // RENAME_EXCHANGE/NOREPLACE unsupported
    std::string vf = V(from), vt = V(to);
    ResolveResult rr = Resolve(*S, vf);
    if (rr.kind == HitKind::None) return -ENOENT;

    // Directory rename spanning layers → EXDEV (recursive dir copy-up deferred). Pure-writelayer dirs rename fine.
    struct stat st;
    bool isDir = (rr.kind == HitKind::ImplicitDir) ||
                 (rr.kind == HitKind::ZipEntry && (rr.zipEntry == nullptr || rr.zipEntry->isDir)) ||
                 ((rr.kind == HitKind::DirLayer || rr.kind == HitKind::WriteLayer) &&
                  ::lstat(rr.hostPath.c_str(), &st) == 0 && S_ISDIR(st.st_mode));
    if (isDir && rr.kind != HitKind::WriteLayer) return -EXDEV;

    if (rr.kind != HitKind::WriteLayer && !rr.rwPassthrough)
        if (int e = CopyUp(*S, vf, rr); e != 0) return e;

    std::string src = rr.rwPassthrough ? rr.hostPath : WLPath(*S, vf);
    std::string dst;
    if (PassthroughHost(*S, vt, dst)) { EnsureHostParent(dst); }
    else { if (int e = EnsureWriteParent(*S, vt); e != 0) return e; RemoveWhiteout(*S, vt); dst = WLPath(*S, vt); }
    if (::rename(src.c_str(), dst.c_str()) != 0) return -errno;

    if (Resolve(*S, vf).kind != HitKind::None) CreateWhiteout(*S, vf); // old name still below → hide it
    return 0;
}

static int op_truncate(const char *path, off_t size, struct fuse_file_info *fi)
{
    VfsState *S = St();
    if (S->readOnly) return -EROFS;
    if (fi && fi->fh)
    {
        auto *of = (OpenFile *)(uintptr_t)fi->fh;
        if (of && of->fd >= 0) return ::ftruncate(of->fd, size) == 0 ? 0 : -errno;
    }
    std::string v = V(path);
    ResolveResult rr = Resolve(*S, v);
    if (rr.kind == HitKind::None) return -ENOENT;
    if (rr.kind != HitKind::WriteLayer && !rr.rwPassthrough)
        if (int e = CopyUp(*S, v, rr); e != 0) return e;
    std::string host = rr.rwPassthrough ? rr.hostPath : WLPath(*S, v);
    return ::truncate(host.c_str(), size) == 0 ? 0 : -errno;
}

static int op_chmod(const char *path, mode_t mode, struct fuse_file_info *)
{
    VfsState *S = St();
    if (S->readOnly) return -EROFS;
    std::string v = V(path);
    ResolveResult rr = Resolve(*S, v);
    if (rr.kind == HitKind::None) return -ENOENT;
    if (rr.kind != HitKind::WriteLayer && !rr.rwPassthrough)
        if (int e = CopyUp(*S, v, rr); e != 0) return e;
    std::string host = rr.rwPassthrough ? rr.hostPath : WLPath(*S, v);
    return ::chmod(host.c_str(), mode) == 0 ? 0 : -errno;
}

static int op_chown(const char *, uid_t, gid_t, struct fuse_file_info *)
{
    // Ownership is presented as uid/gid unconditionally; record nothing. No-op success so installers
    // that chown don't fail.
    return St()->readOnly ? -EROFS : 0;
}

static int op_utimens(const char *path, const struct timespec tv[2], struct fuse_file_info *)
{
    VfsState *S = St();
    if (S->readOnly) return -EROFS;
    std::string v = V(path);
    ResolveResult rr = Resolve(*S, v);
    if (rr.kind == HitKind::None) return -ENOENT;
    // Only touch timestamps on already-writable targets (don't force a copy-up just for mtime).
    if (rr.kind != HitKind::WriteLayer && !rr.rwPassthrough) return 0;
    std::string host = rr.rwPassthrough ? rr.hostPath : WLPath(*S, v);
    return ::utimensat(AT_FDCWD, host.c_str(), tv, AT_SYMLINK_NOFOLLOW) == 0 ? 0 : -errno;
}

static int op_readlink(const char *path, char *buf, size_t size)
{
    VfsState *S = St();
    ResolveResult rr = Resolve(*S, V(path));
    if (rr.kind == HitKind::WriteLayer || rr.kind == HitKind::DirLayer || rr.kind == HitKind::FileLayer)
    {
        ssize_t n = ::readlink(rr.hostPath.c_str(), buf, size - 1);
        if (n < 0) return -errno;
        buf[n] = '\0';
        return 0;
    }
    return -EINVAL; // not a symlink (zip symlinks deferred)
}

static int op_symlink(const char *target, const char *path)
{
    VfsState *S = St();
    if (S->readOnly) return -EROFS;
    std::string v = V(path);
    std::string host;
    if (PassthroughHost(*S, v, host)) { EnsureHostParent(host); return ::symlink(target, host.c_str()) == 0 ? 0 : -errno; }
    RemoveWhiteout(*S, v);
    if (int e = EnsureWriteParent(*S, v); e != 0) return e;
    return ::symlink(target, WLPath(*S, v).c_str()) == 0 ? 0 : -errno;
}

static int op_flush(const char *, struct fuse_file_info *) { return 0; }

static int op_fsync(const char *, int, struct fuse_file_info *fi)
{
    auto *of = (OpenFile *)(uintptr_t)fi->fh;
    if (of && of->fd >= 0) return ::fsync(of->fd) == 0 ? 0 : -errno;
    return 0;
}

static int op_statfs(const char *, struct statvfs *stbuf)
{
    VfsState *S = St();
    std::string ref = !S->writelayer.empty() ? S->writelayer
                    : (!S->layers.empty() ? S->layers.front().source : std::string("/"));
    return ::statvfs(ref.c_str(), stbuf) == 0 ? 0 : -errno;
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
