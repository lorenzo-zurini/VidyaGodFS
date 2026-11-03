// VfsOps — the backend-neutral filesystem operations (see vfsops.h). Bodies lifted from the
// old fuseops.cpp with the FUSE/struct-stat specifics removed: paths are already-normalized
// vrel, host I/O goes through HostIO, attributes come back as a neutral VfsAttr, and readdir
// yields names through a callback. A mount backend (fuse_backend.cpp / winfsp_backend.cpp)
// translates its native interface to/from these calls.
#include "vfsops.h"

#include <set>
#include <string>
#include <filesystem>
#include <cerrno>
#include <fcntl.h>   // O_* flag constants (passed through to HostIO::Open)

// O_NOFOLLOW (don't follow a trailing symlink on open) has no Windows/MinGW equivalent; define it
// as a no-op there so `& ~O_NOFOLLOW` compiles and is inert (Windows opens don't traverse symlinks).
#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0
#endif

// ---- neutral helpers -----------------------------------------------------

// Path segment of `path` immediately after the directory `v` ("" = root); "" if not under v.
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

// Merged child names of directory v (excluding . / ..), honoring whiteouts + opaque masking.
static void CollectChildren(VfsState &S, const std::string &v, std::set<std::string> &out)
{
    std::set<std::string> whiteouts;
    bool opaque = false; // this dir masks the lower layers entirely (.wh..wh..opq present)

    if (!S.writelayer.empty())
        HostIO::ReadDir(WLPath(S, v), [&](const std::string &n) {
            if (n == ".wh..wh..opq")        { opaque = true; return; }
            if (n.rfind(".wh.", 0) == 0)    { whiteouts.insert(n.substr(4)); return; }
            out.insert(n);
        });
    // (No lazy mask enabling here anymore: Init seeds the in-memory masks from the persisted writelayer,
    // and every runtime marker mutation updates them — the listing above is just this dir's disk view.)

    // A delta-backed (opaque) layer covering v masks every LOWER same-subtree layer's children.
    int opaquePrio = -1;
    for (const Layer &L : S.layers)
        if (L.opaque && LayerCovers(L, v) && L.priority > opaquePrio) opaquePrio = L.priority;
    // A kept folder's directory made again over a deleted one masks the lower layers the same way.
    for (const Layer &L : S.layers)
        if (L.type == LayerType::Dir && L.rw && LayerCovers(L, v) && L.priority > opaquePrio && KeptOpaqueDir(L, v))
            opaquePrio = L.priority;
    std::set<std::string> keptWhiteouts, keptOwn;   // a kept folder's markers hide LOWER names, never its own

    for (const Layer &L : S.layers)
    {
        if (L.priority < opaquePrio) continue;   // masked by a higher opaque layer over this subtree

        if (!opaque && LayerCovers(L, v))
        {
            if (L.type == LayerType::Dir)
            {
                std::string rel = SourceRel(L, v);
                std::string host = rel.empty() ? L.source : (L.source + "/" + rel);
                HostIO::ReadDir(host, [&](const std::string &n) {
                    if (L.rw && n.rfind(".wh.", 0) == 0)   // a kept folder's deletion markers: never listed
                    {
                        if (n != ".wh..wh..opq") keptWhiteouts.insert(n.substr(4));
                        return;
                    }
                    if (L.rw) keptOwn.insert(n);
                    out.insert(n);
                });
            }
            else if (L.type == LayerType::Zip)
            {
                std::string rel = SourceRel(L, v);
                auto it = L.zip->dirChildren.find(rel);
                if (it != L.zip->dirChildren.end())
                    for (const std::string &c : it->second)
                    {
                        //A link entry claiming a target longer than any path does not exist (Resolve): not listed.
                        const auto eit = L.zip->byName.find(rel.empty() ? c : rel + "/" + c);
                        if (S.flattenSymlinks && eit != L.zip->byName.end() && eit->second.symlink
                            && (eit->second.size > 4096 || !eit->second.stored) && ResolveZipSymlink(*L.zip, eit->second) == nullptr)
                            continue;
                        out.insert(c);   // a link listed as a file or as a link
                    }
            }
        }
        // File-layer basename and structural child-dir contributions come from LOWER layers too, so an
        // opaque writelayer dir must suppress them exactly like the Dir/Zip content above — otherwise readdir
        // lists names that Resolve (via IsUnderOpaque) reports ENOENT for.
        if (!opaque)
        {
            // File layer: its basename is a child of its containing dir.
            if (L.type == LayerType::File && SegmentAfter(v, L.fileVPath) == L.fileBase)
                out.insert(L.fileBase);
            // Structural child dir from a deeper layer presence (target / fileVPath).
            const std::string &pp = (L.type == LayerType::File) ? L.fileVPath : L.target;
            if (std::string seg = SegmentAfter(v, pp); !seg.empty()) out.insert(seg);
        }
    }

    if (!opaque)
        for (const std::string &d : S.implicitDirs)
            if (std::string seg = SegmentAfter(v, d); !seg.empty()) out.insert(seg);

    for (const std::string &w : whiteouts) out.erase(w);
    for (const std::string &w : keptWhiteouts) if (!keptOwn.count(w)) out.erase(w);
}

// A kept folder holds the user's files and its own `.wh.*` deletion markers side by side; a guest name that looks
// like a marker would read as one on the next mount, so it is refused there.
static bool MarkerName(const std::string &v)
{
    const size_t s = v.find_last_of('/');
    return v.compare(s == std::string::npos ? 0 : s + 1, 4, ".wh.") == 0;
}

// Ensure the host parent directory of `host` exists (for passthrough writes into the source).
static int EnsureHostParent(const std::string &host)
{
    size_t s = host.find_last_of('/');
    if (s == std::string::npos) return 0;
    std::error_code ec;
    std::filesystem::create_directories(host.substr(0, s), ec);
    return ec ? -EIO : 0;
}

// Recursively copy-up the merged subtree rooted at vsrc into the writelayer, so the whole
// subtree becomes writable in place and can then be moved with a single Rename (cross-layer
// directory rename).
static int DeepCopyUp(VfsState &S, const std::string &vsrc)
{
    ResolveResult rr = Resolve(S, vsrc);
    if (rr.kind == HitKind::None) return -ENOENT;
    if (int e = CopyUp(S, vsrc, rr); e != 0) return e;

    bool isDir = (rr.kind == HitKind::ImplicitDir) ||
                 (rr.kind == HitKind::ZipEntry && (rr.zipEntry == nullptr || rr.zipEntry->isDir));
    if (!isDir && (rr.kind == HitKind::WriteLayer || rr.kind == HitKind::DirLayer))
    {
        HostIO::Stat st;
        if (HostIO::Lstat(rr.hostPath, st) == 0 && st.isDir) isDir = true;
    }
    if (!isDir) return 0;

    std::set<std::string> children;
    CollectChildren(S, vsrc, children);
    for (const std::string &c : children)
        if (int e = DeepCopyUp(S, vsrc + "/" + c); e != 0) return e;
    return 0;
}

// ---- ops -----------------------------------------------------------------

int VfsGetattr(VfsState &S, const std::string &v, VfsAttr &out)
{
    out = VfsAttr{};
    out.uid = S.uid; out.gid = S.gid;
    if (v.empty()) { out.isDir = true; out.perms = 0755; out.nlink = 2; return 0; }

    ResolveResult rr = Resolve(S, v);
    switch (rr.kind)
    {
        case HitKind::None:        return -ENOENT;
        case HitKind::ImplicitDir: out.isDir = true; out.perms = 0755; out.nlink = 2; return 0;
        case HitKind::WriteLayer:
        case HitKind::DirLayer:
        case HitKind::FileLayer:
        {
            // Symlink abolition: DATA layers present a link as its target (follow); the writelayer and rw
            // passthrough layers — live guest-written runtime state — still present symlinks as such.
            const bool follow = S.flattenSymlinks && rr.kind != HitKind::WriteLayer && !rr.rwPassthrough;
            HostIO::Stat st;
            if (int e = follow ? HostIO::StatFollow(rr.hostPath, st) : HostIO::Lstat(rr.hostPath, st); e != 0)
                return e;
            out.isDir = st.isDir; out.isSymlink = st.isSymlink;
            out.perms = st.mode & 0777; out.size = st.size; out.mtime = st.mtime; out.nlink = st.nlink;
            return 0;
        }
        case HitKind::ZipEntry:
            if (rr.zipEntry == nullptr || rr.zipEntry->isDir) { out.isDir = true; out.perms = 0555; out.nlink = 2; return 0; }
            out.isSymlink = rr.zipEntry->symlink;
            out.perms = rr.zipEntry->symlink ? 0777 : 0555;
            out.size  = rr.zipEntry->size; out.mtime = rr.zipEntry->mtime; out.nlink = 1;
            return 0;
    }
    return -ENOENT;
}

int VfsReaddir(VfsState &S, const std::string &v, const DirFiller &fill)
{
    std::set<std::string> names;
    CollectChildren(S, v, names);
    for (const std::string &n : names) fill(n);
    return 0;
}

int VfsReaddirTyped(VfsState &S, const std::string &v, const TypedDirFiller &fill)
{
    std::set<std::string> names;
    CollectChildren(S, v, names);
    for (const std::string &n : names)
    {
        VfsAttr a;
        if (VfsGetattr(S, v.empty() ? n : v + "/" + n, a) == 0) fill(n, a);   // a name getattr cannot serve is not listed
    }
    return 0;
}

int VfsOpen(VfsState &S, const std::string &v, int flags, OpenFile *&out)
{
    out = nullptr;
    ResolveResult rr = Resolve(S, v);
    if (rr.kind == HitKind::None) return -ENOENT;

    const bool wantWrite = (flags & (O_WRONLY | O_RDWR)) || (flags & O_TRUNC);

    // Directory opens (rare) — no handle; reads won't follow.
    bool isDir = (rr.kind == HitKind::ImplicitDir) ||
                 (rr.kind == HitKind::ZipEntry && (rr.zipEntry == nullptr || rr.zipEntry->isDir));
    if (!isDir && (rr.kind == HitKind::WriteLayer || rr.kind == HitKind::DirLayer || rr.kind == HitKind::FileLayer))
    {
        HostIO::Stat st;
        if (HostIO::Lstat(rr.hostPath, st) == 0 && st.isDir) isDir = true;
    }
    if (isDir) { if (wantWrite) return -EISDIR; return 0; }   // out stays null → backend uses a null handle

    if (wantWrite && S.readOnly) return -EROFS;

    // Read-only zip entry: serve from a materialized reader.
    if (!wantWrite && rr.kind == HitKind::ZipEntry && rr.zipEntry)
    {
        auto *zr = new ZipReader;
        int e = OpenZipEntry(*const_cast<ZipIndex *>(rr.layer->zip.get()), *rr.zipEntry, *zr);
        if (e != 0) { delete zr; return e; }
        auto *of = new OpenFile; of->zip = zr; out = of;
        return 0;
    }

    // Host-backed open. Write intent copies up first (unless passthrough/already writable).
    std::string host;
    if (wantWrite)
    {
        if (!rr.rwPassthrough && rr.kind != HitKind::WriteLayer)
            if (int e = CopyUp(S, v, rr); e != 0) return e;
        //Post-copy-up destination: the passthrough source when the path lives under a KEEP subtree
        //(CopyUp just landed the bytes THERE), else the writelayer copy.
        if (rr.rwPassthrough) host = rr.hostPath;
        else if (!PassthroughHost(S, v, host)) host = WLPath(S, v);
    }
    else
    {
        host = rr.hostPath; // writelayer copy or under-layer original
    }

    HostIO::Fd fd = HostIO::Open(host, flags);
    if (fd < 0) return (int)fd;
    auto *of = new OpenFile; of->fd = fd; out = of;
    return 0;
}

int VfsCreate(VfsState &S, const std::string &v, uint32_t mode, int flags, OpenFile *&out)
{
    out = nullptr;
    if (S.readOnly) return -EROFS;

    std::string host;
    const bool kept = PassthroughHost(S, v, host);
    if (kept) { if (MarkerName(v)) return -EINVAL; EnsureHostParent(host); }   // straight to the durable source
    else { RemoveWhiteout(S, v); if (int e = EnsureWriteParent(S, v); e != 0) return e; host = WLPath(S, v); }

    HostIO::Fd fd = HostIO::Open(host, (flags | O_CREAT) & ~O_NOFOLLOW, mode);
    if (fd < 0) return (int)fd;
    // Only now: the deleted name is made again. Were the marker to stay (an unlink failure), the new file still
    // shows — the folder's own names are never masked by its markers — and the marker keeps hiding the package copy.
    if (kept) UnhideLower(S, v);
    auto *of = new OpenFile; of->fd = fd; out = of;
    return 0;
}

ssize_t VfsRead(OpenFile *of, void *buf, size_t size, uint64_t off)
{
    if (!of) return -EBADF;
    if (of->zip) return ReadZipEntry(*of->zip, static_cast<char *>(buf), size, (off_t)off);
    if (of->fd >= 0) return HostIO::Pread(of->fd, buf, size, off);
    return -EBADF;
}

ssize_t VfsWrite(VfsState &S, OpenFile *of, const void *buf, size_t size, uint64_t off)
{
    if (S.readOnly) return -EROFS;
    if (!of || of->fd < 0) return -EBADF;
    return HostIO::Pwrite(of->fd, buf, size, off);
}

void VfsRelease(OpenFile *of)
{
    if (of) { if (of->fd >= 0) HostIO::Close(of->fd); delete of->zip; delete of; }
}

int VfsMkdir(VfsState &S, const std::string &v, uint32_t mode)
{
    if (S.readOnly) return -EROFS;
    std::string host;
    if (PassthroughHost(S, v, host))
    {
        if (MarkerName(v)) return -EINVAL;
        // The kept folder's own root, removed this session (VfsRmdir): it still exists, emptied — just show it again.
        if (const Layer *L = KeptLayerFor(S, v); L && SourceRel(*L, v).empty() && IsWhiteouted(S, v))
        { RemoveWhiteout(S, v); return 0; }
        const bool overDeleted = KeptHidden(S, v);   // made again over a deleted lower dir: it must start empty
        EnsureHostParent(host);
        if (int e = HostIO::Mkdir(host, mode); e != 0) return e;
        if (overDeleted)
            if (int e = KeptMarkOpaque(S, v); e != 0) { HostIO::Rmdir(host); return e; }
        UnhideLower(S, v);   // as in VfsCreate: a marker left behind only keeps masking the package's copy
        return 0;
    }
    // A whiteout here means this dir existed below and was deleted; recreating it must yield an
    // EMPTY dir, so mark it opaque to mask the lower layer's old contents.
    bool recreateOverLower = IsWhiteouted(S, v);
    RemoveWhiteout(S, v);
    if (int e = EnsureWriteParent(S, v); e != 0) return e;
    if (int e = HostIO::Mkdir(WLPath(S, v), mode); e != 0) return e;
    if (recreateOverLower) MarkOpaque(S, v);
    return 0;
}

int VfsUnlink(VfsState &S, const std::string &v)
{
    if (S.readOnly) return -EROFS;
    std::string host;
    if (PassthroughHost(S, v, host))
    {
        // The kept folder's own copy goes; a copy a lower layer provides is hidden by a marker in the folder.
        const int e = HostIO::Unlink(host);
        if (e != 0 && e != -ENOENT) return e;
        if (Resolve(S, v).kind != HitKind::None) return HideLower(S, v);
        return e;   // 0 if the kept folder had it, -ENOENT if nothing did
    }
    // Removing the writelayer copy (if any): tolerate ENOENT (it may only exist below), fail loudly on
    // anything else rather than silently returning success.
    if (!S.writelayer.empty())
    {
        int e = HostIO::Unlink(WLPath(S, v));
        if (e != 0 && e != -ENOENT) return e;
    }
    if (Resolve(S, v).kind != HitKind::None) CreateWhiteout(S, v); // still visible below → hide it
    return 0;
}

int VfsRmdir(VfsState &S, const std::string &v)
{
    if (S.readOnly) return -EROFS;
    std::set<std::string> children;
    CollectChildren(S, v, children);
    if (!children.empty()) return -ENOTEMPTY;
    std::string host;
    if (PassthroughHost(S, v, host))
    {
        // Its markers (names deleted inside it) go with it.
        KeptDropMarkersUnder(S, v);
        // The kept folder's own root is a mount point: it stays, emptied for good — opaque over the package's copy
        // (durable), and gone from this session's view until made again.
        if (const Layer *L = KeptLayerFor(S, v); L && SourceRel(*L, v).empty())
        {
            if (int e = KeptMarkOpaque(S, v); e != 0) return e;
            CreateWhiteout(S, v);
            return 0;
        }
        const int e = HostIO::Rmdir(host);
        if (e != 0 && e != -ENOENT) return e;
        if (Resolve(S, v).kind != HitKind::None) return HideLower(S, v);
        return e;
    }
    if (!S.writelayer.empty())
    {
        // The writelayer dir may still hold child whiteouts / an opaque marker (all ".wh."-prefixed),
        // which make it non-empty on disk even though the merged view is empty. Clear them so rmdir works —
        // and mirror each removal in the in-memory masks.
        std::string wl = WLPath(S, v);
        HostIO::ReadDir(wl, [&](const std::string &n) {
            if (n.rfind(".wh.", 0) != 0) return;
            if (n == ".wh..wh..opq") { HostIO::Unlink(wl + "/" + n); UnmarkOpaque(S, v); }
            else RemoveWhiteout(S, v.empty() ? n.substr(4) : v + "/" + n.substr(4)); // unlinks marker + mask erase
        });
        HostIO::Rmdir(wl);
    }
    if (Resolve(S, v).kind != HitKind::None) CreateWhiteout(S, v);
    return 0;
}

int VfsRename(VfsState &S, const std::string &vf, const std::string &vt)
{
    if (S.readOnly) return -EROFS;
    ResolveResult rr = Resolve(S, vf);
    if (rr.kind == HitKind::None) return -ENOENT;

    bool isDir = (rr.kind == HitKind::ImplicitDir) ||
                 (rr.kind == HitKind::ZipEntry && (rr.zipEntry == nullptr || rr.zipEntry->isDir));
    if (!isDir && (rr.kind == HitKind::DirLayer || rr.kind == HitKind::WriteLayer))
    {
        HostIO::Stat st;
        if (HostIO::Lstat(rr.hostPath, st) == 0 && st.isDir) isDir = true;
    }

    // Bring the source fully into the writelayer first, so it can then be moved with one Rename.
    // A DIRECTORY is a MERGED entity: even when a writelayer copy already exists (it may hold only a
    // whiteout from an earlier delete), lower layers can still contribute children — always deep-copy
    // the merged subtree up. A file needs a copy-up only when it isn't already writable.
    // A directory always: a kept one too, whose package contents would otherwise stay behind (and, hidden at the
    // old name, be lost for good). CopyUp is a no-op for what the folder already holds.
    if (isDir) { if (int e = DeepCopyUp(S, vf); e != 0) return e; }
    else if (!rr.rwPassthrough && rr.kind != HitKind::WriteLayer) { if (int e = CopyUp(S, vf, rr); e != 0) return e; }

    // CopyUp put a lower file under a kept folder INTO the folder (its durable store), not the writelayer.
    std::string src;
    if (rr.rwPassthrough) src = rr.hostPath;
    else if (!PassthroughHost(S, vf, src)) src = WLPath(S, vf);
    std::string dst;
    const bool dstKept = PassthroughHost(S, vt, dst);
    if (dstKept && MarkerName(vt)) return -EINVAL;
    const bool dstOverDeleted = dstKept && KeptHidden(S, vt);   // a dir moved onto a deleted one must not show its old contents
    if (dstKept) { EnsureHostParent(dst); }
    else { if (int e = EnsureWriteParent(S, vt); e != 0) return e; RemoveWhiteout(S, vt); dst = WLPath(S, vt); }
    if (int e = HostIO::Rename(src, dst); e != 0) return e;
    if (isDir) KeptRenamePrefix(S, vf, vt);   // the kept markers inside it moved along
    if (dstKept && isDir && dstOverDeleted)
        if (int e = KeptMarkOpaque(S, vt); e != 0) return e;
    if (dstKept) UnhideLower(S, vt);

    // A moved DIRECTORY takes its writelayer `.wh.*` markers with it — rewrite the in-memory masks to the
    // new prefix so they keep matching the relocated disk markers.
    if (isDir) RenameMaskPrefix(S, vf, vt);
    if (Resolve(S, vf).kind != HitKind::None) return HideLower(S, vf); // old name still below → hide it
    return 0;
}

int VfsTruncate(VfsState &S, const std::string &v, OpenFile *of, uint64_t size)
{
    if (S.readOnly) return -EROFS;
    if (of && of->fd >= 0) return HostIO::Ftruncate(of->fd, size);
    ResolveResult rr = Resolve(S, v);
    if (rr.kind == HitKind::None) return -ENOENT;
    if (rr.kind != HitKind::WriteLayer && !rr.rwPassthrough)
        if (int e = CopyUp(S, v, rr); e != 0) return e;
    std::string host;
    if (rr.rwPassthrough) host = rr.hostPath;
    else if (!PassthroughHost(S, v, host)) host = WLPath(S, v);
    return HostIO::Truncate(host, size);
}

int VfsChmod(VfsState &S, const std::string &v, uint32_t mode)
{
    if (S.readOnly) return -EROFS;
    ResolveResult rr = Resolve(S, v);
    if (rr.kind == HitKind::None) return -ENOENT;
    if (rr.kind != HitKind::WriteLayer && !rr.rwPassthrough)
        if (int e = CopyUp(S, v, rr); e != 0) return e;
    std::string host;
    if (rr.rwPassthrough) host = rr.hostPath;
    else if (!PassthroughHost(S, v, host)) host = WLPath(S, v);
    return HostIO::Chmod(host, mode);
}

int VfsUtimens(VfsState &S, const std::string &v, int64_t atimeSec, int64_t mtimeSec)
{
    if (S.readOnly) return -EROFS;
    ResolveResult rr = Resolve(S, v);
    if (rr.kind == HitKind::None) return -ENOENT;
    // Only touch timestamps on already-writable targets (don't force a copy-up just for mtime).
    if (rr.kind != HitKind::WriteLayer && !rr.rwPassthrough) return 0;
    std::string host = rr.rwPassthrough ? rr.hostPath : WLPath(S, v);
    return HostIO::Utimens(host, atimeSec, mtimeSec, /*followSymlink=*/false);
}

int VfsReadlink(VfsState &S, const std::string &v, std::string &target)
{
    ResolveResult rr = Resolve(S, v);
    // Under flattening a host data layer presents targets, not links; the writelayer and rw passthrough layers
    // (guest-written runtime state) hold real ones; an archive serves the links that do not resolve to a file
    // inside it (Resolve) as links.
    if (rr.kind == HitKind::WriteLayer || rr.rwPassthrough
        || (!S.flattenSymlinks && (rr.kind == HitKind::DirLayer || rr.kind == HitKind::FileLayer)))
        return HostIO::Readlink(rr.hostPath, target);
    // Zip symlink entry: the link target IS the entry content. Read it (STORED → zero-copy pread).
    if (rr.kind == HitKind::ZipEntry && rr.zipEntry && rr.zipEntry->symlink)
    {
        if (rr.zipEntry->size > 4096) return -ENAMETOOLONG;   // the archive's claim: never an allocation of it
        ZipReader zr;
        if (int e = OpenZipEntry(*const_cast<ZipIndex *>(rr.layer->zip.get()), *rr.zipEntry, zr); e != 0) return e;
        std::string t(rr.zipEntry->size, '\0');
        int got = ReadZipEntry(zr, t.data(), t.size(), 0);
        if (got < 0) return got;
        t.resize(got);
        target = std::move(t);
        return 0;
    }
    return -EINVAL; // not a symlink
}

int VfsSymlink(VfsState &S, const std::string &target, const std::string &v)
{
    if (S.readOnly) return -EROFS;
    std::string host;
    if (PassthroughHost(S, v, host))
    {
        if (MarkerName(v)) return -EINVAL;
        EnsureHostParent(host);
        if (int e = HostIO::Symlink(target, host); e != 0) return e;
        UnhideLower(S, v);   // as in VfsCreate
        return 0;
    }
    RemoveWhiteout(S, v);
    if (int e = EnsureWriteParent(S, v); e != 0) return e;
    return HostIO::Symlink(target, WLPath(S, v));
}

// A hard link, as rename does it: the existing file is made writable first (a copy-up, unless it lives in a kept
// passthrough folder), then linked host to host. Both names must land on one host file system; across two (the
// writelayer and a kept folder elsewhere) the host refuses with EXDEV, as any file system would. An AppImage's
// squashfs holds hard links, and unpacking one (bbport) failed on the missing op.
int VfsLink(VfsState &S, const std::string &vf, const std::string &vt)
{
    if (S.readOnly) return -EROFS;
    ResolveResult rr = Resolve(S, vf);
    if (rr.kind == HitKind::None) return -ENOENT;
    const bool isDir = (rr.kind == HitKind::ImplicitDir) ||
                       (rr.kind == HitKind::ZipEntry && (rr.zipEntry == nullptr || rr.zipEntry->isDir));
    if (isDir) return -EPERM;                                    // directories cannot be hard-linked
    if (Resolve(S, vt).kind != HitKind::None) return -EEXIST;
    if (!rr.rwPassthrough && rr.kind != HitKind::WriteLayer)
        if (int e = CopyUp(S, vf, rr); e != 0) return e;
    std::string src;   // CopyUp put a lower file under a kept folder INTO the folder (as rename)
    if (rr.rwPassthrough) src = rr.hostPath;
    else if (!PassthroughHost(S, vf, src)) src = WLPath(S, vf);
    std::string dst;
    if (PassthroughHost(S, vt, dst)) { if (MarkerName(vt)) return -EINVAL; EnsureHostParent(dst); }
    else { if (int e = EnsureWriteParent(S, vt); e != 0) return e; dst = WLPath(S, vt); }
    if (int e = HostIO::Link(src, dst); e != 0) return e;
    UnhideLower(S, vt);   // only now: a failed link must not bring back a deleted lower-layer file at that name
    return 0;
}

int VfsFsync(OpenFile *of)
{
    if (of && of->fd >= 0) return HostIO::Fsync(of->fd);
    return 0;
}

int VfsStatfs(VfsState &S, HostIO::StatvfsInfo &out)
{
    std::string ref = !S.writelayer.empty() ? S.writelayer
                    : (!S.layers.empty() ? S.layers.front().source : std::string("/"));
    return HostIO::Statvfs(ref, out);
}
