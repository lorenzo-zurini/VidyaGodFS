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
            if (n.rfind(kCopyTmpPrefix, 0) == 0) return;   // a copy-up under way (or left by a crash): no name
            if (n.rfind(".wh.", 0) == 0)    { whiteouts.insert(n.substr(4)); return; }
            out.insert(n);
        });
    // Under a folder made opaque (made again, or moved over a deleted one), the lower layers show nothing — as Resolve
    // has it: their names are no children here (an emptied folder there was "not empty" to rename and rmdir).
    if (!opaque && IsUnderOpaque(S, v)) opaque = true;
    // (No lazy mask enabling here anymore: Init seeds the in-memory masks from the persisted writelayer,
    // and every runtime marker mutation updates them — the listing above is just this dir's disk view.)

    // A kept folder's directory made again over a deleted one masks every LOWER same-subtree layer's children.
    int opaquePrio = -1;
    for (const Layer &L : S.layers)
        if (L.type == LayerType::Dir && L.rw && LayerCovers(L, v) && L.priority > opaquePrio && KeptOpaqueDir(L, v))
            opaquePrio = L.priority;
    std::set<std::string> keptWhiteouts, keptOwn;   // a kept folder's markers hide LOWER names, never its own

    for (const Layer &L : S.layers)
    {
        if (L.priority < opaquePrio) continue;   // masked by a higher opaque layer over this subtree
        if (LayerMasked(L, v)) continue;          // a base hidden here by the delta built over it

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

    if (S.caseInsensitive)
    {   // a marker hides its name in whatever case it was deleted by, as Resolve has it (MaskKey)
        std::set<std::string> wf, kf, of;
        for (const std::string &w : whiteouts) wf.insert(FoldCase(w));
        for (const std::string &w : keptWhiteouts) kf.insert(FoldCase(w));
        for (const std::string &o : keptOwn) of.insert(FoldCase(o));
        for (auto it = out.begin(); it != out.end();)
        {
            const std::string f = FoldCase(*it);
            it = (wf.count(f) || (kf.count(f) && !of.count(f))) ? out.erase(it) : std::next(it);
        }
        return;
    }
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

static std::atomic<long long> g_LazyOpens{ 0 }, g_LazyCopies{ 0 };
long long DebugLazyOpens() { return g_LazyOpens.load(); }
long long DebugLazyCopies() { return g_LazyCopies.load(); }

//A handle over a lower copy on a writable mount takes the path's marker: a copy-up of the path from now on is what it
//reads (and, lazy, writes). A name change since the path was resolved (Seen.detaches) is looked at: when the path no
//longer names the file this handle has, the marker is the handle's own. A copy-up made since (Seen.copyUps), before
//the marker was there, is taken as this file's copy — when no name changed meanwhile.
struct OpenSeen { unsigned long long copyUps, detaches; };
static void TakeMarker(VfsState &S, const std::string &v, OpenFile *of, const OpenSeen &Seen, const ResolveResult &rr)
{
    if (S.debugHook) S.debugHook("open-before-marker");
    of->pending = S.PendingFor(v, Seen.detaches, [&] {
        const ResolveResult now = Resolve(S, v);
        return now.kind == rr.kind && now.hostPath == rr.hostPath && now.zipEntry == rr.zipEntry && now.layer == rr.layer;
    });
    of->state = &S;
    of->vrel = v;
    if (of->pending->detached.load() || S.copyUps.load() == Seen.copyUps) return;
    std::string dst;
    if (!PassthroughHost(S, v, dst)) dst = WLPath(S, v);
    HostIO::Stat st;
    if (HostIO::Lstat(dst, st) == 0 && !st.isDir) S.AdoptCopy(v, dst);
}

int VfsOpen(VfsState &S, const std::string &v, int flags, OpenFile *&out)
{
    out = nullptr;
    const OpenSeen Seen{ S.copyUps.load(), S.detaches.load() };
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

    //A lower copy a write may copy up while this handle reads it (a lazy handle's first write, an open that truncates):
    //read-only handles follow the copy too — one left on the lower file read what the file was before.
    const bool Followed = !S.readOnly && !S.writelayer.empty() && !rr.rwPassthrough
                       && (rr.kind == HitKind::DirLayer || rr.kind == HitKind::FileLayer || (rr.kind == HitKind::ZipEntry && rr.zipEntry));

    // Read-only zip entry: serve from a materialized reader.
    if (!wantWrite && rr.kind == HitKind::ZipEntry && rr.zipEntry)
    {
        auto *zr = new ZipReader;
        int e = OpenZipEntry(*const_cast<ZipIndex *>(rr.layer->zip.get()), *rr.zipEntry, *zr);
        if (e != 0) { delete zr; return e; }
        auto *of = new OpenFile; of->zip = zr; of->patch = PatchesFor(S, v); out = of;
        if (Followed) TakeMarker(S, v, of, Seen, rr);
        return 0;
    }

    //Opened to read and write a lower file, nothing truncated or appended: it is served from below until it changes,
    //copied up at its first write or truncate. Old games open their data and archive files read-write and never
    //write them: each such open copied the whole file into the writelayer (gigabytes, every launch).
    const bool Lazy = Followed && wantWrite && (flags & O_ACCMODE) == O_RDWR && !(flags & (O_TRUNC | O_APPEND));
    if (Lazy)
    {
        auto *of = new OpenFile;
        if (rr.kind == HitKind::ZipEntry)
        {
            auto *zr = new ZipReader;
            if (int e = OpenZipEntry(*const_cast<ZipIndex *>(rr.layer->zip.get()), *rr.zipEntry, *zr); e != 0)
            { delete zr; delete of; return e; }
            of->zip = zr;
        }
        else if ((of->fd = HostIO::Open(rr.hostPath, O_RDONLY)) < 0) { const int e = (int)of->fd; delete of; return e; }
        of->patch = PatchesFor(S, v);
        TakeMarker(S, v, of, Seen, rr);
        of->flags = flags & ~(O_CREAT | O_EXCL | O_TRUNC);
        ++g_LazyOpens;
        out = of;
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
    //A lower file read as it is: with its patches. A copy (the writelayer's, a kept folder's) is read as it is.
    if (!wantWrite && !rr.rwPassthrough && (rr.kind == HitKind::DirLayer || rr.kind == HitKind::FileLayer)) of->patch = PatchesFor(S, v);
    if (!wantWrite && Followed) TakeMarker(S, v, of, Seen, rr);
    return 0;
}

//What FUSE's kernel lookup answers before a name is made on Linux, and WinFsp leaves to us: a name is made only in a
//folder that is there (else the writelayer's parents were made for it, and a folder no one made appeared) and, with
//Excl, only where none is (a name only a lower layer has is taken: else an empty writelayer entry shadowed it).
static int MayMakeName(VfsState &S, const std::string &v, bool Excl)
{
    VfsAttr a;
    if (Excl && VfsGetattr(S, v, a) == 0) return -EEXIST;
    if (const size_t cut = v.find_last_of('/'); cut != std::string::npos)
    {
        if (int e = VfsGetattr(S, v.substr(0, cut), a); e != 0) return e;
        if (!a.isDir) return -ENOTDIR;
    }
    return 0;
}

int VfsCreate(VfsState &S, const std::string &v, uint32_t mode, int flags, OpenFile *&out)
{
    out = nullptr;
    if (S.readOnly) return -EROFS;
    if (int e = MayMakeName(S, v, (flags & O_EXCL) != 0); e != 0) return e;   // CREATE_NEW / O_EXCL

    std::string host;
    const bool kept = PassthroughHost(S, v, host);
    if (kept) { if (MarkerName(v)) return -EINVAL; EnsureHostParent(host); }   // straight to the durable source
    else { if (int e = EnsureWriteParent(S, v); e != 0) return e; host = WLPath(S, v); }

    S.BeginNameChange();   // a file made at the name is another file than the one its open handles were opened on
    const HostIO::Fd fd = HostIO::Open(host, (flags | O_CREAT) & ~O_NOFOLLOW, mode);
    if (fd < 0) { S.EndNameChange({}); return (int)fd; }
    //Only once it is made: a refused create leaves the deleted file deleted. A marker that will not come off hides the
    //file just made: said (EIO), the file closed.
    if (!kept)
        if (int e = RemoveWhiteout(S, v); e != 0) { HostIO::Close(fd); S.EndNameChange({ { v, false } }); return e; }
    S.EndNameChange({ { v, false } });
    // Only now: the deleted name is made again. Were the marker to stay (an unlink failure), the new file still
    // shows — the folder's own names are never masked by its markers — and the marker keeps hiding the package copy.
    if (kept) UnhideLower(S, v);
    auto *of = new OpenFile; of->fd = fd; out = of;
    return 0;
}

//A handle whose name was unlinked, renamed or made again before any copy-up (detached): its file has no name here any
//more, and a write makes it a copy of its own — of what it reads, in the writelayer under a name no listing shows,
//unlinked at once — shared by the handles opened on the same file.
static int PrivateCopy(OpenFile *of)
{
    VfsState::PendingCopy &P = *of->pending;
    std::lock_guard<std::mutex> g(P.mu);
    if (P.upper.load(std::memory_order_acquire) >= 0) return 0;
    static std::atomic<unsigned long long> Seq{ 0 };
    const std::string tmp = WLPath(*of->state, "") + "/" + kCopyTmpPrefix + "own." + std::to_string(++Seq);
    const HostIO::Fd out = HostIO::Open(tmp, O_CREAT | O_EXCL | O_RDWR, 0644);
    if (out < 0) return (int)out;
    char buf[256 * 1024];
    int rc = 0;
    for (uint64_t off = 0;;)
    {
        const ssize_t got = of->zip ? (ssize_t)ReadZipEntry(*of->zip, buf, sizeof buf, (off_t)off)
                                    : HostIO::Pread(of->fd, buf, sizeof buf, off);
        if (got < 0) { rc = (int)got; break; }
        if (got == 0) break;
        OverlayPatches(of->patch, buf, (size_t)got, off);
        if (int we = HostIO::FullWrite(out, buf, (size_t)got); we != 0) { rc = we; break; }
        off += (uint64_t)got;
    }
    HostIO::Unlink(tmp);
    if (rc != 0) { HostIO::Close(out); return rc; }
    P.upper.store(out, std::memory_order_release);
    return 0;
}

//A lazy handle about to change its file: the copy made now (once, whichever handle comes first), then used. A copy
//found at its name is taken only when no name changed between looking and taking (else it is looked at again).
static int CopyUpForChange(OpenFile *of)
{
    VfsState::PendingCopy &P = *of->pending;
    for (int Tries = 0; Tries < 8; ++Tries)
    {
        if (P.upper.load(std::memory_order_acquire) >= 0) return 0;
        if (P.detached.load(std::memory_order_acquire)) return PrivateCopy(of);
        VfsState &S = *of->state;
        const unsigned long long Seen = S.detaches.load();
        ResolveResult rr = Resolve(S, of->vrel);
        if (rr.kind == HitKind::WriteLayer || rr.rwPassthrough)
            S.AdoptCopy(of->vrel, rr.hostPath);                        // copied before this handle took its marker
        else if (rr.kind == HitKind::None)
        {
            if (S.detaches.load() == Seen) return -ENOENT;
            continue;
        }
        else
        {
            if (int e = CopyUp(S, of->vrel, rr); e != 0) return e;
            ++g_LazyCopies;
        }
        if (P.upper.load(std::memory_order_acquire) >= 0) return 0;
        if (!P.detached.load(std::memory_order_acquire) && S.detaches.load() == Seen) return -EIO;   // logged at the open
    }
    return P.upper.load(std::memory_order_acquire) >= 0 ? 0 : P.detached.load() ? PrivateCopy(of) : -EIO;
}

//What a read of this handle reads: the copy once there is one, else what it was opened on (-1).
static int UpperOf(const OpenFile *of)
{
    return of->pending ? of->pending->upper.load(std::memory_order_acquire) : -1;
}

bool VfsReadFrom(OpenFile *of, size_t size, uint64_t off, int &fd, uint64_t &pos, size_t &len)
{
    if (!of) return false;
    if (const int Up = UpperOf(of); Up >= 0) { fd = Up; pos = off; len = size; return true; }
    if (PatchesOverlap(of->patch, off, size)) return false;   // patched bytes: read through VfsRead
    if (of->zip)
    {
        const ZipReader &R = *of->zip;
        auto *F = dynamic_cast<FdByteSource *>(R.src);
        if (!R.stored || !F || F->fd < 0) return false;
        fd = F->fd;
        pos = R.dataOffset + off;
        len = off >= R.size ? 0 : (size_t)std::min<uint64_t>(size, R.size - off);
        return true;
    }
    if (of->fd < 0) return false;
    fd = (int)of->fd; pos = off; len = size;
    return true;
}

ssize_t VfsRead(OpenFile *of, void *buf, size_t size, uint64_t off)
{
    if (!of) return -EBADF;
    if (const int Up = UpperOf(of); Up >= 0) return HostIO::Pread(Up, buf, size, off);
    ssize_t Got = -EBADF;
    if (of->zip) Got = ReadZipEntry(*of->zip, static_cast<char *>(buf), size, (off_t)off);
    else if (of->fd >= 0) Got = HostIO::Pread(of->fd, buf, size, off);
    if (Got > 0) OverlayPatches(of->patch, buf, (size_t)Got, off);
    return Got;
}

ssize_t VfsWrite(VfsState &S, OpenFile *of, const void *buf, size_t size, uint64_t off)
{
    if (S.readOnly) return -EROFS;
    if (of && of->pending)
    {
        if (!(of->flags & (O_WRONLY | O_RDWR))) return -EBADF;   // opened to read
        if (int e = CopyUpForChange(of); e != 0) return e;
        return HostIO::Pwrite(UpperOf(of), buf, size, off);
    }
    if (!of || of->fd < 0) return -EBADF;
    return HostIO::Pwrite(of->fd, buf, size, off);
}

void VfsRelease(OpenFile *of)
{
    if (!of) return;
    if (of->fd >= 0) HostIO::Close(of->fd);
    delete of->zip;                                   // the copy (pending->upper) goes with the path's last handle
    delete of;
}

int VfsMkdir(VfsState &S, const std::string &v, uint32_t mode)
{
    if (S.readOnly) return -EROFS;
    if (int e = MayMakeName(S, v, true); e != 0) return e;
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
    if (int e = EnsureWriteParent(S, v); e != 0) return e;
    if (int e = HostIO::Mkdir(WLPath(S, v), mode); e != 0) return e;
    if (recreateOverLower)
        if (int e = MarkOpaque(S, v); e != 0) { HostIO::Rmdir(WLPath(S, v)); return e; }
    return RemoveWhiteout(S, v);   // only once it is made (and opaque): a refused mkdir leaves the deleted folder deleted
}

static int UnlinkImpl(VfsState &S, const std::string &v);

//The handles open on the file keep it (POSIX): its name's markers come off with it. The change is announced first
//(BeginNameChange), so an open between the two looks again at what its name names.
int VfsUnlink(VfsState &S, const std::string &v)
{
    if (S.readOnly) return -EROFS;
    S.BeginNameChange();
    const int e = UnlinkImpl(S, v);
    if (e == 0) S.EndNameChange({ { v, false } });
    else S.EndNameChange({});
    return e;
}

static int UnlinkImpl(VfsState &S, const std::string &v)
{
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
    if (Resolve(S, v).kind != HitKind::None) return CreateWhiteout(S, v); // still visible below → hide it (or fail)
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
            return CreateWhiteout(S, v);
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
        std::vector<std::string> names;
        HostIO::ReadDir(wl, [&](const std::string &n) { if (n.rfind(".wh.", 0) == 0) names.push_back(n); });
        std::vector<std::string> swept;
        bool sweptOpaque = false;
        for (const std::string &n : names)
        {
            if (n.rfind(kCopyTmpPrefix, 0) == 0) { HostIO::Unlink(wl + "/" + n); continue; }   // a dead copy: no marker
            if (n == ".wh..wh..opq")
            {
                if (int e = HostIO::Unlink(wl + "/" + n); e == 0 || e == -ENOENT) { UnmarkOpaque(S, v); sweptOpaque = true; }
                continue;
            }
            const std::string c = v.empty() ? n.substr(4) : v + "/" + n.substr(4);
            if (RemoveWhiteout(S, c) == 0) swept.push_back(c);   // unlinks marker + mask erase
        }
        if (int e = HostIO::Rmdir(wl); e != 0 && e != -ENOENT)
        {
            //Not removed: what it said was deleted inside it stays deleted (put back), and the call says so.
            for (const std::string &c : swept) (void)CreateWhiteout(S, c);
            if (sweptOpaque) (void)MarkOpaque(S, v);
            return e;
        }
    }
    if (Resolve(S, v).kind != HitKind::None) return CreateWhiteout(S, v);
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
    if (vf == vt) return 0;   // onto itself: nothing to do (POSIX)
    //A case-insensitive mount: a rename that changes only case names the same entry (the host renames it in place).
    const bool sameEntry = S.caseInsensitive && FoldCase(vf) == FoldCase(vt);

    // What the new name holds now, as POSIX has it: a file is replaced by a file; a directory only by a directory,
    // and only when it is EMPTY (as merged — its lower children count). The lower layers' contents of a directory
    // replaced (or deleted before) must never show through the one moved there.
    bool dstDir = false;
    if (const ResolveResult dr = sameEntry ? ResolveResult{} : Resolve(S, vt); dr.kind != HitKind::None)
    {
        dstDir = (dr.kind == HitKind::ImplicitDir) ||
                 (dr.kind == HitKind::ZipEntry && (dr.zipEntry == nullptr || dr.zipEntry->isDir));
        if (!dstDir && (dr.kind == HitKind::DirLayer || dr.kind == HitKind::WriteLayer))
        {
            HostIO::Stat st;
            if (HostIO::Lstat(dr.hostPath, st) == 0 && st.isDir) dstDir = true;
        }
        if (dstDir && !isDir) return -EISDIR;
        if (!dstDir && isDir) return -ENOTDIR;
        if (dstDir)
        {
            std::set<std::string> kids;
            CollectChildren(S, vt, kids);
            if (!kids.empty()) return -ENOTEMPTY;
        }
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
    if (dstKept) { EnsureHostParent(dst); }
    else { if (int e = EnsureWriteParent(S, vt); e != 0) return e; dst = WLPath(S, vt); }

    // An empty directory replaced may still hold its own markers on disk (names deleted from below, an opaque mark):
    // empty as merged, not to the host, which would refuse the rename. They go — and what they hid below stays
    // hidden: the folder moved there is opaque. Put back if the host refuses anyway.
    bool hidesBelow = false;
    std::vector<std::string> sweptWhiteouts;
    bool sweptOpaque = false;
    const std::string sweepIn = dstKept ? dst : WLPath(S, vt);
    if (dstDir)
    {
        std::vector<std::string> names;
        HostIO::ReadDir(sweepIn, [&](const std::string &n) { if (n.rfind(".wh.", 0) == 0) names.push_back(n); });
        for (const std::string &n : names)
        {
            if (n.rfind(kCopyTmpPrefix, 0) == 0) { HostIO::Unlink(sweepIn + "/" + n); continue; }   // a dead copy, no marker
            if (n == ".wh..wh..opq") { sweptOpaque = true; continue; }
            sweptWhiteouts.push_back(vt.empty() ? n.substr(4) : vt + "/" + n.substr(4));
        }
        hidesBelow = sweptOpaque || !sweptWhiteouts.empty();
        if (dstKept) { if (hidesBelow) KeptDropMarkersUnder(S, vt); }
        else
        {
            if (sweptOpaque) { HostIO::Unlink(sweepIn + "/.wh..wh..opq"); UnmarkOpaque(S, vt); }
            for (const std::string &c : sweptWhiteouts) RemoveWhiteout(S, c);
        }
    }
    // What was swept comes back if the rename does not happen — in a kept folder that is the user's own record of
    // what they deleted, kept across launches.
    bool srcMarked = false;
    const auto putBack = [&] {
        for (const std::string &c : sweptWhiteouts)
        {
            if (dstKept) (void)HideLower(S, c);
            else CreateWhiteout(S, c);
        }
        if (sweptOpaque) (void)(dstKept ? KeptMarkOpaque(S, vt) : MarkOpaque(S, vt));
        if (srcMarked) { HostIO::Unlink(WLPath(S, vf) + "/.wh..wh..opq"); UnmarkOpaque(S, vf); }
    };
    const bool overDeleted = dstKept ? KeptHidden(S, vt) : IsWhiteouted(S, vt);   // a name deleted from below
    const bool needOpaque = isDir && (overDeleted || hidesBelow);
    // The opaque mark goes on the folder BEFORE it moves (a writelayer one: its marker moves with it), so no look in
    // between sees the old contents through it. Its contents are all its own (copied up above): it hides nothing at
    // the old name should the move fail.
    const bool markBefore = needOpaque && !dstKept && !rr.rwPassthrough && src == WLPath(S, vf);
    if (markBefore)
    {
        HostIO::Stat had;
        const bool wasOpaque = HostIO::Lstat(WLPath(S, vf) + "/.wh..wh..opq", had) == 0;
        if (int e = MarkOpaque(S, vf); e != 0) { putBack(); return e; }
        srcMarked = !wasOpaque;   // a mark of its own it had stays, should the move fail
    }
    //Every handle on the moved file holds its copy now (the copy-up above); one on the file it replaces keeps that.
    //Both names, and all under them, name other files from here on.
    S.BeginNameChange();
    if (int e = HostIO::Rename(src, dst); e != 0) { S.EndNameChange({}); putBack(); return e; }
    int markErr = 0;   // only once it moved there: a refused rename leaves the deleted name deleted
    if (!dstKept) markErr = RemoveWhiteout(S, vt);
    if (S.debugHook) S.debugHook("rename-before-detach");
    S.EndNameChange({ { vf, isDir }, { vt, isDir } });
    if (isDir) KeptRenamePrefix(S, vf, vt);   // the kept markers inside it moved along
    if (dstKept) UnhideLower(S, vt);

    // A moved DIRECTORY takes its writelayer `.wh.*` markers with it — rewrite the in-memory masks to the
    // new prefix so they keep matching the relocated disk markers (its opaque mark among them).
    if (isDir) RenameMaskPrefix(S, vf, vt);
    // The bookkeeping is done whatever follows: a mark that cannot be written after the move is reported, with the
    // masks matching the disk.
    int late = 0;
    if (needOpaque && !markBefore) late = dstKept ? KeptMarkOpaque(S, vt) : MarkOpaque(S, vt);
    // The old name still below → hidden. Not a case-only rename on a case-insensitive host: the old spelling IS the
    // moved folder there, and hiding it would hide the folder.
    if (!sameEntry && Resolve(S, vf).kind != HitKind::None) { if (int e = HideLower(S, vf); e != 0) return e; }
    return markErr ? markErr : late;
}

int VfsTruncate(VfsState &S, const std::string &v, OpenFile *of, uint64_t size)
{
    if (S.readOnly) return -EROFS;
    if (of && of->pending)
    {
        if (!(of->flags & (O_WRONLY | O_RDWR))) return -EBADF;   // opened to read
        if (int e = CopyUpForChange(of); e != 0) return e;
        return HostIO::Ftruncate(UpperOf(of), size);
    }
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

int VfsUtimens(VfsState &S, const std::string &v, HostIO::TimeSpec atime, HostIO::TimeSpec mtime)
{
    if (S.readOnly) return -EROFS;
    ResolveResult rr = Resolve(S, v);
    if (rr.kind == HitKind::None) return -ENOENT;
    // Only touch timestamps on already-writable targets (don't force a copy-up just for mtime).
    if (rr.kind != HitKind::WriteLayer && !rr.rwPassthrough) return 0;
    std::string host = rr.rwPassthrough ? rr.hostPath : WLPath(S, v);
    return HostIO::Utimens(host, atime, mtime, /*followSymlink=*/false);
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
    if (int e = MayMakeName(S, v, true); e != 0) return e;
    std::string host;
    if (PassthroughHost(S, v, host))
    {
        if (MarkerName(v)) return -EINVAL;
        EnsureHostParent(host);
        if (int e = HostIO::Symlink(target, host); e != 0) return e;
        UnhideLower(S, v);   // as in VfsCreate
        return 0;
    }
    if (int e = EnsureWriteParent(S, v); e != 0) return e;
    if (int e = HostIO::Symlink(target, WLPath(S, v)); e != 0) return e;
    return RemoveWhiteout(S, v);   // only once it is made
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
    if (int e = MayMakeName(S, vt, true); e != 0) return e;
    if (!rr.rwPassthrough && rr.kind != HitKind::WriteLayer)
        if (int e = CopyUp(S, vf, rr); e != 0) return e;
    std::string src;   // CopyUp put a lower file under a kept folder INTO the folder (as rename)
    if (rr.rwPassthrough) src = rr.hostPath;
    else if (!PassthroughHost(S, vf, src)) src = WLPath(S, vf);
    std::string dst;
    if (PassthroughHost(S, vt, dst)) { if (MarkerName(vt)) return -EINVAL; EnsureHostParent(dst); }
    else { if (int e = EnsureWriteParent(S, vt); e != 0) return e; dst = WLPath(S, vt); }
    S.BeginNameChange();   // a file made at the name is another file than one its open handles were opened on (VfsCreate)
    if (int e = HostIO::Link(src, dst); e != 0) { S.EndNameChange({}); return e; }
    UnhideLower(S, vt);   // only now: a failed link must not bring back a deleted lower-layer file at that name
    S.EndNameChange({ { vt, false } });
    return 0;
}

int VfsFsync(OpenFile *of)
{
    if (of && of->pending) { const int Up = UpperOf(of); return Up >= 0 ? HostIO::Fsync(Up) : 0; }   // unchanged: nothing to sync
    if (of && of->fd >= 0) return HostIO::Fsync(of->fd);
    return 0;
}

int VfsStatfs(VfsState &S, HostIO::StatvfsInfo &out)
{
    std::string ref = !S.writelayer.empty() ? S.writelayer
                    : (!S.layers.empty() ? S.layers.front().source : std::string("/"));
    return HostIO::Statvfs(ref, out);
}
