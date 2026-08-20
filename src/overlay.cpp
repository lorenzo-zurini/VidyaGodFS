#include "overlay.h"
#include "vgdelta.h"
#include "hostio.h"     // all host filesystem I/O goes through the backend-neutral shim

#include <filesystem>
#include <fstream>
#include <cstring>
#include <cerrno>
#include <unordered_map>
#include <fcntl.h>      // O_RDONLY / O_CREAT / O_WRONLY / O_TRUNC flag constants (passed to HostIO::Open)
#include <iostream>

namespace fs = std::filesystem;

// ---- small path helpers --------------------------------------------------

static std::string ParentVRel(const std::string &vrel)
{
    size_t s = vrel.find_last_of('/');
    return (s == std::string::npos) ? std::string() : vrel.substr(0, s);
}

static std::string BaseName(const std::string &p)
{
    size_t s = p.find_last_of('/');
    return (s == std::string::npos) ? p : p.substr(s + 1);
}

std::string WLPath(const VfsState &S, const std::string &vrel)
{
    return vrel.empty() ? S.writelayer : (S.writelayer + "/" + vrel);
}

// ---- VfsState init -------------------------------------------------------

//Adds every directory strictly above `leaf` to implicitDirs.
static void AddAncestors(std::set<std::string> &dst, const std::string &leaf)
{
    std::string cur = ParentVRel(leaf);
    while (!cur.empty()) { dst.insert(cur); cur = ParentVRel(cur); }
}

bool VfsState::Init(const Spec &S, std::string &Err)
{
    writelayer = S.writelayer;
    readOnly   = S.readOnly;
    uid        = S.uid;
    gid        = S.gid;

    std::error_code ec;
    if (!writelayer.empty()) fs::create_directories(writelayer, ec);

    int prio = 0;
    // Delta chaining + folding: within a run of same-target layers ending in delta(s), the base zip and any
    // intermediate deltas are BYTE inputs only — they compose into the topmost delta's single FLAT map (done in
    // DeltaByteSource::Create). Only that top delta surfaces as an overlay layer, so reads never walk the chain
    // and memory stays O(1) in chain depth (hundreds of daisy-chained versions cost the same as one).
    std::unordered_map<std::string, std::shared_ptr<ByteSource>> baseByTarget;   // composed view so far, per target
    std::unordered_map<std::string, size_t> lastDeltaIdx;                        // target → index of its final delta layer
    for (size_t gi = 0; gi < S.layers.size(); ++gi)
        if (S.layers[gi].type == LayerType::Delta) lastDeltaIdx[S.layers[gi].target] = gi;

    for (size_t gi = 0; gi < S.layers.size(); ++gi)
    {
        const LayerSpec &LS = S.layers[gi];
        std::shared_ptr<ZipIndex> zip;
        bool opaque = false;
        if (LS.type == LayerType::Zip || LS.type == LayerType::Delta)
        {
            HostIO::Fd fd = HostIO::Open(LS.source, O_RDONLY);
            if (fd < 0) { std::cerr << "[vidyagodfs] skipping unreadable layer: " << LS.source << "\n"; continue; }
            HostIO::Stat stt;
            if (HostIO::Fstat(fd, stt) != 0) { HostIO::Close(fd); continue; }
            std::shared_ptr<ByteSource> src = std::make_shared<FdByteSource>(fd, stt.size, true);

            if (LS.type == LayerType::Delta)
            {
                // Base = the composed view at this delta's base target. Normally that's its OWN target (the zip
                // directly below), but a cross-target delta names a different `baseTarget` — e.g. a complete
                // archive mounted at the package root, diffed over a base zip that mounts at a sub-target.
                // MULTI-BASE (baseTargets): the byte-base is the CONCATENATION of those composed views, in order —
                // one delta dedups against several sources at once (e.g. a prefix over [wine, dxvk, prev-prefix]).
                // Else the single (cross-)target base. Concat parts are ByteSources (often flattened delta chains);
                // nothing is materialized. The order MUST match what generation concatenated.
                std::shared_ptr<ByteSource> base;
                if (!LS.baseTargets.empty())
                {
                    std::vector<std::shared_ptr<ByteSource>> bs; bool ok = true;
                    for (const std::string &t : LS.baseTargets)
                    {
                        auto bit = baseByTarget.find(t);
                        if (bit == baseByTarget.end() || !bit->second)
                        { std::cerr << "[vidyagodfs] delta multi-base missing target '" << t << "': " << LS.source << "\n"; ok = false; break; }
                        bs.push_back(bit->second);
                    }
                    if (!ok) continue;
                    base = bs.size() == 1 ? bs[0] : std::make_shared<ConcatByteSource>(bs);
                }
                else
                {
                    const std::string &baseTgt = LS.baseTarget.empty() ? LS.target : LS.baseTarget;
                    auto bit = baseByTarget.find(baseTgt);
                    if (bit == baseByTarget.end() || !bit->second)
                    { std::cerr << "[vidyagodfs] delta layer has no base at target '" << baseTgt << "': " << LS.source << "\n"; continue; }
                    base = bit->second;
                }
                std::string derr;
                auto ds = vgdelta::DeltaByteSource::Create(src, base, derr, false);
                if (!ds) { std::cerr << "[vidyagodfs] bad delta " << LS.source << ": " << derr << "\n"; continue; }
                src = ds;
                opaque = true;   // a reconstructed archive is complete → mask anything below at this target
            }
            baseByTarget[LS.target] = src;   // the composed view this target has reached (drops the prior flat)

            // Fold: a base zip or intermediate delta of a chain is a byte input only, subsumed into the top
            // delta's flat map — do not surface it (or even index it) as an overlay layer.
            if (auto ld = lastDeltaIdx.find(LS.target); ld != lastDeltaIdx.end() && gi != ld->second) continue;

            zip = BuildZipIndex(src, LS.source);
            if (!zip) { std::cerr << "[vidyagodfs] skipping unreadable zip layer: " << LS.source << "\n"; continue; }
        }

        // SUBMOUNTS fan-out: one internal Layer per (subpath,target) mount, or a single whole-mount ("" subpath
        // at LS.target) when none are declared. File layers ignore submounts (already a single file).
        std::vector<std::pair<std::string, std::string>> mounts = LS.submounts;
        if (mounts.empty() || LS.type == LayerType::File) mounts = { { std::string(), LS.target } };

        for (const auto &[sub, tgt] : mounts)
        {
            Layer L;
            L.type = (LS.type == LayerType::Delta) ? LayerType::Zip : LS.type;  // delta-backed → a zip layer
            L.source = LS.source;
            L.target = tgt;
            L.subpath = sub;
            L.rw = LS.rw;
            L.opaque = opaque;
            L.zip = zip;
            L.priority = prio++;

            if (LS.type == LayerType::File)
            {
                L.fileBase  = BaseName(LS.source);
                L.fileVPath = L.target.empty() ? L.fileBase : (L.target + "/" + L.fileBase);
                AddAncestors(implicitDirs, L.fileVPath); // includes the containing target dir
            }
            else // Dir or Zip — target itself is real (a dir, or the file for a file-submount) via the layer
                AddAncestors(implicitDirs, L.target.empty() ? std::string("\x01") : L.target);

            layers.push_back(std::move(L));
        }
    }
    implicitDirs.erase("\x01");
    implicitDirs.erase("");
    return true;
    (void)Err;
}

std::shared_ptr<std::mutex> VfsState::CopyUpLock(const std::string &vrel)
{
    std::lock_guard<std::mutex> g(copyUpMapMtx);
    auto &slot = copyUpLocks[vrel];
    if (!slot) slot = std::make_shared<std::mutex>();
    return slot;
}

// ---- coverage / relative path --------------------------------------------

bool LayerCovers(const Layer &L, const std::string &vrel)
{
    if (L.type == LayerType::File) return vrel == L.fileVPath;
    if (L.target.empty()) return true;
    return vrel == L.target || vrel.rfind(L.target + "/", 0) == 0;
}

std::string RelUnder(const Layer &L, const std::string &vrel)
{
    if (L.target.empty()) return vrel;
    if (vrel == L.target) return "";
    return vrel.substr(L.target.size() + 1);
}

//The source/zip-side relative path for vrel: the path under target (RelUnder), prefixed by the layer's
//subpath. With subpath set, the layer exposes source/subpath at target (subpath="" → whole source).
std::string SourceRel(const Layer &L, const std::string &vrel)
{
    std::string rel = RelUnder(L, vrel);
    if (L.subpath.empty()) return rel;
    if (rel.empty())       return L.subpath;
    return L.subpath + "/" + rel;
}

// ---- whiteouts -----------------------------------------------------------

std::string WhiteoutPath(const VfsState &S, const std::string &vrel)
{
    return WLPath(S, ParentVRel(vrel)) + "/.wh." + BaseName(vrel);
}

bool IsWhiteouted(const VfsState &S, const std::string &vrel)
{
    if (S.writelayer.empty() || vrel.empty()) return false;
    HostIO::Stat st;
    return HostIO::Lstat(WhiteoutPath(S, vrel), st) == 0;
}

void CreateWhiteout(const VfsState &S, const std::string &vrel)
{
    if (S.writelayer.empty()) return;
    std::error_code ec;
    fs::create_directories(WLPath(S, ParentVRel(vrel)), ec);
    HostIO::Fd fd = HostIO::Open(WhiteoutPath(S, vrel), O_CREAT | O_WRONLY, 0644);
    if (fd >= 0) HostIO::Close(fd);
}

void RemoveWhiteout(const VfsState &S, const std::string &vrel)
{
    if (S.writelayer.empty()) return;
    HostIO::Unlink(WhiteoutPath(S, vrel));
}

// ---- opaque directories --------------------------------------------------

static std::string OpaqueMarker(const VfsState &S, const std::string &vrel)
{
    return WLPath(S, vrel) + "/.wh..wh..opq";
}

bool IsOpaqueDir(const VfsState &S, const std::string &vrel)
{
    if (S.writelayer.empty()) return false;
    HostIO::Stat st;
    return HostIO::Lstat(OpaqueMarker(S, vrel), st) == 0;
}

void MarkOpaque(VfsState &S, const std::string &vrel)
{
    if (S.writelayer.empty()) return;
    HostIO::Fd fd = HostIO::Open(OpaqueMarker(S, vrel), O_CREAT | O_WRONLY, 0644);
    if (fd >= 0) HostIO::Close(fd);
    S.hasOpaque.store(true, std::memory_order_relaxed);
}

//True if any ancestor directory of vrel (including the root) is opaque — meaning the lower layers are
//masked here. Gated by hasOpaque so it costs nothing until an opaque dir actually exists.
bool IsUnderOpaque(const VfsState &S, const std::string &vrel)
{
    if (!S.hasOpaque.load(std::memory_order_relaxed) || S.writelayer.empty()) return false;
    for (std::string cur = ParentVRel(vrel); !cur.empty(); cur = ParentVRel(cur))
        if (IsOpaqueDir(S, cur)) return true;
    return IsOpaqueDir(S, ""); // root opaque masks everything
}

// ---- resolution ----------------------------------------------------------

ResolveResult Resolve(VfsState &S, const std::string &vrel)
{
    ResolveResult R;

    if (!S.writelayer.empty())
    {
        if (IsWhiteouted(S, vrel)) return R; // deleted → None
        std::string wp = WLPath(S, vrel);
        HostIO::Stat st;
        if (HostIO::Lstat(wp, st) == 0) { R.kind = HitKind::WriteLayer; R.hostPath = wp; return R; }
        // Not in the writelayer, but masked by an opaque ancestor → the lower layers don't show here.
        if (IsUnderOpaque(S, vrel)) return R;
    }

    // Highest priority first.
    for (auto it = S.layers.rbegin(); it != S.layers.rend(); ++it)
    {
        const Layer &L = *it;
        if (!LayerCovers(L, vrel)) continue;

        if (L.type == LayerType::Dir)
        {
            std::string rel = SourceRel(L, vrel);
            std::string host = rel.empty() ? L.source : (L.source + "/" + rel);
            HostIO::Stat st;
            if (HostIO::Lstat(host, st) == 0)
            {
                // Symlink abolition: a DATA layer never serves a link. Followable on the host (the layer
                // source tree is complete there) → serve as the target; dangling → this layer doesn't have
                // the path (fall through to lower layers). rw (passthrough) layers are EXEMPT like the
                // writelayer: they hold live guest-written state (persisted user dirs where proton keeps
                // its own user-path links), which must round-trip as authored.
                if (S.flattenSymlinks && !L.rw && st.isSymlink && HostIO::StatFollow(host, st) != 0)
                    continue;
                R.kind = HitKind::DirLayer; R.hostPath = host; R.layer = &L; R.rwPassthrough = L.rw;
                return R;
            }
        }
        else if (L.type == LayerType::File)
        {
            HostIO::Stat st;
            if (HostIO::Lstat(L.source, st) == 0)
            {
                if (S.flattenSymlinks && st.isSymlink && HostIO::StatFollow(L.source, st) != 0)
                    continue;
                R.kind = HitKind::FileLayer; R.hostPath = L.source; R.layer = &L;
                return R;
            }
        }
        else // Zip
        {
            std::string rel = SourceRel(L, vrel);
            auto fit = L.zip->byName.find(rel);
            bool isDir = (fit != L.zip->byName.end() && fit->second.isDir) || L.zip->dirChildren.count(rel);
            if (fit != L.zip->byName.end() || isDir)
            {
                const ZipEntry *e = (fit != L.zip->byName.end()) ? &fit->second : nullptr; // null → synthesized dir
                // Symlink abolition: chase an archive link to its in-archive target file; a link that
                // escapes the archive, dangles, or targets a directory simply does not exist in this
                // layer (fall through — e.g. dosdevices/c: vanishes and wine recreates it at boot in
                // the writelayer, where runtime symlinks legitimately live).
                if (S.flattenSymlinks && e && e->symlink)
                {
                    e = ResolveZipSymlink(*L.zip, *e);
                    if (e == nullptr)
                    {
                        if (L.opaque) return R;
                        continue;
                    }
                }
                R.kind = HitKind::ZipEntry; R.layer = &L; R.zipEntry = e;
                return R;
            }
            // Miss on an opaque (delta-reconstructed, complete) archive → the path does not exist; the older
            // versions it was diffed against are fully masked, so do not fall through to them.
            if (L.opaque) return R;
        }
    }

    if (S.implicitDirs.count(vrel)) { R.kind = HitKind::ImplicitDir; return R; }
    return R;
}

// ---- copy-up -------------------------------------------------------------

bool PassthroughHost(VfsState &S, const std::string &vrel, std::string &HostOut)
{
    for (auto it = S.layers.rbegin(); it != S.layers.rend(); ++it)
    {
        const Layer &L = *it;
        if (L.type == LayerType::Dir && L.rw && LayerCovers(L, vrel))
        {
            std::string rel = SourceRel(L, vrel);
            HostOut = rel.empty() ? L.source : (L.source + "/" + rel);
            return true;
        }
    }
    return false;
}

int EnsureWriteParent(VfsState &S, const std::string &vrel)
{
    std::string parent = ParentVRel(vrel);
    std::error_code ec;
    fs::create_directories(WLPath(S, parent), ec);
    return ec ? -EIO : 0;
}

int CopyUp(VfsState &S, const std::string &vrel, const ResolveResult &rr)
{
    if (S.writelayer.empty()) return -EROFS;
    if (rr.kind == HitKind::WriteLayer) return 0;       // already writable
    if (rr.rwPassthrough) return 0;                     // writes pass straight to source

    auto lock = S.CopyUpLock(vrel);
    std::lock_guard<std::mutex> g(*lock);

    std::string dst = WLPath(S, vrel);
    HostIO::Stat st;
    if (HostIO::Lstat(dst, st) == 0) return 0;          // another thread already copied it up

    if (int e = EnsureWriteParent(S, vrel); e != 0) return e;

    // Directory copy-up: just create the dir in the writelayer.
    bool isDir = (rr.kind == HitKind::ImplicitDir) ||
                 (rr.kind == HitKind::DirLayer && HostIO::Lstat(rr.hostPath, st) == 0 && st.isDir) ||
                 (rr.kind == HitKind::ZipEntry && (rr.zipEntry == nullptr || rr.zipEntry->isDir));
    if (isDir)
    {
        std::error_code ec;
        fs::create_directories(dst, ec);
        return ec ? -EIO : 0;
    }

    // Symlink copy-up: recreate the link itself; never dereference it into a regular file. Under symlink
    // abolition these branches are dead by construction — Resolve already flattened archive links to their
    // target entries and host-layer links are followed (the generic file copy-up below then copies the
    // TARGET's content, which is exactly the abolition semantics).
    if (!S.flattenSymlinks)
    {
        if (rr.kind == HitKind::ZipEntry && rr.zipEntry && rr.zipEntry->symlink)
        {
            ZipReader zr;
            if (int e = OpenZipEntry(*const_cast<ZipIndex *>(rr.layer->zip.get()), *rr.zipEntry, zr); e != 0) return e;
            std::string tgt(rr.zipEntry->size, '\0');
            int got = ReadZipEntry(zr, tgt.data(), tgt.size(), 0);
            if (got < 0) return got;
            tgt.resize(got);
            return HostIO::Symlink(tgt, dst);
        }
        if ((rr.kind == HitKind::DirLayer || rr.kind == HitKind::FileLayer) &&
            HostIO::Lstat(rr.hostPath, st) == 0 && st.isSymlink)
        {
            std::string tgt;
            if (int e = HostIO::Readlink(rr.hostPath, tgt); e != 0) return e;
            return HostIO::Symlink(tgt, dst);
        }
    }

    // File copy-up: materialize full content into the writelayer.
    HostIO::Fd out = HostIO::Open(dst, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (out < 0) return out;

    int rc = 0;
    if (rr.kind == HitKind::ZipEntry && rr.zipEntry)
    {
        ZipReader zr;
        rc = OpenZipEntry(*const_cast<ZipIndex *>(rr.layer->zip.get()), *rr.zipEntry, zr);
        if (rc == 0)
        {
            char buf[256 * 1024];
            off_t off = 0;
            for (;;)
            {
                int got = ReadZipEntry(zr, buf, sizeof buf, off);
                if (got < 0) { rc = got; break; }
                if (got == 0) break;
                if (HostIO::Write(out, buf, (size_t)got) != got) { rc = -EIO; break; }
                off += got;
            }
        }
    }
    else // DirLayer or FileLayer host file
    {
        HostIO::Fd in = HostIO::Open(rr.hostPath, O_RDONLY);
        if (in < 0) { rc = (int)in; }
        else
        {
            char buf[256 * 1024];
            ssize_t got;
            while ((got = HostIO::Read(in, buf, sizeof buf)) > 0)
                if (HostIO::Write(out, buf, (size_t)got) != got) { rc = -EIO; break; }
            if (got < 0 && rc == 0) rc = (int)got;
            HostIO::Close(in);
            if (HostIO::Lstat(rr.hostPath, st) == 0) HostIO::Fchmod(out, st.mode & 0777);
        }
    }
    HostIO::Close(out);
    if (rc != 0) HostIO::Unlink(dst);
    return rc;
}
