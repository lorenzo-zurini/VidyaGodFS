#include "overlay.h"

#include <filesystem>
#include <fstream>
#include <cstring>
#include <cerrno>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
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
    for (const LayerSpec &LS : S.layers)
    {
        Layer L;
        L.type = LS.type;
        L.source = LS.source;
        L.target = LS.target;
        L.rw = LS.rw;
        L.priority = prio++;

        if (LS.type == LayerType::Zip)
        {
            L.zip = BuildZipIndex(LS.source);
            if (!L.zip) { std::cerr << "[vidyagodfs] skipping unreadable zip layer: " << LS.source << "\n"; continue; }
            AddAncestors(implicitDirs, L.target.empty() ? std::string("\x01") : L.target); // ancestors of target
            // (target itself is real via the zip root)
        }
        else if (LS.type == LayerType::File)
        {
            L.fileBase  = BaseName(LS.source);
            L.fileVPath = L.target.empty() ? L.fileBase : (L.target + "/" + L.fileBase);
            AddAncestors(implicitDirs, L.fileVPath); // includes the containing target dir
        }
        else // Dir
        {
            AddAncestors(implicitDirs, L.target.empty() ? std::string("\x01") : L.target);
        }
        layers.push_back(std::move(L));
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

// ---- whiteouts -----------------------------------------------------------

std::string WhiteoutPath(const VfsState &S, const std::string &vrel)
{
    return WLPath(S, ParentVRel(vrel)) + "/.wh." + BaseName(vrel);
}

bool IsWhiteouted(const VfsState &S, const std::string &vrel)
{
    if (S.writelayer.empty() || vrel.empty()) return false;
    struct stat st;
    return ::lstat(WhiteoutPath(S, vrel).c_str(), &st) == 0;
}

void CreateWhiteout(const VfsState &S, const std::string &vrel)
{
    if (S.writelayer.empty()) return;
    std::error_code ec;
    fs::create_directories(WLPath(S, ParentVRel(vrel)), ec);
    int fd = ::open(WhiteoutPath(S, vrel).c_str(), O_CREAT | O_WRONLY, 0644);
    if (fd >= 0) ::close(fd);
}

void RemoveWhiteout(const VfsState &S, const std::string &vrel)
{
    if (S.writelayer.empty()) return;
    ::unlink(WhiteoutPath(S, vrel).c_str());
}

// ---- resolution ----------------------------------------------------------

ResolveResult Resolve(VfsState &S, const std::string &vrel)
{
    ResolveResult R;

    if (!S.writelayer.empty())
    {
        if (IsWhiteouted(S, vrel)) return R; // deleted → None
        std::string wp = WLPath(S, vrel);
        struct stat st;
        if (::lstat(wp.c_str(), &st) == 0) { R.kind = HitKind::WriteLayer; R.hostPath = wp; return R; }
    }

    // Highest priority first.
    for (auto it = S.layers.rbegin(); it != S.layers.rend(); ++it)
    {
        const Layer &L = *it;
        if (!LayerCovers(L, vrel)) continue;

        if (L.type == LayerType::Dir)
        {
            std::string rel = RelUnder(L, vrel);
            std::string host = rel.empty() ? L.source : (L.source + "/" + rel);
            struct stat st;
            if (::lstat(host.c_str(), &st) == 0)
            {
                R.kind = HitKind::DirLayer; R.hostPath = host; R.layer = &L; R.rwPassthrough = L.rw;
                return R;
            }
        }
        else if (L.type == LayerType::File)
        {
            struct stat st;
            if (::lstat(L.source.c_str(), &st) == 0)
            {
                R.kind = HitKind::FileLayer; R.hostPath = L.source; R.layer = &L;
                return R;
            }
        }
        else // Zip
        {
            std::string rel = RelUnder(L, vrel);
            auto fit = L.zip->byName.find(rel);
            bool isDir = (fit != L.zip->byName.end() && fit->second.isDir) || L.zip->dirChildren.count(rel);
            if (fit != L.zip->byName.end() || isDir)
            {
                R.kind = HitKind::ZipEntry; R.layer = &L;
                R.zipEntry = (fit != L.zip->byName.end()) ? &fit->second : nullptr; // null → synthesized dir
                return R;
            }
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
            std::string rel = RelUnder(L, vrel);
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
    struct stat st;
    if (::lstat(dst.c_str(), &st) == 0) return 0;       // another thread already copied it up

    if (int e = EnsureWriteParent(S, vrel); e != 0) return e;

    // Directory copy-up: just create the dir in the writelayer.
    bool isDir = (rr.kind == HitKind::ImplicitDir) ||
                 (rr.kind == HitKind::DirLayer && ::lstat(rr.hostPath.c_str(), &st) == 0 && S_ISDIR(st.st_mode)) ||
                 (rr.kind == HitKind::ZipEntry && (rr.zipEntry == nullptr || rr.zipEntry->isDir));
    if (isDir)
    {
        std::error_code ec;
        fs::create_directories(dst, ec);
        return ec ? -EIO : 0;
    }

    // File copy-up: materialize full content into the writelayer.
    int out = ::open(dst.c_str(), O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (out < 0) return -errno;

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
                if (::write(out, buf, (size_t)got) != got) { rc = -EIO; break; }
                off += got;
            }
        }
    }
    else // DirLayer or FileLayer host file
    {
        int in = ::open(rr.hostPath.c_str(), O_RDONLY);
        if (in < 0) { rc = -errno; }
        else
        {
            char buf[256 * 1024];
            ssize_t got;
            while ((got = ::read(in, buf, sizeof buf)) > 0)
                if (::write(out, buf, (size_t)got) != got) { rc = -EIO; break; }
            if (got < 0 && rc == 0) rc = -errno;
            ::close(in);
            if (::lstat(rr.hostPath.c_str(), &st) == 0) ::fchmod(out, st.st_mode & 0777);
        }
    }
    ::close(out);
    if (rc != 0) ::unlink(dst.c_str());
    return rc;
}
