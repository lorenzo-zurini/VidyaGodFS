// Win32 implementation of the HostIO shim (Windows/WinFsp backend). Mirrors hostio_posix.cpp:
// the neutral core (overlay.cpp, bytesource.h) calls these; here they map to Win32.
//
// HostIO::Fd stays a plain `int` (>=0 valid, <0 == -errno) exactly like POSIX. Windows file
// objects are HANDLEs (pointers), so an internal table maps small int fds -> HANDLE. This keeps
// the shim's contract identical across platforms with zero changes to the callers.
#include "hostio.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <winioctl.h>   // FSCTL_GET_REPARSE_POINT

#include <cerrno>
#include <cstring>
#include <mutex>
#include <unordered_map>
#include <string>
#include <fcntl.h>   // O_* flag values (MinGW)

namespace HostIO {

// ---- fd <-> HANDLE table --------------------------------------------------
static std::mutex g_mtx;
static std::unordered_map<int, HANDLE> g_table;
static int g_next = 3;   // skip 0/1/2 (stdin/out/err) so an fd is always a small positive int

static int Register(HANDLE h) { std::lock_guard<std::mutex> g(g_mtx); int fd = g_next++; g_table[fd] = h; return fd; }
static HANDLE Grab(int fd)    { std::lock_guard<std::mutex> g(g_mtx); auto it = g_table.find(fd); return it == g_table.end() ? INVALID_HANDLE_VALUE : it->second; }
static void   Drop(int fd)    { std::lock_guard<std::mutex> g(g_mtx); g_table.erase(fd); }

// ---- helpers --------------------------------------------------------------

// Map a Win32 error to a negative errno (the contract the callers expect).
static int Err(DWORD e = ::GetLastError())
{
    switch (e)
    {
        case ERROR_FILE_NOT_FOUND:
        case ERROR_PATH_NOT_FOUND:
        case ERROR_INVALID_DRIVE:      return -ENOENT;
        case ERROR_ACCESS_DENIED:
        case ERROR_SHARING_VIOLATION:
        case ERROR_LOCK_VIOLATION:     return -EACCES;
        case ERROR_FILE_EXISTS:
        case ERROR_ALREADY_EXISTS:     return -EEXIST;
        case ERROR_DIR_NOT_EMPTY:      return -ENOTEMPTY;
        case ERROR_INVALID_NAME:
        case ERROR_INVALID_PARAMETER:  return -EINVAL;
        case ERROR_DISK_FULL:          return -ENOSPC;
        case ERROR_TOO_MANY_OPEN_FILES:return -EMFILE;
        case ERROR_PRIVILEGE_NOT_HELD: return -EPERM;
        default:                       return -EIO;
    }
}

// UTF-8 host path -> wide, with '/' normalized to '\' (the neutral core joins paths with '/').
static std::wstring Wide(const std::string &s)
{
    std::wstring w;
    if (!s.empty())
    {
        int n = ::MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), nullptr, 0);
        w.resize(n);
        ::MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), w.data(), n);
    }
    for (wchar_t &c : w) if (c == L'/') c = L'\\';
    return w;
}

static std::string Narrow(const wchar_t *w, int wlen)
{
    if (wlen <= 0) return {};
    int n = ::WideCharToMultiByte(CP_UTF8, 0, w, wlen, nullptr, 0, nullptr, nullptr);
    std::string s(n, '\0');
    ::WideCharToMultiByte(CP_UTF8, 0, w, wlen, s.data(), n, nullptr, nullptr);
    return s;
}

static const uint64_t kEpochDelta = 116444736000000000ULL; // 100ns ticks between 1601 and 1970
static int64_t  FtToUnix(const FILETIME &ft) { ULARGE_INTEGER u; u.LowPart = ft.dwLowDateTime; u.HighPart = ft.dwHighDateTime; return (int64_t)((u.QuadPart - kEpochDelta) / 10000000ULL); }
static FILETIME UnixToFt(int64_t sec) { ULARGE_INTEGER u; u.QuadPart = (uint64_t)sec * 10000000ULL + kEpochDelta; FILETIME ft; ft.dwLowDateTime = u.LowPart; ft.dwHighDateTime = u.HighPart; return ft; }

static void FillStat(DWORD attrs, uint64_t size, const FILETIME &mtime, Stat &out)
{
    out.isDir     = (attrs & FILE_ATTRIBUTE_DIRECTORY) != 0;
    out.isSymlink = (attrs & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
    out.isRegular = !out.isDir && !out.isSymlink;
    out.size      = size;
    out.mtime     = FtToUnix(mtime);
    out.nlink     = 1;
    // Windows has no POSIX permission bits; present the conventional ones the FS reports anyway.
    out.mode      = (out.isDir ? 0040000u : (out.isSymlink ? 0120000u : 0100000u)) | (out.isDir ? 0755u : 0644u);
}

// ---- fd-based --------------------------------------------------------------

Fd Open(const std::string &path, int flags, uint32_t /*mode*/)
{
    DWORD access = 0;
    if ((flags & O_WRONLY) || (flags & O_RDWR)) access |= GENERIC_WRITE;
    if (!(flags & O_WRONLY))                    access |= GENERIC_READ;   // O_RDONLY(0) and O_RDWR both read

    DWORD disp;
    const bool creat = (flags & O_CREAT), excl = (flags & O_EXCL), trunc = (flags & O_TRUNC);
    if (creat && excl)      disp = CREATE_NEW;
    else if (creat && trunc)disp = CREATE_ALWAYS;
    else if (creat)         disp = OPEN_ALWAYS;
    else if (trunc)         disp = TRUNCATE_EXISTING;
    else                    disp = OPEN_EXISTING;

    // BACKUP_SEMANTICS lets us open directories; OPEN_REPARSE_POINT means we act on a symlink itself
    // (not its target), matching lstat/O_NOFOLLOW semantics the core relies on.
    DWORD attr = FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT;
    HANDLE h = ::CreateFileW(Wide(path).c_str(), access, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                             nullptr, disp, attr, nullptr);
    if (h == INVALID_HANDLE_VALUE) return Err();
    return Register(h);
}

int Close(Fd fd)
{
    HANDLE h = Grab(fd);
    if (h == INVALID_HANDLE_VALUE) return -EBADF;
    Drop(fd);
    return ::CloseHandle(h) ? 0 : Err();
}

ssize_t Pread(Fd fd, void *buf, size_t n, uint64_t off)
{
    HANDLE h = Grab(fd);
    if (h == INVALID_HANDLE_VALUE) return -EBADF;
    OVERLAPPED ov{}; ov.Offset = (DWORD)(off & 0xffffffffULL); ov.OffsetHigh = (DWORD)(off >> 32);
    DWORD got = 0;
    if (!::ReadFile(h, buf, (DWORD)n, &got, &ov))
    {
        DWORD e = ::GetLastError();
        if (e == ERROR_HANDLE_EOF) return 0;
        return Err(e);
    }
    return (ssize_t)got;
}

ssize_t Pwrite(Fd fd, const void *buf, size_t n, uint64_t off)
{
    HANDLE h = Grab(fd);
    if (h == INVALID_HANDLE_VALUE) return -EBADF;
    OVERLAPPED ov{}; ov.Offset = (DWORD)(off & 0xffffffffULL); ov.OffsetHigh = (DWORD)(off >> 32);
    DWORD put = 0;
    if (!::WriteFile(h, buf, (DWORD)n, &put, &ov)) return Err();
    return (ssize_t)put;
}

ssize_t Read(Fd fd, void *buf, size_t n)
{
    HANDLE h = Grab(fd);
    if (h == INVALID_HANDLE_VALUE) return -EBADF;
    DWORD got = 0;
    if (!::ReadFile(h, buf, (DWORD)n, &got, nullptr)) return Err();
    return (ssize_t)got;   // 0 at EOF
}

ssize_t Write(Fd fd, const void *buf, size_t n)
{
    HANDLE h = Grab(fd);
    if (h == INVALID_HANDLE_VALUE) return -EBADF;
    DWORD put = 0;
    if (!::WriteFile(h, buf, (DWORD)n, &put, nullptr)) return Err();
    return (ssize_t)put;
}

int Fsync(Fd fd)
{
    HANDLE h = Grab(fd);
    if (h == INVALID_HANDLE_VALUE) return -EBADF;
    return ::FlushFileBuffers(h) ? 0 : Err();
}

int Ftruncate(Fd fd, uint64_t size)
{
    HANDLE h = Grab(fd);
    if (h == INVALID_HANDLE_VALUE) return -EBADF;
    LARGE_INTEGER li; li.QuadPart = (LONGLONG)size;
    if (!::SetFilePointerEx(h, li, nullptr, FILE_BEGIN)) return Err();
    return ::SetEndOfFile(h) ? 0 : Err();
}

int Fchmod(Fd, uint32_t) { return 0; }   // no POSIX mode bits on Windows — cosmetic, succeed

int Fstat(Fd fd, Stat &out)
{
    HANDLE h = Grab(fd);
    if (h == INVALID_HANDLE_VALUE) return -EBADF;
    BY_HANDLE_FILE_INFORMATION bi;
    if (!::GetFileInformationByHandle(h, &bi)) return Err();
    uint64_t size = ((uint64_t)bi.nFileSizeHigh << 32) | bi.nFileSizeLow;
    FillStat(bi.dwFileAttributes, size, bi.ftLastWriteTime, out);
    out.nlink = bi.nNumberOfLinks ? bi.nNumberOfLinks : 1;
    return 0;
}

// ---- path-based ------------------------------------------------------------

int Lstat(const std::string &path, Stat &out)
{
    WIN32_FILE_ATTRIBUTE_DATA d;
    if (!::GetFileAttributesExW(Wide(path).c_str(), GetFileExInfoStandard, &d)) return Err();
    uint64_t size = ((uint64_t)d.nFileSizeHigh << 32) | d.nFileSizeLow;
    FillStat(d.dwFileAttributes, size, d.ftLastWriteTime, out);
    return 0;
}

int StatFollow(const std::string &path, Stat &out)
{
    // Open WITHOUT OPEN_REPARSE_POINT so the handle refers to the link's TARGET; a dangling link fails.
    HANDLE h = ::CreateFileW(Wide(path).c_str(), FILE_READ_ATTRIBUTES,
                             FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                             OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
    if (h == INVALID_HANDLE_VALUE) return Err();
    BY_HANDLE_FILE_INFORMATION bi;
    BOOL ok = ::GetFileInformationByHandle(h, &bi);
    ::CloseHandle(h);
    if (!ok) return Err();
    uint64_t size = ((uint64_t)bi.nFileSizeHigh << 32) | bi.nFileSizeLow;
    FillStat(bi.dwFileAttributes, size, bi.ftLastWriteTime, out);
    return 0;
}

int Mkdir(const std::string &path, uint32_t) { return ::CreateDirectoryW(Wide(path).c_str(), nullptr) ? 0 : Err(); }
int Unlink(const std::string &path)          { return ::DeleteFileW(Wide(path).c_str()) ? 0 : Err(); }
int Rmdir(const std::string &path)           { return ::RemoveDirectoryW(Wide(path).c_str()) ? 0 : Err(); }
int Rename(const std::string &from, const std::string &to)
{
    return ::MoveFileExW(Wide(from).c_str(), Wide(to).c_str(),
                         MOVEFILE_REPLACE_EXISTING | MOVEFILE_COPY_ALLOWED) ? 0 : Err();
}

int Truncate(const std::string &path, uint64_t size)
{
    Fd fd = Open(path, O_RDWR);
    if (fd < 0) return (int)fd;
    int r = Ftruncate(fd, size);
    Close(fd);
    return r;
}

int Chmod(const std::string &, uint32_t) { return 0; }   // cosmetic on Windows

int Utimens(const std::string &path, int64_t /*atimeSec*/, int64_t mtimeSec, bool /*followSymlink*/)
{
    HANDLE h = ::CreateFileW(Wide(path).c_str(), FILE_WRITE_ATTRIBUTES,
                             FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                             OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    if (h == INVALID_HANDLE_VALUE) return Err();
    FILETIME ft = UnixToFt(mtimeSec);
    BOOL ok = ::SetFileTime(h, nullptr, nullptr, &ft);   // set mtime only (atime often relatime/ignored)
    ::CloseHandle(h);
    return ok ? 0 : Err();
}

// Reparse-buffer layout for a symbolic link (from ntifs.h; redeclared to avoid the DDK dependency).
typedef struct {
    ULONG  ReparseTag;
    USHORT ReparseDataLength;
    USHORT Reserved;
    USHORT SubstituteNameOffset;
    USHORT SubstituteNameLength;
    USHORT PrintNameOffset;
    USHORT PrintNameLength;
    ULONG  Flags;
    WCHAR  PathBuffer[1];
} VG_SYMLINK_REPARSE;

int Readlink(const std::string &path, std::string &target)
{
    HANDLE h = ::CreateFileW(Wide(path).c_str(), 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                             nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    if (h == INVALID_HANDLE_VALUE) return Err();
    char buf[16 * 1024];
    DWORD ret = 0;
    BOOL ok = ::DeviceIoControl(h, FSCTL_GET_REPARSE_POINT, nullptr, 0, buf, sizeof buf, &ret, nullptr);
    ::CloseHandle(h);
    if (!ok) return Err();
    auto *rp = reinterpret_cast<VG_SYMLINK_REPARSE *>(buf);
    if (rp->ReparseTag != IO_REPARSE_TAG_SYMLINK) return -EINVAL;
    const wchar_t *name = rp->PathBuffer + (rp->PrintNameOffset / sizeof(wchar_t));
    std::string t = Narrow(name, rp->PrintNameLength / (int)sizeof(wchar_t));
    for (char &c : t) if (c == '\\') c = '/';
    target = std::move(t);
    return 0;
}

int Symlink(const std::string &target, const std::string &linkpath)
{
    // Best-effort: needs Developer Mode / SeCreateSymbolicLinkPrivilege. ALLOW_UNPRIVILEGED_CREATE works
    // when Developer Mode is on. Directory vs file flag is guessed from whether the target resolves to a dir.
    DWORD flags = SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE;
    std::wstring wt = Wide(target);
    DWORD ta = ::GetFileAttributesW(wt.c_str());
    if (ta != INVALID_FILE_ATTRIBUTES && (ta & FILE_ATTRIBUTE_DIRECTORY)) flags |= SYMBOLIC_LINK_FLAG_DIRECTORY;
    return ::CreateSymbolicLinkW(Wide(linkpath).c_str(), wt.c_str(), flags) ? 0 : Err();
}

int Statvfs(const std::string &path, StatvfsInfo &out)
{
    // GetDiskFreeSpaceExW wants a directory or volume — unlike POSIX statvfs it FAILS on a plain
    // file path (and a read-only mount hands us the backing zip's file path). Resolve the containing
    // volume root first so any path (file, dir, drive) works. This must be robust: WinFsp calls
    // statfs during mount and aborts the whole mount if it returns an error.
    std::wstring wp = Wide(path);
    wchar_t vol[MAX_PATH];
    const wchar_t *q = (::GetVolumePathNameW(wp.c_str(), vol, MAX_PATH)) ? vol : wp.c_str();
    ULARGE_INTEGER avail, total, freeb;
    if (!::GetDiskFreeSpaceExW(q, &avail, &total, &freeb)) return Err();
    out.bsize   = 4096;
    out.blocks  = total.QuadPart / 4096;
    out.bfree   = freeb.QuadPart / 4096;
    out.bavail  = avail.QuadPart / 4096;
    out.files   = 0;
    out.ffree   = 0;
    out.namemax = 255;
    return 0;
}

int ReadDir(const std::string &path, const std::function<void(const std::string &)> &cb)
{
    std::wstring pat = Wide(path);
    if (!pat.empty() && pat.back() != L'\\') pat += L'\\';
    pat += L'*';
    WIN32_FIND_DATAW fd;
    HANDLE h = ::FindFirstFileW(pat.c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) return 0;   // matches POSIX ReadDir: unreadable dir -> no entries
    do {
        const wchar_t *n = fd.cFileName;
        if (n[0] == L'.' && (n[1] == 0 || (n[1] == L'.' && n[2] == 0))) continue;   // skip "." / ".."
        cb(Narrow(n, (int)wcslen(n)));
    } while (::FindNextFileW(h, &fd));
    ::FindClose(h);
    return 0;
}

} // namespace HostIO
