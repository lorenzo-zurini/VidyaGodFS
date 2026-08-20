#ifndef VIDYAGODFS_HOSTIO_H
#define VIDYAGODFS_HOSTIO_H

// ---------------------------------------------------------------------------
// HostIO — the host-filesystem primitives the NEUTRAL VidyaGodFS core (overlay.cpp,
// bytesource.h) uses, behind one backend-agnostic surface. The core must never call
// POSIX (`::open`/`::pread`/`::lstat`/…) directly, so the same core compiles against
// either mount backend:
//   - Linux/FUSE : hostio_posix.cpp — thin wrappers over the POSIX syscalls (this keeps
//                  behavior byte-for-byte identical to the pre-shim code).
//   - Windows/WinFsp (later) : hostio_win.cpp — CreateFile / positioned ReadFile+WriteFile
//                  / SetFileTime / GetDiskFreeSpaceEx / FindFirstFile, etc.
// One impl is selected at compile time by VidyaGodFS/CMakeLists.txt.
//
// Conventions (unchanged from the raw syscalls they replace, so callers don't change
// their error handling):
//   * fd-returning calls return a non-negative descriptor, or -errno.
//   * byte calls return bytes transferred (>= 0), or -errno.
//   * status calls (Mkdir/Unlink/…) return 0, or -errno.
// `Fd` is an int descriptor: a real POSIX fd on Linux; on Windows an index the Win32
// impl maps to a HANDLE. The core treats it opaquely (open → use → close).
// ---------------------------------------------------------------------------

#include <cstdint>
#include <cstddef>
#include <string>
#include <functional>

#include <sys/types.h>   // ssize_t (POSIX). The Windows impl provides an equivalent via its own headers.

namespace HostIO {

// Backend-neutral file metadata — the subset the core actually reads. `mode` carries
// POSIX-style bits (S_IF* | perms) so `mode & 0777` still works for copy-up preservation;
// the Windows impl synthesizes them from file attributes. isDir/isSymlink/isRegular are
// the type predicates the core uses (replacing S_ISDIR / S_ISLNK).
struct Stat {
    uint32_t mode      = 0;
    uint64_t size      = 0;
    int64_t  mtime     = 0;   // seconds since epoch
    uint32_t nlink     = 1;
    bool     isDir     = false;
    bool     isSymlink = false;
    bool     isRegular = false;
};

// Free-space info for statfs (subset filled; a backend leaves fields it can't supply at 0).
struct StatvfsInfo {
    uint64_t bsize   = 0;
    uint64_t blocks  = 0;
    uint64_t bfree   = 0;
    uint64_t bavail  = 0;
    uint64_t files   = 0;
    uint64_t ffree   = 0;
    uint64_t namemax = 0;
};

using Fd = int;

// ---- fd-based --------------------------------------------------------------
// `flags` are POSIX open flags (O_RDONLY/O_CREAT/O_WRONLY/O_TRUNC …); the Windows impl
// translates them to CreateFile. `mode` is the create permission (POSIX-style).
Fd      Open (const std::string &path, int flags, uint32_t mode = 0);
int     Close(Fd fd);
ssize_t Pread (Fd fd, void *buf, size_t n, uint64_t off);        // positioned, no shared cursor (thread-safe)
ssize_t Pwrite(Fd fd, const void *buf, size_t n, uint64_t off);
ssize_t Read (Fd fd, void *buf, size_t n);                       // sequential (copy-up stream loop)
ssize_t Write(Fd fd, const void *buf, size_t n);
int     Fsync(Fd fd);
int     Ftruncate(Fd fd, uint64_t size);
int     Fstat(Fd fd, Stat &out);
int     Fchmod(Fd fd, uint32_t mode);

// ---- path-based ------------------------------------------------------------
int     Lstat   (const std::string &path, Stat &out);            // does NOT follow a trailing symlink
int     StatFollow(const std::string &path, Stat &out);          // follows a trailing symlink (dangling → error)
int     Mkdir   (const std::string &path, uint32_t mode);
int     Unlink  (const std::string &path);
int     Rmdir   (const std::string &path);
int     Rename  (const std::string &from, const std::string &to);
int     Truncate(const std::string &path, uint64_t size);
int     Chmod   (const std::string &path, uint32_t mode);
int     Utimens (const std::string &path, int64_t atimeSec, int64_t mtimeSec, bool followSymlink);
int     Readlink(const std::string &path, std::string &target);  // reads a symlink's target
int     Symlink (const std::string &target, const std::string &linkpath);
int     Statvfs (const std::string &path, StatvfsInfo &out);

// Enumerate a directory, invoking `cb` for each entry name (excluding "." / ".."). Returns
// 0 on success (a missing/unreadable dir yields no entries and 0 — matching the core's
// existing "opendir may fail, just skip" behavior), or -errno on a hard error.
int     ReadDir (const std::string &path, const std::function<void(const std::string &)> &cb);

} // namespace HostIO

#endif // VIDYAGODFS_HOSTIO_H
