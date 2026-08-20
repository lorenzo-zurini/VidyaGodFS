// POSIX implementation of the HostIO shim (Linux/FUSE backend). Thin wrappers over the
// syscalls the neutral core used to call directly, so behavior is byte-for-byte identical.
// The Windows/WinFsp build compiles hostio_win.cpp instead of this file (see CMakeLists).
#include "hostio.h"

#include <cerrno>
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/statvfs.h>

namespace HostIO {

// Fill a neutral Stat from a POSIX struct stat.
static void FromStat(const struct stat &st, Stat &out)
{
    out.mode      = static_cast<uint32_t>(st.st_mode);
    out.size      = static_cast<uint64_t>(st.st_size);
    out.mtime     = static_cast<int64_t>(st.st_mtime);
    out.nlink     = static_cast<uint32_t>(st.st_nlink);
    out.isDir     = S_ISDIR(st.st_mode);
    out.isSymlink = S_ISLNK(st.st_mode);
    out.isRegular = S_ISREG(st.st_mode);
}

// ---- fd-based --------------------------------------------------------------

Fd Open(const std::string &path, int flags, uint32_t mode)
{
    int fd = ::open(path.c_str(), flags, static_cast<mode_t>(mode));
    return fd < 0 ? -errno : fd;
}

int Close(Fd fd) { return ::close(fd) == 0 ? 0 : -errno; }

ssize_t Pread(Fd fd, void *buf, size_t n, uint64_t off)
{
    ssize_t r = ::pread(fd, buf, n, static_cast<off_t>(off));
    return r < 0 ? -errno : r;
}

ssize_t Pwrite(Fd fd, const void *buf, size_t n, uint64_t off)
{
    ssize_t w = ::pwrite(fd, buf, n, static_cast<off_t>(off));
    return w < 0 ? -errno : w;
}

ssize_t Read(Fd fd, void *buf, size_t n)
{
    ssize_t r = ::read(fd, buf, n);
    return r < 0 ? -errno : r;
}

ssize_t Write(Fd fd, const void *buf, size_t n)
{
    ssize_t w = ::write(fd, buf, n);
    return w < 0 ? -errno : w;
}

int Fsync(Fd fd)     { return ::fsync(fd) == 0 ? 0 : -errno; }
int Ftruncate(Fd fd, uint64_t size) { return ::ftruncate(fd, static_cast<off_t>(size)) == 0 ? 0 : -errno; }
int Fchmod(Fd fd, uint32_t mode)    { return ::fchmod(fd, static_cast<mode_t>(mode)) == 0 ? 0 : -errno; }

int Fstat(Fd fd, Stat &out)
{
    struct stat st;
    if (::fstat(fd, &st) != 0) return -errno;
    FromStat(st, out);
    return 0;
}

// ---- path-based ------------------------------------------------------------

int Lstat(const std::string &path, Stat &out)
{
    struct stat st;
    if (::lstat(path.c_str(), &st) != 0) return -errno;
    FromStat(st, out);
    return 0;
}

int StatFollow(const std::string &path, Stat &out)
{
    struct stat st;
    if (::stat(path.c_str(), &st) != 0) return -errno;
    FromStat(st, out);
    return 0;
}

int Mkdir(const std::string &path, uint32_t mode) { return ::mkdir(path.c_str(), static_cast<mode_t>(mode)) == 0 ? 0 : -errno; }
int Unlink(const std::string &path)               { return ::unlink(path.c_str()) == 0 ? 0 : -errno; }
int Rmdir(const std::string &path)                { return ::rmdir(path.c_str()) == 0 ? 0 : -errno; }
int Rename(const std::string &from, const std::string &to) { return ::rename(from.c_str(), to.c_str()) == 0 ? 0 : -errno; }
int Truncate(const std::string &path, uint64_t size)       { return ::truncate(path.c_str(), static_cast<off_t>(size)) == 0 ? 0 : -errno; }
int Chmod(const std::string &path, uint32_t mode)          { return ::chmod(path.c_str(), static_cast<mode_t>(mode)) == 0 ? 0 : -errno; }

int Utimens(const std::string &path, int64_t atimeSec, int64_t mtimeSec, bool followSymlink)
{
    struct timespec tv[2];
    tv[0].tv_sec = static_cast<time_t>(atimeSec); tv[0].tv_nsec = 0;
    tv[1].tv_sec = static_cast<time_t>(mtimeSec); tv[1].tv_nsec = 0;
    int flags = followSymlink ? 0 : AT_SYMLINK_NOFOLLOW;
    return ::utimensat(AT_FDCWD, path.c_str(), tv, flags) == 0 ? 0 : -errno;
}

int Readlink(const std::string &path, std::string &target)
{
    char buf[4096];
    ssize_t n = ::readlink(path.c_str(), buf, sizeof buf - 1);
    if (n < 0) return -errno;
    target.assign(buf, static_cast<size_t>(n));
    return 0;
}

int Symlink(const std::string &target, const std::string &linkpath)
{
    return ::symlink(target.c_str(), linkpath.c_str()) == 0 ? 0 : -errno;
}

int Statvfs(const std::string &path, StatvfsInfo &out)
{
    struct statvfs sv;
    if (::statvfs(path.c_str(), &sv) != 0) return -errno;
    out.bsize   = sv.f_bsize;
    out.blocks  = sv.f_blocks;
    out.bfree   = sv.f_bfree;
    out.bavail  = sv.f_bavail;
    out.files   = sv.f_files;
    out.ffree   = sv.f_ffree;
    out.namemax = sv.f_namemax;
    return 0;
}

int ReadDir(const std::string &path, const std::function<void(const std::string &)> &cb)
{
    DIR *d = ::opendir(path.c_str());
    if (!d) return 0;   // matches the core's prior behavior: an unreadable dir simply yields no children
    while (dirent *e = ::readdir(d))
    {
        const char *n = e->d_name;
        if (n[0] == '.' && (n[1] == '\0' || (n[1] == '.' && n[2] == '\0'))) continue;   // skip "." / ".."
        cb(std::string(n));
    }
    ::closedir(d);
    return 0;
}

} // namespace HostIO
