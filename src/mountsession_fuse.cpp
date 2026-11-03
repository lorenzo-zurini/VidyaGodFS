// FUSE mount lifecycle (Linux backend of MountSession). fuse_main() daemonizes (forks; the
// parent exits once the mount is live) and serves multithreaded, so the VidyaGod app's blocking
// spawn returns as soon as the mount is established. The SERVER itself watches the spawner and
// lazily unmounts the moment it exits. Moved from the old main.cpp; the Windows build compiles
// mountsession_win.cpp instead.
//
// Why the server and not a watchdog process of its own: that is how it used to be, forked before
// fuse_main, and it leaked mounts for hours. The watchdog stayed in the spawner's process group
// while fuse's daemonize setsid()s the server out of it, so a group kill (a test runner's timeout,
// Ctrl-C, a closed terminal) took the watchdog and left the mount. It also probed the spawner with
// kill(pid, 0), which reads a zombie as running. A watch inside the server can only end with the
// mount it guards, and a pidfd fires on exit itself, reaped or not, and can't name a recycled pid.
#include "mountsession.h"
#include "fuseops.h"     // VidyagodfsOps()

#include <fuse.h>

#include <string>
#include <thread>
#include <vector>
#include <iostream>

#include <unistd.h>
#include <cerrno>
#include <cstring>
#include <poll.h>
#include <spawn.h>
#include <syslog.h>
#include <sys/syscall.h>
#include <sys/wait.h>

extern char **environ;

namespace {

// Set once in Run, before fuse_main, and read by the init op in the serving daemon.
int         g_spawnerFd = -1;   // pidfd of the spawner, or -1 when nothing is watched
std::string g_mountpoint;
void *(*g_innerInit)(struct fuse_conn_info *, struct fuse_config *) = nullptr;

// Blocks until the spawner has exited, then lazily unmounts (-z, so the mount detaches even if the
// now-orphaned game still holds files open; the server keeps serving those until they close, and
// fuse_main returns once the kernel drops the connection).
void WatchSpawner(int pidfd, const std::string &mp)
{
    pollfd P { pidfd, POLLIN, 0 };
    while (poll(&P, 1, -1) < 0 && errno == EINTR) {}

    const char *Argv[] = { "fusermount3", "-u", "-z", mp.c_str(), nullptr };
    pid_t Pid = 0;
    const int Err = posix_spawnp(&Pid, "fusermount3", nullptr, nullptr, const_cast<char **>(Argv), environ);
    if (Err != 0)   // stderr is /dev/null once daemonized; this must not fail silently
    {
        syslog(LOG_ERR, "vidyagodfs: spawner gone but cannot run fusermount3 to unmount %s: %s", mp.c_str(), strerror(Err));
        return;
    }
    waitpid(Pid, nullptr, 0);
}

// The init op runs in the daemon that will serve the mount (threads do not survive fuse's daemonize
// fork, so the watch cannot start any earlier).
void *InitWithWatch(struct fuse_conn_info *conn, struct fuse_config *cfg)
{
    void *Data = g_innerInit ? g_innerInit(conn, cfg) : fuse_get_context()->private_data;
    if (g_spawnerFd >= 0) std::thread(WatchSpawner, g_spawnerFd, g_mountpoint).detach();
    return Data;
}

} // namespace

int MountSession::Run(VfsState &state, const std::string &mountpoint, long long watchPid,
                      const std::vector<std::string> &backendArgs)
{
    // Pin the spawner NOW, while it is certainly the process that asked: a pidfd names that process
    // and no later one with its pid, and it is inherited by the daemonized server. A spawner already
    // gone gets no mount at all, since nothing would ever take it down.
    if (watchPid > 0)
    {
        g_spawnerFd = (int)syscall(SYS_pidfd_open, (pid_t)watchPid, 0);
        if (g_spawnerFd < 0)
        {
            std::cerr << "[vidyagodfs] cannot watch pid " << watchPid << ": " << strerror(errno) << "\n";
            return 1;
        }
        g_mountpoint = mountpoint;
    }
    static struct fuse_operations Ops = *VidyagodfsOps();
    g_innerInit = Ops.init;
    Ops.init    = InitWithWatch;

    // Build the argv libfuse expects: prog, mountpoint, then any extra opts passed through.
    std::vector<std::string> fa = { "vidyagodfs", mountpoint };
    for (const std::string &s : backendArgs) fa.push_back(s);

    std::vector<char *> cargv;
    for (std::string &s : fa) cargv.push_back(const_cast<char *>(s.c_str()));

    return fuse_main((int)cargv.size(), cargv.data(), &Ops, &state);
}
