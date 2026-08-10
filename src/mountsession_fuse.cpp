// FUSE mount lifecycle (Linux backend of MountSession). fuse_main() daemonizes (forks; the
// parent exits once the mount is live) and serves multithreaded, so the VidyaGod app's blocking
// spawn returns as soon as the mount is established. A watchdog forked BEFORE fuse_main (so it
// survives the daemonize fork) lazily unmounts the moment the spawner pid dies. Moved verbatim
// from the old main.cpp; the Windows build compiles mountsession_win.cpp instead.
#include "mountsession.h"
#include "fuseops.h"     // VidyagodfsOps()

#include <fuse.h>

#include <string>
#include <vector>
#include <filesystem>

#include <unistd.h>
#include <csignal>
#include <cerrno>
#include <cstdio>
#include <sys/stat.h>

namespace {

// Is `mp` currently a mountpoint? A FUSE mount has a different st_dev than its parent directory;
// once unmounted it collapses back onto the parent's filesystem. Cheap and namespace-local.
bool IsMounted(const std::string &mp)
{
    struct stat a {}, b {};
    if (stat(mp.c_str(), &a) != 0) return false;
    std::string parent = std::filesystem::path(mp).parent_path().string();
    if (parent.empty() || stat(parent.c_str(), &b) != 0) return true;
    return a.st_dev != b.st_dev;
}

bool ProcessAlive(pid_t pid) { return kill(pid, 0) == 0 || errno != ESRCH; }

// Runs only in the forked watchdog child. Never returns.
[[noreturn]] void RunWatchdog(pid_t watchPid, const std::string &mp)
{
    // Detach from the spawner's captured stdio pipe so it can close cleanly.
    if (std::freopen("/dev/null", "r", stdin))  {}
    if (std::freopen("/dev/null", "w", stdout)) {}
    if (std::freopen("/dev/null", "w", stderr)) {}

    // Poll until the spawner dies, then unmount if anything is still mounted. Once we've seen the
    // mount come up, treat its disappearance as a normal teardown and exit (so we never linger).
    // Before we've ever seen it mounted, keep waiting — but cap that so a mount that never appears
    // doesn't leave us spinning forever.
    bool everMounted = false;
    int  preMountTicks = 0;
    while (ProcessAlive(watchPid))
    {
        if (IsMounted(mp))        everMounted = true;
        else if (everMounted)     _exit(0);                 // came up, now gone → normal unmount, done
        else if (++preMountTicks > 150) _exit(0);           // ~30s and never saw it mount → give up
        usleep(200000);                                     // 200ms — snappy unmount-on-crash
    }

    // Spawner died: if the mount is still up, tear it down (lazy -z, so it detaches even if the
    // now-orphaned game still holds files open).
    if (IsMounted(mp))
        execlp("fusermount3", "fusermount3", "-u", "-z", mp.c_str(), (char *)nullptr);

    _exit(0);
}

} // namespace

int MountSession::Run(VfsState &state, const std::string &mountpoint, long long watchPid,
                      const std::vector<std::string> &backendArgs)
{
    // Fork the watchdog BEFORE fuse_main — it must be its own process so it survives fuse's
    // daemonize fork and the spawner's exit (it reparents to init and keeps polling).
    if (watchPid > 0)
    {
        pid_t wd = fork();
        if (wd == 0) RunWatchdog((pid_t)watchPid, mountpoint);   // child: never returns
        // parent falls through; if fork failed we simply run without the watchdog.
    }

    // Build the argv libfuse expects: prog, mountpoint, then any extra opts passed through.
    std::vector<std::string> fa = { "vidyagodfs", mountpoint };
    for (const std::string &s : backendArgs) fa.push_back(s);

    std::vector<char *> cargv;
    for (std::string &s : fa) cargv.push_back(const_cast<char *>(s.c_str()));

    return fuse_main((int)cargv.size(), cargv.data(), VidyagodfsOps(), &state);
}
