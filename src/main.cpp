#include "layerspec.h"
#include "overlay.h"
#include "fuseops.h"

#include <fuse.h>

#include <iostream>
#include <vector>
#include <string>
#include <filesystem>

#include <unistd.h>
#include <csignal>
#include <cerrno>
#include <sys/stat.h>

//vidyagodfs <spec.json> <mountpoint> [--watch-pid <pid>] [extra fuse opts...]
//
//Parses the layer-spec, builds the merged-filesystem state, and hands off to libfuse. fuse_main
//daemonizes by default (forks; the parent exits once the mount is live) and runs multithreaded —
//so the VidyaGod app's blocking spawn returns as soon as the mount is established, and the daemon
//serves the game session in the background until `fusermount -u` (in Cleanup) tears it down.
//
//--watch-pid <pid>: if given, fork a watchdog process (before fuse_main, so it survives the daemonize
//fork) that lazily unmounts the moment that pid dies — so a crash/kill of the VidyaGod app can't leave
//the mount dangling. The watchdog also exits as soon as the mount goes away normally, so it never lingers.

//Is `mp` currently a mountpoint? A FUSE mount has a different st_dev than its parent directory; once
//unmounted it collapses back onto the parent's filesystem. Cheap and namespace-local (no /proc scan).
static bool IsMounted(const std::string &mp)
{
    struct stat a {}, b {};
    if (stat(mp.c_str(), &a) != 0) return false;
    std::string parent = std::filesystem::path(mp).parent_path().string();
    if (parent.empty() || stat(parent.c_str(), &b) != 0) return true;
    return a.st_dev != b.st_dev;
}

static bool ProcessAlive(pid_t pid)
{
    return kill(pid, 0) == 0 || errno != ESRCH;
}

//Runs only in the forked watchdog child. Never returns.
[[noreturn]] static void RunWatchdog(pid_t watchPid, const std::string &mp)
{
    //Detach from the spawner's captured stdio pipe so it can close cleanly.
    if (std::freopen("/dev/null", "r", stdin))  {}
    if (std::freopen("/dev/null", "w", stdout)) {}
    if (std::freopen("/dev/null", "w", stderr)) {}

    //Poll until the spawner dies, then unmount if anything is still mounted. While the spawner lives:
    //once we've seen the mount come up, treat its disappearance as a normal teardown and exit (so we
    //never linger). Before we've ever seen it mounted, keep waiting — but cap that so a mount that
    //never appears (failed/missed) doesn't leave us spinning forever.
    bool everMounted = false;
    int  preMountTicks = 0;
    while (ProcessAlive(watchPid))
    {
        if (IsMounted(mp))        everMounted = true;
        else if (everMounted)     _exit(0);                 // came up, now gone → normal unmount, done
        else if (++preMountTicks > 150) _exit(0);           // ~30s and never saw it mount → give up
        usleep(200000);                                     // 200ms — snappy unmount-on-crash
    }

    //Spawner died: if the mount is still up, tear it down (lazy -z, so it detaches even if the
    //now-orphaned game still holds files open).
    if (IsMounted(mp))
        execlp("fusermount3", "fusermount3", "-u", "-z", mp.c_str(), (char *)nullptr);

    _exit(0);
}

int main(int argc, char **argv)
{
    if (argc < 3)
    {
        std::cerr << "usage: vidyagodfs <spec.json> <mountpoint> [--watch-pid <pid>] [fuse opts...]\n";
        return 2;
    }

    std::string specPath   = argv[1];
    std::string mountpoint = argv[2];

    // Pull out --watch-pid <pid> (not a fuse option); everything else is passed through to libfuse.
    pid_t watchPid = 0;
    std::vector<std::string> passthrough;
    for (int i = 3; i < argc; ++i)
    {
        std::string a = argv[i];
        if (a == "--watch-pid" && i + 1 < argc) { watchPid = (pid_t)std::stol(argv[++i]); continue; }
        passthrough.push_back(a);
    }

    Spec spec;
    std::string err;
    if (!ParseSpec(specPath, spec, err)) { std::cerr << "[vidyagodfs] " << err << "\n"; return 1; }
    if (spec.mountpoint.empty()) spec.mountpoint = mountpoint;

    static VfsState state;
    if (!state.Init(spec, err)) { std::cerr << "[vidyagodfs] init: " << err << "\n"; return 1; }

    // Fork the watchdog BEFORE fuse_main — it must be its own process so it survives fuse's daemonize
    // fork and the spawner's exit (it reparents to init and keeps polling).
    if (watchPid > 0)
    {
        pid_t wd = fork();
        if (wd == 0) RunWatchdog(watchPid, spec.mountpoint);   // child: never returns
        // parent falls through; if fork failed we simply run without the watchdog.
    }

    // Build the argv libfuse expects: prog, mountpoint, then any extra opts passed through.
    std::vector<std::string> fa = { argv[0], mountpoint };
    for (auto &s : passthrough) fa.push_back(s);

    std::vector<char *> cargv;
    for (auto &s : fa) cargv.push_back(const_cast<char *>(s.c_str()));

    return fuse_main((int)cargv.size(), cargv.data(), VidyagodfsOps(), &state);
}
