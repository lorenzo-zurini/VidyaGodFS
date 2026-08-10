// WinFsp mount lifecycle (Windows backend of MountSession). WinFsp's FUSE layer serves the
// filesystem from fuse_main() until it is unmounted, and it auto-unmounts when the hosting process
// exits — so the spawner-death watchdog is simply "wait on the spawner pid, then exit this
// process." The Linux analogue is mountsession_fuse.cpp (fork + fusermount3 -uz).
#include "mountsession.h"

#define FUSE_USE_VERSION 30
#include <fuse3/fuse.h>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <thread>
#include <vector>
#include <string>

// The fuse3_operations table (winfsp_backend.cpp).
extern const struct fuse3_operations *VidyagodfsFuse3Ops();

namespace {

// Wait for the spawner to die, then exit — WinFsp tears the mount down on process exit, so a
// crash/kill of the VidyaGod app can never leave the drive dangling.
void WatchSpawner(long long pid)
{
    HANDLE h = ::OpenProcess(SYNCHRONIZE, FALSE, (DWORD)pid);
    if (h == nullptr) return;              // already gone / not permitted → no watchdog
    ::WaitForSingleObject(h, INFINITE);
    ::CloseHandle(h);
    ::ExitProcess(0);
}

} // namespace

int MountSession::Run(VfsState &state, const std::string &mountpoint, long long watchPid,
                      const std::vector<std::string> &backendArgs)
{
    if (watchPid > 0)
        std::thread(WatchSpawner, watchPid).detach();

    // WinFsp-FUSE argv: prog, any pass-through opts, then the mountpoint (a drive letter like "Z:"
    // or a non-existent directory path). fuse_main blocks serving until unmount.
    std::vector<std::string> fa = { "vidyagodfs" };
    for (const std::string &s : backendArgs) fa.push_back(s);
    fa.push_back(mountpoint);

    std::vector<char *> cargv;
    cargv.reserve(fa.size());
    for (std::string &s : fa) cargv.push_back(const_cast<char *>(s.c_str()));

    const struct fuse3_operations *ops = VidyagodfsFuse3Ops();
    return fuse_main((int)cargv.size(), cargv.data(), ops, &state);
}
