#ifndef VIDYAGODFS_MOUNTSESSION_H
#define VIDYAGODFS_MOUNTSESSION_H

// ---------------------------------------------------------------------------
// MountSession — the backend-neutral mount lifecycle. main.cpp (neutral) parses the spec,
// builds the VfsState, and hands off here; the platform backend owns HOW the filesystem is
// actually mounted, kept alive, watched, and torn down:
//   - Linux/FUSE  (mountsession_fuse.cpp): fuse_main() daemonizes + serves multithreaded; a
//                 forked watchdog lazily `fusermount3 -uz`'s the moment the spawner dies.
//   - Windows/WinFsp (mountsession_win.cpp, later): FspFileSystemCreate + SetMountPoint (drive
//                 letter or directory) + a Job Object that reaps the FS with the spawner.
// One impl is selected at compile time (VGFS_BACKEND in CMakeLists).
// ---------------------------------------------------------------------------

#include "overlay.h"   // VfsState

#include <string>
#include <vector>

namespace MountSession {

// Mount `state` at `mountpoint` and BLOCK serving the filesystem until it is unmounted.
// If `watchPid` > 0, arrange that the mount auto-unmounts the moment that process dies (so a
// crash/kill of the VidyaGod app can never leave the mount dangling). `backendArgs` are extra
// backend-specific options passed through verbatim (FUSE mount opts on Linux). Returns a
// process exit code (0 on clean teardown).
int Run(VfsState &state, const std::string &mountpoint, long long watchPid,
        const std::vector<std::string> &backendArgs);

} // namespace MountSession

#endif // VIDYAGODFS_MOUNTSESSION_H
