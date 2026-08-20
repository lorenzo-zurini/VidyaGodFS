#include "layerspec.h"
#include "overlay.h"
#include "mountsession.h"

#include <iostream>
#include <vector>
#include <string>

// vidyagodfs <spec.json> <mountpoint> [--watch-pid <pid>] [extra backend opts...]
//
// Backend-neutral entry point: parse the layer-spec, build the merged-filesystem state, and hand
// off to the platform mount backend (MountSession::Run — FUSE on Linux, WinFsp on Windows). All
// mount/serve/watchdog/unmount mechanics live in the backend; this file knows nothing about them.
//
// --watch-pid <pid>: auto-unmount the moment that pid dies, so a crash/kill of the VidyaGod app
// can't leave the mount dangling (the backend implements the watchdog).
int main(int argc, char **argv)
{
    if (argc < 3)
    {
        std::cerr << "usage: vidyagodfs <spec.json> <mountpoint> [--watch-pid <pid>] [backend opts...]\n";
        return 2;
    }

    std::string specPath   = argv[1];
    std::string mountpoint = argv[2];

    // Pull out --watch-pid <pid> and `-o keep-symlinks` (ours, not backend options); everything else
    // passes through to the backend. keep-symlinks restores pre-abolition behavior: data layers serve
    // symlink entries as symlinks instead of flattening them to their targets (default: flatten).
    long long watchPid = 0;
    bool keepSymlinks = false;
    std::vector<std::string> backendArgs;
    for (int i = 3; i < argc; ++i)
    {
        std::string a = argv[i];
        if (a == "--watch-pid" && i + 1 < argc) { watchPid = std::stoll(argv[++i]); continue; }
        if (a == "-o" && i + 1 < argc && std::string(argv[i + 1]) == "keep-symlinks") { keepSymlinks = true; ++i; continue; }
        if (a == "keep-symlinks") { keepSymlinks = true; continue; }
        backendArgs.push_back(a);
    }

    Spec spec;
    std::string err;
    if (!ParseSpec(specPath, spec, err)) { std::cerr << "[vidyagodfs] " << err << "\n"; return 1; }
    if (spec.mountpoint.empty()) spec.mountpoint = mountpoint;

    static VfsState state;
    state.flattenSymlinks = !keepSymlinks;
    if (!state.Init(spec, err)) { std::cerr << "[vidyagodfs] init: " << err << "\n"; return 1; }

    return MountSession::Run(state, mountpoint, watchPid, backendArgs);
}
