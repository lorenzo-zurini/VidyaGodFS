#include "layerspec.h"
#include "overlay.h"
#include "fuseops.h"

#include <fuse.h>

#include <iostream>
#include <vector>
#include <string>

//vidyagodfs <spec.json> <mountpoint> [extra fuse opts...]
//
//Parses the layer-spec, builds the merged-filesystem state, and hands off to libfuse. fuse_main
//daemonizes by default (forks; the parent exits once the mount is live) and runs multithreaded —
//so the VidyaGod app's blocking spawn returns as soon as the mount is established, and the daemon
//serves the game session in the background until `fusermount -u` (in Cleanup) tears it down.
int main(int argc, char **argv)
{
    if (argc < 3)
    {
        std::cerr << "usage: vidyagodfs <spec.json> <mountpoint> [fuse opts...]\n";
        return 2;
    }

    std::string specPath  = argv[1];
    std::string mountpoint = argv[2];

    Spec spec;
    std::string err;
    if (!ParseSpec(specPath, spec, err)) { std::cerr << "[vidyagodfs] " << err << "\n"; return 1; }
    if (spec.mountpoint.empty()) spec.mountpoint = mountpoint;

    static VfsState state;
    if (!state.Init(spec, err)) { std::cerr << "[vidyagodfs] init: " << err << "\n"; return 1; }

    // Build the argv libfuse expects: prog, mountpoint, then any extra opts passed through.
    std::vector<std::string> fa = { argv[0], mountpoint };
    for (int i = 3; i < argc; ++i) fa.push_back(argv[i]);

    std::vector<char *> cargv;
    for (auto &s : fa) cargv.push_back(const_cast<char *>(s.c_str()));

    return fuse_main((int)cargv.size(), cargv.data(), VidyagodfsOps(), &state);
}
