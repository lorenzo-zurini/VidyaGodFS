#ifndef VIDYAGODFS_LAYERSPEC_H
#define VIDYAGODFS_LAYERSPEC_H

#include <string>
#include <vector>
#include <cstdint>

//The JSON layer-spec is the only contract between the VidyaGod app and this helper. The app writes
//one per launch (TempPath/vidyagodfs.spec.json) describing an ordered, target-rooted layer stack;
//the helper serves the merged tree from it. See the plan / README for the format.

enum class LayerType { Dir, Zip, File };

struct LayerSpec {
    LayerType   type = LayerType::Dir;
    std::string source;      // absolute host path (dir / archive / single file)
    std::string target;      // normalized virtual subtree root: no leading/trailing '/', "" == mount root
    bool        rw = false;  // rw:true dir layer = RW passthrough straight to source (durable persist)
};

struct Spec {
    std::string             mountpoint;
    uint32_t                uid = 1000;
    uint32_t                gid = 1000;
    bool                    readOnly = false;
    std::string             writelayer;   // empty when readOnly (or absent) — the COW top branch host dir
    std::vector<LayerSpec>  layers;       // LOWEST priority first → HIGHEST last
};

//Parses the spec file at Path into Out. Returns false (with Err set) on read/parse error.
bool ParseSpec(const std::string &Path, Spec &Out, std::string &Err);

//Strips leading/trailing '/' from a virtual path; "/" and "" both normalize to "".
std::string NormalizeVPath(const std::string &Path);

#endif // VIDYAGODFS_LAYERSPEC_H
