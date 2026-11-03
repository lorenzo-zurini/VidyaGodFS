#ifndef VIDYAGODFS_LAYERSPEC_H
#define VIDYAGODFS_LAYERSPEC_H

#include <string>
#include <vector>
#include <utility>
#include <cstdint>

//The JSON layer-spec is the only contract between the VidyaGod app and this helper. The app writes
//one per launch (TempPath/vidyagodfs.spec.json) describing an ordered, target-rooted layer stack;
//the helper serves the merged tree from it. See the plan / README for the format.

enum class LayerType { Dir, Zip, File, Delta };

struct LayerSpec {
    LayerType   type = LayerType::Dir;
    std::string source;      // absolute host path (dir / archive / single file)
    std::string target;      // normalized virtual subtree root: no leading/trailing '/', "" == mount root
    std::vector<std::string> baseTargets;  // DELTA only: the delta's byte-base is the CONCATENATION (in this exact
                             // order) of the composed views at these targets — one entry is the ordinary
                             // cross-target delta, several let one delta dedup against independent sources at once
                             // (a prefix over [wine, dxvk, prev-prefix]). EMPTY means no base was declared: the base
                             // is then the composed view at `target` itself (the overlay-relative delta, the common
                             // case). There is deliberately no singular key — "" is a real target (the mount root),
                             // so a lone string could not tell "based at the root" apart from "no base declared",
                             // and the FS would silently reconstruct against the wrong bytes.
    // SUBMOUNTS (dir/zip/DELTA): Docker-style "src:dst" mounts of paths WITHIN source. Each (source,target)
    // pair is normalized and fanned out into its own single-subpath internal layer at Init. Empty → mount the
    // whole source at `target`. A pair's `first` is the in-source path ("" == whole source), `second` the dest.
    // A Delta layer reconstructs to a flat archive first (see overlay.cpp), then submounts fan out over that
    // exactly like a zip — so ONE delta can present the whole build at root ("":target) AND re-rooted subpaths
    // (e.g. share/default_pfx:pfx) in a single self-contained mount, zero-copy.
    std::vector<std::pair<std::string,std::string>> submounts;
    bool        rw = false;  // rw:true dir layer = RW passthrough straight to source (durable persist)
};

struct Spec {
    std::string             mountpoint;
    uint32_t                uid = 1000;
    uint32_t                gid = 1000;
    bool                    readOnly = false;
    std::string             writelayer;   // empty when readOnly (or absent) — the COW top branch host dir
    std::vector<LayerSpec>  layers;       // LOWEST priority first → HIGHEST last
    // Names match whatever their case (Windows: a program asks for "DATA\\X.DRS" in a package that has
    // "Data/x.drs"). Spec key "caseInsensitive"; default on for a Windows build only. See CanonicalCase.
    bool                    caseInsensitive = false;
};

//Parses the spec file at Path into Out. Returns false (with Err set) on read/parse error.
bool ParseSpec(const std::string &Path, Spec &Out, std::string &Err);

//Strips leading/trailing '/' from a virtual path; "/" and "" both normalize to "".
std::string NormalizeVPath(const std::string &Path);

#endif // VIDYAGODFS_LAYERSPEC_H
