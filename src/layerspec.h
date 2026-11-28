#ifndef VIDYAGODFS_LAYERSPEC_H
#define VIDYAGODFS_LAYERSPEC_H

#include <string>
#include <vector>
#include <utility>
#include <cstdint>

//The JSON layer-spec is the only contract between the VidyaGod app and this helper. The app writes
//one per launch (TempPath/vidyagodfs.spec.json) describing an ordered, target-rooted layer stack;
//the helper serves the merged tree from it. See the plan / README for the format.

enum class LayerType { Dir, Zip, File, Delta, Coded };

struct LayerSpec {
    LayerType   type = LayerType::Dir;
    std::string source;      // absolute host path (dir / archive / single file)
    std::string target;      // normalized virtual subtree root: no leading/trailing '/', "" == mount root
    std::string cid;         // zip/delta/file: the CID of `source`'s bytes — what a delta names it by ("" = none)
    bool        basesNamed = true;   // DELTA: false when the layer named no base at all ("bases": null): it cannot rebuild
    std::vector<std::string> bases;   // DELTA only, REQUIRED: the CIDs of the files whose bytes, joined in this order,
                             // are the delta's base (a zip's file; a single file's own bytes — a disc image; a delta's
                             // rebuilt archive). Where those files are
                             // placed never matters to the bytes; it only decides what the delta hides (treeplan.h).
    // SUBMOUNTS (dir/zip/DELTA): Docker-style "src:dst" mounts of paths WITHIN source. A FILE's ("its name:a path")
    // places the file itself at that path, renamed (a TAKE of one file). Each (source,target)
    // pair is normalized and fanned out into its own single-subpath internal layer at Init. Empty → mount the
    // whole source at `target`. A pair's `first` is the in-source path ("" == whole source), `second` the dest.
    // A Delta layer reconstructs to a flat archive first (see overlay.cpp), then submounts fan out over that
    // exactly like a zip — so ONE delta can present the whole build at root ("":target) AND re-rooted subpaths
    // (e.g. share/default_pfx:pfx) in a single self-contained mount, zero-copy.
    std::vector<std::pair<std::string,std::string>> submounts;
    bool        rw = false;  // rw:true dir layer = RW passthrough straight to source (durable persist)
    //dir: its source cannot change while mounted (package content, a folder built before the mount) — its lookups are
    //answered from one listing taken at the mount (a small enough one). A folder another mount fills, or the user's,
    //is not: each lookup asks the host.
    bool        fixed = false;
    bool        bytesOnly = false;   // zip/delta/file/coded: read as a later delta's base, surfacing nowhere (a TAKE shows none of it)
    //CODED only: a compressed stream served from its decoded content (the one CID in `bases`, any layer carrying bytes:
    //a file, a delta's rebuild) and its decisions (`source`, the record) through a format description: data, never
    //code (MetaPackageFormat 22.16) — its layer's DESCRIPTION, carried in the spec itself. It appears as one file, `name`,
    //in its target folder.
    std::string description;
    std::string name;
    //Places (virtual paths, normalized) this layer does not serve: a file, or a folder and everything below it. What a
    //re-provided copy of a node's layer leaves to the layers beneath it (MetaPackageFormat 05 §5.4: the paths later
    //layers of the same composition rewrite). Hidden like a delta hides its bases (TreePlan::maskedUnder).
    std::vector<std::string> hide;
};

//Bytes a launch puts into a file a lower layer serves (a BinaryPatch the app resolved against it): every read of the
//file gets them, and so does its copy when it is copied up into the writelayer. No layer's own file is ever written,
//and the cost is the patch's size, never the file's. A file the writelayer or a kept folder serves is not patched.
struct BytePatch {
    std::string          path;   // the virtual path (normalized)
    uint64_t             at = 0; // the offset in the file
    std::vector<uint8_t> bytes;  // what is read there
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
    //How many mounts the launch that made this one makes (a runner build and the game: 2). They share one budget for
    //decompressed delta blocks — each took a 32nd of the machine's memory, so two mounts a 16th.
    int                     launchMounts = 1;
    std::vector<BytePatch>  patches;      // in order: a later one wins where two cover the same byte
};

//Parses the spec file at Path (or the spec JSON Text) into Out. Returns false (with Err set) on read/parse error.
bool ParseSpec(const std::string &Path, Spec &Out, std::string &Err);
bool ParseSpecText(const std::string &Text, Spec &Out, std::string &Err);

//Strips leading/trailing '/' from a virtual path; "/" and "" both normalize to "".
std::string NormalizeVPath(const std::string &Path);
// An archive member's name as the mount serves it: '\\' read as '/', "." and empty parts dropped ("./Bin/" → "Bin");
// "" for one with a ".." part (a crafted package: its folder's copy-up wrote OUTSIDE the writelayer).
std::string CleanMemberName(const std::string &Raw);
// A name that is its own clean form (CleanMemberName).
bool SafeMemberName(const std::string &VRel);

#endif // VIDYAGODFS_LAYERSPEC_H
