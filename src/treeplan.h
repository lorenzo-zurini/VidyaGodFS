#ifndef VIDYAGODFS_TREEPLAN_H
#define VIDYAGODFS_TREEPLAN_H

#include "layerspec.h"
#include "bytesource.h"

#include <functional>
#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

//What a spec's layers make of the merged tree, decided from the spec alone, before any byte is read: where each layer
//appears, which file each CID a delta names is, and what each delta hides. The mount (VfsState::Init), the app's check
//before it mounts and its validator all ask this one plan, so none of them holds a rule of its own. (The validator asks
//of the plan in the package's coordinates, before the runner's layout is applied; the mount, of the mapped one.)
//
//A delta's base is BYTES: the files its CIDs name, joined in order (a zip's file, a delta's rebuilt archive). One CID is
//one file, so any layer carrying it will do, wherever it is placed. Placement decides only what a delta hides: every
//placement of a file it replaces (its bases, and what they were rebuilt from) that lies beneath it, inside the places
//the delta itself appears. Elsewhere a base is only a source of bytes.
struct TreePlan
{
    //Per layer: where it appears, as (path inside its source, place in the tree) — its submounts, else ("", target).
    //None for a bytes-only layer: it is read for its bytes and appears nowhere.
    std::vector<std::vector<std::pair<std::string, std::string>>> mounts;
    //Per delta: for each CID it names, in order, the layer whose file that is.
    std::vector<std::vector<size_t>> bases;
    //Per layer: the subtrees where a delta hides it; and whether that is every place it appears (or it is bytes-only),
    //so it never surfaces.
    std::vector<std::vector<std::string>> maskedUnder;
    std::vector<bool> whole;
    //Per delta: it cannot rebuild — a CID it names is on no zip or delta here, its bases name each other in a ring, or
    //its bytes did not rebuild (Failed). It mounts nothing and hides nothing. One line per broken delta in problems.
    std::vector<bool> broken;
    std::vector<std::string> problems;
};

//Failed: the deltas whose bytes did not rebuild (only reading them tells) — planned as broken.
TreePlan PlanTree(const Spec &S, const std::vector<bool> &Failed = {});

//vrel lies at root or inside it ("" is the whole tree).
bool Within(const std::string &vrel, const std::string &root);

//The bytes of a spec's zip and delta layers, built on demand and kept while something still needs them: a delta over
//the layers the plan names, joined in order (a chain flattens, so a thousand versions read like one archive). A base
//no surfacing layer is and no unbuilt delta still needs is released once the last delta over it is built, so a long
//chain holds one rebuilt map at a time, not one per version.
class LayerBytes
{
public:
    //Keep[i]: layer i's bytes are wanted after it is built (it surfaces) — never released.
    LayerBytes(const Spec &S, const TreePlan &P, std::vector<bool> Keep);
    //Null when the layer is not a zip or delta, cannot be read, or (a delta) did not rebuild — then Err says why.
    std::shared_ptr<ByteSource> Get(size_t I, std::string *Err = nullptr);
    //Whether a delta was tried and did not rebuild.
    bool Failed(size_t I) const { return I < State.size() && State[I] == St::Failed; }
    //Called with each layer's bytes as they are built (a chain's every member, on the way to its top).
    std::function<void(size_t, const std::shared_ptr<ByteSource> &)> OnBuilt;
    //How many layers' bytes are held right now.
    size_t Held() const { size_t N = 0; for (const auto &M : Memo) N += M != nullptr; return N; }

private:
    enum class St : unsigned char { None, Building, Built, Failed };
    const Spec &S;
    const TreePlan &P;
    std::vector<bool> Keep;
    std::vector<St> State;
    std::vector<std::shared_ptr<ByteSource>> Memo;
    std::vector<size_t> Uses;      // deltas still to be built over each layer
};

//The names of layer I's contents as its source holds them, '/'-separated (a folder may end in '/'), or null when they
//cannot be read here. The caller lists them however it caches them: a zip's or a delta's member names, a dir's files.
using EntriesFn = std::function<const std::vector<std::string> *(size_t)>;

//Two layers putting names that differ only in case into the merged tree, each where it appears and unhidden: the first
//component that differs (key: the lower-cased path down to it), as each layer spells it, and whether it is a folder.
struct CaseConflict
{
    std::string key;
    size_t first = 0, second = 0;
    std::string firstName, secondName;
    bool dir = false;
};
//Every conflicting component once, lowest layer first. A file mounted twice does not conflict with itself.
std::vector<CaseConflict> CaseConflicts(const Spec &S, const TreePlan &P, const EntriesFn &Entries);
//Per layer: {entry as its source holds it -> that entry spelt as the tree first spells each of its folders and its
//name, lowest layer first} — the entries a rename to the tree's own case would rewrite. Hidden entries spell nothing
//and are not renamed; an entry whose place would itself change case is left alone.
std::map<size_t, std::map<std::string, std::string>> CaseRenames(const Spec &S, const TreePlan &P, const EntriesFn &Entries);

#endif // VIDYAGODFS_TREEPLAN_H
