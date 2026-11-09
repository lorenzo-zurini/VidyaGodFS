#include "treeplan.h"
#include "vgdelta.h"
#include "hostio.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <fcntl.h>
#include <set>
#include <unordered_map>
#include <unordered_set>

bool Within(const std::string &vrel, const std::string &root)
{
    return root.empty() || vrel == root || vrel.rfind(root + "/", 0) == 0;
}

static bool Archive(const LayerSpec &L) { return L.type == LayerType::Zip || L.type == LayerType::Delta; }
static std::string Name(const LayerSpec &L)
{
    const size_t S = L.source.find_last_of("/\\");
    return S == std::string::npos ? L.source : L.source.substr(S + 1);
}

TreePlan PlanTree(const Spec &S, const std::vector<bool> &Failed)
{
    const size_t N = S.layers.size();
    TreePlan P;
    P.mounts.resize(N); P.bases.resize(N); P.maskedUnder.resize(N); P.whole.assign(N, false); P.broken.assign(N, false);
    std::unordered_map<std::string, size_t> Carrier;   // CID -> the first layer carrying it (one CID, one file)
    for (size_t I = 0; I < N; ++I)
    {
        const LayerSpec &L = S.layers[I];
        if (!L.bytesOnly)
        {
            if (L.type != LayerType::File) for (const auto &M : L.submounts) P.mounts[I].push_back(M);
            if (P.mounts[I].empty()) P.mounts[I].push_back({ std::string(), L.target });
        }
        if (Archive(L) && !L.cid.empty()) Carrier.try_emplace(L.cid, I);
    }
    //Which deltas can rebuild: every CID on a zip or a delta that can, no ring.
    enum Mark : unsigned char { Unseen, Visiting, Done };
    std::vector<Mark> Seen(N, Unseen);
    std::function<bool(size_t)> Rebuilds = [&](size_t D) -> bool {
        if (Seen[D] == Done) return !P.broken[D];
        if (Seen[D] == Visiting) return false;
        Seen[D] = Visiting;
        std::string Why;
        if (D < Failed.size() && Failed[D]) Why = "its bytes did not rebuild over its bases";
        if (S.layers[D].bases.empty() && Why.empty()) Why = "it names no base";
        for (const std::string &C : S.layers[D].bases)
        {
            const auto It = Carrier.find(C);
            if (It == Carrier.end()) { if (Why.empty()) Why = "it names " + C + ", which no zip or delta here carries"; continue; }
            P.bases[D].push_back(It->second);
            if (S.layers[It->second].type == LayerType::Delta)
            {
                if (Seen[It->second] == Visiting) { if (Why.empty()) Why = "its bases name each other in a ring"; }
                else if (!Rebuilds(It->second) && Why.empty()) Why = "it names " + C + ", the delta " + Name(S.layers[It->second]) + " that cannot rebuild";
            }
        }
        P.broken[D] = !Why.empty();
        if (P.broken[D]) P.problems.push_back("delta " + Name(S.layers[D]) + " (at '" + S.layers[D].target + "') cannot rebuild: " + Why);
        Seen[D] = Done;
        return !P.broken[D];
    };
    for (size_t I = 0; I < N; ++I) if (S.layers[I].type == LayerType::Delta) Rebuilds(I);
    //Where each file is hidden, and up to which layer: a delta that rebuilds hides the files it names, beneath it, inside
    //its places — and what they were rebuilt from too, so whatever hides a file it names (from beneath that one) also
    //hides that file's own bases. Passed down the names, once per file: a chain of a thousand versions is a thousand
    //steps, not a million. Per CID: place -> the highest layer whose placements beneath it are hidden there.
    std::unordered_map<std::string, std::vector<size_t>> NamedBy;   // CID -> the rebuilding deltas naming it
    for (size_t D = 0; D < N; ++D)
        if (S.layers[D].type == LayerType::Delta && !P.broken[D])
            for (const std::string &C : S.layers[D].bases) NamedBy[C].push_back(D);
    std::unordered_map<std::string, std::map<std::string, size_t>> Down;
    std::unordered_set<std::string> Passed;
    std::function<const std::map<std::string, size_t> &(const std::string &)> DownOf = [&](const std::string &C) -> const std::map<std::string, size_t> & {
        auto &Out = Down[C];
        if (!Passed.insert(C).second) return Out;          // a ring was refused above, this only terminates
        const auto Add = [&](const std::string &Place, size_t Upto) { auto &U = Out[Place]; U = std::max(U, Upto); };
        const auto It = NamedBy.find(C);
        if (It == NamedBy.end()) return Out;
        for (size_t D : It->second)
        {
            for (const auto &M : P.mounts[D]) Add(M.second, D);
            if (!S.layers[D].cid.empty())
                for (const auto &[Place, Upto] : std::map<std::string, size_t>(DownOf(S.layers[D].cid))) Add(Place, Upto);   // whatever hides D hides D's bases
        }
        return Out;
    };
    for (size_t L = 0; L < N; ++L)
    {
        if (!Archive(S.layers[L]) || S.layers[L].cid.empty()) continue;
        for (const auto &[Place, Upto] : DownOf(S.layers[L].cid))
            if (L < Upto) P.maskedUnder[L].push_back(Place);
    }
    for (size_t L = 0; L < N; ++L)
        P.whole[L] = S.layers[L].bytesOnly
                  || (!P.maskedUnder[L].empty() && std::all_of(P.mounts[L].begin(), P.mounts[L].end(), [&](const auto &M) {
                         return std::any_of(P.maskedUnder[L].begin(), P.maskedUnder[L].end(),
                                            [&](const std::string &U) { return Within(M.second, U); }); }));
    return P;
}

LayerBytes::LayerBytes(const Spec &Sp, const TreePlan &Pl, std::vector<bool> K)
    : S(Sp), P(Pl), Keep(std::move(K)), State(Sp.layers.size(), St::None), Memo(Sp.layers.size()), Uses(Sp.layers.size(), 0)
{
    for (size_t D = 0; D < S.layers.size(); ++D)
        if (S.layers[D].type == LayerType::Delta && !P.broken[D])
            for (size_t B : P.bases[D]) ++Uses[B];
}

std::shared_ptr<ByteSource> LayerBytes::Get(size_t I, std::string *Err)
{
    auto Fail = [&](const std::string &Why) -> std::shared_ptr<ByteSource> {
        if (Err) *Err = Why;
        if (S.layers[I].type == LayerType::Delta) State[I] = St::Failed; else State[I] = St::None;
        return nullptr;
    };
    if (I >= S.layers.size() || !Archive(S.layers[I])) return nullptr;
    if (State[I] == St::Built) return Memo[I];
    if (State[I] == St::Failed) return Fail("it did not rebuild");
    if (State[I] == St::Building) return Fail("its bases name each other in a ring");
    const LayerSpec &L = S.layers[I];
    if (L.type == LayerType::Delta && P.broken[I]) return Fail("it cannot rebuild (see the plan's problems)");
    State[I] = St::Building;
    HostIO::Fd Fd = HostIO::Open(L.source, O_RDONLY);
    if (Fd < 0) return Fail("cannot open " + L.source);
    HostIO::Stat St_;
    if (HostIO::Fstat(Fd, St_) != 0) { HostIO::Close(Fd); return Fail("cannot stat " + L.source); }
    std::shared_ptr<ByteSource> Src = std::make_shared<FdByteSource>(Fd, St_.size, true);
    if (L.type == LayerType::Delta)
    {
        std::vector<std::shared_ptr<ByteSource>> Parts;
        for (size_t B : P.bases[I])
        {
            std::string Why;
            auto V = Get(B, &Why);
            if (!V) return Fail("its base " + S.layers[B].cid + " has no bytes (" + Why + ")");
            Parts.push_back(std::move(V));
        }
        std::shared_ptr<ByteSource> Base = Parts.size() == 1 ? Parts[0] : std::make_shared<ConcatByteSource>(Parts);
        std::string Why;
        Src = vgdelta::DeltaByteSource::Create(Src, Base, Why, false);
        if (!Src) return Fail("bad delta " + L.source + ": " + Why);
        Parts.clear(); Base.reset();
        for (size_t B : P.bases[I])                          // a flattened delta needs nothing of its bases' views
        {
            if (Uses[B] == 0) continue;
            --Uses[B];
            if (Uses[B] == 0 && !(B < Keep.size() && Keep[B])) { Memo[B].reset(); State[B] = St::None; }
        }
    }
    Memo[I] = Src;
    State[I] = St::Built;
    if (OnBuilt) OnBuilt(I, Src);
    return Src;
}

namespace
{
std::string Lower(std::string S) { for (char &C : S) C = (char)std::tolower((unsigned char)C); return S; }

std::vector<std::string> Split(const std::string &S)
{
    std::vector<std::string> V; size_t A = 0, B;
    while ((B = S.find('/', A)) != std::string::npos) { V.push_back(S.substr(A, B - A)); A = B + 1; }
    V.push_back(S.substr(A));
    return V;
}

//Each visible name layer I puts in the tree: (entry as its source holds it, its path in the tree, that path lower-cased,
//the mount that put it there). Prepared once per listing and mount when a cache is given.
using NameFn = std::function<void(const std::string &, const std::string &, const std::string &, const std::pair<std::string, std::string> &)>;
void Visible(const Spec &S, const TreePlan &P, size_t I, const EntriesFn &Entries, PreparedNames *Cache, const NameFn &Out)
{
    if (P.whole[I]) return;
    const LayerSpec &L = S.layers[I];
    auto Masked = [&](const std::string &V) {
        return std::any_of(P.maskedUnder[I].begin(), P.maskedUnder[I].end(), [&](const std::string &U) { return Within(V, U); });
    };
    if (L.type == LayerType::File)
    {
        const size_t Sl = L.source.find_last_of("/\\");
        const std::string Base = Sl == std::string::npos ? L.source : L.source.substr(Sl + 1);
        const std::string V = L.target.empty() ? Base : L.target + "/" + Base;
        if (!Masked(V)) Out(Base, V, Lower(V), P.mounts[I].front());
        return;
    }
    const std::vector<std::string> *E = Entries(I);
    if (!E) return;
    for (const auto &M : P.mounts[I])
    {
        const auto &[Sub, Place] = M;
        std::vector<std::array<std::string, 3>> Local;
        std::vector<std::array<std::string, 3>> *Names = &Local;
        bool Fresh = true;
        if (Cache)
        {
            auto [It, New] = Cache->Of.try_emplace(std::to_string(reinterpret_cast<uintptr_t>(E)) + '\x1f' + Sub + '\x1f' + Place);
            Names = &It->second;
            Fresh = New;
        }
        if (Fresh)
            for (const std::string &Raw : *E)
            {
                std::string Entry = Raw;
                while (!Entry.empty() && Entry.back() == '/') Entry.pop_back();
                if (Entry.empty()) continue;
                std::string Rel;
                if (Sub.empty()) Rel = Entry;
                else if (Entry == Sub) Rel.clear();                                // the mount is this one entry (a file a TAKE takes)
                else if (Entry.size() > Sub.size() && Entry.compare(0, Sub.size(), Sub) == 0 && Entry[Sub.size()] == '/') Rel = Entry.substr(Sub.size() + 1);
                else continue;
                std::string V = Rel.empty() ? Place : Place.empty() ? Rel : Place + "/" + Rel;
                if (V.empty()) continue;
                std::string Lv = Lower(V);
                Names->push_back({ Raw, std::move(V), std::move(Lv) });
            }
        for (const auto &[Raw, V, Lv] : *Names)
            if (!Masked(V)) Out(Raw, V, Lv, M);
    }
}
} // namespace

std::vector<CaseConflict> CaseConflicts(const Spec &S, const TreePlan &P, const EntriesFn &Entries, PreparedNames *Cache)
{
    std::vector<CaseConflict> Out;
    std::unordered_map<std::string, std::pair<std::string, size_t>> Seen;   // lower-cased path -> (spelling, layer)
    std::unordered_set<std::string> Reported;
    for (size_t I = 0; I < S.layers.size(); ++I)
        Visible(S, P, I, Entries, Cache, [&](const std::string &, const std::string &V, const std::string &Lv, const auto &) {
            const auto [It, New] = Seen.try_emplace(Lv, V, I);
            if (New) return;
            const auto &[Prev, J] = It->second;
            if (Prev == V || S.layers[J].source == S.layers[I].source) return;   // one file mounted twice is no conflict
            const std::vector<std::string> A = Split(Prev), B = Split(V);
            size_t K = 0;
            while (K < A.size() && K < B.size() && A[K] == B[K]) ++K;
            if (K >= A.size() || K >= B.size()) return;
            std::string Key;
            for (size_t C = 0; C <= K; ++C) { if (C) Key += '/'; Key += Lower(A[C]); }
            if (!Reported.insert(Key).second) return;
            Out.push_back({ Key, J, I, A[K], B[K], K + 1 < A.size() || K + 1 < B.size() });
        });
    return Out;
}

std::map<size_t, std::map<std::string, std::string>> CaseRenames(const Spec &S, const TreePlan &P, const EntriesFn &Entries)
{
    std::map<size_t, std::map<std::string, std::string>> Out;
    std::unordered_map<std::string, std::string> Canon;   // lower-cased path prefix -> the tree's spelling of its last part
    for (size_t I = 0; I < S.layers.size(); ++I)
        Visible(S, P, I, Entries, nullptr, [&](const std::string &Raw, const std::string &V, const std::string &, const std::pair<std::string, std::string> &M) {
            const std::vector<std::string> C = Split(V);
            std::string Prefix, Fixed;
            bool Changed = false;
            for (size_t K = 0; K < C.size(); ++K)
            {
                const std::string Key = Prefix.empty() ? Lower(C[K]) : Prefix + "/" + Lower(C[K]);
                const std::string &Spelt = Canon.try_emplace(Key, C[K]).first->second;
                Changed = Changed || Spelt != C[K];
                if (K) Fixed += '/';
                Fixed += Spelt;
                Prefix = Key;
            }
            if (!Changed || S.layers[I].type == LayerType::File) return;
            //Back from the tree to the entry, through the mount that put it there: its place must keep its case, or it
            //is not this entry's to fix.
            const auto &[Sub, Place] = M;
            const std::string Pfx = Place.empty() ? std::string() : Place + "/";
            if (V == Place || Fixed.compare(0, Pfx.size(), Pfx) != 0) return;   // only its place would change case
            std::string Entry = (Sub.empty() ? std::string() : Sub + "/") + Fixed.substr(Pfx.size());
            if (!Raw.empty() && Raw.back() == '/') Entry += '/';
            if (Entry != Raw) Out[I][Raw] = Entry;
        });
    return Out;
}
