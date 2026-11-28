// A TREE (.vgtz): an install as files over its bases' bytes, readable. treelayer.h says what it is; MetaPackageFormat
// 04 and 22.18 are the contract.
#include "treelayer.h"
#include "viewmode.h"
#include "zipscan.h"

#include <zstd.h>

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <list>
#include <mutex>
#include <string_view>
#include <unordered_map>
#include <unordered_set>

namespace vgtree {
namespace {

std::string Dec(uint64_t V) { return std::to_string(V); }
bool Num(std::string_view S, uint64_t &V) {
    if (S.empty() || S.size() > 20 || (S.size() > 1 && S[0] == '0')) return false;
    V = 0;
    for (const char c : S) { if (c < '0' || c > '9') return false; const uint64_t d = (uint64_t)(c - '0'); if (V > (UINT64_MAX - d) / 10) return false; V = V * 10 + d; }
    return true;
}
// The next field of S from At up to By (or S's end); false past the end.
bool Field(std::string_view S, size_t &At, std::string_view By, std::string_view &F) {
    if (At > S.size()) return false;
    const size_t T = S.find(By, At);
    F = S.substr(At, T == std::string_view::npos ? std::string_view::npos : T - At);
    At = T == std::string_view::npos ? S.size() + 1 : T + By.size();
    return true;
}
bool GoodPath(const std::string &P) { return P.size() <= coding::kViewMaxPath && coding::GoodViewPath(P) && coding::ValidUtf8Text(P); }
bool GoodBasePath(const std::string &P) { return P.empty() || GoodPath(P); }
std::string Mode(uint32_t M) { if (!M) return "-"; char B[16]; snprintf(B, sizeof B, "%o", M); return B; }
bool ModeOf(std::string_view S, uint32_t &M) {
    if (S == "-") { M = 0; return true; }
    if (S.empty() || S.size() > 4 || S[0] == '0') return false;
    M = 0; for (const char c : S) { if (c < '0' || c > '7') return false; M = M * 8 + (uint32_t)(c - '0'); }
    return M <= 07777;
}
std::string PiecesText(const std::vector<Piece> &V) {
    std::string O;
    for (size_t i = 0; i < V.size(); ++i) {
        if (i) O += ", ";
        if (V[i].kind == Piece::Keep) O += "keep " + Dec(V[i].off) + ".." + Dec(V[i].off + V[i].len);
        else O += std::string(V[i].kind == Piece::New ? "new " : "zero ") + Dec(V[i].len);
    }
    return O;
}
} // namespace
// A link's target stays inside the tree: relative, never above its top from the link's own folder.
bool InsideLink(const std::string &Path, const std::string &Target) {
    if (Target.empty() || Target[0] == '/') return false;
    long Depth = (long)std::count(Path.begin(), Path.end(), '/');
    size_t At = 0; std::string_view C;
    while (Field(Target, At, "/", C)) {
        if (C.empty()) return false;
        if (C == "..") { if (--Depth < 0) return false; }
        else if (C != ".") ++Depth;
    }
    return true;
}
namespace {

bool Check(const Table &T, std::string &Err) {
    if (T.entries.size() > kMaxEntries) { Err = "a tree of too many entries"; return false; }
    if (T.bases.size() > kMaxBases) { Err = "a tree of too many bases"; return false; }
    std::unordered_set<std::string> Cids;
    for (const std::string &B : T.bases) {
        if (B.empty() || B.size() > 256 || B.find_first_of("\t\n\r") != std::string::npos) { Err = "a tree base is not a CID"; return false; }
        if (!Cids.insert(B).second) { Err = "a tree names the base '" + B + "' twice"; return false; }
    }
    std::unordered_set<std::string> Dirs;
    size_t NPieces = 0;
    for (size_t i = 0; i < T.entries.size(); ++i) {
        const Entry &E = T.entries[i];
        if (!GoodPath(E.path)) { Err = "a tree path is malformed: '" + coding::PrintablePath(E.path) + "'"; return false; }
        if (i && !(T.entries[i - 1].path < E.path)) { Err = "a tree's entries out of order (or a path twice): '" + coding::PrintablePath(E.path) + "'"; return false; }
        if (const size_t S = E.path.rfind('/'); S != std::string::npos && !Dirs.count(E.path.substr(0, S))) { Err = "a tree missing the folder '" + coding::PrintablePath(E.path.substr(0, S)) + "'"; return false; }
        if (E.kind == Entry::Dir) { Dirs.insert(E.path); continue; }
        if (E.kind == Entry::Link) {
            if (E.link.empty() || E.link.size() > 4096) { Err = "a tree link's target is malformed"; return false; }
            for (const char c : E.link) if ((uint8_t)c < 0x20 || c == 0x7F) { Err = "a tree link's target is malformed"; return false; }
            if (!coding::ValidUtf8Text(E.link) || !InsideLink(E.path, E.link)) { Err = "a tree link leaves the tree: '" + coding::PrintablePath(E.path) + "'"; return false; }
            continue;
        }
        const std::string P = coding::PrintablePath(E.path);
        if (E.mode > 07777) { Err = "a tree file's mode is malformed"; return false; }
        if (E.size == 0 && E.op != Entry::New) { Err = "an empty tree file is written 'new': '" + P + "'"; return false; }
        if (E.op != Entry::New && (E.base >= T.bases.size() || !GoodBasePath(E.basePath))) { Err = "a tree file names no base file: '" + P + "'"; return false; }
        if (E.op == Entry::Range && (E.len != E.size || E.off > UINT64_MAX - E.len)) { Err = "a tree range is not its size: '" + P + "'"; return false; }
        if (E.op == Entry::Patch && E.size > kMaxPatch) { Err = "a patched tree file over 16 MiB: '" + P + "'"; return false; }
        if (E.op == Entry::Pieces) {
            if (E.pieces.size() < 2 && !(E.pieces.size() == 1 && E.pieces[0].kind != Piece::Keep)) { Err = "a tree file of one kept piece is a range: '" + P + "'"; return false; }
            if ((NPieces += E.pieces.size()) > kMaxPieces) { Err = "a tree of too many pieces"; return false; }
            uint64_t Sum = 0; bool Kept = false;
            for (size_t k = 0; k < E.pieces.size(); ++k) {
                const Piece &Q = E.pieces[k];
                if (Q.len == 0 || Sum > UINT64_MAX - Q.len || (Q.kind == Piece::Keep && Q.off > UINT64_MAX - Q.len)) { Err = "a tree file's piece is malformed: '" + P + "'"; return false; }
                if (k && Q.kind == E.pieces[k - 1].kind && (Q.kind != Piece::Keep || E.pieces[k - 1].off + E.pieces[k - 1].len == Q.off)) { Err = "a tree file's touching pieces are not one: '" + P + "'"; return false; }
                Sum += Q.len; Kept |= Q.kind == Piece::Keep;
            }
            if (!Kept) { Err = "a tree file of pieces keeps nothing of its base (it is 'new'): '" + P + "'"; return false; }
            if (Sum != E.size) { Err = "a tree file's size is not its pieces': '" + P + "'"; return false; }
        }
    }
    return true;
}
std::string LineText(const Entry &E) {
    if (E.kind == Entry::Dir) return "dir\t" + E.path + "\n";
    if (E.kind == Entry::Link) return "link\t" + E.path + "\t" + E.link + "\n";
    static const char *const Ops[] = { "same", "range", "patch", "pieces", "new" };
    std::string O = std::string(Ops[E.op]) + "\t" + E.path + "\t" + Dec(E.size) + "\t" + Mode(E.mode);
    if (E.op != Entry::New) O += "\tfrom " + Dec(E.base) + "\t" + E.basePath;
    if (E.op == Entry::Range) O += "\t" + Dec(E.off) + ".." + Dec(E.off + E.len);
    if (E.op == Entry::Pieces) O += "\t" + PiecesText(E.pieces);
    return O + "\n";
}

// ---- CRC-32 (zip's, IEEE 802.3): its own table, so the core needs no zlib
uint32_t Crc32(uint32_t C, const uint8_t *P, size_t N) {
    static const struct T { uint32_t t[256]; T() { for (uint32_t i = 0; i < 256; ++i) { uint32_t c = i; for (int k = 0; k < 8; ++k) c = c & 1 ? 0xEDB88320u ^ (c >> 1) : c >> 1; t[i] = c; } } } Tab;
    C = ~C;
    for (size_t i = 0; i < N; ++i) C = Tab.t[(C ^ P[i]) & 0xFF] ^ (C >> 8);
    return ~C;
}

int Seek(std::FILE *F, uint64_t At) {
#ifdef _WIN32
    return _fseeki64(F, (__int64)At, SEEK_SET);
#else
    return fseeko(F, (off_t)At, SEEK_SET);
#endif
}

// ---- a deterministic STORE zip (UTF-8 names, 1980-01-01, no extras but ZIP64's, external attributes 0). A member
// is written whole (member) or streamed (begin, write, end: its CRC and size patched into its header after); whether it
// takes ZIP64 is decided from an upper bound of its size, so the same input makes the same bytes.
struct ZipW {
    std::FILE *F = nullptr; uint64_t at = 0; bool ok = true;
    struct M { std::string name; uint32_t crc; uint64_t size, off; bool big; };
    std::vector<M> members;
    uint32_t crc = 0; uint64_t n = 0;
    void put(const void *P, size_t N) { if (ok && N && std::fwrite(P, 1, N, F) != N) ok = false; at += N; }
    void u16(uint16_t v) { uint8_t b[2] = { (uint8_t)v, (uint8_t)(v >> 8) }; put(b, 2); }
    void u32(uint32_t v) { uint8_t b[4]; for (int i = 0; i < 4; ++i) b[i] = (uint8_t)(v >> (8 * i)); put(b, 4); }
    void u64(uint64_t v) { uint8_t b[8]; for (int i = 0; i < 8; ++i) b[i] = (uint8_t)(v >> (8 * i)); put(b, 8); }
    void header(bool Big, uint32_t Crc, uint64_t N, const std::string &Name) {
        u32(0x04034b50); u16(Big ? 45 : 20); u16(0x0800); u16(0); u16(0); u16(0x0021); u32(Crc);
        u32(Big ? 0xFFFFFFFFu : (uint32_t)N); u32(Big ? 0xFFFFFFFFu : (uint32_t)N); u16((uint16_t)Name.size()); u16(Big ? 20 : 0);
        put(Name.data(), Name.size());
        if (Big) { u16(1); u16(16); u64(N); u64(N); }
    }
    void begin(const std::string &Name, uint64_t Bound) {
        const bool Big = Bound >= 0xFFFFFFFFull || at >= 0xFFFFFFFFull;
        members.push_back({ Name, 0, 0, at, Big });
        header(Big, 0, 0, Name);
        crc = 0; n = 0;
    }
    void write(const void *P, size_t N) { crc = Crc32(crc, (const uint8_t *)P, N); n += N; put(P, N); }
    void end() {
        M &m = members.back(); m.crc = crc; m.size = n;
        if (!ok) return;
        const uint64_t Here = at;
        if (Seek(F, m.off) != 0) { ok = false; return; }
        const uint64_t Save = at; at = m.off;
        header(m.big, m.crc, m.size, m.name);
        at = Save;
        if (Seek(F, Here) != 0) ok = false;
    }
    void member(const std::string &Name, const uint8_t *P, size_t N) { begin(Name, N); write(P, N); end(); }
    void finish() {
        const uint64_t Cd = at;
        for (const M &m : members) {
            const bool Big = m.big || m.off >= 0xFFFFFFFFull;
            u32(0x02014b50); u16(Big ? 45 : 20); u16(Big ? 45 : 20); u16(0x0800); u16(0); u16(0); u16(0x0021); u32(m.crc);
            u32(Big ? 0xFFFFFFFFu : (uint32_t)m.size); u32(Big ? 0xFFFFFFFFu : (uint32_t)m.size); u16((uint16_t)m.name.size());
            u16(Big ? 28 : 0); u16(0); u16(0); u16(0); u32(0); u32(Big ? 0xFFFFFFFFu : (uint32_t)m.off);
            put(m.name.data(), m.name.size());
            if (Big) { u16(1); u16(24); u64(m.size); u64(m.size); u64(m.off); }
        }
        const uint64_t CdLen = at - Cd, Eocd64 = at;
        u32(0x06064b50); u64(44); u16(45); u16(45); u32(0); u32(0); u64(members.size()); u64(members.size()); u64(CdLen); u64(Cd);
        u32(0x07064b50); u32(0); u64(Eocd64); u32(1);
        u32(0x06054b50); u16(0); u16(0); u16(0xFFFF); u16(0xFFFF); u32(0xFFFFFFFFu); u32(0xFFFFFFFFu); u16(0);
    }
};

// ---- one byte-bounded LRU per kind, for the whole process (FUSE reads come on many threads)
class Lru {
public:
    explicit Lru(uint64_t Budget) : budget(Budget) {}
    std::shared_ptr<const std::vector<uint8_t>> get(uint64_t K) {
        std::lock_guard<std::mutex> g(mu);
        const auto It = at.find(K);
        if (It == at.end()) return nullptr;
        order.splice(order.begin(), order, It->second);
        return It->second->second;
    }
    void put(uint64_t K, std::shared_ptr<const std::vector<uint8_t>> V) {
        std::lock_guard<std::mutex> g(mu);
        if (at.count(K) || V->size() > budget) return;
        order.emplace_front(K, V); at[K] = order.begin(); bytes += V->size();
        while (bytes > budget) { bytes -= order.back().second->size(); at.erase(order.back().first); order.pop_back(); }
    }
private:
    std::mutex mu;
    uint64_t budget, bytes = 0;
    std::list<std::pair<uint64_t, std::shared_ptr<const std::vector<uint8_t>>>> order;
    std::unordered_map<uint64_t, std::list<std::pair<uint64_t, std::shared_ptr<const std::vector<uint8_t>>>>::iterator> at;
};
Lru &FrameCache() { static Lru L(64ull << 20); return L; }
Lru &PatchCache() { static Lru L(256ull << 20); return L; }
uint64_t NewId() { static std::atomic<uint64_t> N{ 1 }; return N++; }

// ---- seekable zstd
constexpr uint32_t kSkippable = 0x184D2A5E, kSeekMagic = 0x8F92EAB1;
struct SeekSource : ByteSource {
    std::shared_ptr<ByteSource> z;
    std::vector<uint64_t> cOff, dOff;          // per frame: compressed and decompressed starts (and one past the last)
    const uint64_t id = NewId();
    std::atomic<bool> told{ false };
    std::shared_ptr<const std::vector<uint8_t>> frame(size_t k) {
        const uint64_t K = (id << 24) | k;
        if (auto F = FrameCache().get(K)) return F;
        std::vector<uint8_t> C((size_t)(cOff[k + 1] - cOff[k]));
        auto D = std::make_shared<std::vector<uint8_t>>((size_t)(dOff[k + 1] - dOff[k]));
        const bool Read = z->preadAll(C.data(), C.size(), cOff[k]);
        const size_t R = Read ? ZSTD_decompress(D->data(), D->size(), C.data(), C.size()) : 0;
        if (!Read || ZSTD_isError(R) || R != D->size()) {
            if (!told.exchange(true)) std::fprintf(stderr, "vidyagodfs: a tree's added bytes do not read (frame %zu: %s)\n", k, Read ? "not its zstd" : "a short read");
            return nullptr;
        }
        FrameCache().put(K, D);
        return D;
    }
    ssize_t pread(void *buf, size_t n, uint64_t off) override {
        size_t done = 0;
        while (done < n && off + done < dOff.back()) {
            const uint64_t pos = off + done;
            const size_t k = (size_t)(std::upper_bound(dOff.begin(), dOff.end(), pos) - dOff.begin()) - 1;
            const auto F = frame(k);
            if (!F) return done ? (ssize_t)done : -EIO;
            const size_t in = (size_t)(pos - dOff[k]), take = std::min(n - done, F->size() - in);
            std::memcpy((uint8_t *)buf + done, F->data() + in, take);
            done += take;
        }
        return (ssize_t)done;
    }
    uint64_t size() const override { return dOff.back(); }
};

struct OnFirstRead : ByteSource {
    uint64_t n; std::function<std::shared_ptr<ByteSource>(std::string &)> open; std::string what;
    std::once_flag once; std::shared_ptr<ByteSource> src;
    std::shared_ptr<ByteSource> get() {
        std::call_once(once, [&] {
            std::string Err;
            auto S = open(Err);
            if (S && S->size() != n) { Err = "it is " + Dec(S->size()) + " bytes, not " + Dec(n); S = nullptr; }
            if (!S) std::fprintf(stderr, "vidyagodfs: %s does not read: %s\n", what.c_str(), Err.c_str());
            src = std::move(S); open = nullptr; });
        return src;
    }
    ssize_t pread(void *buf, size_t len, uint64_t off) override {
        if (off >= n || !len) return 0;
        const auto S = get();
        return S ? S->pread(buf, len, off) : -EIO;
    }
    void prefetch(uint64_t off, uint64_t len) override { if (const auto S = get()) S->prefetch(off, len); }
    uint64_t size() const override { return n; }
};

// ---- line diffs
std::vector<std::pair<size_t, size_t>> Lines(const std::string &S) {          // (start, length incl. its ending)
    std::vector<std::pair<size_t, size_t>> L;
    for (size_t b = 0; b < S.size();) { const size_t e = S.find('\n', b); const size_t end = e == std::string::npos ? S.size() : e + 1; L.push_back({ b, end - b }); b = end; }
    return L;
}
// Myers's greedy diff over lines (common prefix and suffix first): the matched (a, b) line pairs, in order; false when
// the edit distance passes MaxD, or the line comparisons Fuel. Each step d keeps only its 2d+1 diagonals (int32), so
// its memory is about MaxD² words.
bool Matches(const std::string &A, const std::vector<std::pair<size_t, size_t>> &La, const std::string &B,
             const std::vector<std::pair<size_t, size_t>> &Lb, std::vector<std::pair<size_t, size_t>> &Out, long MaxD, uint64_t Fuel) {
    const auto Eq = [&](size_t i, size_t j) { return La[i].second == Lb[j].second && A.compare(La[i].first, La[i].second, B, Lb[j].first, Lb[j].second) == 0; };
    const long N = (long)La.size(), M = (long)Lb.size();
    long pre = 0; while (pre < N && pre < M && Eq((size_t)pre, (size_t)pre)) ++pre;
    long suf = 0; while (suf < N - pre && suf < M - pre && Eq((size_t)(N - 1 - suf), (size_t)(M - 1 - suf))) ++suf;
    const long n = N - pre - suf, m = M - pre - suf;
    if (n > INT32_MAX - 2 || m > INT32_MAX - 2) return false;
    std::vector<std::vector<int32_t>> Trace;               // Trace[d][k + d]: the furthest x on diagonal k after step d
    std::vector<int32_t> V((size_t)(2 * MaxD + 5), 0);
    const long off = MaxD + 2;
    bool Done = n == 0 && m == 0;
    for (long D = 0; !Done; ++D) {
        if (D > MaxD) return false;
        for (long k = -D; k <= D; k += 2) {
            long x = (k == -D || (k != D && V[(size_t)(off + k - 1)] < V[(size_t)(off + k + 1)])) ? V[(size_t)(off + k + 1)] : V[(size_t)(off + k - 1)] + 1;
            long y = x - k;
            while (x < n && y < m) { if (!Fuel--) return false; if (!Eq((size_t)(pre + x), (size_t)(pre + y))) break; ++x; ++y; }
            V[(size_t)(off + k)] = (int32_t)x;
            if (x >= n && y >= m) Done = true;
        }
        Trace.emplace_back(V.begin() + (off - D), V.begin() + (off + D + 1));
    }
    const auto At = [&](long d, long k) { return (long)Trace[(size_t)d][(size_t)(k + d)]; };
    std::vector<std::pair<size_t, size_t>> Mid;
    long x = n, y = m;
    for (long d = (long)Trace.size() - 1; d >= 1 && (x > 0 || y > 0); --d) {
        const long k = x - y;
        const long pk = (k == -d || (k != d && At(d - 1, k - 1) < At(d - 1, k + 1))) ? k + 1 : k - 1;
        const long px = At(d - 1, pk), py = px - pk;
        while (x > px && y > py) { --x; --y; Mid.push_back({ (size_t)(pre + x), (size_t)(pre + y) }); }
        x = px; y = py;
    }
    while (x > 0 && y > 0) { --x; --y; Mid.push_back({ (size_t)(pre + x), (size_t)(pre + y) }); }
    Out.clear();
    for (long i = 0; i < pre; ++i) Out.push_back({ (size_t)i, (size_t)i });
    for (auto It = Mid.rbegin(); It != Mid.rend(); ++It) Out.push_back(*It);
    for (long i = 0; i < suf; ++i) Out.push_back({ (size_t)(N - suf + i), (size_t)(M - suf + i) });
    return true;
}
std::string Utf16To8(const std::string &S, bool Le, bool &Ok) {
    std::string O; Ok = S.size() % 2 == 0;
    for (size_t i = 0; Ok && i < S.size(); i += 2) {
        uint32_t c = Le ? ((uint8_t)S[i] | ((uint32_t)(uint8_t)S[i + 1] << 8)) : (((uint32_t)(uint8_t)S[i] << 8) | (uint8_t)S[i + 1]);
        if (c >= 0xD800 && c < 0xDC00) {
            if (i + 4 > S.size()) { Ok = false; break; }
            const uint32_t l = Le ? ((uint8_t)S[i + 2] | ((uint32_t)(uint8_t)S[i + 3] << 8)) : (((uint32_t)(uint8_t)S[i + 2] << 8) | (uint8_t)S[i + 3]);
            if (l < 0xDC00 || l >= 0xE000) { Ok = false; break; }
            c = 0x10000 + ((c - 0xD800) << 10) + (l - 0xDC00); i += 2;
        } else if (c >= 0xDC00 && c < 0xE000) { Ok = false; break; }
        if (c < 0x80) O += (char)c;
        else if (c < 0x800) { O += (char)(0xC0 | (c >> 6)); O += (char)(0x80 | (c & 0x3F)); }
        else if (c < 0x10000) { O += (char)(0xE0 | (c >> 12)); O += (char)(0x80 | ((c >> 6) & 0x3F)); O += (char)(0x80 | (c & 0x3F)); }
        else { O += (char)(0xF0 | (c >> 18)); O += (char)(0x80 | ((c >> 12) & 0x3F)); O += (char)(0x80 | ((c >> 6) & 0x3F)); O += (char)(0x80 | (c & 0x3F)); }
    }
    return O;
}
// UTF-8 to UTF-16 (to Out when given); its length in bytes, or false when not UTF-8.
bool Utf8To16(std::string_view S, bool Le, std::string *Out, uint64_t &Bytes) {
    Bytes = 0;
    auto put = [&](uint32_t u) { Bytes += 2; if (!Out) return; if (Le) { *Out += (char)(u & 0xFF); *Out += (char)(u >> 8); } else { *Out += (char)(u >> 8); *Out += (char)(u & 0xFF); } };
    for (size_t i = 0; i < S.size();) {
        const uint8_t c = (uint8_t)S[i]; uint32_t u; size_t n;
        if (c < 0x80) { u = c; n = 1; } else if ((c >> 5) == 6) { u = c & 0x1F; n = 2; } else if ((c >> 4) == 14) { u = c & 0x0F; n = 3; } else if ((c >> 3) == 30) { u = c & 0x07; n = 4; } else return false;
        if (i + n > S.size()) return false;
        for (size_t k = 1; k < n; ++k) { if (((uint8_t)S[i + k] & 0xC0) != 0x80) return false; u = (u << 6) | ((uint8_t)S[i + k] & 0x3F); }
        if ((n == 2 && u < 0x80) || (n == 3 && u < 0x800) || (n == 4 && (u < 0x10000 || u > 0x10FFFF)) || (u >= 0xD800 && u < 0xE000)) return false;
        if (u >= 0x10000) { u -= 0x10000; put(0xD800 + (u >> 10)); put(0xDC00 + (u & 0x3FF)); } else put(u);
        i += n;
    }
    return true;
}
bool Plain(const uint8_t *P, size_t N) {
    const size_t L = std::min<size_t>(N, 1u << 16);
    size_t Ok = 0;
    for (size_t i = 0; i < L; ++i) { const uint8_t c = P[i]; if (c == 0) return false; Ok += (c >= 32 || c == 9 || c == 10 || c == 13); }
    return L == 0 || Ok * 100 >= L * 95;
}
std::string Diff(const std::string &A, const std::string &B, const std::string &An, const std::string &Bn, bool &Ok) {
    Ok = false;
    const auto La = Lines(A), Lb = Lines(B);
    if (La.size() > kMaxPatchLines || Lb.size() > kMaxPatchLines) return std::string();
    std::vector<std::pair<size_t, size_t>> Mt;
    if (!Matches(A, La, B, Lb, Mt, (long)kMaxDiffSteps, 1ull << 27)) return std::string();
    //opcodes: runs of equal lines between changes; then hunks with 3 lines of context (difflib's grouping)
    struct Op { bool eq; size_t a1, a2, b1, b2; };
    std::vector<Op> Ops;
    size_t i = 0, j = 0;
    for (size_t k = 0; k <= Mt.size(); ++k) {
        const size_t ai = k < Mt.size() ? Mt[k].first : La.size(), bj = k < Mt.size() ? Mt[k].second : Lb.size();
        if (ai > i || bj > j) Ops.push_back({ false, i, ai, j, bj });
        if (k < Mt.size()) {
            if (!Ops.empty() && Ops.back().eq && Ops.back().a2 == ai && Ops.back().b2 == bj) { ++Ops.back().a2; ++Ops.back().b2; }
            else Ops.push_back({ true, ai, ai + 1, bj, bj + 1 });
        }
        i = ai + 1; j = bj + 1;
    }
    const size_t C = 3;
    std::vector<std::vector<Op>> Groups;
    std::vector<Op> G;
    for (size_t k = 0; k < Ops.size(); ++k) {
        Op o = Ops[k];
        if (o.eq) {
            if (k == 0) { const size_t s = o.a2 > C ? o.a2 - C : 0; o.b1 += s - o.a1; o.a1 = s; }
            if (k == Ops.size() - 1) { o.a2 = std::min(o.a2, o.a1 + C); o.b2 = std::min(o.b2, o.b1 + C); }
            if (o.a2 - o.a1 > 2 * C && k != 0 && k != Ops.size() - 1) {
                G.push_back({ true, o.a1, o.a1 + C, o.b1, o.b1 + C });
                Groups.push_back(G); G.clear();
                o.a1 = o.a2 - C; o.b1 = o.b2 - C;
            }
            if (o.a2 > o.a1) G.push_back(o);
        } else G.push_back(o);
    }
    if (!G.empty() && !(G.size() == 1 && G[0].eq)) Groups.push_back(G);
    if (Groups.empty()) return std::string();               // no change: the file is its base's (same)
    std::string O = "--- a/" + An + "\n+++ b/" + Bn + "\n";
    const auto Emit = [&](char T, const std::string &S, std::pair<size_t, size_t> L) {
        O += T; O.append(S, L.first, L.second);
        if (L.second == 0 || S[L.first + L.second - 1] != '\n') O += "\n\\ No newline at end of file\n";
    };
    for (const auto &Gr : Groups) {
        if (Gr.empty()) continue;
        const size_t a1 = Gr.front().a1, a2 = Gr.back().a2, b1 = Gr.front().b1, b2 = Gr.back().b2;
        O += "@@ -" + Dec(a2 > a1 ? a1 + 1 : a1) + "," + Dec(a2 - a1) + " +" + Dec(b2 > b1 ? b1 + 1 : b1) + "," + Dec(b2 - b1) + " @@\n";
        for (const Op &o : Gr) {
            if (o.eq) { for (size_t a = o.a1; a < o.a2; ++a) Emit(' ', A, La[a]); continue; }
            for (size_t a = o.a1; a < o.a2; ++a) Emit('-', A, La[a]);
            for (size_t b = o.b1; b < o.b2; ++b) Emit('+', B, Lb[b]);
        }
    }
    Ok = true;
    return O;
}

// ---- a unified diff, read strictly (22.18.4): "--- " and "+++ " lines, then one hunk or more in order, each
// "@@ -a,n +b,m @@" with exactly n old and m new lines, the new start where the old one says, at least one change;
// "\ No newline at end of file" after a side's last line only. Each hunk's 0-based old start goes to Hunk, each line
// (its kind, its bytes with their newline or without) to Line.
constexpr std::string_view kNoNl = "\\ No newline at end of file\n";
bool HunkHeader(std::string_view L, uint64_t &a, uint64_t &an, uint64_t &b, uint64_t &bn) {
    if (L.substr(0, 4) != "@@ -" || L.size() < 7 || L.substr(L.size() - 3) != " @@") return false;
    const std::string_view In = L.substr(4, L.size() - 7);
    const size_t Sp = In.find(" +");
    if (Sp == std::string_view::npos) return false;
    const std::string_view A = In.substr(0, Sp), B = In.substr(Sp + 2);
    const size_t Ca = A.find(','), Cb = B.find(',');
    if (Ca == std::string_view::npos || Cb == std::string_view::npos) return false;
    if (!Num(A.substr(0, Ca), a) || !Num(A.substr(Ca + 1), an) || !Num(B.substr(0, Cb), b) || !Num(B.substr(Cb + 1), bn)) return false;
    if (a > (1ull << 32) || an > (1ull << 32) || b > (1ull << 32) || bn > (1ull << 32)) return false;
    return (an == 0 || a >= 1) && (bn == 0 || b >= 1);
}
bool WalkPatch(std::string_view P, std::string_view &OldName, std::string_view &NewName,
               const std::function<bool(uint64_t)> &Hunk, const std::function<bool(char, std::string_view)> &Line, std::string &Err) {
    size_t at = 0;
    std::string_view L;
    const auto Next = [&]() { if (at >= P.size()) return false; const size_t e = P.find('\n', at); if (e == std::string_view::npos) return false; L = P.substr(at, e - at); at = e + 1; return true; };
    if (!Next() || L.substr(0, 4) != "--- " || L.size() == 4) { Err = "a patch without its '--- ' line"; return false; }
    OldName = L.substr(4);
    if (!Next() || L.substr(0, 4) != "+++ " || L.size() == 4) { Err = "a patch without its '+++ ' line"; return false; }
    NewName = L.substr(4);
    uint64_t PosA = 0, Hunks = 0;
    int64_t Shift = 0;                                        // new lines minus old lines before this hunk
    bool Ended = false;                                       // a side ended without its newline: nothing may follow
    while (at < P.size()) {
        if (Ended) { Err = "a hunk past its file's end"; return false; }
        if (!Next()) { Err = "a patch's last line is unfinished"; return false; }
        uint64_t a, an, b, bn;
        if (!HunkHeader(L, a, an, b, bn)) { Err = "a malformed hunk header"; return false; }
        const uint64_t Sa = an ? a - 1 : a, Sb = bn ? b - 1 : b;
        if (Sa < PosA || (Hunks && Sa == PosA)) { Err = "a hunk out of order"; return false; }
        if ((int64_t)Sb - (int64_t)Sa != Shift) { Err = "a hunk's new start is not where its old start puts it"; return false; }
        if (!Hunk(Sa)) return false;
        uint64_t Ca = 0, Cb = 0;
        bool Changed = false, EndA = false, EndB = false;
        while (Ca < an || Cb < bn) {
            if (!Next() || L.empty()) { Err = "a hunk shorter than its counts"; return false; }
            const char T = L[0];
            const bool OnA = T == ' ' || T == '-', OnB = T == ' ' || T == '+';
            if (!OnA && !OnB) { Err = "a malformed patch line"; return false; }
            if ((OnA && (Ca == an || EndA)) || (OnB && (Cb == bn || EndB))) { Err = "a hunk longer than its counts"; return false; }
            const bool NoNl = P.substr(at, kNoNl.size()) == kNoNl;
            const std::string_view Body(L.data() + 1, L.size() - 1 + (NoNl ? 0 : 1));
            if (NoNl) { at += kNoNl.size(); EndA |= OnA; EndB |= OnB; }
            Ca += OnA; Cb += OnB; Changed |= T != ' ';
            if (!Line(T, Body)) return false;
        }
        if (!Changed) { Err = "a hunk that changes nothing"; return false; }
        if (EndA || EndB) Ended = true;
        PosA = Sa + an; Shift += (int64_t)bn - (int64_t)an; ++Hunks;
    }
    if (!Hunks) { Err = "a patch of no hunk (the file is its base's: 'same')"; return false; }
    return true;
}
bool Apply(const std::string &A, std::string_view P, std::string &Out, std::string &Err) {
    Out.clear();
    size_t Cur = 0; uint64_t Line = 0;
    bool OutEnded = false;
    const auto LineEnd = [&](size_t c) { const size_t e = A.find('\n', c); return e == std::string::npos ? A.size() : e + 1; };
    std::string_view On, Nn;
    const bool Ok = WalkPatch(P, On, Nn,
        [&](uint64_t To) {
            while (Line < To && Cur < A.size()) { const size_t e = LineEnd(Cur); Out.append(A, Cur, e - Cur); Cur = e; ++Line; }
            if (Line != To) { Err = "a hunk past its base's end"; return false; }
            if (Out.size() > kMaxPatch) { Err = "a patched file over 16 MiB"; return false; }
            return true; },
        [&](char T, std::string_view Body) {
            if (T != '+') {
                if (Cur >= A.size()) { Err = "a patch that does not fit its base"; return false; }
                const size_t e = LineEnd(Cur);
                if (std::string_view(A).substr(Cur, e - Cur) != Body) { Err = "a patch that does not fit its base"; return false; }
                Cur = e; ++Line;
            }
            if (T != '-') {
                Out.append(Body);
                OutEnded = Body.empty() || Body.back() != '\n';
                if (Out.size() > kMaxPatch) { Err = "a patched file over 16 MiB"; return false; }
            }
            return true; }, Err);
    if (!Ok) return false;
    if (OutEnded && Cur < A.size()) { Err = "a patch ends its file before its base does"; return false; }
    if (A.size() - Cur > kMaxPatch - std::min<uint64_t>(Out.size(), kMaxPatch)) { Err = "a patched file over 16 MiB"; return false; }
    Out.append(A, Cur, std::string::npos);
    return true;
}
// The "# text <encoding>" line of a UTF-16 file's patch: its encoding ("" none), and where its diff starts.
bool TextLine(const std::string &Patch, std::string &Enc, size_t &From, std::string &Err) {
    Enc.clear(); From = 0;
    if (Patch.rfind("# text ", 0) != 0) return true;
    const size_t E = Patch.find('\n');
    if (E == std::string::npos) { Err = "a patch of only its encoding line"; return false; }
    Enc = Patch.substr(7, E - 7);
    if (Enc != "utf-16-le" && Enc != "utf-16-be") { Err = "a patch of an unknown text encoding"; return false; }
    From = E + 1;
    return true;
}

struct Zeros : ByteSource {
    uint64_t n; explicit Zeros(uint64_t N) : n(N) {}
    ssize_t pread(void *buf, size_t len, uint64_t off) override { if (off >= n) return 0; const size_t k = (size_t)std::min<uint64_t>(len, n - off); std::memset(buf, 0, k); return (ssize_t)k; }
    uint64_t size() const override { return n; }
};
struct Joined : ByteSource {
    std::vector<std::shared_ptr<ByteSource>> parts; std::vector<uint64_t> start; uint64_t total = 0;
    void add(std::shared_ptr<ByteSource> P) { start.push_back(total); total += P->size(); parts.push_back(std::move(P)); }
    ssize_t pread(void *buf, size_t n, uint64_t off) override {
        size_t done = 0;
        while (done < n && off + done < total) {
            const uint64_t pos = off + done;
            const size_t k = (size_t)(std::upper_bound(start.begin(), start.end(), pos) - start.begin()) - 1;
            const uint64_t local = pos - start[k];
            const size_t want = (size_t)std::min<uint64_t>(n - done, parts[k]->size() - local);
            const ssize_t r = parts[k]->pread((uint8_t *)buf + done, want, local);
            if (r <= 0) return done ? (ssize_t)done : r;
            done += (size_t)r;
        }
        return (ssize_t)done;
    }
    void prefetch(uint64_t off, uint64_t n) override {
        for (size_t k = 0; k < parts.size(); ++k) {
            const uint64_t s = start[k], e = s + parts[k]->size();
            if (e <= off || s >= off + n) continue;
            const uint64_t a = std::max(off, s), b = std::min(off + n, e);
            parts[k]->prefetch(a - s, b - a);
        }
    }
    bool scattered() const override { return true; }
    uint64_t size() const override { return total; }
};
// A patched file, applied when first read, its result kept in a byte-bounded cache. Its patch and its base are read
// first, with no lock held (its base may be a patched file of an older tree: a chain of versions); then one application
// at a time in the process (a patch, its base and its result are 16 MiB each at most). A failure is remembered.
struct Patched : ByteSource {
    std::shared_ptr<ByteSource> base; std::function<bool(std::string &)> patch; uint64_t n = 0; std::string what;
    const uint64_t id = NewId();
    std::atomic<bool> failed{ false };
    std::shared_ptr<const std::vector<uint8_t>> bytes() {
        if (failed.load(std::memory_order_acquire)) return nullptr;
        if (auto B = PatchCache().get(id)) return B;
        std::string Pt, Old, New, Err;
        if (!patch(Pt)) Err = "its patch does not read";
        else if (base->size() > kMaxPatch) Err = "its base file is over 16 MiB";
        else {
            Old.resize((size_t)base->size());
            if (!base->preadAll(Old.data(), Old.size(), 0)) Err = "its base file does not read";
            else {
                static std::mutex One;
                std::lock_guard<std::mutex> g(One);
                if (auto B = PatchCache().get(id)) return B;
                if (ApplyPatch(Old, Pt, New, Err) && New.size() != n) Err = "its patch makes another size";
            }
        }
        if (!Err.empty()) {
            if (!failed.exchange(true)) std::fprintf(stderr, "vidyagodfs: the tree file %s does not read: %s\n", what.c_str(), Err.c_str());
            return nullptr;
        }
        auto V = std::make_shared<const std::vector<uint8_t>>(New.begin(), New.end());
        PatchCache().put(id, V);
        return V;
    }
    ssize_t pread(void *buf, size_t len, uint64_t off) override {
        if (off >= n || !len) return 0;
        const auto B = bytes();
        if (!B) return -EIO;
        const size_t k = (size_t)std::min<uint64_t>(len, n - off);
        std::memcpy(buf, B->data() + off, k);
        return (ssize_t)k;
    }
    uint64_t size() const override { return n; }
};

} // namespace

std::shared_ptr<ByteSource> Lazily(uint64_t Size, std::function<std::shared_ptr<ByteSource>(std::string &)> Open, std::string What) {
    auto S = std::make_shared<OnFirstRead>();
    S->n = Size; S->open = std::move(Open); S->what = std::move(What);
    return S;
}

bool TextEncoding(const uint8_t *P, size_t N, std::string &Enc) {
    if (N >= 2 && P[0] == 0xFF && P[1] == 0xFE) { bool Ok; Utf16To8(std::string((const char *)P, N), true, Ok); Enc = "utf-16-le"; return Ok; }
    if (N >= 2 && P[0] == 0xFE && P[1] == 0xFF) { bool Ok; Utf16To8(std::string((const char *)P, N), false, Ok); Enc = "utf-16-be"; return Ok; }
    Enc.clear();
    return Plain(P, N);
}

bool MakePatch(const std::string &Old, const std::string &New, const std::string &On, const std::string &Nn, std::string &Patch) {
    if (Old.size() > kMaxPatch || New.size() > kMaxPatch) return false;
    std::string Eo, En;
    if (!TextEncoding((const uint8_t *)Old.data(), Old.size(), Eo) || !TextEncoding((const uint8_t *)New.data(), New.size(), En) || Eo != En) return false;
    bool Ok = false;
    if (Eo.empty()) Patch = Diff(Old, New, On, Nn, Ok);
    else {
        bool A, B;
        const std::string O8 = Utf16To8(Old, Eo == "utf-16-le", A), N8 = Utf16To8(New, Eo == "utf-16-le", B);
        if (!A || !B) return false;
        Patch = "# text " + Eo + "\n" + Diff(O8, N8, On, Nn, Ok);
    }
    if (!Ok || Patch.size() >= New.size() + 64) return false;          // a diff no smaller than the file (give or take its header): not worth it
    std::string Back, Err;
    return ApplyPatch(Old, Patch, Back, Err) && Back == New;         // exact, or not a patch
}

bool ApplyPatch(const std::string &Old, const std::string &Patch, std::string &New, std::string &Err) {
    if (Patch.size() > kMaxPatch || Old.size() > kMaxPatch) { Err = "a patch or its base over 16 MiB"; return false; }
    std::string Enc; size_t From = 0;
    if (!TextLine(Patch, Enc, From, Err)) return false;
    if (Enc.empty()) return Apply(Old, Patch, New, Err);
    bool A;
    const std::string O8 = Utf16To8(Old, Enc == "utf-16-le", A);
    if (!A) { Err = "a patch's base is not " + Enc; return false; }
    std::string N8;
    if (!Apply(O8, std::string_view(Patch).substr(From), N8, Err)) return false;
    New.clear(); uint64_t Bytes = 0;
    if (!Utf8To16(N8, Enc == "utf-16-le", &New, Bytes)) { Err = "a patch's result is not text"; return false; }
    return true;
}

bool PatchInfo(const std::string &Patch, std::string &OldName, std::string &NewName, uint64_t &Removed, uint64_t &Added, std::string &Err) {
    Removed = Added = 0;
    if (Patch.size() > kMaxPatch) { Err = "a patch over 16 MiB"; return false; }
    std::string Enc; size_t From = 0;
    if (!TextLine(Patch, Enc, From, Err)) return false;
    std::string_view On, Nn;
    const bool Ok = WalkPatch(std::string_view(Patch).substr(From), On, Nn, [](uint64_t) { return true; },
        [&](char T, std::string_view Body) {
            uint64_t N = Body.size();
            if (!Enc.empty() && !Utf8To16(Body, Enc == "utf-16-le", nullptr, N)) { Err = "a patch line that is not UTF-8"; return false; }
            if (T == '-') Removed += N;
            if (T == '+') Added += N;
            return true; }, Err);
    if (!Ok) return false;
    OldName.assign(On); NewName.assign(Nn);
    return true;
}

bool SeekableZstdTo(const uint8_t *P, size_t N, const std::function<bool(const void *, size_t)> &Sink, std::string &Err) {
    std::vector<std::pair<uint32_t, uint32_t>> Seek;
    std::vector<uint8_t> Buf(ZSTD_compressBound(kZstdFrame));
    ZSTD_CCtx *Cx = ZSTD_createCCtx();
    if (!Cx || ZSTD_isError(ZSTD_CCtx_setParameter(Cx, ZSTD_c_compressionLevel, kZstdLevel)) || ZSTD_isError(ZSTD_CCtx_setParameter(Cx, ZSTD_c_checksumFlag, 1)))
    { if (Cx) ZSTD_freeCCtx(Cx); Err = "no zstd context"; return false; }   // each frame checksummed: a flipped byte reads as an error
    size_t at = 0;
    do {
        const size_t n = std::min<size_t>(kZstdFrame, N - at);
        const size_t c = ZSTD_compress2(Cx, Buf.data(), Buf.size(), P + at, n);
        if (ZSTD_isError(c)) { ZSTD_freeCCtx(Cx); Err = "a frame did not compress"; return false; }
        if (!Sink(Buf.data(), c)) { ZSTD_freeCCtx(Cx); Err = "a frame was not written"; return false; }
        Seek.push_back({ (uint32_t)c, (uint32_t)n });
        at += n;
    } while (at < N);
    ZSTD_freeCCtx(Cx);
    std::string O;
    const auto u32 = [&](uint32_t v) { for (int i = 0; i < 4; ++i) O += (char)(v >> (8 * i)); };
    u32(kSkippable); u32((uint32_t)(Seek.size() * 8 + 9));
    for (const auto &[c, d] : Seek) { u32(c); u32(d); }
    u32((uint32_t)Seek.size()); O += '\0'; u32(kSeekMagic);
    if (!Sink(O.data(), O.size())) { Err = "the seek table was not written"; return false; }
    return true;
}
std::string SeekableZstd(const uint8_t *P, size_t N, std::string &Err) {
    std::string O;
    if (!SeekableZstdTo(P, N, [&](const void *B, size_t n) { O.append((const char *)B, n); return true; }, Err)) return std::string();
    return O;
}

std::shared_ptr<ByteSource> SeekableZstdSource(std::shared_ptr<ByteSource> Z, std::string &Err) {
    const uint64_t N = Z->size();
    uint8_t F[9];
    if (N < 17 || !Z->preadAll(F, 9, N - 9)) { Err = "not seekable zstd"; return nullptr; }
    const auto Rd = [](const uint8_t *p) { return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24); };
    const uint32_t Frames = Rd(F), Magic = Rd(F + 5);
    if (Magic != kSeekMagic || F[4] != 0 || Frames == 0 || Frames > (1u << 24) || (uint64_t)Frames * 8 + 17 > N) { Err = "not seekable zstd (its seek table)"; return nullptr; }
    const uint64_t TableAt = N - 9 - (uint64_t)Frames * 8;
    uint8_t H[8];
    if (!Z->preadAll(H, 8, TableAt - 8) || Rd(H) != kSkippable || Rd(H + 4) != Frames * 8 + 9) { Err = "not seekable zstd (its skippable frame)"; return nullptr; }
    std::vector<uint8_t> T((size_t)Frames * 8);
    if (!Z->preadAll(T.data(), T.size(), TableAt)) { Err = "a seek table that does not read"; return nullptr; }
    auto S = std::make_shared<SeekSource>();
    const uint64_t Bound = ZSTD_compressBound(kZstdFrame);
    uint64_t c = 0, d = 0;
    for (uint32_t k = 0; k < Frames; ++k) {
        S->cOff.push_back(c); S->dOff.push_back(d);
        const uint32_t cl = Rd(&T[k * 8]), dl = Rd(&T[k * 8 + 4]);
        if (dl == 0 || dl > kZstdFrame || cl == 0 || cl > Bound) { Err = "a seekable frame over its size"; return nullptr; }
        c += cl; d += dl;
    }
    if (c != TableAt - 8) { Err = "a seek table that does not cover its frames"; return nullptr; }
    S->cOff.push_back(c); S->dOff.push_back(d);
    S->z = std::move(Z);
    return S;
}

bool TableText(const Table &T, std::string &O, std::string &Err) {
    if (!Check(T, Err)) return false;
    O = "VGTZ 1\n";
    for (size_t i = 0; i < T.bases.size(); ++i) O += "base\t" + Dec(i) + "\t" + T.bases[i] + "\n";
    for (const Entry &E : T.entries) O += LineText(E);
    return true;
}

bool ReadTable(const std::string &Text, Table &T, std::string &Err) {
    T = Table();
    if (Text.size() > kMaxTable) { Err = "a tree table over 64 MiB"; return false; }
    if (Text.compare(0, 7, "VGTZ 1\n") != 0) { Err = "not a tree table (VGTZ 1)"; return false; }
    const std::string_view All(Text);
    bool BasesDone = false;
    size_t NPieces = 0;
    for (size_t B = 7; B < All.size();) {
        const size_t E = All.find('\n', B);
        if (E == std::string_view::npos) { Err = "a tree table's last line is unfinished"; return false; }
        const std::string_view Line = All.substr(B, E - B + 1), Body = All.substr(B, E - B);
        B = E + 1;
        const auto bad = [&](const char *W) { Err = std::string("a tree table's line is malformed (") + W + ")"; return false; };
        std::vector<std::string_view> F;
        { size_t At = 0; std::string_view X; while (F.size() < 8 && Field(Body, At, "\t", X)) F.push_back(X); if (At <= Body.size()) return bad("too many fields"); }
        if (F[0] == "base") {
            uint64_t i = 0;
            if (BasesDone || F.size() != 3 || !Num(F[1], i) || i != T.bases.size()) return bad("a base");
            if (T.bases.size() >= kMaxBases) { Err = "a tree of too many bases"; return false; }
            T.bases.emplace_back(F[2]);
            if (Line != "base\t" + Dec(i) + "\t" + T.bases.back() + "\n") return bad("a base");
            continue;
        }
        BasesDone = true;
        if (T.entries.size() >= kMaxEntries) { Err = "a tree of too many entries"; return false; }
        Entry X;
        if (F[0] == "dir" && F.size() == 2) { X.kind = Entry::Dir; X.path = F[1]; }
        else if (F[0] == "link" && F.size() == 3) { X.kind = Entry::Link; X.path = F[1]; X.link = F[2]; }
        else {
            static const std::pair<std::string_view, std::pair<Entry::Op, size_t>> Ops[] = {
                {"same", {Entry::Same, 6}}, {"range", {Entry::Range, 7}}, {"patch", {Entry::Patch, 6}}, {"pieces", {Entry::Pieces, 7}}, {"new", {Entry::New, 4}} };
            const auto It = std::find_if(std::begin(Ops), std::end(Ops), [&](const auto &O) { return O.first == F[0]; });
            if (It == std::end(Ops) || F.size() != It->second.second) return bad("a kind");
            X.op = It->second.first; X.path = F[1];
            if (!Num(F[2], X.size)) return bad("a size");
            if (!ModeOf(F[3], X.mode)) return bad("a mode");
            if (X.op != Entry::New) {
                uint64_t i = 0;
                if (F[4].substr(0, 5) != "from " || !Num(F[4].substr(5), i) || i > 0xFFFFFFFFu) return bad("a base");
                X.base = (uint32_t)i; X.basePath = F[5];
            }
            if (X.op == Entry::Range) {
                const size_t D = F[6].find(".."); uint64_t a = 0, b = 0;
                if (D == std::string_view::npos || !Num(F[6].substr(0, D), a) || !Num(F[6].substr(D + 2), b) || b < a) return bad("a range");
                X.off = a; X.len = b - a;
            }
            if (X.op == Entry::Pieces) {
                size_t At = 0; std::string_view W;
                while (Field(F[6], At, ", ", W)) {
                    if (++NPieces > kMaxPieces) { Err = "a tree of too many pieces"; return false; }
                    Piece P; uint64_t a = 0, b = 0;
                    if (W.substr(0, 5) == "keep ") { const size_t D = W.find("..", 5); if (D == std::string_view::npos || !Num(W.substr(5, D - 5), a) || !Num(W.substr(D + 2), b) || b <= a) return bad("a piece"); P.kind = Piece::Keep; P.off = a; P.len = b - a; }
                    else if (W.substr(0, 4) == "new " && Num(W.substr(4), a) && a) { P.kind = Piece::New; P.len = a; }
                    else if (W.substr(0, 5) == "zero " && Num(W.substr(5), a) && a) { P.kind = Piece::Zero; P.len = a; }
                    else return bad("a piece");
                    X.pieces.push_back(P);
                }
            }
        }
        if (Line != LineText(X)) { Err = "a tree table not in its canonical form: '" + coding::PrintablePath(X.path) + "'"; return false; }   // one form: what TableText writes
        T.entries.push_back(std::move(X));
    }
    return Check(T, Err);
}

bool WriteTree(const std::string &OutPath, const Table &T, const std::map<std::string, AddBytes> &Adds,
               const std::map<std::string, std::string> &Patches, std::string &Err) {
    std::string Text;
    if (!TableText(T, Text, Err)) return false;
    for (const Entry &E : T.entries) {                       // every file's members there, every member a file's
        if (E.kind != Entry::File) continue;
        uint64_t NewBytes = E.op == Entry::New ? E.size : 0;
        if (E.op == Entry::Pieces) for (const Piece &P : E.pieces) if (P.kind == Piece::New) NewBytes += P.len;
        const auto A = Adds.find(E.path);
        if ((NewBytes > 0) != (A != Adds.end()) || (A != Adds.end() && A->second.n != NewBytes)) { Err = "a tree file's add is not its new bytes: " + E.path; return false; }
        if ((E.op == Entry::Patch) != (Patches.count(E.path) > 0)) { Err = "a tree file's patch is missing or not its own: " + E.path; return false; }
        if (E.op == Entry::Patch) {
            std::string On, Nn, W; uint64_t Rm, Ad;
            if (!PatchInfo(Patches.at(E.path), On, Nn, Rm, Ad, W) || On != "a/" + E.basePath || Nn != "b/" + E.path) { Err = "a tree file's patch is not its own: " + E.path + (W.empty() ? "" : " (" + W + ")"); return false; }
        }
    }
    for (const auto &[P, A] : Adds) { (void)A; if (std::none_of(T.entries.begin(), T.entries.end(), [&](const Entry &E) { return E.path == P && E.kind == Entry::File; })) { Err = "an add of no file: " + P; return false; } }
    uint64_t PatchBytes = 0;
    for (const auto &[P, Pt] : Patches) PatchBytes += Pt.size();
    if (PatchBytes > kMaxPatches) { Err = "a tree's patches over 256 MiB together"; return false; }
    const std::string Part = OutPath + ".part";
    ZipW Z; Z.F = std::fopen(Part.c_str(), "wb");
    if (!Z.F) { Err = "cannot write " + OutPath; return false; }
    const auto Fail = [&](const std::string &Why) { std::fclose(Z.F); std::remove(Part.c_str()); Err = Why; return false; };
    Z.member("TREE.txt", (const uint8_t *)Text.data(), Text.size());
    for (const auto &[P, A] : Adds) {                        // (path order: the map's)
        if (A.text) { Z.member("add/" + P + ".add", A.p, A.n); continue; }
        const uint64_t Frames = A.n / kZstdFrame + 1;
        Z.begin("add/" + P + ".add.zst", Frames * ZSTD_compressBound(kZstdFrame) + Frames * 8 + 17);
        std::string W;
        if (!SeekableZstdTo(A.p, A.n, [&](const void *B, size_t n) { Z.write(B, n); return Z.ok; }, W)) return Fail("cannot write " + OutPath + ": " + W);
        Z.end();
    }
    for (const auto &[P, Pt] : Patches) Z.member("patch/" + P + ".patch", (const uint8_t *)Pt.data(), Pt.size());
    Z.finish();
    if (!Z.ok) return Fail("cannot write " + OutPath);
    if (std::fclose(Z.F) != 0 || std::rename(Part.c_str(), OutPath.c_str()) != 0) { std::remove(Part.c_str()); Err = "cannot write " + OutPath; return false; }
    return true;
}

bool OpenTree(std::shared_ptr<ByteSource> File, Opened &Out, std::string &Err) {
    struct Mem { uint64_t lh, size; };
    auto Members = std::make_shared<std::map<std::string, Mem>>();
    bool Bad = false;
    const bool Walked = File && zipscan::WalkCentralDirFull(*File, [&](const zipscan::CdEntry &E) {
        if (E.method != 0 || E.compSize != E.uncompSize || (E.flags & 1) || E.uncompSize > File->size() || E.lhOffset >= File->size()) { Bad = true; return false; }
        if (!Members->emplace(E.rawName, Mem{ E.lhOffset, E.uncompSize }).second || Members->size() > 2 * kMaxEntries + 1) { Bad = true; return false; }
        return true; });
    if (!Walked || Bad) { Err = "not a .vgtz (a STORE zip of its own)"; return false; }
    //a member's bytes, its local header read only now
    const auto Data = [File](const Mem &M, std::string &Why) -> std::shared_ptr<ByteSource> {
        const uint64_t D = zipscan::LocalDataOffset(*File, M.lh);
        if (D == UINT64_MAX || D > File->size() || M.size > File->size() - D) { Why = "a member outside its .vgtz"; return nullptr; }
        return std::make_shared<SliceByteSource>(File, D, M.size);
    };
    const auto It = Members->find("TREE.txt");
    if (It == Members->end()) { Err = "a .vgtz without its TREE.txt"; return false; }
    if (It->second.size > kMaxTable) { Err = "a tree table over 64 MiB"; return false; }
    auto TS = Data(It->second, Err);
    if (!TS) return false;
    std::string Text((size_t)It->second.size, '\0');
    if (!TS->preadAll(Text.data(), Text.size(), 0)) { Err = "a .vgtz whose table does not read"; return false; }
    if (!ReadTable(Text, Out.table, Err)) return false;
    // Exactly the members its table needs: each add once, in one of its two forms; each patch; nothing else.
    size_t Need = 1;
    uint64_t PatchBytes = 0;
    for (const Entry &E : Out.table.entries) {
        if (E.kind != Entry::File) continue;
        const bool Adds = (E.op == Entry::New && E.size > 0)
                       || (E.op == Entry::Pieces && std::any_of(E.pieces.begin(), E.pieces.end(), [](const Piece &P) { return P.kind == Piece::New; }));
        const size_t Forms = Members->count("add/" + E.path + ".add") + Members->count("add/" + E.path + ".add.zst");
        if (Forms != (Adds ? 1u : 0u)) { Err = "a .vgtz whose adds are not its table's: '" + coding::PrintablePath(E.path) + "'"; return false; }
        if (E.op == Entry::Patch) {
            const auto P = Members->find("patch/" + E.path + ".patch");
            if (P == Members->end()) { Err = "a .vgtz whose patches are not its table's: '" + coding::PrintablePath(E.path) + "'"; return false; }
            if ((PatchBytes += P->second.size) > kMaxPatches) { Err = "a tree's patches over 256 MiB together"; return false; }
        }
        Need += Forms + (E.op == Entry::Patch);
    }
    if (Members->size() != Need) { Err = "a .vgtz holding members its table does not name"; return false; }
    Out.add = [File, Members, Data](const std::string &P, uint64_t Size) -> std::shared_ptr<ByteSource> {
        if (const auto A = Members->find("add/" + P + ".add"); A != Members->end()) {
            if (A->second.size != Size) return nullptr;
            const Mem M = A->second;
            return Lazily(Size, [Data, M](std::string &Why) { return Data(M, Why); }, "the tree add " + coding::PrintablePath(P));
        }
        if (const auto Z = Members->find("add/" + P + ".add.zst"); Z != Members->end()) {
            const Mem M = Z->second;
            return Lazily(Size, [Data, M](std::string &Why) -> std::shared_ptr<ByteSource> {
                auto S = Data(M, Why);
                return S ? SeekableZstdSource(S, Why) : nullptr; }, "the tree add " + coding::PrintablePath(P));
        }
        return nullptr;
    };
    Out.patch = [Members, Data](const std::string &P, std::string &Pt) {
        const auto M = Members->find("patch/" + P + ".patch");
        if (M == Members->end() || M->second.size > kMaxPatch) return false;
        std::string Why;
        const auto S = Data(M->second, Why);
        if (!S) return false;
        Pt.assign((size_t)M->second.size, '\0');
        return S->preadAll(Pt.data(), Pt.size(), 0);
    };
    return true;
}

std::shared_ptr<ByteSource> EntryBytes(const Entry &E, const BaseFileFn &BaseFile, const Opened &Tree, std::string &Err) {
    if (E.kind != Entry::File) { Err = "not a file"; return nullptr; }
    if (E.op == Entry::New) {
        if (E.size == 0) return std::make_shared<Zeros>(0);
        auto A = Tree.add ? Tree.add(E.path, E.size) : nullptr;
        if (!A) { Err = "its add is missing or not its size"; return nullptr; }
        return A;
    }
    auto F = BaseFile(E.base, E.basePath);
    if (!F) { Err = "its base " + std::to_string(E.base) + " has no file '" + E.basePath + "'"; return nullptr; }
    switch (E.op) {
        case Entry::Same:
            if (F->size() != E.size) { Err = "its base file '" + E.basePath + "' is not its size"; return nullptr; }
            return F;
        case Entry::Range:
            if (E.off > F->size() || E.len > F->size() - E.off) { Err = "its range passes its base file '" + E.basePath + "'"; return nullptr; }
            if (E.off == 0 && E.len == F->size()) { Err = "its range is its whole base file (it is 'same')"; return nullptr; }
            return std::make_shared<SliceByteSource>(F, E.off, E.len);
        case Entry::Patch: {
            //checked whole now (its grammar, its files, the size it makes); applied when first read
            std::string Pt, On, Nn;
            uint64_t Rm = 0, Ad = 0;
            if (!Tree.patch || !Tree.patch(E.path, Pt)) { Err = "its patch is missing"; return nullptr; }
            if (F->size() > kMaxPatch) { Err = "its base file is over 16 MiB"; return nullptr; }
            if (!PatchInfo(Pt, On, Nn, Rm, Ad, Err)) return nullptr;
            if (On != "a/" + E.basePath || Nn != "b/" + E.path) { Err = "its patch names other files ('" + On + "', '" + Nn + "')"; return nullptr; }
            if (Rm > F->size() || F->size() - Rm + Ad != E.size) { Err = "its patch makes another size"; return nullptr; }
            auto S = std::make_shared<Patched>();
            S->base = F; S->n = E.size; S->what = coding::PrintablePath(E.path);
            S->patch = [P = Tree.patch, Path = E.path](std::string &Out) { return P(Path, Out); };
            return S;
        }
        case Entry::Pieces: {
            uint64_t NewBytes = 0;
            for (const Piece &P : E.pieces) if (P.kind == Piece::New) NewBytes += P.len;
            std::shared_ptr<ByteSource> A;
            if (NewBytes) { A = Tree.add ? Tree.add(E.path, NewBytes) : nullptr; if (!A) { Err = "its add is missing or not its new bytes"; return nullptr; } }
            auto J = std::make_shared<Joined>();
            uint64_t AddAt = 0;
            for (const Piece &P : E.pieces) {
                if (P.kind == Piece::Keep) {
                    if (P.off > F->size() || P.len > F->size() - P.off) { Err = "a piece passes its base file '" + E.basePath + "'"; return nullptr; }
                    J->add(std::make_shared<SliceByteSource>(F, P.off, P.len));
                } else if (P.kind == Piece::Zero) J->add(std::make_shared<Zeros>(P.len));
                else { J->add(std::make_shared<SliceByteSource>(A, AddAt, P.len)); AddAt += P.len; }
            }
            return J;
        }
        default: Err = "an unknown op"; return nullptr;
    }
}

} // namespace vgtree
