// VIEW mode (ISA 10): a description listing the files in a content. viewmode.h says what it is; MetaPackageFormat
// chapter 22.17 is the contract. The runner is its own small machine: 64-bit values (a disc image passes 4 GiB), no
// coder. It shares the description format and its validation with the codecs (coding.cpp Validate).
#include "viewmode.h"

#include <algorithm>
#include <cstring>
#include <functional>
#include <map>
#include <set>

#ifdef _WIN32
#include <windows.h>
#else
#include <iconv.h>
#endif

namespace coding {
namespace {

// The content read in blocks, a few kept: a file table's reads cluster (a directory's records, then the next one's).
struct Reader {
    explicit Reader(ByteSource &S) : src(S), size(S.size()) {}
    ByteSource &src;
    uint64_t size;
    static constexpr uint64_t kBlock = 64ull * 1024;
    static constexpr size_t kKept = 16;
    struct Blk { uint64_t at = UINT64_MAX; std::vector<uint8_t> b; uint64_t used = 0; };
    Blk blk[kKept];
    uint64_t clock = 0;
    bool failed = false;
    const Blk *get(uint64_t At) {
        const uint64_t B = At / kBlock * kBlock;
        Blk *Free = &blk[0];
        for (Blk &k : blk) {
            if (k.at == B) { k.used = ++clock; return &k; }
            if (k.used < Free->used) Free = &k;
        }
        const uint64_t N = std::min<uint64_t>(kBlock, size - B);
        Free->b.resize((size_t)N);
        size_t Got = 0;
        while (Got < N) {
            const ssize_t R = src.pread(Free->b.data() + Got, (size_t)(N - Got), B + Got);
            if (R <= 0) { failed = true; Free->at = UINT64_MAX; return nullptr; }
            Got += (size_t)R;
        }
        Free->at = B; Free->used = ++clock;
        return Free;
    }
    // byte At (0 outside the content, as EX_BYTE)
    uint8_t byte(uint64_t At) {
        if (At >= size) return 0;
        const Blk *K = get(At);
        return K ? K->b[(size_t)(At - K->at)] : 0;
    }
    uint64_t le(uint64_t At, int N) { uint64_t v = 0; for (int i = N - 1; i >= 0; --i) v = (v << 8) | (At + (uint64_t)i < At ? 0 : byte(At + (uint64_t)i)); return v; }
    uint64_t be(uint64_t At, int N) { uint64_t v = 0; for (int i = 0; i < N; ++i) v = (v << 8) | (At + (uint64_t)i < At ? 0 : byte(At + (uint64_t)i)); return v; }
    bool bytes(uint64_t At, uint64_t N, std::string &Out) {
        while (N) {
            const Blk *K = get(At);
            if (!K) return false;
            const uint64_t In = At - K->at, Take = std::min<uint64_t>(N, K->b.size() - In);
            Out.append(reinterpret_cast<const char *>(K->b.data() + In), (size_t)Take);
            At += Take; N -= Take;
        }
        return true;
    }
};

bool Utf8Append(uint32_t C, std::string &O) {
    if (C == 0 || (C >= 0xD800 && C < 0xE000) || C > 0x10FFFF) return false;
    if (C < 0x80) O += (char)C;
    else if (C < 0x800) { O += (char)(0xC0 | (C >> 6)); O += (char)(0x80 | (C & 0x3F)); }
    else if (C < 0x10000) { O += (char)(0xE0 | (C >> 12)); O += (char)(0x80 | ((C >> 6) & 0x3F)); O += (char)(0x80 | (C & 0x3F)); }
    else { O += (char)(0xF0 | (C >> 18)); O += (char)(0x80 | ((C >> 12) & 0x3F)); O += (char)(0x80 | ((C >> 6) & 0x3F)); O += (char)(0x80 | (C & 0x3F)); }
    return true;
}

bool ValidUtf8(const std::string &S) {
    for (size_t i = 0; i < S.size();) {
        const uint8_t c = (uint8_t)S[i];
        size_t n = c < 0x80 ? 1 : (c >> 5) == 6 ? 2 : (c >> 4) == 14 ? 3 : (c >> 3) == 30 ? 4 : 0;
        if (!n || i + n > S.size() || c == 0) return false;
        uint32_t C = n == 1 ? c : n == 2 ? (c & 0x1F) : n == 3 ? (c & 0x0F) : (c & 0x07);
        for (size_t k = 1; k < n; ++k) { const uint8_t d = (uint8_t)S[i + k]; if ((d >> 6) != 2) return false; C = (C << 6) | (d & 0x3F); }
        if ((n == 2 && C < 0x80) || (n == 3 && C < 0x800) || (n == 4 && C < 0x10000) || C > 0x10FFFF || (C >= 0xD800 && C < 0xE000)) return false;
        i += n;
    }
    return true;
}

bool ShiftJis(const std::string &Raw, std::string &O) {
#ifdef _WIN32
    if (Raw.empty()) { O.clear(); return true; }
    const int W = MultiByteToWideChar(932, MB_ERR_INVALID_CHARS, Raw.data(), (int)Raw.size(), nullptr, 0);
    if (W <= 0) return false;
    std::wstring Ws((size_t)W, L'\0');
    MultiByteToWideChar(932, MB_ERR_INVALID_CHARS, Raw.data(), (int)Raw.size(), Ws.data(), W);
    const int U = WideCharToMultiByte(CP_UTF8, 0, Ws.data(), W, nullptr, 0, nullptr, nullptr);
    if (U <= 0) return false;
    O.assign((size_t)U, '\0');
    WideCharToMultiByte(CP_UTF8, 0, Ws.data(), W, O.data(), U, nullptr, nullptr);
    return true;
#else
    iconv_t Cd = iconv_open("UTF-8", "CP932");                        // Windows-31J: Shift JIS as discs carry it
    if (Cd == (iconv_t)-1) Cd = iconv_open("UTF-8", "SHIFT_JIS");
    if (Cd == (iconv_t)-1) return false;
    std::string In = Raw;
    O.assign(Raw.size() * 4 + 4, '\0');
    char *Ip = In.data(), *Op = O.data();
    size_t Il = In.size(), Ol = O.size();
    const size_t R = iconv(Cd, &Ip, &Il, &Op, &Ol);
    iconv_close(Cd);
    if (R == (size_t)-1 || Il) return false;
    O.resize(O.size() - Ol);
    return true;
#endif
}

// A path as a VIEW may list it: parts between '/', none empty, ".", ".." or holding a NUL, '\', tab or newline (a
// listing's own separators).
bool GoodPath(const std::string &P) {
    if (P.empty()) return false;
    size_t B = 0;
    for (;;) {
        const size_t E = P.find('/', B);
        const std::string Part = P.substr(B, E == std::string::npos ? std::string::npos : E - B);
        if (Part.empty() || Part == "." || Part == "..") return false;
        if (E == std::string::npos) break;
        B = E + 1;
    }
    for (const char c : P) if (c == '\0' || c == '\\' || c == '\t' || c == '\n' || c == '\r') return false;
    return true;
}

std::string Dec(uint64_t V) { return std::to_string(V); }

} // namespace

bool DecodeViewName(uint8_t Names, const std::string &Raw, std::string &O, std::string &Err) {
    O.clear();
    bool ok = true;
    switch (Names) {
        case kNamesUtf8: ok = ValidUtf8(Raw); if (ok) O = Raw; break;
        case kNamesAscii: for (const char c : Raw) { if ((uint8_t)c >= 0x80 || c == 0) { ok = false; break; } O += c; } break;
        case kNamesLatin1: for (const char c : Raw) if (!Utf8Append((uint8_t)c, O)) { ok = false; break; } break;
        case kNamesUtf16be:
            if (Raw.size() % 2) { ok = false; break; }
            for (size_t i = 0; i < Raw.size() && ok; i += 2) {
                uint32_t C = ((uint32_t)(uint8_t)Raw[i] << 8) | (uint8_t)Raw[i + 1];
                if (C >= 0xD800 && C < 0xDC00) {                       // a surrogate pair
                    if (i + 4 > Raw.size()) { ok = false; break; }
                    const uint32_t L = ((uint32_t)(uint8_t)Raw[i + 2] << 8) | (uint8_t)Raw[i + 3];
                    if (L < 0xDC00 || L >= 0xE000) { ok = false; break; }
                    C = 0x10000 + ((C - 0xD800) << 10) + (L - 0xDC00); i += 2;
                }
                ok = Utf8Append(C, O);
            }
            break;
        case kNamesShiftJis: ok = ShiftJis(Raw, O) && ValidUtf8(O); break;
        default: Err = "a view's NAMES encoding is unknown"; return false;
    }
    if (!ok) { Err = "a name that is not text in the view's NAMES encoding"; return false; }
    return true;
}

bool RunView(const Description &D, ByteSource &Content, std::vector<ViewEntry> &Out, std::string &Err, uint64_t Fuel) {
    Out.clear();
    if (!Validate(D, Err)) return false;
    if (!D.view) { Err = "not a VIEW (a codec lists no files)"; return false; }
    const size_t nex = D.ex.size();
    //Expressions refer only to earlier ones: their depth, bounded so evaluation can recurse.
    std::vector<uint16_t> depth(nex, 1);
    for (size_t i = 0; i < nex; ++i) {
        const Ex &e = D.ex[i];
        const bool bin = (e.op >= EX_ADD && e.op <= EX_GE) || e.op == EX_DIV || e.op == EX_MOD;
        const bool un = e.op == EX_BYTE || e.op == EX_TABLE || e.op == EX_ARR || e.op == EX_LOG2SLOT || (e.op >= EX_U16 && e.op <= EX_U32BE);
        uint32_t d = 1;
        if (bin) d = 1 + std::max(depth[e.a], depth[e.b]);
        else if (un) d = 1 + depth[e.a];
        if (d > 512) { Err = "a view's expression nests too deep"; return false; }
        depth[i] = (uint16_t)d;
    }
    Reader C(Content);
    uint64_t R[kRegs] = {0};
    std::vector<std::vector<uint64_t>> A(D.arrays.size());
    for (size_t i = 0; i < D.arrays.size(); ++i) A[i].assign(D.arrays[i].begin(), D.arrays[i].end());
    bool bad = false;
    std::string why;
    auto refuse = [&](const std::string &m) { if (!bad) { bad = true; why = m; } return (uint64_t)0; };
    //(recursive: depth ≤ 512)
    std::function<uint64_t(uint16_t)> ev = [&](uint16_t i) -> uint64_t {
        const Ex &e = D.ex[i];
        switch (e.op) {
            case EX_CONST: return e.imm;
            case EX_REG: return R[e.imm];
            case EX_ADD: return ev(e.a) + ev(e.b);
            case EX_SUB: return ev(e.a) - ev(e.b);
            case EX_MUL: return ev(e.a) * ev(e.b);
            case EX_SHL: { const uint64_t a = ev(e.a), b = ev(e.b); return b >= 64 ? 0 : a << b; }
            case EX_SHR: { const uint64_t a = ev(e.a), b = ev(e.b); return b >= 64 ? 0 : a >> b; }
            case EX_AND: return ev(e.a) & ev(e.b);
            case EX_OR: return ev(e.a) | ev(e.b);
            case EX_XOR: return ev(e.a) ^ ev(e.b);
            case EX_LT: return ev(e.a) < ev(e.b);
            case EX_EQ: return ev(e.a) == ev(e.b);
            case EX_NE: return ev(e.a) != ev(e.b);
            case EX_GE: return ev(e.a) >= ev(e.b);
            case EX_DIV: { const uint64_t a = ev(e.a), b = ev(e.b); return b ? a / b : refuse("a division by zero"); }
            case EX_MOD: { const uint64_t a = ev(e.a), b = ev(e.b); return b ? a % b : refuse("a division by zero"); }
            case EX_BYTE: return C.byte(ev(e.a));
            case EX_U16: return C.le(ev(e.a), 2);
            case EX_U32: return C.le(ev(e.a), 4);
            case EX_U16BE: return C.be(ev(e.a), 2);
            case EX_U32BE: return C.be(ev(e.a), 4);
            case EX_TABLE: { const uint64_t k = ev(e.a); const auto &T = D.tables[e.imm]; return k < T.size() ? T[(size_t)k] : refuse("a table read past its end"); }
            case EX_ARR: { const uint64_t k = ev(e.a); const auto &T = A[e.imm]; return k < T.size() ? T[(size_t)k] : refuse("an array read past its end"); }
            case EX_LOG2SLOT: { const uint64_t a = ev(e.a); if (a < 4) return a; const int n = 63 - __builtin_clzll(a); return 2 * (uint64_t)n + ((a >> (n - 1)) & 1); }
            case EX_XLEFT: return C.size > R[kRegPlace] ? C.size - R[kRegPlace] : 0;
            default: return refuse("an expression a view cannot evaluate");
        }
    };
    struct Raw { std::string name; bool dir; std::vector<std::pair<uint64_t, uint64_t>> ext; };
    std::vector<Raw> Got;
    std::string Name;
    std::vector<std::pair<uint64_t, uint64_t>> Parts;
    size_t Extents = 0;
    std::vector<uint32_t> Stack;
    const auto inside = [&](uint64_t O, uint64_t N) { return O <= C.size && N <= C.size - O; };
    const auto addExt = [&](std::vector<std::pair<uint64_t, uint64_t>> &V, uint64_t O, uint64_t N) {
        if (!N) return true;
        if (!inside(O, N)) { refuse("an extent outside the content"); return false; }
        if (!V.empty() && V.back().first + V.back().second == O) { V.back().second += N; return true; }   // touching: one run
        if (++Extents > kViewMaxExtents) { refuse("a view of too many extents"); return false; }
        V.push_back({O, N});
        return true;
    };
    const auto entry = [&](bool Dir, std::vector<std::pair<uint64_t, uint64_t>> Ext) {
        if (Got.size() >= kViewMaxEntries) { refuse("a view of too many entries"); return; }
        Got.push_back({Name, Dir, std::move(Ext)});
        Name.clear();
    };
    const auto nameAdd = [&](uint64_t N) { if (Name.size() + N > kViewMaxName) { refuse("a name over 4096 bytes"); return false; } return true; };
    uint32_t pc = D.entryStream;
    for (;;) {
        if (bad) break;
        if (Fuel-- == 0) { refuse("a view that runs too long"); break; }
        if (pc >= D.ops.size()) { refuse("a view that runs past its last op"); break; }
        const Op &p = D.ops[pc++];
        switch (p.op) {
            case OP_SET: R[p.tgt] = ev(p.v); break;
            case OP_STA: { const uint64_t k = ev(p.x), v = ev(p.v); if (k >= A[p.nb].size()) refuse("an array write past its end"); else A[p.nb][(size_t)k] = v; break; }
            case OP_JZ: if (ev(p.v) == 0) pc = p.target; break;
            case OP_JMP: pc = p.target; break;
            case OP_CALL: if (Stack.size() >= kViewMaxCalls) refuse("a view's calls nest too deep"); else { Stack.push_back(pc); pc = p.target; } break;
            case OP_RET: if (Stack.empty()) refuse("a return with no call"); else { pc = Stack.back(); Stack.pop_back(); } break;
            case OP_ASSERT: if (ev(p.v) == 0) refuse("the view's assert at op " + Dec(pc - 1) + " failed (" + Dec(Got.size()) + " entries listed)"); break;
            case OP_END: goto done;
            case OP_ENAME: {
                const uint64_t o = ev(p.x), n = ev(p.v);
                if (bad || !nameAdd(n)) break;
                if (!inside(o, n)) { refuse("a name outside the content"); break; }
                if (Fuel < n) { refuse("a view that runs too long"); break; }
                Fuel -= n;
                if (!C.bytes(o, n, Name)) refuse("the content could not be read");
                break;
            }
            case OP_ECHAR: { const uint64_t c = ev(p.v); if (c > 255) refuse("a name byte over 255"); else if (nameAdd(1)) Name += (char)c; break; }
            case OP_ETAB: {
                const auto &T = D.tables[p.imm];
                if (!nameAdd(T.size())) break;
                for (const uint32_t c : T) { if (c > 255) { refuse("a name table holding a value over 255"); break; } Name += (char)c; }
                break;
            }
            case OP_EDIR: entry(true, {}); break;
            case OP_EFINISH: { const uint64_t o = ev(p.x), n = ev(p.v); std::vector<std::pair<uint64_t, uint64_t>> E; if (!bad && addExt(E, o, n)) entry(false, std::move(E)); break; }
            case OP_ESTRIDE: {
                uint64_t o = ev(p.x), n = ev(p.v); const uint64_t ch = p.imm, st = ev(p.m);
                if (bad) break;
                if (ch == 0 || st < ch) { refuse("a stride shorter than its runs"); break; }
                std::vector<std::pair<uint64_t, uint64_t>> E;
                while (n && !bad) {
                    const uint64_t k = std::min(ch, n);
                    if (Fuel-- == 0) { refuse("a view that runs too long"); break; }
                    if (!addExt(E, o, k)) break;
                    n -= k;
                    if (n && o > UINT64_MAX - st) { refuse("an extent outside the content"); break; }
                    o += st;
                }
                if (!bad) entry(false, std::move(E));
                break;
            }
            case OP_EPART: { const uint64_t o = ev(p.x), n = ev(p.v); if (!bad) addExt(Parts, o, n); break; }
            case OP_EFIN: entry(false, std::move(Parts)); Parts.clear(); break;
            default: refuse("an op a view cannot run"); break;
        }
    }
done:
    if (!bad && C.failed) refuse("the content could not be read");
    if (bad) { Err = why; return false; }
    if (!Name.empty() || !Parts.empty()) { Err = "a view that ends with an entry unfinished"; return false; }
    //Names read as text, paths checked; a folder for every ancestor; one entry a path.
    std::map<std::string, size_t> At;
    std::vector<ViewEntry> All;
    std::set<std::string> Dirs;
    for (Raw &G : Got) {
        ViewEntry E;
        if (!DecodeViewName(D.names, G.name, E.path, Err)) return false;
        if (!GoodPath(E.path)) { Err = "a path a view may not list: '" + E.path + "'"; return false; }
        E.dir = G.dir;
        E.extents = std::move(G.ext);
        const auto It = At.find(E.path);
        if (It != At.end()) {
            if (E.dir && All[It->second].dir) continue;                         // a folder named twice is one folder
            Err = "a path listed twice: '" + E.path + "'"; return false;
        }
        At.emplace(E.path, All.size());
        All.push_back(std::move(E));
    }
    for (const ViewEntry &E : All)
        for (size_t S = E.path.find('/'); S != std::string::npos; S = E.path.find('/', S + 1)) Dirs.insert(E.path.substr(0, S));
    for (const std::string &P : Dirs) {
        const auto It = At.find(P);
        if (It == At.end()) { ViewEntry E; E.path = P; E.dir = true; At.emplace(P, All.size()); All.push_back(std::move(E)); }
        else if (!All[It->second].dir) { Err = "a file that is also a folder: '" + P + "'"; return false; }
    }
    if (All.size() > kViewMaxEntries) { Err = "a view of too many entries"; return false; }
    std::sort(All.begin(), All.end(), [](const ViewEntry &a, const ViewEntry &b) { return a.path < b.path; });
    Out = std::move(All);
    return true;
}

std::string ViewListing(const std::vector<ViewEntry> &Entries) {
    std::string O = "VGVIEW 1\n";
    for (const ViewEntry &E : Entries) {
        if (E.dir) { O += "d\t" + E.path + "\n"; continue; }
        O += "f\t" + E.path + "\t" + Dec(E.size()) + "\t";
        if (E.extents.empty()) O += '-';
        for (size_t i = 0; i < E.extents.size(); ++i) O += (i ? "," : "") + Dec(E.extents[i].first) + "+" + Dec(E.extents[i].second);
        O += "\n";
    }
    return O;
}

bool ReadViewListing(const std::string &T, std::vector<ViewEntry> &Out, std::string &Err, uint64_t ContentSize) {
    Out.clear();
    static const std::string Head = "VGVIEW 1\n";
    if (T.compare(0, Head.size(), Head) != 0) { Err = "not a view listing (VGVIEW 1)"; return false; }
    const auto num = [](const std::string &S, uint64_t &V) {
        if (S.empty() || S.size() > 20 || (S.size() > 1 && S[0] == '0')) return false;
        V = 0;
        for (const char c : S) { if (c < '0' || c > '9') return false; const uint64_t d = (uint64_t)(c - '0'); if (V > (UINT64_MAX - d) / 10) return false; V = V * 10 + d; }
        return true;
    };
    size_t Extents = 0;
    for (size_t B = Head.size(); B < T.size();) {
        const size_t E = T.find('\n', B);
        if (E == std::string::npos) { Err = "a view listing's last line is unfinished"; return false; }
        const std::string L = T.substr(B, E - B);
        B = E + 1;
        std::vector<std::string> F;
        for (size_t s = 0;;) { const size_t t = L.find('\t', s); F.push_back(L.substr(s, t == std::string::npos ? std::string::npos : t - s)); if (t == std::string::npos) break; s = t + 1; }
        ViewEntry V;
        if (F.size() == 2 && F[0] == "d") V.dir = true;
        else if (F.size() == 4 && F[0] == "f") {
            uint64_t Size = 0, Sum = 0;
            if (!num(F[2], Size)) { Err = "a view listing's size is not a number"; return false; }
            if (F[3] != "-")
                for (size_t s = 0;;) {
                    const size_t t = F[3].find(',', s);
                    const std::string X = F[3].substr(s, t == std::string::npos ? std::string::npos : t - s);
                    const size_t Pl = X.find('+');
                    uint64_t O = 0, N = 0;
                    if (Pl == std::string::npos || !num(X.substr(0, Pl), O) || !num(X.substr(Pl + 1), N) || N == 0) { Err = "a view listing's extent is malformed"; return false; }
                    if (ContentSize && (O > ContentSize || N > ContentSize - O)) { Err = "a view listing's extent lies outside its content"; return false; }
                    if (!V.extents.empty() && V.extents.back().first + V.extents.back().second == O) { Err = "a view listing's touching extents are not one"; return false; }
                    if (++Extents > kViewMaxExtents || N > UINT64_MAX - Sum) { Err = "a view listing of too many extents"; return false; }
                    Sum += N;
                    V.extents.push_back({O, N});
                    if (t == std::string::npos) break;
                    s = t + 1;
                }
            if (Sum != Size) { Err = "a view listing's size is not its extents'"; return false; }
        }
        else { Err = "a view listing's line is malformed"; return false; }
        V.path = F[1];
        if (!GoodPath(V.path) || !ValidUtf8(V.path)) { Err = "a view listing's path is malformed"; return false; }
        if (!Out.empty() && !(Out.back().path < V.path)) { Err = "a view listing out of order (or a path twice)"; return false; }
        if (Out.size() >= kViewMaxEntries) { Err = "a view listing of too many entries"; return false; }
        Out.push_back(std::move(V));
    }
    //every ancestor a folder in the listing
    std::set<std::string> Dirs;
    for (const ViewEntry &V : Out) if (V.dir) Dirs.insert(V.path);
    for (const ViewEntry &V : Out)
        for (size_t S = V.path.find('/'); S != std::string::npos; S = V.path.find('/', S + 1))
            if (!Dirs.count(V.path.substr(0, S))) { Err = "a view listing missing the folder '" + V.path.substr(0, S) + "'"; return false; }
    return true;
}

} // namespace coding
