#include "coding.h"

#include <zstd.h>

#include <algorithm>
#include <cstring>
#include <functional>

namespace coding {

namespace {

// ================================================================================================ varints
void PutVar(std::vector<uint8_t> &o, uint64_t v) { while (v >= 0x80) { o.push_back((uint8_t)(v | 0x80)); v >>= 7; } o.push_back((uint8_t)v); }
struct Rd {
    const uint8_t *p; size_t n, at = 0; bool bad = false;
    uint64_t var() {
        uint64_t v = 0;
        for (int sh = 0; sh < 64; sh += 7) {
            if (at >= n) { bad = true; return 0; }
            const uint8_t x = p[at++]; v |= (uint64_t)(x & 0x7F) << sh;
            if (!(x & 0x80)) return v;
        }
        bad = true; return 0;
    }
    uint8_t u8() { if (at >= n) { bad = true; return 0; } return p[at++]; }
};

// ================================================================================================ limits
constexpr size_t kMaxEx = 65535, kMaxOps = 65535, kMaxTable = 1u << 20, kMaxTables = 16, kMaxArrays = 16, kMaxSlots = 1u << 22,
                 kMaxHuff = 4, kMaxSym = 320, kMaxStack = 64;
bool BinaryEx(uint8_t op) { return op >= EX_ADD && op <= EX_GE; }
bool UnaryEx(uint8_t op) { return op == EX_BYTE || op == EX_TABLE || op == EX_ARR || op == EX_LOG2SLOT; }
bool CodingOp(uint8_t op) { return op <= OP_HUFF; }

} // namespace

// ================================================================================================ the description format
std::vector<uint8_t> Serialize(const Description &D) {
    std::vector<uint8_t> o = {'V', 'G', 'C', 'D'};
    PutVar(o, D.isa); o.push_back(D.coder); o.push_back(D.shift);
    PutVar(o, D.name.size()); o.insert(o.end(), D.name.begin(), D.name.end());
    PutVar(o, D.nslots); o.push_back(D.nhuff); PutVar(o, D.entryStream); PutVar(o, (uint64_t)(D.entryToken + 1));
    PutVar(o, D.window); PutVar(o, D.maxlen); o.push_back((uint8_t)(D.len1slot + 1));
    for (uint8_t b : {D.histbase, D.histlen, D.tokK, D.tokL, D.tokSL, D.tokD}) o.push_back(b);
    PutVar(o, D.ex.size());
    for (const Ex &e : D.ex) { o.push_back(e.op); PutVar(o, e.a); PutVar(o, e.b); PutVar(o, e.imm); }
    PutVar(o, D.ops.size());
    for (const Op &p : D.ops) { for (uint8_t b : {p.op, p.modes, p.flags, p.nb, p.tgt}) o.push_back(b); for (uint16_t w : {p.x, p.v, p.m, p.target}) PutVar(o, w); PutVar(o, p.imm); }
    PutVar(o, D.tables.size());
    for (const auto &t : D.tables) { PutVar(o, t.size()); for (uint32_t v : t) PutVar(o, v); }
    PutVar(o, D.arrays.size());
    for (const auto &a : D.arrays) { size_t init = a.size(); while (init && !a[init - 1]) --init; PutVar(o, a.size()); PutVar(o, init); for (size_t i = 0; i < init; ++i) PutVar(o, a[i]); }
    return o;
}

bool Parse(const uint8_t *Data, size_t N, Description &D, std::string &Err) {
    D = Description();
    Rd r{Data, N};
    if (N < 4 || memcmp(Data, "VGCD", 4) != 0) { Err = "not a coding description"; return false; }
    r.at = 4;
    D.isa = (uint32_t)r.var(); D.coder = r.u8(); D.shift = r.u8();
    if (D.isa == 0 || D.isa > kIsa) { Err = "a description for a newer instruction set"; return false; }
    if (D.coder > kBits || D.shift < 1 || D.shift > 15) { Err = "a description with an unknown coder"; return false; }
    const uint64_t nl = r.var(); if (r.bad || nl > 256 || r.at + nl > N) { Err = "a malformed description name"; return false; }
    D.name.assign((const char *)Data + r.at, (size_t)nl); r.at += (size_t)nl;
    D.nslots = (uint32_t)r.var(); D.nhuff = r.u8(); D.entryStream = (uint16_t)r.var(); D.entryToken = (int32_t)r.var() - 1;
    D.window = (uint32_t)r.var(); D.maxlen = (uint32_t)r.var(); D.len1slot = (int8_t)((int)r.u8() - 1);
    D.histbase = r.u8(); D.histlen = r.u8(); D.tokK = r.u8(); D.tokL = r.u8(); D.tokSL = r.u8(); D.tokD = r.u8();
    if (r.bad || D.nslots > kMaxSlots || D.nhuff > kMaxHuff || D.histbase + D.histlen > kRegs || D.tokK >= kRegs || D.tokL >= kRegs || D.tokSL >= kRegs || D.tokD >= kRegs)
    { Err = "a description whose header is out of range"; return false; }
    const uint64_t nex = r.var(); if (r.bad || nex == 0 || nex > kMaxEx) { Err = "a description without expressions"; return false; }
    D.ex.resize((size_t)nex);
    for (size_t i = 0; i < nex; ++i) {
        Ex &e = D.ex[i]; e.op = r.u8(); const uint64_t a = r.var(), b = r.var(), imm = r.var();
        if (r.bad || e.op >= EX_COUNT || a > 0xFFFF || b > 0xFFFF || imm > 0xFFFFFFFFu) { Err = "a malformed expression"; return false; }
        e.a = (uint16_t)a; e.b = (uint16_t)b; e.imm = (uint32_t)imm;
        // an expression refers only to EARLIER expressions: no cycles, evaluation in index order
        if ((BinaryEx(e.op) && (e.a >= i || e.b >= i)) || (UnaryEx(e.op) && e.a >= i)) { Err = "an expression that refers forward"; return false; }
        if (e.op == EX_REG && e.imm >= (uint32_t)kRegs) { Err = "an expression naming no register"; return false; }
    }
    const uint64_t nops = r.var(); if (r.bad || nops == 0 || nops > kMaxOps) { Err = "a description without ops"; return false; }
    D.ops.resize((size_t)nops);
    for (Op &p : D.ops) {
        p.op = r.u8(); p.modes = r.u8(); p.flags = r.u8(); p.nb = r.u8(); p.tgt = r.u8();
        const uint64_t x = r.var(), v = r.var(), m = r.var(), t = r.var(), imm = r.var();
        if (r.bad || p.op >= OP_COUNT || p.modes > kAll || p.flags > kFree || (p.flags && !CodingOp(p.op)) || p.tgt >= kRegs ||
            x >= nex || v >= nex || m >= nex || t >= nops || imm > 0xFFFFFFFFu) { Err = "a malformed op"; return false; }
        p.x = (uint16_t)x; p.v = (uint16_t)v; p.m = (uint16_t)m; p.target = (uint16_t)t; p.imm = (uint32_t)imm;
    }
    if (D.entryStream >= nops || D.entryToken >= (int32_t)nops) { Err = "an entry past the ops"; return false; }
    const uint64_t nt = r.var(); if (r.bad || nt > kMaxTables) { Err = "too many tables"; return false; }
    D.tables.resize((size_t)nt);
    for (auto &t : D.tables) { const uint64_t n = r.var(); if (r.bad || n > kMaxTable) { Err = "a table too large"; return false; } t.resize((size_t)n);
        for (auto &v : t) { const uint64_t x = r.var(); if (r.bad || x > 0xFFFFFFFFu) { Err = "a malformed table"; return false; } v = (uint32_t)x; } }
    const uint64_t na = r.var(); if (r.bad || na > kMaxArrays) { Err = "too many arrays"; return false; }
    D.arrays.resize((size_t)na);
    for (auto &a : D.arrays) { const uint64_t n = r.var(), init = r.var(); if (r.bad || n > kMaxTable || init > n) { Err = "an array too large"; return false; }
        a.assign((size_t)n, 0); for (uint64_t i = 0; i < init; ++i) { const uint64_t x = r.var(); if (r.bad || x > 0xFFFFFFFFu) { Err = "a malformed array"; return false; } a[(size_t)i] = (uint32_t)x; } }
    if (r.at != N) { Err = "bytes after the description"; return false; }
    // what the ops name must exist
    for (const Op &p : D.ops) {
        const bool bad =
            ((p.op == OP_TREE || p.op == OP_RTREE) && p.nb > 24) ||
            ((p.op == OP_HUFF || p.op == OP_BUILD) && p.imm >= D.nhuff) ||
            ((p.op == OP_BUILD || p.op == OP_STA) && p.nb >= na) ||
            ((p.op == OP_HMTF || p.op == OP_HPUSH) && (p.nb == 0 || p.tgt + p.nb > kRegs));
        if (bad) { Err = "an op naming something the description lacks"; return false; }
    }
    for (const Ex &e : D.ex) {
        if ((e.op == EX_TABLE && e.imm >= nt) || (e.op == EX_ARR && e.imm >= na)) { Err = "an expression naming something the description lacks"; return false; }
    }
    return true;
}

// ================================================================================================ the machine
namespace {

uint32_t gPrice[128];
struct PriceInit { PriceInit() { for (uint32_t i = 8; i < 2048; i += 16) { uint32_t w = i, bc = 0; for (int j = 0; j < 4; ++j) { w = w * w; bc <<= 1; while (w >= (1u << 16)) { w >>= 1; bc++; } } gPrice[i >> 4] = (11u << 4) - 15 - bc; } } } gPriceInit;

// Each expression an op uses, flattened once into the list of the expressions it needs, in index order (axiom 9:
// specialise at mount). Evaluation is a loop over that list: no recursion, no cycles.
struct Spec {
    std::vector<uint32_t> start, len; std::vector<uint16_t> list;
    explicit Spec(const Description &D) {
        const size_t n = D.ex.size(); start.assign(n, 0); len.assign(n, 0);
        std::vector<uint8_t> need(n), used(n);
        for (const Op &p : D.ops) used[p.x] = used[p.v] = used[p.m] = 1;
        for (size_t r = 0; r < n; ++r) {
            if (!used[r]) continue;
            std::fill(need.begin(), need.begin() + (long)r + 1, 0); need[r] = 1;
            for (size_t i = r + 1; i-- > 0;) {
                if (!need[i]) continue;
                const Ex &e = D.ex[i];
                if (BinaryEx(e.op)) { need[e.a] = need[e.b] = 1; } else if (UnaryEx(e.op)) need[e.a] = 1;
            }
            start[r] = (uint32_t)list.size();
            for (size_t i = 0; i <= r; ++i) if (need[i] && D.ex[i].op != EX_CONST) list.push_back((uint16_t)i);
            len[r] = (uint32_t)(list.size() - start[r]);
        }
    }
};

struct Huff { uint16_t code[kMaxSym]; uint8_t len[kMaxSym]; int16_t count[16], sym[kMaxSym]; int nsym = 0; };

// Content as the machine sees it: DECODE writes it; CODE reads it through a window over a ByteSource.
struct Content {
    uint8_t *w = nullptr; size_t cap = 0;            // DECODE: the buffer written
    const uint8_t *mem = nullptr; uint64_t size = 0; // CODE: all in memory ...
    ByteSource *src = nullptr; std::vector<uint8_t> buf; uint64_t lo = 0, hi = 0; uint32_t window = 0; bool err = false;   // ... or windowed
    uint8_t at(uint64_t i) {
        if (mem) return i < size ? mem[i] : 0;
        if (i >= size) return 0;
        if (i < lo || i >= hi) {
            const uint64_t from = i > (uint64_t)window + 4096 ? i - window - 4096 : 0, to = std::min<uint64_t>(size, i + (1u << 20));
            buf.resize((size_t)(to - from));
            if (!src->preadAll(buf.data(), buf.size(), from)) { err = true; return 0; }
            lo = from; hi = to;
        }
        return buf[(size_t)(i - lo)];
    }
};

// The decisions a CODE run consumes, chunk by chunk (a chunk per checkpoint segment).
struct Decisions {
    const uint32_t *mem = nullptr; size_t memN = 0;                  // all in memory (mint)
    std::vector<uint32_t> chunk; size_t ci = 0; uint64_t base = 0;   // or one chunk of a record
    uint64_t total = 0;
    std::function<bool(std::vector<uint32_t> &, uint64_t &)> next;   // loads the following chunk
    uint64_t consumed() const { return mem ? ci : base + ci; }
    bool get(uint32_t &v) {
        if (mem) { if (ci >= memN) return false; v = mem[ci++]; return true; }
        while (ci >= chunk.size()) { if (!next || !next(chunk, base)) return false; ci = 0; }
        v = chunk[ci++]; return true;
    }
};

struct Machine {
    const Description &D; const Spec &S; int mode;
    const char *why = nullptr;
    std::vector<uint32_t> v;                       // registers, then one value per expression
    std::vector<uint16_t> slot;
    std::vector<std::vector<uint32_t>> arr;
    Huff hf[kMaxHuff];
    std::vector<uint8_t> hlens[kMaxHuff];           // the lengths each code was built from (checkpoints keep them)
    // range coder
    uint64_t low = 0; uint32_t range = 0xFFFFFFFFu; uint8_t cache = 0; uint64_t cacheSize = 1; uint32_t code = 0;
    // bit coder
    uint64_t acc = 0; int bn = 0; uint64_t bipos = 0;
    // bytes in (DECODE) / out (CODE)
    const uint8_t *in = nullptr; size_t inn = 0, ip = 0;
    std::vector<uint8_t> *out = nullptr;
    Content X; Decisions Dc; std::vector<uint32_t> *decOut = nullptr;
    uint32_t price = 0;
    int pc = 0; std::vector<int> stk;
    uint64_t fuel = 0, fuelBase = 0;
    uint64_t stopAt = UINT64_MAX;                   // CODE: pause at a MARK once this much output exists

    Machine(const Description &d, const Spec &s, int m) : D(d), S(s), mode(m) {
        v.assign(kRegs + D.ex.size(), 0); slot.assign(D.nslots, 1024);
        arr = D.arrays; for (auto &h : hf) h.nsym = 0;
    }
    bool fail(const char *m) { if (!why) why = m; return false; }

    uint32_t &reg(int i) { return v[(size_t)i]; }
    uint32_t place() const { return v[kRegPlace]; }

    // ---- expressions
    uint32_t ev(uint16_t r) {
        const Ex &e0 = D.ex[r];
        if (e0.op == EX_CONST) return e0.imm;
        if (e0.op == EX_REG) return v[e0.imm];
        const uint16_t *l = &S.list[S.start[r]]; const uint32_t n = S.len[r];
        uint32_t *x = &v[kRegs];
        for (uint32_t k = 0; k < n; ++k) {
            const uint16_t i = l[k]; const Ex &e = D.ex[i];
            auto A = [&]() { const Ex &c = D.ex[e.a]; return c.op == EX_CONST ? c.imm : x[e.a]; };
            auto B = [&]() { const Ex &c = D.ex[e.b]; return c.op == EX_CONST ? c.imm : x[e.b]; };
            uint32_t &o = x[i];
            switch (e.op) {
            case EX_REG: o = v[e.imm]; break;
            case EX_ADD: o = A() + B(); break;
            case EX_SUB: o = A() - B(); break;
            case EX_MUL: o = A() * B(); break;
            case EX_SHL: { const uint32_t s = B(); o = s >= 32 ? 0 : A() << s; break; }
            case EX_SHR: { const uint32_t s = B(); o = s >= 32 ? 0 : A() >> s; break; }
            case EX_AND: o = A() & B(); break;
            case EX_OR: o = A() | B(); break;
            case EX_XOR: o = A() ^ B(); break;
            case EX_LT: o = A() < B(); break;
            case EX_EQ: o = A() == B(); break;
            case EX_NE: o = A() != B(); break;
            case EX_GE: o = A() >= B(); break;
            case EX_BYTE: { const uint32_t a = A(); o = mode == kDecode ? (a < place() && a < X.cap ? X.w[a] : 0) : X.at(a); break; }
            case EX_TABLE: { const uint32_t a = A(); const auto &t = D.tables[e.imm]; if (a >= t.size()) { fail("a table read out of range"); o = 0; } else o = t[a]; break; }
            case EX_ARR: { const uint32_t a = A(); auto &t = arr[e.imm]; if (a >= t.size()) { fail("an array read out of range"); o = 0; } else o = t[a]; break; }
            case EX_LOG2SLOT: { const uint32_t a = A(); if (a < 4) o = a; else { const uint32_t z = 31 - (uint32_t)__builtin_clz(a); o = 2 * z + ((a >> (z - 1)) & 1); } break; }
            case EX_BITPOS: o = mode == kDecode ? (uint32_t)(bipos & 7) : (uint32_t)(bn & 7); break;
            case EX_DLEFT: o = (uint32_t)std::min<uint64_t>(0xFFFFFFFFu, Dc.total > Dc.consumed() ? Dc.total - Dc.consumed() : 0); break;
            case EX_XLEFT: { const uint64_t sz = mode == kDecode ? X.cap : X.size; o = sz > place() ? (uint32_t)std::min<uint64_t>(0xFFFFFFFFu, sz - place()) : 0; break; }
            case EX_INLEFT: o = mode == kDecode ? (uint32_t)std::min<uint64_t>(0xFFFFFFFFu, inn * 8 > bipos ? inn * 8 - bipos : 0) : 0; break;
            default: o = 0; break;
            }
        }
        return x[r];
    }

    // ---- the range coder
    void rcShift() {
        if ((uint32_t)low < 0xFF000000u || (int)(low >> 32) != 0) {
            uint8_t t = cache; do { out->push_back((uint8_t)(t + (uint8_t)(low >> 32))); t = 0xFF; } while (--cacheSize != 0);
            cache = (uint8_t)((uint32_t)low >> 24);
        }
        cacheSize++; low = (uint32_t)low << 8;
    }
    uint8_t inByte() { return ip < inn ? in[ip++] : (ip++, 0); }
    uint32_t rbit(uint16_t &p, uint32_t b) {
        const int sh = D.shift;
        if (mode == kPrice) { price += gPrice[(p ^ ((0u - b) & 2047u)) >> 4]; return b; }
        const uint32_t bound = (range >> 11) * p;
        if (mode == kDecode) {
            if (code < bound) { range = bound; p += (uint16_t)((2048 - p) >> sh); b = 0; } else { range -= bound; code -= bound; p -= (uint16_t)(p >> sh); b = 1; }
            if (range < (1u << 24)) { range <<= 8; code = (code << 8) | inByte(); }
            return b;
        }
        if (!b) { range = bound; p += (uint16_t)((2048 - p) >> sh); } else { low += bound; range -= bound; p -= (uint16_t)(p >> sh); }
        while (range < (1u << 24)) { range <<= 8; rcShift(); }
        return b;
    }
    // ---- the bit coder
    void bput(uint32_t val, int n) {
        if (!n) return;
        acc |= (uint64_t)(val & (n >= 32 ? 0xFFFFFFFFu : ((1u << n) - 1))) << bn; bn += n;
        while (bn >= 8) { out->push_back((uint8_t)acc); acc >>= 8; bn -= 8; }
    }
    uint32_t bget(int n) {
        uint32_t r = 0;
        for (int i = 0; i < n; ++i) { const uint64_t q = bipos >> 3; if (q >= inn) { fail("the stream ends early"); return 0; } r |= (uint32_t)((in[q] >> (bipos & 7)) & 1) << i; ++bipos; }
        return r;
    }
    bool build(int t, const uint32_t *len, uint32_t n) {
        Huff &h = hf[t];
        if (n > kMaxSym) return fail("a code with too many symbols");
        memset(h.count, 0, sizeof h.count); h.nsym = (int)n; hlens[t].assign(n, 0);
        for (uint32_t s = 0; s < n; ++s) { if (len[s] > 15) return fail("a code length over 15"); h.count[len[s]]++; h.len[s] = (uint8_t)len[s]; hlens[t][s] = (uint8_t)len[s]; }
        h.count[0] = 0; int left = 1;
        for (int l = 1; l < 16; ++l) { left <<= 1; left -= h.count[l]; if (left < 0) return fail("an over-subscribed code"); }
        int16_t offs[16] = {0}; for (int l = 1; l < 15; ++l) offs[l + 1] = (int16_t)(offs[l] + h.count[l]);
        for (uint32_t s = 0; s < n; ++s) if (len[s]) h.sym[offs[len[s]]++] = (int16_t)s;
        int next[16] = {0}, c = 0; for (int l = 1; l < 16; ++l) { c = (c + h.count[l - 1]) << 1; next[l] = c; }
        for (uint32_t s = 0; s < n; ++s) { if (!len[s]) continue; int cc = next[len[s]]++, rv = 0; for (uint32_t i = 0; i < len[s]; ++i) { rv = (rv << 1) | (cc & 1); cc >>= 1; } h.code[s] = (uint16_t)rv; }
        return true;
    }
    uint32_t huff(int t, uint32_t sym) {
        Huff &h = hf[t];
        if (mode == kDecode) {
            int c = 0, first = 0, index = 0;
            for (int l = 1; l < 16; ++l) { c |= (int)bget(1); if (why) return 0; const int k = h.count[l];
                if (c - k < first) return (uint32_t)h.sym[index + (c - first)];
                index += k; first += k; first <<= 1; c <<= 1; }
            fail("a code its table does not have"); return 0;
        }
        if ((int)sym >= h.nsym || !h.len[sym]) { fail("a symbol its code cannot say"); return sym; }
        if (mode == kPrice) { price += (uint32_t)h.len[sym] << 4; return sym; }
        bput(h.code[sym], h.len[sym]); return sym;
    }
    bool slots(uint32_t at, uint32_t n) { if ((uint64_t)at + n > slot.size()) return fail("a slot out of range"); return true; }
    void record(uint32_t val) { decOut->push_back(val); }

    // ---- run: 1 done (RET at the entry's depth, or END), 2 paused at a MARK (stopAt reached), 0 refused
    int run(int entry, bool resume = false) {
        if (!resume) { pc = entry; stk.clear(); }
        const size_t depth0 = resume ? 0 : stk.size();
        const size_t nops = D.ops.size();
        for (;;) {
            if (why) return 0;
            if ((uint32_t)pc >= nops) { fail("the program runs off its end"); return 0; }
            if (++fuel > fuelBase + (1u << 22) + 512 * ((uint64_t)(out ? out->size() : 0) + place() + ip + (bipos >> 3))) { fail("a description that works without making progress"); return 0; }
            const Op &o = D.ops[(size_t)pc++];
            if (o.modes && !(o.modes & mode)) continue;
            uint32_t val = 0; const bool coding = CodingOp(o.op);
            if (coding && mode != kDecode) {
                if ((o.flags & kFree) && mode == kCode) { if (!Dc.get(val)) { fail("out of decisions"); return 0; } }
                else val = ev(o.v);
            }
            switch (o.op) {
            case OP_BIT: { const uint32_t s = ev(o.x); if (!slots(s, 1)) return 0; val = rbit(slot[s], val & 1); break; }
            case OP_TREE: case OP_RTREE: {
                const uint32_t s = ev(o.x); const int nb = o.nb ? o.nb : (int)ev(o.m);
                if (nb > 24 || !slots(s, 1u << nb)) { fail("a tree out of range"); return 0; }
                uint32_t m = 1, r = 0;
                if (o.op == OP_TREE) { for (int i = nb - 1; i >= 0; --i) { const uint32_t b = rbit(slot[s + m], (val >> i) & 1); m = (m << 1) | b; } r = m - (1u << nb); }
                else { for (int i = 0; i < nb; ++i) { const uint32_t b = rbit(slot[s + m], (val >> i) & 1); m = (m << 1) | b; r |= b << i; } }
                val = r; break; }
            case OP_DIRECT: {
                const uint32_t n = ev(o.x); if (n > 32) { fail("too many direct bits"); return 0; }
                if (mode == kPrice) { price += n << 4; break; }
                if (mode == kDecode) { uint32_t r = 0; for (uint32_t k = 0; k < n; ++k) { range >>= 1; code -= range; const uint32_t t = 0u - (code >> 31); code += range & t;
                        if (range < (1u << 24)) { range <<= 8; code = (code << 8) | inByte(); } r = (r << 1) + t + 1; } val = r; break; }
                for (uint32_t k = n; k-- > 0;) { range >>= 1; low += range & (0u - ((val >> k) & 1)); if (range < (1u << 24)) { range <<= 8; rcShift(); } }
                break; }
            case OP_MLIT: {
                const uint32_t s = ev(o.x); if (!slots(s, 0x300)) return 0;
                uint32_t mb = ev(o.m), offs = 0x100, ds = 1;
                for (int i = 7; i >= 0; --i) { mb <<= 1; const uint32_t idx = offs + (mb & offs) + ds; const uint32_t b = rbit(slot[s + (idx & 0x3FF)], (val >> i) & 1); ds = (ds << 1) | b; offs &= ~(mb ^ (ds << 8)); }
                val = ds & 0xFF; break; }
            case OP_RAW: {
                const uint32_t n = ev(o.x); if (n > 32) { fail("too many raw bits"); return 0; }
                if (mode == kDecode) val = bget((int)n); else if (mode == kPrice) price += n << 4; else bput(val, (int)n);
                break; }
            case OP_HUFF: val = huff((int)o.imm, val); break;
            case OP_BUILD: {
                const uint32_t a = ev(o.x), n = ev(o.v); const auto &t = arr[o.nb];
                if ((uint64_t)a + n > t.size()) { fail("a code past its array"); return 0; }
                if (!build((int)o.imm, t.data() + a, n)) return 0;
                break; }
            case OP_STA: { const uint32_t i = ev(o.x); auto &t = arr[o.nb]; if (i >= t.size()) { fail("an array write out of range"); return 0; } t[i] = ev(o.v); break; }
            case OP_SET: v[o.tgt] = ev(o.v); break;
            case OP_DEC:
                if (mode == kCode) { uint32_t x; if (!Dc.get(x)) { fail("out of decisions"); return 0; } v[o.tgt] = x; }
                else if (mode == kDecode) record(v[o.tgt]);
                break;
            case OP_OUTLIT: {
                const uint32_t p = place();
                if (mode == kDecode) { if (p >= X.cap) { fail("more content than expected"); return 0; } X.w[p] = (uint8_t)ev(o.v); }
                v[kRegPlace] = p + 1; break; }
            case OP_OUTCOPY: {
                const uint32_t p = place(), len = ev(o.x), dist = ev(o.v);
                if (mode == kDecode) {
                    if (!dist || dist > p) { fail("a copy from before the start"); return 0; }
                    if ((uint64_t)p + len > X.cap) { fail("more content than expected"); return 0; }
                    for (uint32_t i = 0; i < len; ++i) X.w[p + i] = X.w[p + i - dist];
                }
                v[kRegPlace] = p + len; break; }
            case OP_HMTF: { const uint32_t s = ev(o.v); if (s >= o.nb) { fail("no such history slot"); return 0; } const uint32_t h = v[o.tgt + s];
                for (uint32_t j = s; j > 0; --j) v[o.tgt + j] = v[o.tgt + j - 1];
                v[o.tgt] = h; break; }
            case OP_HPUSH: { const uint32_t x = ev(o.v); for (int j = o.nb - 1; j > 0; --j) v[(size_t)(o.tgt + j)] = v[(size_t)(o.tgt + j - 1)]; v[o.tgt] = x; break; }
            case OP_JZ: if (!ev(o.v)) pc = o.target; break;
            case OP_JMP: pc = o.target; break;
            case OP_CALL: if (stk.size() >= kMaxStack) { fail("calls too deep"); return 0; } stk.push_back(pc); pc = o.target; break;
            case OP_RET: if (stk.size() == depth0) return 1; pc = stk.back(); stk.pop_back(); break;
            case OP_ASSERT: if (!ev(o.v)) { fail("the stream breaks a rule of its format"); return 0; } break;
            case OP_FLUSH: if (mode == kCode) { if (D.coder == kRange) for (int i = 0; i < 5; ++i) rcShift(); else if (bn) bput(0, 8 - bn); } break;
            case OP_MARK: if (mode == kCode && out && out->size() >= stopAt) return 2; break;
            case OP_END: return 1;
            default: fail("an unknown op"); return 0;
            }
            if (why) return 0;
            if (coding) { v[o.tgt] = val; if ((o.flags & kFree) && mode == kDecode) record(val); }
        }
    }

    // ---- checkpoints: everything a CODE run needs to resume at a MARK
    std::vector<uint8_t> snapshot() const {
        std::vector<uint8_t> o;
        PutVar(o, (uint64_t)pc); PutVar(o, stk.size()); for (int s : stk) PutVar(o, (uint64_t)s);
        for (int i = 0; i < kRegs; ++i) PutVar(o, v[(size_t)i]);
        PutVar(o, low); PutVar(o, range); o.push_back(cache); PutVar(o, cacheSize); PutVar(o, acc); PutVar(o, (uint64_t)bn);
        for (uint16_t s : slot) PutVar(o, s);
        for (const auto &a : arr) for (uint32_t x : a) PutVar(o, x);
        for (int t = 0; t < D.nhuff; ++t) { PutVar(o, hlens[t].size()); o.insert(o.end(), hlens[t].begin(), hlens[t].end()); }
        return o;
    }
    bool restore(const uint8_t *p, size_t n) {
        Rd r{p, n};
        pc = (int)r.var(); const uint64_t ns = r.var(); if (r.bad || ns > kMaxStack || (uint64_t)pc >= D.ops.size()) return fail("a malformed checkpoint");
        stk.resize((size_t)ns); for (auto &s : stk) { s = (int)r.var(); if ((uint64_t)s >= D.ops.size()) return fail("a malformed checkpoint"); }
        for (int i = 0; i < kRegs; ++i) v[(size_t)i] = (uint32_t)r.var();
        low = r.var(); range = (uint32_t)r.var(); cache = r.u8(); cacheSize = r.var(); acc = r.var(); bn = (int)r.var();
        for (auto &s : slot) s = (uint16_t)r.var();
        for (auto &a : arr) for (auto &x : a) x = (uint32_t)r.var();
        for (int t = 0; t < D.nhuff; ++t) {
            const uint64_t k = r.var(); if (r.bad || k > kMaxSym || r.at + k > n) return fail("a malformed checkpoint");
            std::vector<uint32_t> l(p + r.at, p + r.at + k); r.at += (size_t)k;
            if (k && !build(t, l.data(), (uint32_t)k)) return false;
            if (!k) hf[t].nsym = 0;
        }
        if (r.bad || r.at != n || bn < 0 || bn > 7) return fail("a malformed checkpoint");
        return true;
    }
};

bool Unzstd(const std::vector<uint8_t> &z, std::vector<uint8_t> &o) {
    const unsigned long long n = ZSTD_getFrameContentSize(z.data(), z.size());
    if (n == ZSTD_CONTENTSIZE_ERROR || n == ZSTD_CONTENTSIZE_UNKNOWN || n > (1ull << 31)) return false;
    o.resize((size_t)n); return ZSTD_decompress(o.data(), o.size(), z.data(), z.size()) == n;
}
std::vector<uint8_t> Zstd(const std::vector<uint8_t> &x) {
    std::vector<uint8_t> z(ZSTD_compressBound(x.size())); z.resize(ZSTD_compress(z.data(), z.size(), x.data(), x.size(), 19)); return z;
}

} // namespace

// ================================================================================================ mint
// Record: "VGCR" | varint total decisions | varint checkpoints | per checkpoint: varint shipped offset, varint
// decisions before it, varint payload length | payloads. A payload is one zstd frame: varint snapshot length,
// snapshot, varint decision count, the segment's decisions as varints.
bool Mint(const Description &D, const uint8_t *Shipped, size_t N, size_t ContentSize, size_t ContentCap, uint64_t Spacing,
          std::vector<uint8_t> &Content, std::vector<uint8_t> &Record, std::string &Err) {
    Spec S(D);
    Content.assign(ContentCap, 0);
    std::vector<uint32_t> dec;
    {
        Machine m(D, S, kDecode); m.in = Shipped; m.inn = N; m.X.w = Content.data(); m.X.cap = ContentSize ? ContentSize : ContentCap; m.decOut = &dec;
        if (D.coder == kRange) { m.ip = 1; for (int i = 0; i < 4; ++i) m.code = (m.code << 8) | m.inByte(); }
        if (m.run(D.entryStream) != 1) { Err = std::string("decode: ") + (m.why ? m.why : "refused"); return false; }
        if (ContentSize && m.place() != ContentSize) { Err = "decode: the content is not the size expected"; return false; }
        Content.resize(m.place());
    }
    // code it back, taking checkpoints at MARKs every Spacing shipped bytes
    std::vector<uint8_t> out; out.reserve(N + 64);
    struct C { uint64_t out, dec; std::vector<uint8_t> snap; };
    std::vector<C> cks;
    Machine m(D, S, kCode); m.out = &out; m.X.mem = Content.data(); m.X.size = Content.size(); m.Dc.mem = dec.data(); m.Dc.memN = dec.size(); m.Dc.total = dec.size();
    m.pc = D.entryStream;
    cks.push_back({0, 0, m.snapshot()});
    for (bool first = true;; first = false) {
        m.stopAt = (uint64_t)cks.size() * Spacing;
        const int r = m.run(D.entryStream, !first);
        if (r == 0) { Err = std::string("code: ") + (m.why ? m.why : "refused"); return false; }
        if (r == 1) break;
        cks.push_back({out.size(), m.Dc.consumed(), m.snapshot()});
    }
    if (out.size() != N || memcmp(out.data(), Shipped, N) != 0) { Err = "the stream does not code back to its own bytes"; return false; }
    if (m.Dc.consumed() != dec.size()) { Err = "decisions left over"; return false; }
    // the record
    std::vector<std::vector<uint8_t>> pay;
    for (size_t k = 0; k < cks.size(); ++k) {
        std::vector<uint8_t> p; PutVar(p, cks[k].snap.size()); p.insert(p.end(), cks[k].snap.begin(), cks[k].snap.end());
        const uint64_t e = k + 1 < cks.size() ? cks[k + 1].dec : dec.size();
        PutVar(p, e - cks[k].dec); for (uint64_t i = cks[k].dec; i < e; ++i) PutVar(p, dec[(size_t)i]);
        pay.push_back(Zstd(p));
    }
    Record = {'V', 'G', 'C', 'R'}; PutVar(Record, dec.size()); PutVar(Record, cks.size());
    for (size_t k = 0; k < cks.size(); ++k) { PutVar(Record, cks[k].out); PutVar(Record, cks[k].dec); PutVar(Record, pay[k].size()); }
    for (const auto &p : pay) Record.insert(Record.end(), p.begin(), p.end());
    return true;
}

// ================================================================================================ the read side
struct CodedByteSource::Impl { Description D; std::unique_ptr<Spec> S; uint64_t total = 0; uint64_t payloadAt = 0; };

std::shared_ptr<CodedByteSource> CodedByteSource::Create(std::shared_ptr<ByteSource> Desc, std::shared_ptr<ByteSource> Record,
                                                         std::shared_ptr<ByteSource> Content, uint64_t ShippedSize, std::string &Err) {
    if (!Desc || !Record || !Content) { Err = "no description, record or content"; return nullptr; }
    auto S = std::shared_ptr<CodedByteSource>(new CodedByteSource());
    S->I = std::make_shared<Impl>();
    std::vector<uint8_t> d(Desc->size());
    if (d.size() > (64u << 20) || (!d.empty() && !Desc->preadAll(d.data(), d.size(), 0))) { Err = "the description does not read"; return nullptr; }
    if (!Parse(d.data(), d.size(), S->I->D, Err)) return nullptr;
    S->I->S = std::make_unique<Spec>(S->I->D);
    // the record's index
    const uint64_t rn = Record->size(); std::vector<uint8_t> h((size_t)std::min<uint64_t>(rn, 1u << 16));
    if (h.size() < 4 || !Record->preadAll(h.data(), h.size(), 0) || memcmp(h.data(), "VGCR", 4) != 0) { Err = "not a coding record"; return nullptr; }
    for (;;) {
        Rd r{h.data(), h.size()}; r.at = 4; S->Cks.clear();
        S->I->total = r.var(); const uint64_t nck = r.var();
        uint64_t off = 0, lastOut = 0, lastDec = 0;
        bool ok = !r.bad && nck >= 1 && nck <= (1u << 24);
        for (uint64_t k = 0; ok && k < nck; ++k) {
            Ck c; c.out = r.var(); c.dec = r.var(); c.recLen = r.var(); c.rec = off; off += c.recLen;
            if (r.bad) break;
            if ((k == 0 && (c.out || c.dec)) || (k && (c.out < lastOut || c.dec < lastDec)) || c.dec > S->I->total || c.out > ShippedSize) { ok = false; break; }
            lastOut = c.out; lastDec = c.dec; S->Cks.push_back(c);
        }
        if (r.bad && h.size() < rn) { h.resize((size_t)std::min<uint64_t>(rn, h.size() * 4)); if (!Record->preadAll(h.data(), h.size(), 0)) { Err = "the record does not read"; return nullptr; } continue; }
        if (!ok || r.bad) { Err = "a malformed coding record"; return nullptr; }
        S->I->payloadAt = r.at;
        if (r.at + off != rn) { Err = "the record is not the size its index says"; return nullptr; }
        break;
    }
    S->Rec = std::move(Record); S->Content = std::move(Content); S->Size = ShippedSize;
    return S;
}

ssize_t CodedByteSource::pread(void *Buf, size_t N, uint64_t Off) {
    if (Off >= Size || !N) return 0;
    if (N > Size - Off) N = (size_t)(Size - Off);
    size_t k = Cks.size() - 1; while (Cks[k].out > Off) --k;
    const Description &D = I->D;
    auto payload = [&](size_t j, std::vector<uint8_t> &p) {
        std::vector<uint8_t> z((size_t)Cks[j].recLen);
        return Rec->preadAll(z.data(), z.size(), I->payloadAt + Cks[j].rec) && Unzstd(z, p);
    };
    std::vector<uint8_t> p; if (!payload(k, p)) return -EIO;
    Rd r{p.data(), p.size()}; const uint64_t sn = r.var(); if (r.bad || r.at + sn > p.size()) return -EIO;
    std::vector<uint8_t> out; out.reserve(N + 4096);
    Machine m(D, *I->S, kCode); m.out = &out;
    if (!m.restore(p.data() + r.at, (size_t)sn)) return -EIO;
    m.X.src = Content.get(); m.X.size = Content->size(); m.X.window = D.window;
    // decisions: this segment's, then each following segment's as the run reaches it
    size_t seg = k;
    auto chunk = [&](size_t j, const std::vector<uint8_t> &q, size_t at, std::vector<uint32_t> &c, uint64_t &base) {
        Rd rr{q.data(), q.size()}; rr.at = at; const uint64_t n = rr.var(); if (rr.bad || n > (q.size() - rr.at)) return false;
        c.resize((size_t)n); for (auto &x : c) x = (uint32_t)rr.var();
        base = Cks[j].dec; return !rr.bad && rr.at == q.size() && base + n == (j + 1 < Cks.size() ? Cks[j + 1].dec : I->total);
    };
    if (!chunk(k, p, r.at + (size_t)sn, m.Dc.chunk, m.Dc.base)) return -EIO;
    m.Dc.total = I->total;
    m.Dc.next = [&](std::vector<uint32_t> &c, uint64_t &base) {
        if (seg + 1 >= Cks.size()) return false;
        std::vector<uint8_t> q; if (!payload(++seg, q)) return false;
        Rd rr{q.data(), q.size()}; const uint64_t s2 = rr.var(); if (rr.bad || rr.at + s2 > q.size()) return false;
        return chunk(seg, q, rr.at + (size_t)s2, c, base);
    };
    m.stopAt = Off + N - Cks[k].out;
    m.fuelBase = 0;
    const int res = m.run(D.entryStream, true);
    if (res == 0 || m.X.err) return -EIO;
    const uint64_t from = Off - Cks[k].out;
    if (out.size() < from + N) return -EIO;
    memcpy(Buf, out.data() + from, N);
    return (ssize_t)N;
}

} // namespace coding
