#include "coding.h"
#include "lz4family.h"
#include "zfamily.h"
#include "lzxmakecab.h"

#include <zstd.h>

#include <algorithm>
#include <atomic>
#include <cstdlib>
#include <cstring>
#include <condition_variable>
#include <deque>
#include <functional>
#include <array>
#include <map>
#include <mutex>
#include <queue>
#include <set>
#include <thread>
#include <tuple>

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
                 kMaxHuff = 4, kMaxSym = 1024, kMaxStack = 64;   // (LZX's main code: 256 + 8 x position slots, 656 at a 2 MiB window)
bool BinaryEx(uint8_t op) { return (op >= EX_ADD && op <= EX_GE) || op == EX_DIV || op == EX_MOD; }
bool DivEx(uint8_t op) { return op == EX_DIV || op == EX_MOD; }
bool UsesE8(const Description &D) { for (const Op &o : D.ops) if (o.op == OP_E8FRAME) return true; return false; }
bool UsesLzx(const Description &D) { for (const Op &o : D.ops) if (o.op == OP_LZXFOLDER) return true; return false; }
bool LzxKnob(uint32_t k) { const uint32_t w = k & 0xFF, sp = (k >> 8) & 0xFF; return w >= 15 && w <= 21 && sp >= 1 && sp <= 32 && (k >> 16) == 0; }
bool UnaryEx(uint8_t op) { return op == EX_BYTE || op == EX_TABLE || op == EX_ARR || op == EX_LOG2SLOT || (op >= EX_U16 && op <= EX_U32BE); }
bool CodingOp(uint8_t op) { return op <= OP_HUFF || op == OP_RAWBYTES; }

} // namespace

// ================================================================================================ the description format
bool Validate(const Description &D, std::string &Err) {
    if (D.isa == 0 || D.isa > kIsa) { Err = "a description for a newer instruction set"; return false; }
    if (D.coder > kBits16M || D.shift < 1 || D.shift > 15 || (D.coder == kBits16M && D.isa < 7)) { Err = "a description with an unknown coder"; return false; }
    if (D.name.size() > 256) { Err = "a malformed description name"; return false; }
    if (D.nslots > kMaxSlots || D.nhuff > kMaxHuff || D.histbase + D.histlen > kRegs || D.tokK >= kRegs || D.tokL >= kRegs || D.tokSL >= kRegs || D.tokD >= kRegs)
    { Err = "a description whose header is out of range"; return false; }
    const size_t nex = D.ex.size(); if (nex == 0 || nex > kMaxEx) { Err = "a description without expressions"; return false; }
    for (size_t i = 0; i < nex; ++i) {
        const Ex &e = D.ex[i];
        if (e.op >= EX_COUNT) { Err = "a malformed expression"; return false; }
        // an expression refers only to EARLIER expressions: no cycles, evaluation in index order
        if ((BinaryEx(e.op) && (e.a >= i || e.b >= i)) || (UnaryEx(e.op) && e.a >= i)) { Err = "an expression that refers forward"; return false; }
        if (e.op == EX_REG && e.imm >= (uint32_t)kRegs) { Err = "an expression naming no register"; return false; }
    }
    const size_t nops = D.ops.size(); if (nops == 0 || nops > kMaxOps) { Err = "a description without ops"; return false; }
    for (const Op &p : D.ops)
        if (p.op >= OP_COUNT || p.modes > kAll || p.flags > (kFree | kBounded) || ((p.flags & kFree) && !CodingOp(p.op)) ||
            ((p.flags & kBounded) && p.op != OP_HUFFRUN) || p.tgt >= kRegs ||
            p.x >= nex || p.v >= nex || p.m >= nex || p.target >= nops) { Err = "a malformed op"; return false; }
    if (D.entryStream >= nops || D.entryToken < -1 || D.entryToken >= (int32_t)nops) { Err = "an entry past the ops"; return false; }
    const size_t nt = D.tables.size(), na = D.arrays.size();
    if (nt > kMaxTables) { Err = "too many tables"; return false; }
    for (const auto &t : D.tables) if (t.size() > kMaxTable) { Err = "a table too large"; return false; }
    if (na > kMaxArrays) { Err = "too many arrays"; return false; }
    for (const auto &a : D.arrays) if (a.size() > kMaxTable) { Err = "an array too large"; return false; }
    {   bool fam = false, e8 = false, near = false; for (const Op &p : D.ops) { fam |= p.op == OP_PREDICT; e8 |= p.op == OP_E8FRAME; near |= p.op == OP_NEAREST; }
        if (fam && e8) { Err = "a family predicting through an E8 view (not yet: families parse the real bytes)"; return false; }
        if ((e8 || near) && D.window > (1u << 25)) { Err = "a WINDOW over 32 MiB with E8 frames or NEAREST"; return false; } }
    for (const Op &p : D.ops)
        if ((((p.flags & kBounded) || p.op == OP_RAWBYTES) && D.isa < 7) || ((p.op == OP_E8FRAME || p.op == OP_E8END || p.op == OP_NEAREST) && D.isa < 8) || (p.op >= OP_LZXFOLDER && p.op <= OP_LZXEMIT && D.isa < 9)) { Err = "an op newer than the instruction set it names"; return false; }
    for (const Op &p : D.ops) if (p.op == OP_LZXFOLDER && !LzxKnob(p.imm)) { Err = "an LZX folder's knob is window bits 15..21 | second partition (1..32 x 32 KiB) << 8"; return false; }
    { size_t tt = 0, ta = 0; for (const auto &t : D.tables) tt += t.size(); for (const auto &a : D.arrays) ta += a.size();
      if (tt > (16u << 20) || ta > (4u << 20)) { Err = "a description too large"; return false; } }
    // what the ops name must exist
    for (const Op &p : D.ops) {
        const bool bad =
            ((p.op == OP_TREE || p.op == OP_RTREE) && p.nb > 24) ||
            ((p.op == OP_HUFF || p.op == OP_BUILD) && p.imm >= D.nhuff) ||
            ((p.op == OP_BUILD || p.op == OP_STA) && p.nb >= na) ||
            ((p.op == OP_HMTF || p.op == OP_HPUSH) && (p.nb == 0 || p.tgt + p.nb > kRegs)) ||
            (p.op >= OP_HUFFRUN && D.isa < 3) ||
            (p.op == OP_HUFFRUN && (p.imm >= D.nhuff || p.nb >= kRegs)) ||
            (p.op == OP_HUFFRUN && !(p.flags & kBounded) && !(D.ex[p.v].op == EX_CONST && D.ex[p.v].imm == 0)) ||   // (v: the bound's)
            (p.op == OP_RAWBYTES && D.isa < 7) ||
            (p.op == OP_PREDICT && (D.isa < 5 || p.tgt + 3 > kRegs ||
                                    !((p.nb == kFamilyLz4hc && p.imm != 0 && p.imm <= kLz4hcMaxAttempts) || (p.nb == kFamilyZlib && ZlibParser::ValidKnob(p.imm)))));
        if (bad) { Err = "an op naming something the description lacks"; return false; }
    }
    for (const Ex &e : D.ex) {
        if ((e.op == EX_TABLE && e.imm >= nt) || (e.op == EX_ARR && e.imm >= na)) { Err = "an expression naming something the description lacks"; return false; }
        if ((e.op == EX_STREAMPOS && D.isa < 4) || (e.op >= EX_U16 && e.op <= EX_U32BE && D.isa < 6) || (DivEx(e.op) && D.isa < 7)) { Err = "an expression newer than the instruction set it names"; return false; }
    }
    return true;
}

// ================================================================================================ the machine
uint64_t WorkPerByte(uint8_t Family, uint32_t Knob);
uint64_t MaxWorkPerByte(const Description &D);
namespace {

uint32_t gPrice[128];
struct PriceInit { PriceInit() { for (uint32_t i = 8; i < 2048; i += 16) { uint32_t w = i, bc = 0; for (int j = 0; j < 4; ++j) { w = w * w; bc <<= 1; while (w >= (1u << 16)) { w >>= 1; bc++; } } gPrice[i >> 4] = (11u << 4) - 15 - bc; } } } gPriceInit;

// Each expression an op uses, compiled once into three-address micro-ops (axiom 9: specialise at mount): constants
// folded, register and constant operands read in place, evaluation in index order. No recursion, no cycles.
enum : uint8_t { M_ADD, M_ADDI, M_SUB, M_SUBI, M_RSUBI, M_MUL, M_MULI, M_SHL, M_SHLI, M_SHR, M_SHRI, M_AND, M_ANDI, M_OR, M_ORI, M_XOR, M_XORI,
                 M_LT, M_LTI, M_EQ, M_EQI, M_NE, M_NEI, M_GE, M_GEI, M_LDI, M_COPY,
                 M_BYTE, M_TABLE, M_ARR, M_LOG2, M_BITPOS, M_DLEFT, M_XLEFT, M_INLEFT, M_SPOS, M_U16, M_U32, M_U16BE, M_U32BE,
                 M_DIV, M_DIVI, M_MOD, M_MODI };
struct Mu { uint8_t c; uint16_t d, a, b; uint32_t imm; };
// An operand resolved once: a constant, a register, an AFFINE form (a constant plus up to four terms, each
// ((src >> rs) & mask) << ls times mul, src a register or the content byte at a register + offset: what nearly every
// slot index and length of a description is), or a run of micro-ops whose value ends in v[r].
struct Term { uint8_t byte = 0, rs = 0, ls = 0; uint16_t reg = 0; uint32_t off = 0, mask = 0xFFFFFFFFu, mul = 1; };   // byte: 0 register, 1 content byte at register + off, 2 table off [register]
struct Affine { uint32_t c0 = 0; uint8_t n = 0; Term t[4]; };
struct Opnd { uint8_t k = 0; uint16_t r = 0; uint32_t a = 0, n = 0; };   // k: 0 constant a, 1 register r, 2 micro-ops, 3 affine a,
                                                                           // 4 register r compared (n: EX_EQ/NE/LT/GE) with a, 5 table a [register r]
// Fused instructions (a mode's program only; checkpoints keep original op numbers, so records never see them).
enum : uint8_t { F_BITJZ = OP_COUNT, F_SETBITJZ, F_DECN, F_OFFEND };
struct Ins { uint8_t op = 0, flags = 0, nb = 0, tgt = 0; Opnd x, v, m; uint32_t target = 0, orig = 0, imm = 0, skip = 0, fall = 0; uint8_t regs[8] = {0}; };   // fall: the next instruction, JMPs followed
// A mode's program: only the ops that run in it, targets remapped, operands resolved, common patterns fused.
struct Prog { std::vector<Ins> ins; std::vector<uint32_t> from; };   // from: original op -> the first instruction at or after it
struct Spec {
    std::vector<Mu> mu; std::vector<uint32_t> start, len; std::vector<uint16_t> res; std::vector<uint8_t> isConst; std::vector<uint32_t> cval;
    std::vector<uint16_t> skip[8];                     // per mode: the first op at or after pc that runs in it
    bool ok = true;                                    // false: the compiled form would be too large (a hostile description)
    explicit Spec(const Description &D) {
        const size_t n = D.ex.size();
        start.assign(n, 0); len.assign(n, 0); res.assign(n, 0); isConst.assign(n, 0); cval.assign(n, 0);
        // fold: a node is constant when its children are (and it reads nothing but them)
        for (size_t i = 0; i < n; ++i) {
            const Ex &e = D.ex[i];
            if (e.op == EX_CONST) { isConst[i] = 1; cval[i] = e.imm; continue; }
            if (BinaryEx(e.op) && isConst[e.a] && isConst[e.b] && !(DivEx(e.op) && cval[e.b] == 0)) {   // (÷0: refused when it runs)
                const uint32_t a = cval[e.a], b = cval[e.b]; uint32_t r = 0;
                switch (e.op) { case EX_ADD: r = a + b; break; case EX_SUB: r = a - b; break; case EX_MUL: r = a * b; break; case EX_SHL: r = b >= 32 ? 0 : a << b; break;
                case EX_SHR: r = b >= 32 ? 0 : a >> b; break; case EX_AND: r = a & b; break; case EX_OR: r = a | b; break; case EX_XOR: r = a ^ b; break;
                case EX_LT: r = a < b; break; case EX_EQ: r = a == b; break; case EX_NE: r = a != b; break; case EX_GE: r = a >= b; break;
                case EX_DIV: r = a / b; break; case EX_MOD: r = a % b; break; }
                isConst[i] = 1; cval[i] = r; continue;
            }
            if (e.op == EX_LOG2SLOT && isConst[e.a]) { const uint32_t a = cval[e.a]; isConst[i] = 1; cval[i] = a < 4 ? a : 2 * (31 - (uint32_t)__builtin_clz(a)) + ((a >> (30 - __builtin_clz(a))) & 1); continue; }
        }
        // where a node's value lives: a register (for EX_REG) or its own slot
        auto loc = [&](size_t i) -> uint16_t { return D.ex[i].op == EX_REG ? (uint16_t)D.ex[i].imm : (uint16_t)(kRegs + i); };
        std::vector<uint8_t> used(n); std::vector<uint32_t> seen(n, 0); std::vector<uint16_t> stack, nodes; uint32_t epoch = 0; size_t work = 0;
        for (const Op &p : D.ops) used[p.x] = used[p.v] = used[p.m] = 1;
        for (size_t r = 0; r < n; ++r) {
            if (!used[r]) continue;
            if (isConst[r]) continue;
            if (D.ex[r].op == EX_REG) { res[r] = (uint16_t)D.ex[r].imm; continue; }
            ++epoch; nodes.clear(); stack.assign(1, (uint16_t)r); seen[r] = epoch;
            while (!stack.empty()) {                                     // only what this expression needs
                const uint16_t i = stack.back(); stack.pop_back(); nodes.push_back(i);
                if (++work > (4u << 20)) { ok = false; return; }
                const Ex &e = D.ex[i]; if (isConst[i] || e.op == EX_REG) continue;
                auto visit = [&](uint16_t c) { if (seen[c] != epoch) { seen[c] = epoch; stack.push_back(c); } };
                if (BinaryEx(e.op)) { visit(e.a); visit(e.b); } else if (UnaryEx(e.op)) visit(e.a);
            }
            std::sort(nodes.begin(), nodes.end());
            start[r] = (uint32_t)mu.size(); res[r] = loc(r);
            for (const uint16_t i : nodes) {
                if (isConst[i] || D.ex[i].op == EX_REG) continue;
                const Ex &e = D.ex[i]; const uint16_t d = (uint16_t)(kRegs + i);
                if (UnaryEx(e.op) || e.op == EX_BITPOS || e.op == EX_DLEFT || e.op == EX_XLEFT || e.op == EX_INLEFT || e.op == EX_STREAMPOS) {
                    uint16_t a = 0;
                    if (UnaryEx(e.op)) { if (isConst[e.a]) { mu.push_back({M_LDI, d, 0, 0, cval[e.a]}); a = d; } else a = loc(e.a); }
                    const uint8_t c = e.op == EX_BYTE ? M_BYTE : e.op == EX_TABLE ? M_TABLE : e.op == EX_ARR ? M_ARR : e.op == EX_LOG2SLOT ? M_LOG2 :
                                      e.op == EX_BITPOS ? M_BITPOS : e.op == EX_DLEFT ? M_DLEFT : e.op == EX_XLEFT ? M_XLEFT : e.op == EX_INLEFT ? M_INLEFT :
                                      e.op == EX_U16 ? M_U16 : e.op == EX_U32 ? M_U32 : e.op == EX_U16BE ? M_U16BE : e.op == EX_U32BE ? M_U32BE : M_SPOS;
                    mu.push_back({c, d, a, 0, e.imm}); continue;
                }
                static const uint8_t RR0[] = {0, 0, M_ADD, M_SUB, M_MUL, M_SHL, M_SHR, M_AND, M_OR, M_XOR, M_LT, M_EQ, M_NE, M_GE};
                static const uint8_t RI0[] = {0, 0, M_ADDI, M_SUBI, M_MULI, M_SHLI, M_SHRI, M_ANDI, M_ORI, M_XORI, M_LTI, M_EQI, M_NEI, M_GEI};
                const auto RR = [](uint8_t o) -> uint8_t { return o == EX_DIV ? (uint8_t)M_DIV : o == EX_MOD ? (uint8_t)M_MOD : RR0[o]; };
                const auto RI = [](uint8_t o) -> uint8_t { return o == EX_DIV ? (uint8_t)M_DIVI : o == EX_MOD ? (uint8_t)M_MODI : RI0[o]; };
                const bool ca = isConst[e.a], cb = isConst[e.b];
                if (!ca && !cb) mu.push_back({RR(e.op), d, loc(e.a), loc(e.b), 0});
                else if (cb) mu.push_back({RI(e.op), d, loc(e.a), 0, cval[e.b]});
                else if (e.op == EX_ADD || e.op == EX_MUL || e.op == EX_AND || e.op == EX_OR || e.op == EX_XOR || e.op == EX_EQ || e.op == EX_NE) mu.push_back({RI(e.op), d, loc(e.b), 0, cval[e.a]});
                else if (e.op == EX_SUB) mu.push_back({M_RSUBI, d, loc(e.b), 0, cval[e.a]});
                else { mu.push_back({M_LDI, d, 0, 0, cval[e.a]}); mu.push_back({RR(e.op), d, d, loc(e.b), 0}); }
            }
            len[r] = (uint32_t)(mu.size() - start[r]);
        }
        // per mode, the next op that runs in it, and the mode's compiled program
        const size_t nops = D.ops.size();
        for (int m : {kCode, kDecode, kPrice}) {
            auto &k = skip[m]; k.assign(nops + 1, (uint16_t)nops);
            for (size_t pc = nops; pc-- > 0;) { const Op &o = D.ops[pc]; k[pc] = (!o.modes || (o.modes & m)) ? (uint16_t)pc : k[pc + 1]; }
            compile(D, m);
        }
    }
    Prog prog[8];
    std::vector<Affine> aff;
    // the affine form of expression i, if it has one
    bool affine(const Description &D, uint16_t i, Affine &f, int depth = 0) const {
        if (depth > 32) return false;
        if (isConst[i]) { f = Affine(); f.c0 = cval[i]; return true; }
        const Ex &e = D.ex[i]; Affine a, b;
        auto single = [](const Affine &x) { return x.n == 1 && x.c0 == 0; };
        switch (e.op) {
        case EX_REG: f = Affine(); f.n = 1; f.t[0].reg = (uint16_t)e.imm; return true;
        case EX_ADD:
            if (!affine(D, e.a, a, depth + 1) || !affine(D, e.b, b, depth + 1) || a.n + b.n > 4) return false;
            f = a; f.c0 += b.c0; for (int k = 0; k < b.n; ++k) f.t[f.n++] = b.t[k]; return true;
        case EX_SUB:
            if (!affine(D, e.a, a, depth + 1) || !affine(D, e.b, b, depth + 1) || a.n + b.n > 4) return false;
            f = a; f.c0 -= b.c0; for (int k = 0; k < b.n; ++k) { Term t = b.t[k]; t.mul = 0u - t.mul; f.t[f.n++] = t; } return true;
        case EX_MUL: case EX_SHL: {
            uint16_t x = e.a, c = e.b; if (e.op == EX_MUL && isConst[e.a] && !isConst[e.b]) { x = e.b; c = e.a; }
            if (!isConst[c] || !affine(D, x, f, depth + 1)) return false;
            const uint32_t k = e.op == EX_MUL ? cval[c] : (cval[c] >= 32 ? 0 : 1u << cval[c]);
            f.c0 *= k; for (int q = 0; q < f.n; ++q) f.t[q].mul *= k; return true; }
        case EX_AND:
            if (!isConst[e.b] || !affine(D, e.a, f, depth + 1) || !single(f) || f.t[0].ls || f.t[0].mul != 1) return false;
            f.t[0].mask &= cval[e.b]; return true;
        case EX_SHR:
            if (!isConst[e.b] || cval[e.b] >= 32 || !affine(D, e.a, f, depth + 1) || !single(f) || f.t[0].ls || f.t[0].mul != 1 || f.t[0].rs + cval[e.b] >= 32) return false;
            f.t[0].rs = (uint8_t)(f.t[0].rs + cval[e.b]); f.t[0].mask >>= cval[e.b]; return true;
        case EX_BYTE:
            if (!affine(D, e.a, a, depth + 1) || a.n != 1 || a.t[0].byte || a.t[0].rs || a.t[0].ls || a.t[0].mask != 0xFFFFFFFFu || a.t[0].mul != 1) return false;
            f = Affine(); f.n = 1; f.t[0].byte = 1; f.t[0].reg = a.t[0].reg; f.t[0].off = a.c0; return true;
        case EX_TABLE:
            if (D.ex[e.a].op != EX_REG) return false;
            f = Affine(); f.n = 1; f.t[0].byte = 2; f.t[0].reg = (uint16_t)D.ex[e.a].imm; f.t[0].off = e.imm; return true;
        default: return false;
        }
    }
    Opnd operand(const Description &D, uint16_t i) {
        Opnd q; if (isConst[i]) { q.k = 0; q.a = cval[i]; return q; }
        if (D.ex[i].op == EX_REG) { q.k = 1; q.r = (uint16_t)D.ex[i].imm; return q; }
        const Ex &e = D.ex[i];
        if ((e.op == EX_EQ || e.op == EX_NE || e.op == EX_LT || e.op == EX_GE) && D.ex[e.a].op == EX_REG && isConst[e.b]) { q.k = 4; q.r = (uint16_t)D.ex[e.a].imm; q.a = cval[e.b]; q.n = e.op; return q; }
        if (e.op == EX_TABLE && D.ex[e.a].op == EX_REG) { q.k = 5; q.r = (uint16_t)D.ex[e.a].imm; q.a = e.imm; return q; }
        Affine f; if (affine(D, i, f) && f.n >= 1) { q.k = 3; q.a = (uint32_t)aff.size(); aff.push_back(f); return q; }
        q.k = 2; q.r = res[i]; q.a = start[i]; q.n = len[i]; return q;
    }
    void compile(const Description &D, int m) {
        Prog &P = prog[m]; const size_t nops = D.ops.size();
        std::vector<uint32_t> idx(nops + 1, 0);
        for (size_t i = 0; i < nops; ++i) { const Op &o = D.ops[i]; if (!o.modes || (o.modes & m)) { idx[i] = (uint32_t)P.ins.size(); Ins in; in.orig = (uint32_t)i; P.ins.push_back(in); } }
        P.from.assign(nops + 1, (uint32_t)P.ins.size());
        for (size_t i = nops; i-- > 0;) P.from[i] = (!D.ops[i].modes || (D.ops[i].modes & m)) ? idx[i] : P.from[i + 1];
        for (Ins &in : P.ins) {
            const Op &o = D.ops[in.orig];
            in.op = o.op; in.flags = o.flags; in.nb = o.nb; in.tgt = o.tgt; in.imm = o.imm;
            in.x = operand(D, o.x); in.v = operand(D, o.v); in.m = operand(D, o.m);
            in.target = (o.op == OP_JZ || o.op == OP_JMP || o.op == OP_CALL) ? P.from[o.target] : 0;
        }
        { Ins end; end.op = F_OFFEND; end.orig = (uint32_t)nops; P.ins.push_back(end); }      // running off the end refuses
        // fuse: the fused form replaces only the FIRST instruction of its pattern and the rest stay in place, so a jump,
        // a return or a resumed read that lands inside a pattern runs the originals from there
        const size_t n = P.ins.size() - 1;
        auto isReg = [](const Opnd &q, uint8_t r) { return q.k == 1 && q.r == r; };
        for (size_t c = 0; c < n; ++c) {
            Ins &a = P.ins[c];
            if (a.op == OP_SET && c + 2 < n) {          // compute a bit, code it, branch on it
                const Ins &b = P.ins[c + 1], &j = P.ins[c + 2];
                if (b.op == OP_BIT && !b.flags && b.tgt == a.tgt && isReg(b.v, a.tgt) && j.op == OP_JZ && isReg(j.v, a.tgt)) {
                    Ins f = a; f.op = F_SETBITJZ; f.x = b.x; f.target = j.target; f.skip = 3; a = f; continue; }
            }
            if (a.op == OP_BIT && !a.flags && c + 1 < n) {                  // code a bit, branch on it
                const Ins &j = P.ins[c + 1];
                if (j.op == OP_JZ && isReg(j.v, a.tgt)) { a.op = F_BITJZ; a.target = j.target; a.skip = 2; continue; }
            }
            if (a.op == OP_DEC) {                                                             // a run of decisions
                size_t k = 1; while (k < 8 && c + k < n && P.ins[c + k].op == OP_DEC) ++k;
                if (k > 1) { Ins f = a; f.op = F_DECN; f.nb = (uint8_t)k; for (size_t q = 0; q < k; ++q) f.regs[q] = P.ins[c + q].tgt; f.skip = (uint32_t)k; a = f; }
            }
        }
        // jump threading: where an instruction falls through or branches to a JMP, it goes where the JMP goes (a chain is
        // followed a bounded number of hops; a JMP to itself stays)
        auto thread = [&](uint32_t t) { for (int h = 0; h < 64 && t < P.ins.size() && P.ins[t].op == OP_JMP && P.ins[t].target != t; ++h) t = P.ins[t].target; return t; };
        for (size_t c = 0; c < P.ins.size(); ++c) {
            Ins &a = P.ins[c];
            a.fall = thread((uint32_t)(c + (a.skip ? a.skip : 1)));
            if (a.op == OP_JZ || a.op == OP_JMP || a.op == OP_CALL || a.op == F_BITJZ || a.op == F_SETBITJZ) a.target = thread(a.target);
        }
    }
};

struct Huff { uint16_t code[kMaxSym], mcode[kMaxSym]; uint8_t len[kMaxSym]; int16_t count[17], sym[kMaxSym]; int nsym = 0; };   // code: bit-reversed (LSB-first coders); mcode: as is (BITS16M)

// Content as the machine sees it: DECODE writes it; CODE reads it through a window over a ByteSource.
// E8 (x86 CALL) translation of one frame (LZX's; not BCJ's, which also handles E9 and carries state): the encoder's forward transform (relative call targets made
// absolute) and the decoder's inverse, over a frame of n bytes whose first byte is at stream position `cur`; the last 10
// bytes are left as they are, and the 4 bytes after an E8 are skipped whether or not they changed. A bijection: the E8
// positions are the same either way, and each operand maps [-cur, fs) onto itself.
void E8Forward(uint8_t *b, uint32_t n, uint32_t cur, uint32_t fs) {     // (fs below 2^31: E8FRAME refuses more)
    if (n <= 10) return;
    for (uint32_t i = 0; i < n - 10; ++i) {
        if (b[i] != 0xE8) continue;
        const int64_t pos = (int64_t)cur + i, F = fs, rel = (int32_t)(b[i + 1] | b[i + 2] << 8 | b[i + 3] << 16 | (uint32_t)b[i + 4] << 24);
        if (rel >= -pos && rel < F) {
            const uint32_t abs = (uint32_t)(rel < F - pos ? rel + pos : rel - F);
            b[i + 1] = (uint8_t)abs; b[i + 2] = (uint8_t)(abs >> 8); b[i + 3] = (uint8_t)(abs >> 16); b[i + 4] = (uint8_t)(abs >> 24);
        }
        i += 4;
    }
}
void E8Inverse(uint8_t *b, uint32_t n, uint32_t cur, uint32_t fs) {
    if (n <= 10) return;
    for (uint32_t i = 0; i < n - 10; ++i) {
        if (b[i] != 0xE8) continue;
        const int64_t pos = (int64_t)cur + i, F = fs, abs = (int32_t)(b[i + 1] | b[i + 2] << 8 | b[i + 3] << 16 | (uint32_t)b[i + 4] << 24);
        if (abs >= -pos && abs < F) {
            const uint32_t rel = (uint32_t)(abs >= 0 ? abs - pos : abs + F);
            b[i + 1] = (uint8_t)rel; b[i + 2] = (uint8_t)(rel >> 8); b[i + 3] = (uint8_t)(rel >> 16); b[i + 4] = (uint8_t)(rel >> 24);
        }
        i += 4;
    }
}
struct ViewFrame { uint32_t n = 0, cur = 0, fs = 0; };

struct Content {
    uint8_t *w = nullptr; size_t cap = 0;            // DECODE: the buffer written
    const uint8_t *mem = nullptr; uint64_t size = 0; // CODE: all in memory ...
    ByteSource *src = nullptr; std::vector<uint8_t> buf; uint64_t lo = 0, hi = 0; uint32_t window = 0, grow = 16u << 10; bool err = false;   // ... or windowed
    //CODE (ISA 8): frames the format's code sees TRANSLATED (E8): what it reads there is the encoder's bytes, made from
    //the content's frame by the forward transform (one frame cached); the content itself is the real bytes
    std::map<uint64_t, ViewFrame> vframes; uint64_t wAt = UINT64_MAX, wEnd = 0; std::vector<uint8_t> *wcur = nullptr;
    std::map<uint64_t, std::pair<uint64_t, std::vector<uint8_t>>> wcache;   // translated frames (start -> last use, bytes)
    uint64_t wbytes = 0, wclock = 0, work = 0, workMark = 0;           // work: bytes translated (the machine's progress guard counts
                                                                         // it; past 64 MiB between two of its checks, reads stop)
    const ViewFrame *viewOf(uint64_t i, uint64_t &start) const {
        auto it = vframes.upper_bound(i);
        if (it == vframes.begin()) return nullptr;
        --it;
        if (i >= it->first + it->second.n) return nullptr;
        start = it->first; return &it->second;
    }
    uint8_t at(uint64_t i) {
        if (__builtin_expect(!vframes.empty(), 0)) {
            if (i >= wAt && i < wEnd) return (*wcur)[(size_t)(i - wAt)];   // the frame at hand (nearly every read)
            uint64_t s0; const ViewFrame *f = viewOf(i, s0);
            if (f) {
                auto it = wcache.find(s0);
                if (it == wcache.end() || it->second.second.size() != f->n) {
                    if (it != wcache.end()) { wbytes -= it->second.second.size(); wcache.erase(it); }
                    while (!wcache.empty() && wbytes + f->n > (8u << 20)) {   // 8 MiB of frames: an LZX window and more
                        auto old = wcache.begin(); for (auto j = wcache.begin(); j != wcache.end(); ++j) if (j->second.first < old->second.first) old = j;
                        wbytes -= old->second.second.size(); wcache.erase(old);
                    }
                    if (work - workMark > (64u << 20)) { err = true; return 0; }   // (a burst no check has seen: refused)
                    std::vector<uint8_t> b(f->n); for (uint32_t k = 0; k < f->n; ++k) b[k] = rawAt(s0 + k); E8Forward(b.data(), f->n, f->cur, f->fs);
                    work += f->n; wbytes += f->n; it = wcache.emplace(s0, std::make_pair(0, std::move(b))).first;
                }
                it->second.first = ++wclock; wcur = &it->second.second; wAt = s0; wEnd = s0 + f->n;
                return (*wcur)[(size_t)(i - s0)];
            }
        }
        return rawAt(i);
    }
    bool viewed(uint64_t i, uint64_t n) const {                       // does [i, i+n) touch a translated frame?
        if (vframes.empty() || !n) return false;
        auto it = vframes.upper_bound(i + n - 1);
        if (it == vframes.begin()) return false;
        --it;
        return it->first + it->second.n > i;
    }
    uint8_t rawAt(uint64_t i) {
        if (mem) return i < size ? mem[i] : 0;
        if (i >= size) return 0;
        if (i < lo || i >= hi) { refill(i); if (err || i < lo || i >= hi) return 0; }
        return buf[(size_t)(i - lo)];
    }
    // The window SLIDES: reading forward fetches only the new bytes from the layer below and drops what falls out of the
    // format's window in batches, so a layer reads each byte of the one below about once, however deep the stack.
    // It GROWS with demand (16 KiB, doubling to 1 MiB while reads are contiguous): a segment that needs a little of the layer below asks for a
    // little, so the layers under it are not made to decode far ahead of what is read (that serialises the pipeline).
    // What lies BEHIND is fetched only when it is read (an LZMA literal's match byte): a format whose code never looks back
    // (LZ4, deflate: copies do not read their source to be coded) asks the layer below for nothing before its segment.
    void refill(uint64_t i, uint32_t need = 1) {
        const uint64_t back = std::min<uint64_t>(window, 8u << 20) + 4096;
        if (hi > lo && i < lo && lo - i <= back) {                        // behind, within the format's window: prepend
            // doubling (a description reading further and further back fetches in few reads), never past the format's
            // window, and the far end is dropped so the window stays about 2 windows big: a description walking
            // backwards cannot make it hold the whole content
            const uint64_t ext = std::max<uint64_t>(lo - i, std::min<uint64_t>(back, std::max<uint64_t>(buf.size(), 64u << 10))), from = lo > ext ? lo - ext : 0;
            const size_t keepHi = (size_t)std::min<uint64_t>(buf.size(), 2 * back + (4u << 20));
            std::vector<uint8_t> b((size_t)(lo - from) + keepHi);
            if (!src->preadAll(b.data(), (size_t)(lo - from), from)) { err = true; return; }
            memcpy(b.data() + (lo - from), buf.data(), keepHi); buf.swap(b); hi = lo + keepHi; lo = from;
            return;
        }
        if (hi > lo && i >= hi && i - hi <= (64u << 10)) {               // forward, contiguous (or a small gap): append
            grow = std::min<uint32_t>(grow * 2, 1u << 20);
            const uint64_t to2 = std::min<uint64_t>(size, std::max<uint64_t>(i + need, hi + grow));
            const size_t o = buf.size(); buf.resize(o + (size_t)(to2 - hi));
            if (!src->preadAll(buf.data() + o, (size_t)(to2 - hi), hi)) { err = true; buf.resize(o); return; }
            hi = to2; ahead();
            const uint64_t keep = i > back ? i - back : 0;
            if (keep > lo + (4u << 20)) { buf.erase(buf.begin(), buf.begin() + (long)(keep - lo)); lo = keep; }
            return;
        }
        // anywhere else: a fresh window. After a JUMP forward the format reads sparsely here (the bytes between were copy
        // runs, handed down, or matches, never read), so the window starts small instead of fetching what it skips.
        grow = 16u << 10;
        const uint64_t from = i, to3 = std::min<uint64_t>(size, i + std::max<uint32_t>(grow, need));
        buf.resize((size_t)(to3 - from));
        if (!src->preadAll(buf.data(), buf.size(), from)) { err = true; lo = hi = 0; buf.clear(); return; }
        lo = from; hi = to3; ahead();
    }
    void ahead() { if (hi < size) src->prefetch(hi, std::min<uint64_t>(size - hi, grow)); }   // the next window, decoding below while this one is used
    // n content bytes from i appended to `out` in one go: a copy run passes straight through to the layer below (a delta
    // underneath composes its own chain into one map), never byte by byte
    bool copyTo(std::vector<uint8_t> &out, uint64_t i, uint32_t n) {
        if (i + n > size) return false;
        if (mem) { out.insert(out.end(), mem + i, mem + i + n); return true; }
        if ((i < lo || i + n > hi) && n <= (32u << 10)) { refill(i, n); if (err) return false; }   // a short run slides the window (one read below, not one per run)
        if (i >= lo && i + n <= hi) { out.insert(out.end(), buf.data() + (i - lo), buf.data() + (i - lo) + n); return true; }
        const size_t o = out.size(); out.resize(o + n);
        if (!src->preadAll(out.data() + o, n, i)) { err = true; return false; }
        return true;
    }
};

// The decisions a CODE run consumes, chunk by chunk (a chunk per checkpoint segment).
struct Decisions {
    std::vector<uint32_t> chunk;                                     // a record's current chunk (the storage)
    const uint32_t *b = nullptr, *p = nullptr, *e = nullptr;         // what is being read: the chunk, or all in memory (mint)
    uint64_t base = 0, total = 0;
    std::function<bool(std::vector<uint32_t> &, uint64_t &)> next;   // loads the following chunk
    void setMem(const uint32_t *m, size_t n) { b = p = m; e = m + n; base = 0; }
    void setChunk() { b = p = chunk.data(); e = b + chunk.size(); }
    uint64_t consumed() const { return base + (uint64_t)(p - b); }
    __attribute__((always_inline)) bool get(uint32_t &v) { if (__builtin_expect(p < e, 1)) { v = *p++; return true; } return refill(v); }
    bool refill(uint32_t &v) { while (p >= e) { if (!next || !next(chunk, base)) return false; setChunk(); } v = *p++; return true; }
};

// DEMAND (22.15 axiom 10): a CODE run's output is GENERATED bytes (the pool) and COPY runs - content bytes passed through
// as they are (a byte run of the bit coder: LZ4 literals, stored blocks, container members). A copy run is kept as a range
// of the content, never materialised: a read hands it to the layer below, which hands ITS copy runs further down, so
// a byte copied through any number of layers is written once, by the layer that holds it, straight into the reader's buffer.
struct CopyRun { uint64_t at = 0, from = 0, pool = 0; uint32_t n = 0; };

// PREDICT's parses (22.15.4): one per block, shared by every machine of a stream (the segments of one block, decoding in
// parallel, wait for the one parse instead of each running it), the least recently used going first.
using Seqs = std::shared_ptr<const std::vector<Lz4Seq>>;
struct PredictCache {
    struct E { Seqs seqs; bool ready = false; uint64_t used = 0; };
    std::mutex mu; std::condition_variable cv; std::map<std::tuple<uint32_t, uint32_t, uint32_t>, E> m; uint64_t clock = 0;
    //the whole stream's parse work, every segment's together (a record of many tiny segments gets no allowance per
    //segment): 128 steps a byte of the stream and its content, plus two of the largest blocks. Each DISTINCT block is
    //charged once, by its first parse: parsing it again (its parse evicted, a segment decoded again) is reading, which
    //a mount does for as long as it lives, never a reason to refuse it
    std::atomic<uint64_t> steps{0}; uint64_t streamBudget = UINT64_MAX;
    //zlib-family parses are each machine's own (a reader's segments decode in parallel: one shared incremental parse,
    //which keeps only a window of tokens behind it, was dragged back and forth between them and re-parsed from the
    //stream's start over and over). Shared: how far each stream has been parsed, so only NEW ground is charged to the
    //stream's account (a million streams remembered at most; past that, parses are charged again)
    std::map<std::tuple<uint64_t, uint64_t, uint32_t>, uint64_t> zfurthest;   // (guarded by mu)
    //the LZX family (ISA 9): one compressor for the stream's folders, in order, fed 32 KiB at a time and only as far as a
    //frame asked for; the frames it made: past lzxKept bytes the oldest a CODE run has written go (segments decode out of
    //order: a frame no run has written yet is kept, up to 8 x lzxKept); one asked for again is made again from the
    //stream's start, paid once. Shared by a stream's segments; a mint carries it from its second decode to its coding.
    struct LzxFolder { uint64_t at = 0, n = 0, fed = 0, base = 0, steps0 = 0; uint32_t e8 = 0, knob = 0; bool started = false, flushed = false;
                       struct Fr { std::vector<uint8_t> b; bool used = false; };
                       std::deque<Fr> frames; };   // (frames: [base, base + size) of the folder's)
    struct LzxFamily { std::mutex m; LzxMakecab *ctx = nullptr; uint32_t ctxKnob = 0; bool dead = false; std::atomic<bool> over{false};
                       std::deque<LzxFolder> folders; uint64_t kept = 0, total = 0, paid = 0, rework = 0;   // frame bytes held; steps this build, ever paid, made again
                       ~LzxFamily() { LzxMakecabFree(ctx); } };
    std::shared_ptr<LzxFamily> lzx; uint64_t lzxKept = 64ull << 20;   // (frame bytes a family keeps; tests lower it)                                      // (made under mu)
    std::shared_ptr<LzxFamily> lzxFamily() { std::lock_guard<std::mutex> l(mu); if (!lzx) lzx = std::make_shared<LzxFamily>(); return lzx; }
    uint64_t zFurthest(uint64_t Lo, uint64_t Hi, uint32_t K) { std::lock_guard<std::mutex> l(mu); auto it = zfurthest.find({Lo, Hi, K}); return it == zfurthest.end() ? 0 : it->second; }
    void zReached(uint64_t Lo, uint64_t Hi, uint32_t K, uint64_t R) {
        std::lock_guard<std::mutex> l(mu);
        auto it = zfurthest.find({Lo, Hi, K});
        if (it != zfurthest.end()) it->second = std::max(it->second, R); else if (zfurthest.size() < (1u << 20)) zfurthest[{Lo, Hi, K}] = R;
    }
    std::set<std::tuple<uint32_t, uint32_t, uint32_t>> charged;     // (guarded by mu)
    bool isCharged(uint32_t Lo, uint32_t Hi, uint32_t Att) { std::lock_guard<std::mutex> l(mu); return charged.count({Lo, Hi, Att}) > 0; }
    //(a million blocks at most are remembered: a real stream has thousands; past that every parse is charged again)
    void charge(uint32_t Lo, uint32_t Hi, uint32_t Att, uint64_t S) {
        std::lock_guard<std::mutex> l(mu);
        if (charged.count({Lo, Hi, Att})) return;
        steps += S;
        if (charged.size() < (1u << 20)) charged.insert({Lo, Hi, Att});
    }
    // the block [Lo, Hi)'s parse, made by `Make` here if no machine has it or is making it
    template <class F> Seqs get(uint32_t Lo, uint32_t Hi, uint32_t Att, F &&Make) {
        const auto k = std::make_tuple(Lo, Hi, Att);
        std::unique_lock<std::mutex> l(mu);
        for (;;) {
            auto it = m.find(k);
            if (it == m.end()) break;
            if (it->second.ready) { it->second.used = ++clock; return it->second.seqs; }
            cv.wait(l);                                                  // another machine is parsing it
        }
        m[k] = E{}; l.unlock();
        auto v = std::make_shared<std::vector<Lz4Seq>>(); const bool ok = Make(*v);
        l.lock();
        if (!ok) { m.erase(k); cv.notify_all(); return nullptr; }
        E &e = m[k]; e.seqs = v; e.ready = true; e.used = ++clock;
        auto held = [&] { size_t b = 0; for (const auto &x : m) if (x.second.seqs) b += x.second.seqs->size() * sizeof(Lz4Seq); return b; };
        while (m.size() > 64 || (m.size() > 1 && held() > (64u << 20))) { // a few blocks per decoding thread, 64 MiB at most
            auto victim = m.end(); for (auto j = m.begin(); j != m.end(); ++j) if (j->second.ready && j->first != k && (victim == m.end() || j->second.used < victim->second.used)) victim = j;
            if (victim == m.end()) break;
            m.erase(victim);
        }
        cv.notify_all(); return v;
    }
};   // segment offset, content offset, pool bytes before it, length
constexpr uint32_t kRunMin = 256;                                          // shorter runs are copied into the pool (a hand-down costs more)

struct Machine {
    const Description &D; const Spec &S; int mode;
    const char *why = nullptr;
    int failOp = -1;                               // the description's op that refused (an assert), for the message
    std::vector<uint32_t> v;                       // registers, then one value per expression
    std::vector<uint16_t> slot;
    std::vector<std::vector<uint32_t>> arr;
    Huff hf[kMaxHuff];
    std::vector<uint8_t> hlens[kMaxHuff];           // the lengths each code was built from (checkpoints keep them)
    // range coder
    uint64_t low = 0; uint32_t range = 0xFFFFFFFFu; uint8_t cache = 0; uint64_t cacheSize = 1; uint32_t code = 0;
    // bit coder
    uint64_t acc = 0; int bn = 0; uint64_t bipos = 0;
    //DECODE, BITS16M: words are counted from where bits begin (a container's bitstream starts wherever its block does): wb
    //is that bit position; after bytes (byterun, rawbytes) the next bits start a new run of words where they stand
    uint64_t wb = 0; bool bytesMode = true;
    // bytes in (DECODE) / out (CODE)
    const uint8_t *in = nullptr; size_t inn = 0, ip = 0;
    std::vector<uint8_t> *out = nullptr;
    std::vector<CopyRun> *runs = nullptr; uint64_t copied = 0;   // CODE on the read side: copy runs kept as ranges
    uint64_t outBase = 0;                                         // CODE: where this run's output starts in the stream (a segment's checkpoint)
    Content X; Decisions Dc; std::vector<uint32_t> *decOut = nullptr;
    uint32_t price = 0;
    int pc = 0; std::vector<int> stk;
    uint64_t fuel = 0, fuelBase = 0;
    uint64_t prog0 = 0;                            // progress at the start or the restore: budgets count what this run does
    bool zCatchUp = false; uint64_t zCaught = 0;   // the one zlib catch-up this run (since its start or restore) was granted
    //DECODE (ISA 8): the frame opened by E8FRAME (its decision's slot, filled at E8END), and the translated frames, converted
    //to the real bytes when the run ends (until then the buffer holds what the encoder's window held: copies read that)
    struct E8Open { uint64_t at = 0; ViewFrame f; size_t slot = 0; bool open = false; } e8open;
    //the LZX family (ISA 9): the folders this stream has opened, in order (CODE: a checkpoint carries them, so a restored
    //reader can bring the compressor to the open one); the open one; DECODE: its decision's slot; CODE: the family's?
    struct LzxRef { uint64_t at = 0, n = 0; uint32_t e8 = 0, knob = 0; };
    std::vector<LzxRef> lzxList; int lzxCur = -1; size_t lzxSlot = 0; bool lzxOpen = false, lzxAvail = false, lzxBad = false; uint32_t lzxUse = 0;
    const std::vector<std::pair<uint64_t, ViewFrame>> *e8prev = nullptr;   // DECODE, a mint's second pass: the first's frames
    //the real bytes [a, b) of folder [fa, fb): CODE reads the content; DECODE has what the encoder saw, made real again
    //with the first pass's translated frames (each undone whole: a frame may reach past the piece asked for)
    bool lzxReal(uint64_t a, uint64_t b, uint64_t fa, uint64_t fb, uint8_t *o) {
        if (mode != kDecode) {
            if (b > X.size) return fail("an LZX folder past the content"), false;
            if (X.mem) { memcpy(o, X.mem + a, (size_t)(b - a)); return true; }
            if (!X.src || !X.src->preadAll(o, (size_t)(b - a), a)) return fail("the content does not read"), false;
            return true;
        }
        if (b > X.cap) return fail("an LZX folder past the content"), false;
        if (!e8prev) { memcpy(o, X.w + a, (size_t)(b - a)); return true; }
        const auto &V = *e8prev;
        auto it = std::partition_point(V.begin(), V.end(), [&](const auto &f) { return f.first + f.second.n <= a; });
        uint64_t lo = a, hi = b; auto e = it;
        for (; e != V.end() && e->first < b; ++e) {
            if (e->first < fa || e->first + e->second.n > fb) return fail("an E8 frame across an LZX folder's edge"), false;
            lo = std::min<uint64_t>(lo, e->first); hi = std::max<uint64_t>(hi, e->first + e->second.n);
        }
        if (it == e) { memcpy(o, X.w + a, (size_t)(b - a)); return true; }
        std::vector<uint8_t> t(X.w + lo, X.w + hi);
        for (auto f = it; f != e; ++f) E8Inverse(t.data() + (f->first - lo), f->second.n, f->second.cur, f->second.fs);
        memcpy(o, t.data() + (a - lo), (size_t)(b - a)); return true;
    }
    //one step of the family toward folder `idx`: the first folder not yet flushed is started, fed 32 KiB, or flushed.
    //Its work is the stream's account (new ground only: a build made again after frames were dropped is paid already),
    //and at most 64 steps a folder byte (real data: 7-35)
    bool lzxStep(PredictCache::LzxFamily &f, size_t want, uint64_t wantK) {
        size_t j = 0; while (j < f.folders.size() && f.folders[j].flushed) ++j;
        if (j == f.folders.size()) return false;
        auto &T = f.folders[j];
        if (!T.started) {
            const uint32_t wbits = T.knob & 0xFF, second = ((T.knob >> 8) & 0xFF) << 15;
            const int r0 = !f.ctx ? ((f.ctx = LzxMakecabNew(wbits, second)) ? LZXMK_OK : LZXMK_ERROR)
                         : f.ctxKnob == T.knob ? LzxMakecabNextFolder(f.ctx) : LzxMakecabNextFolderWindow(f.ctx, wbits, second);   // (another window: MAKECAB's new compressor)
            f.ctxKnob = T.knob;
            if (r0 != LZXMK_OK) { f.dead = true; return false; }
            T.started = true; T.steps0 = f.total;
        }
        struct Sink { static int put(void *a, const uint8_t *p, uint32_t n, uint32_t) {
            auto *x = static_cast<std::pair<PredictCache::LzxFolder *, uint64_t *> *>(a); x->first->frames.push_back({std::vector<uint8_t>(p, p + n), false}); *x->second += n; return 0; } };
        std::pair<PredictCache::LzxFolder *, uint64_t *> arg{&T, &f.kept};
        const uint64_t had = LzxMakecabSteps(f.ctx), spent = pcache->steps.load();
        //(ground made again after its frames were dropped is paid, but not free: 8 x the stream's account at most, so
        //readers far apart, or a description asking back and forth, cannot rebuild without end)
        const uint64_t budget = pcache->streamBudget, reworkCap = budget > UINT64_MAX / 8 ? UINT64_MAX : budget * 8;
        const uint64_t paidLeft = std::min(f.paid - std::min(f.paid, f.total), reworkCap - std::min(reworkCap, f.rework));
        const uint64_t room = paidLeft + (budget > spent ? budget - spent : 0);
        const uint64_t cap = T.steps0 + 64 * T.n + (1u << 20);
        LzxMakecabLimit(f.ctx, had + std::min(room, cap > f.total ? cap - f.total : 0));
        int r;
        if (T.fed < T.n) {
            const uint32_t len = (uint32_t)std::min<uint64_t>(0x8000, T.n - T.fed);
            uint8_t buf[0x8000];
            if (!lzxReal(T.at + T.fed, T.at + T.fed + len, T.at, T.at + T.n, buf)) return false;
            r = LzxMakecabCompress(f.ctx, buf, len, T.e8, 1, &Sink::put, &arg); T.fed += len;
        } else { r = LzxMakecabFlush(f.ctx, &Sink::put, &arg); T.flushed = true; }
        const uint64_t did = LzxMakecabSteps(f.ctx) - had;
        f.rework += std::min(did, f.paid - std::min(f.paid, f.total));   // (the part on ground already paid)
        f.total += did;
        if (f.total > f.paid) { pcache->steps += f.total - f.paid; f.paid = f.total; }
        if (r != LZXMK_OK) { f.dead = true; if (r == LZXMK_OVER) f.over = true; return false; }
        //(past the bound the oldest written frames go, past 8 x the bound any; the frame asked for, and its folder's after
        //it, stay)
        const uint64_t keep = pcache->lzxKept, hard = keep * 8;
        for (size_t q = 0; q < f.folders.size() && f.kept > keep; ++q)
            while (f.kept > keep && !f.folders[q].frames.empty() && !(q == want && f.folders[q].base >= wantK)
                   && (f.folders[q].frames.front().used || f.kept > hard)) {
                f.kept -= f.folders[q].frames.front().b.size(); f.folders[q].frames.pop_front(); ++f.folders[q].base; }
        return true;
    }
    //frame k of folder idx, handed to `use` under the family's lock: 1 done, 0 the folder has no frame k, -1 the family
    //does not make it (not this encoder, or past the account), -2 refused (`why` says)
    template <class U> int lzxFrame(int idx, uint64_t k, U &&use, bool written = false) {
        if (idx < 0 || idx >= (int)lzxList.size()) return -1;
        if (!pcache) pcache = std::make_shared<PredictCache>();
        auto fam = pcache->lzxFamily();
        std::lock_guard<std::mutex> g(fam->m);
        PredictCache::LzxFamily &f = *fam;
        for (int i = 0; i <= idx; ++i) {                                  // the folders as this stream opens them
            const LzxRef &L = lzxList[(size_t)i];
            if (i < (int)f.folders.size()) {
                const auto &F = f.folders[(size_t)i];
                if (F.at != L.at || F.n != L.n || F.e8 != L.e8 || F.knob != L.knob) { fail("LZX folders out of step with the family's"); return -2; }
            } else { PredictCache::LzxFolder F; F.at = L.at; F.n = L.n; F.e8 = L.e8; F.knob = L.knob; f.folders.push_back(std::move(F)); }
        }
        auto *T = &f.folders[(size_t)idx];
        if (k < T->base) {                                                // dropped: made again from the stream's start
            LzxMakecabFree(f.ctx); f.ctx = nullptr; f.dead = false; f.over = false; f.kept = 0; f.total = 0;
            for (auto &F : f.folders) { F.fed = 0; F.base = 0; F.started = false; F.flushed = false; F.frames.clear(); }   // (written or not)
        }
        for (;;) {
            if (k < T->base + T->frames.size()) { auto &F = T->frames[(size_t)(k - T->base)]; use(F.b); F.used |= written; predictedAny = true; return 1; }
            if (T->flushed) return 0;
            if (f.dead) return -1;
            if (!lzxStep(f, (size_t)idx, k)) return why ? -2 : -1;
        }
    }
    //NEAREST's index: hash chains (3-byte and 2-byte keys, newest first) over the content from `lo` up to `upto`, the
    //machine's own; positions the window no longer reaches are dropped by the ring
    struct NIdx { uint64_t lo = UINT64_MAX, upto = 0; uint32_t mask = 0; std::vector<uint32_t> h3, h2, p3, p2; } nidx;
    uint8_t cbyte(uint64_t i) { return mode == kDecode ? (i < X.cap ? X.w[i] : 0) : X.at(i); }
    bool overBudget() const { return fuel + X.work > fuelBase + (1u << 22) + 512 * (progress() - std::min(prog0, progress())); }
    uint32_t nearest(uint64_t at, uint32_t len, uint64_t lo, uint32_t maxd) {
        if (len < 2 || at <= lo || maxd == 0) return kNoPrediction;
        const uint64_t have = mode == kDecode ? X.cap : X.size;
        if (at + len > have) return kNoPrediction;
        uint64_t ring64 = 1; while (ring64 < (uint64_t)maxd + 1) ring64 <<= 1;   // (maxd <= WINDOW <= 2^25: Validate)
        if (ring64 > (1u << 26)) return kNoPrediction;
        const uint32_t ring = (uint32_t)ring64;
        NIdx &n = nidx;
        if (n.lo != lo || n.mask != ring - 1 || at < n.upto) {           // another stream, window or a step back: anew
            if (n.mask != ring - 1 || n.p3.empty()) { n.p3.assign(ring, UINT32_MAX); n.p2.assign(ring, UINT32_MAX); n.h3.assign(1u << 16, UINT32_MAX); n.h2.assign(1u << 16, UINT32_MAX); }
            else { std::fill(n.p3.begin(), n.p3.end(), UINT32_MAX); std::fill(n.p2.begin(), n.p2.end(), UINT32_MAX); std::fill(n.h3.begin(), n.h3.end(), UINT32_MAX); std::fill(n.h2.begin(), n.h2.end(), UINT32_MAX); }
            fuel += 2ull * ring + (1u << 17);                             // (making the index is work too)
            if (overBudget()) { fail("a description that works without making progress"); return kNoPrediction; }
            n.lo = lo; n.mask = ring - 1;
            n.upto = at - std::min<uint64_t>(at - lo, maxd);
        }
        if (at - n.upto > maxd) n.upto = at - maxd;                       // (what the window cannot reach is not indexed)
        fuel += at - n.upto;                                              // (the indexing is work: the progress guard sees it)
        if (overBudget()) { fail("a description that works without making progress"); return kNoPrediction; }
        for (; n.upto < at; ++n.upto) {
            const uint64_t q = n.upto; const uint8_t b0 = cbyte(q), b1 = cbyte(q + 1), b2 = cbyte(q + 2);
            const uint32_t k2 = (uint32_t)b0 << 8 | b1, k3 = ((uint32_t)b0 << 16 | (uint32_t)b1 << 8 | b2) * 2654435761u >> 16;
            n.p2[q & n.mask] = n.h2[k2]; n.h2[k2] = (uint32_t)(q - lo);
            n.p3[q & n.mask] = n.h3[k3]; n.h3[k3] = (uint32_t)(q - lo);
        }
        const uint8_t a0 = cbyte(at), a1 = cbyte(at + 1), a2 = len >= 3 ? cbyte(at + 2) : 0;
        const bool three = len >= 3;
        uint32_t c = three ? n.h3[((uint32_t)a0 << 16 | (uint32_t)a1 << 8 | a2) * 2654435761u >> 16] : n.h2[(uint32_t)a0 << 8 | a1];
        fuel += 128;
        for (int steps = 0; c != UINT32_MAX && steps < 128; ++steps) {
            const uint64_t cand = lo + c;
            if (cand >= at || at - cand > maxd) break;
            uint32_t k = 0; while (k < len && cbyte(cand + k) == cbyte(at + k)) ++k;
            if (k == len) return (uint32_t)(at - cand);
            c = three ? n.p3[cand & n.mask] : n.p2[cand & n.mask];
            if (c != UINT32_MAX && lo + c >= cand) break;                // (a ring slot reused: older than the window)
        }
        return kNoPrediction;
    }
    std::vector<std::pair<uint64_t, ViewFrame>> e8done;
    void e8finish() { for (const auto &[at, f] : e8done) if (at + f.n <= X.cap) E8Inverse(X.w + at, f.n, f.cur, f.fs); e8done.clear(); }
    // CODE: what a reader restored here needs of the frame table (the frames its window can still read)
    void e8prune() {
        const uint64_t keep = place() > D.window ? place() - D.window : 0;
        for (auto it = X.vframes.begin(); it != X.vframes.end();) { if (it->first + it->second.n <= keep) it = X.vframes.erase(it); else ++it; }
        X.wAt = UINT64_MAX; X.wEnd = 0; X.wcur = nullptr; X.wcache.clear(); X.wbytes = 0;
    }
    std::map<std::tuple<uint64_t, uint64_t, uint32_t>, std::unique_ptr<ZlibParser>> zown;   // this machine's zlib parses (2 at most)
    uint64_t progress() const { return (uint64_t)(out ? out->size() + copied : 0) + place() + ip + (bipos >> 3); }
    uint64_t stopAt = UINT64_MAX;                   // CODE: pause at a MARK once this much output exists
    uint64_t maxCache = UINT64_MAX;                 // a restored range coder may hold back at most this many bytes
    // PREDICT (ISA 5): off in a PLAIN run (its record never takes a prediction) and in PRICE; DECODE predicts only once
    // the whole content is there (a mint's second pass: the parse of a block reads all of it)
    bool noPredict = false, wholeContent = false;
    std::shared_ptr<PredictCache> pcache; Seqs pseqs; uint32_t plo = 0, phi = 0, patt = 0; uint64_t psteps = 0;
    bool predictedAny = false;                     // a token was predicted (a mint whose family never predicts mints plain)

    Machine(const Description &d, const Spec &s, int m) : D(d), S(s), mode(m) {
        v.assign(kRegs + D.ex.size(), 0); slot.assign(D.nslots, 1024);
        arr = D.arrays; for (auto &h : hf) h.nsym = 0;
    }
    bool fail(const char *m) { if (!why) why = m; return false; }

    uint32_t &reg(int i) { return v[(size_t)i]; }
    uint32_t place() const { return v[kRegPlace]; }

    // ---- expressions: the compiled micro-ops
    template <int M> __attribute__((always_inline)) uint32_t term(const Term &t) {
        uint32_t x = v[t.reg];
        if (t.byte == 1) { const uint32_t a = x + t.off; x = M == kDecode ? (a < place() && a < X.cap ? X.w[a] : 0) : X.at(a); }
        else if (t.byte == 2) { const auto &tb = D.tables[t.off]; if (__builtin_expect(x >= tb.size(), 0)) { fail("a table read out of range"); return 0; } x = tb[x]; }
        return (((x >> t.rs) & t.mask) << t.ls) * t.mul;
    }
    template <int M> __attribute__((always_inline)) uint32_t opnd(const Opnd &q) {
        switch (q.k) {
        case 0: return q.a;
        case 1: return v[q.r];
        case 3: { const Affine &f = S.aff[q.a]; uint32_t r = f.c0 + term<M>(f.t[0]);
            if (f.n > 1) { r += term<M>(f.t[1]); for (int k = 2; k < f.n; ++k) r += term<M>(f.t[k]); }
            return r; }
        case 4: { const uint32_t x = v[q.r]; return q.n == EX_EQ ? x == q.a : q.n == EX_NE ? x != q.a : q.n == EX_LT ? x < q.a : x >= q.a; }
        case 5: { const auto &t = D.tables[q.a]; const uint32_t i = v[q.r]; if (__builtin_expect(i >= t.size(), 0)) { fail("a table read out of range"); return 0; } return t[i]; }
        default: return evRange<M>(q.a, q.n, q.r);
        }
    }
    template <int M> __attribute__((always_inline)) uint32_t evT(uint16_t r) {
        if (S.isConst[r]) return S.cval[r];
        return evRange<M>(S.start[r], S.len[r], S.res[r]);
    }
    template <int M> uint32_t evRange(uint32_t start, uint32_t len, uint16_t res) {
        const Mu *m = S.mu.data() + start, *e = m + len;
        uint32_t *x = v.data();
        for (; m < e; ++m) {
            uint32_t &o = x[m->d];
            switch (m->c) {
            case M_ADD: o = x[m->a] + x[m->b]; break;    case M_ADDI: o = x[m->a] + m->imm; break;
            case M_SUB: o = x[m->a] - x[m->b]; break;    case M_SUBI: o = x[m->a] - m->imm; break; case M_RSUBI: o = m->imm - x[m->a]; break;
            case M_MUL: o = x[m->a] * x[m->b]; break;    case M_MULI: o = x[m->a] * m->imm; break;
            case M_SHL: { const uint32_t s = x[m->b]; o = s >= 32 ? 0 : x[m->a] << s; break; } case M_SHLI: o = m->imm >= 32 ? 0 : x[m->a] << m->imm; break;
            case M_SHR: { const uint32_t s = x[m->b]; o = s >= 32 ? 0 : x[m->a] >> s; break; } case M_SHRI: o = m->imm >= 32 ? 0 : x[m->a] >> m->imm; break;
            case M_AND: o = x[m->a] & x[m->b]; break;    case M_ANDI: o = x[m->a] & m->imm; break;
            case M_OR: o = x[m->a] | x[m->b]; break;     case M_ORI: o = x[m->a] | m->imm; break;
            case M_XOR: o = x[m->a] ^ x[m->b]; break;    case M_XORI: o = x[m->a] ^ m->imm; break;
            case M_LT: o = x[m->a] < x[m->b]; break;     case M_LTI: o = x[m->a] < m->imm; break;
            case M_EQ: o = x[m->a] == x[m->b]; break;    case M_EQI: o = x[m->a] == m->imm; break;
            case M_NE: o = x[m->a] != x[m->b]; break;    case M_NEI: o = x[m->a] != m->imm; break;
            case M_GE: o = x[m->a] >= x[m->b]; break;    case M_GEI: o = x[m->a] >= m->imm; break;
            case M_LDI: o = m->imm; break;
            case M_DIV: case M_MOD: { const uint32_t b = x[m->b]; if (!b) { fail("a division by zero"); o = 0; } else o = m->c == M_DIV ? x[m->a] / b : x[m->a] % b; break; }
            case M_DIVI: case M_MODI: if (!m->imm) { fail("a division by zero"); o = 0; } else o = m->c == M_DIVI ? x[m->a] / m->imm : x[m->a] % m->imm; break;
            case M_COPY: o = x[m->a]; break;
            case M_BYTE: { const uint32_t a = x[m->a]; o = M == kDecode ? (a < place() && a < X.cap ? X.w[a] : 0) : X.at(a); break; }
            case M_U16: case M_U32: case M_U16BE: case M_U32BE: {        // (each byte read as M_BYTE reads one)
                const uint32_t a = x[m->a]; const int n = m->c == M_U16 || m->c == M_U16BE ? 2 : 4; const bool be = m->c == M_U16BE || m->c == M_U32BE;
                o = 0;
                for (int k = 0; k < n; ++k) {
                    const uint64_t q = (uint64_t)a + (uint64_t)k; uint32_t b = 0;
                    if (q <= 0xFFFFFFFFu) b = M == kDecode ? (q < place() && q < X.cap ? X.w[q] : 0) : X.at(q);
                    o |= b << (be ? 8 * (n - 1 - k) : 8 * k);
                }
                break; }
            case M_TABLE: { const uint32_t a = x[m->a]; const auto &t = D.tables[m->imm]; if (a >= t.size()) { fail("a table read out of range"); o = 0; } else o = t[a]; break; }
            case M_ARR: { const uint32_t a = x[m->a]; const auto &t = arr[m->imm]; if (a >= t.size()) { fail("an array read out of range"); o = 0; } else o = t[a]; break; }
            case M_LOG2: { const uint32_t a = x[m->a]; if (a < 4) o = a; else { const uint32_t z = 31 - (uint32_t)__builtin_clz(a); o = 2 * z + ((a >> (z - 1)) & 1); } break; }
            case M_BITPOS: o = D.coder == kBits16M ? (M == kDecode ? (bytesMode ? 0u : (uint32_t)((bipos - wb) & 15)) : (uint32_t)(bn & 15)) : M == kDecode ? (uint32_t)(bipos & 7) : (uint32_t)(bn & 7); break;
            case M_DLEFT: o = (uint32_t)std::min<uint64_t>(0xFFFFFFFFu, Dc.total > Dc.consumed() ? Dc.total - Dc.consumed() : 0); break;
            case M_XLEFT: { const uint64_t sz = M == kDecode ? X.cap : X.size; o = sz > place() ? (uint32_t)std::min<uint64_t>(0xFFFFFFFFu, sz - place()) : 0; break; }
            case M_INLEFT: o = M == kDecode ? (uint32_t)std::min<uint64_t>(0xFFFFFFFFu, inn * 8 > bipos ? inn * 8 - bipos : 0) : 0; break;
            case M_SPOS: o = (uint32_t)std::min<uint64_t>(0xFFFFFFFFu, M == kDecode ? (D.coder != kRange ? bipos >> 3 : ip) : M == kCode && out ? outBase + out->size() + copied + (uint64_t)(bn >> 3) : 0); break;
            }
        }
        return x[res];
    }

    uint32_t ev(uint16_t r) { return mode == kDecode ? evT<kDecode>(r) : mode == kPrice ? evT<kPrice>(r) : evT<kCode>(r); }

    // ---- the range coder
    void rcShift() {
        if ((uint32_t)low < 0xFF000000u || (int)(low >> 32) != 0) {
            uint8_t t = cache; do { out->push_back((uint8_t)(t + (uint8_t)(low >> 32))); t = 0xFF; } while (--cacheSize != 0);
            cache = (uint8_t)((uint32_t)low >> 24);
        }
        cacheSize++; low = (uint32_t)low << 8;
    }
    uint8_t inByte() { return ip < inn ? in[ip++] : (ip++, 0); }
    template <int M> __attribute__((always_inline)) uint32_t rbitT(uint16_t &p, uint32_t b) {
        const int sh = D.shift;
        if (M == kPrice) { price += gPrice[((p ^ ((0u - b) & 2047u)) & 2047u) >> 4]; return b; }
        const uint32_t bound = (range >> 11) * p;
        if (M == kDecode) {
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
        if (D.coder == kBits16M) {                                       // MSB-first into 16-bit words, each written low byte first
            acc = (acc << n) | (val & (n >= 32 ? 0xFFFFFFFFu : ((1u << n) - 1))); bn += n;
            while (bn >= 16) { const uint32_t w = (uint32_t)(acc >> (bn - 16)) & 0xFFFF; out->push_back((uint8_t)w); out->push_back((uint8_t)(w >> 8)); bn -= 16; }
            acc &= bn ? ((1ull << bn) - 1) : 0; return;
        }
        acc |= (uint64_t)(val & (n >= 32 ? 0xFFFFFFFFu : ((1u << n) - 1))) << bn; bn += n;
        while (bn >= 8) { out->push_back((uint8_t)acc); acc >>= 8; bn -= 8; }
    }
    uint32_t bget(int n) {
        uint32_t r = 0;
        if (D.coder == kBits16M) {                                       // MSB-first from 16-bit little-endian words
            if (bytesMode) { wb = bipos; bytesMode = false; }               // (bytes leave the position byte-aligned)
            for (int i = 0; i < n; ++i) {
                const uint64_t rel = bipos - wb, b = rel & 15, q = (wb >> 3) + (rel >> 4) * 2 + (b < 8 ? 1 : 0);
                if (q >= inn) { fail("the stream ends early"); return 0; }
                r = (r << 1) | ((in[q] >> (b < 8 ? 7 - b : 15 - b)) & 1); ++bipos;
            }
            return r;
        }
        for (int i = 0; i < n; ++i) { const uint64_t q = bipos >> 3; if (q >= inn) { fail("the stream ends early"); return 0; } r |= (uint32_t)((in[q] >> (bipos & 7)) & 1) << i; ++bipos; }
        return r;
    }
    bool build(int t, const uint32_t *len, uint32_t n) {
        Huff &h = hf[t];
        if (n > kMaxSym || (D.isa < 7 && n > 320)) return fail("a code with too many symbols");
        memset(h.count, 0, sizeof h.count); h.nsym = (int)n; hlens[t].assign(n, 0);
        //lengths to 15 (16 from ISA 7: LZX's pretree adds mod 17)
        for (uint32_t s = 0; s < n; ++s) { if (len[s] > (D.isa < 7 ? 15u : 16u)) return fail("a code length over its instruction set's"); h.count[len[s]]++; h.len[s] = (uint8_t)len[s]; hlens[t][s] = (uint8_t)len[s]; }
        h.count[0] = 0; int left = 1;
        for (int l = 1; l < 17; ++l) { left <<= 1; left -= h.count[l]; if (left < 0) return fail("an over-subscribed code"); }   // (lengths to 16: LZX's)
        int16_t offs[17] = {0}; for (int l = 1; l < 16; ++l) offs[l + 1] = (int16_t)(offs[l] + h.count[l]);
        for (uint32_t s = 0; s < n; ++s) if (len[s]) h.sym[offs[len[s]]++] = (int16_t)s;
        int next[17] = {0}, c = 0; for (int l = 1; l < 17; ++l) { c = (c + h.count[l - 1]) << 1; next[l] = c; }
        for (uint32_t s = 0; s < n; ++s) { if (!len[s]) continue; int cc = next[len[s]]++, rv = 0; h.mcode[s] = (uint16_t)cc; for (uint32_t i = 0; i < len[s]; ++i) { rv = (rv << 1) | (cc & 1); cc >>= 1; } h.code[s] = (uint16_t)rv; }
        return true;
    }
    uint32_t huff(int t, uint32_t sym) {
        Huff &h = hf[t];
        if (mode == kDecode) {
            int c = 0, first = 0, index = 0;
            for (int l = 1; l < 17; ++l) { c |= (int)bget(1); if (why) return 0; const int k = h.count[l];
                if (c - k < first) return (uint32_t)h.sym[index + (c - first)];
                index += k; first += k; first <<= 1; c <<= 1; }
            fail("a code its table does not have"); return 0;
        }
        if ((int)sym >= h.nsym || !h.len[sym]) { fail("a symbol its code cannot say"); return sym; }
        if (mode == kPrice) { price += (uint32_t)h.len[sym] << 4; return sym; }
        bput(D.coder == kBits16M ? h.mcode[sym] : h.code[sym], h.len[sym]); return sym;
    }
    bool slots(uint32_t at, uint32_t n) { if ((uint64_t)at + n > slot.size()) return fail("a slot out of range"); return true; }
    // the family's token anchored at At, from its parse of the block [Lo, Hi): false refuses (a block the content does not
    // have, or too big)
    bool predict(uint32_t At, uint32_t Lo, uint32_t Hi, uint32_t Att, uint32_t *T) {
        T[0] = 0; T[1] = kNoPrediction; T[2] = 0;
        if (Hi < Lo || Hi - Lo > kLz4hcMaxBlock) return fail("a predicted block too big");
        const uint64_t have = mode == kDecode ? X.cap : X.size;
        if (Hi > have) return fail("a predicted block past the content");
        if (!pseqs || Lo != plo || Hi != phi || Att != patt) {
            // parses have their own budget, in WORK (chain steps, ~12 ns each at worst) since this run started or was restored:
            // 128 a byte of its progress, plus one largest block's (real archives take about 4 a byte, 73 in Skyrim SE's
            // worst block). A description asking for parse after parse, or content built to make a parse crawl (393 a byte),
            // is refused within seconds a block; a real one never.
            const uint64_t budget = WorkPerByte(kFamilyLz4hc, Att) * (progress() - std::min(prog0, progress()) + kLz4hcMaxBlock);
            bool over = false;
            auto make = [&](std::vector<Lz4Seq> &V) {
                static thread_local std::unique_ptr<Lz4hcParser> P; if (!P) P = std::make_unique<Lz4hcParser>();
                const uint8_t *b = nullptr; std::vector<uint8_t> tmp;
                if (mode == kDecode) b = X.w + Lo;
                else if (X.mem) b = X.mem + Lo;
                else { tmp.resize(Hi - Lo); if (!X.src->preadAll(tmp.data(), tmp.size(), Lo)) return false; b = tmp.data(); }
                const uint64_t before = psteps, shared = pcache->steps.load();
                const bool again = pcache->isCharged(Lo, Hi, Att);             // parsed before: its work is paid
                const uint64_t room = again ? UINT64_MAX : pcache->streamBudget > shared ? pcache->streamBudget - shared : 0;
                const bool ok = P->parse(b, Hi - Lo, Att, V, psteps, room == UINT64_MAX ? budget : std::min(budget, before + room));
                if (!ok) { over = true; return false; }
                pcache->charge(Lo, Hi, Att, psteps - before);
                return true;
            };
            if (!pcache) pcache = std::make_shared<PredictCache>();
            pseqs = pcache->get(Lo, Hi, Att, make); plo = Lo; phi = Hi; patt = Att;
            if (!pseqs) return fail(over ? "a description that parses without making progress" : "the content does not read");
        }
        if (At < Lo || At > Hi) return true;
        const uint32_t a = At - Lo; const auto &V = *pseqs;
        auto it = std::lower_bound(V.begin(), V.end(), a, [](const Lz4Seq &q, uint32_t x) { return q.anchor < x; });
        if (it != V.end() && it->anchor == a) { T[0] = it->lit; T[1] = it->ml; T[2] = it->off; predictedAny = true; }
        return true;
    }
    // zlib's token at At (the literals left to its copy, the copy; copy 0: the stream's last literals), from the stream's
    // incremental parse of [Lo, Hi). Its work: WorkPerByte a byte of this run's progress and of the stream up to At (a
    // run restored deep in a stream parses it from its start), and the stream's account for new ground only.
    bool predictZ(uint64_t At, uint64_t Lo, uint64_t Hi, uint32_t Knob, uint32_t *T) {
        T[0] = 0; T[1] = kNoPrediction; T[2] = 0;
        const uint64_t have = mode == kDecode ? X.cap : X.size;
        if (Hi < Lo || Hi > have) return fail("a predicted stream past the content");
        if (At < Lo || At >= Hi) return true;
        if (!pcache) pcache = std::make_shared<PredictCache>();
        const auto key = std::make_tuple(Lo, Hi, Knob);
        auto zit = zown.find(key);
        if (zit == zown.end()) {
            if (zown.size() >= 2) zown.erase(zown.begin());                // (a stream at a time, and one more)
            zit = zown.emplace(key, nullptr).first;
        }
        std::unique_ptr<ZlibParser> &zp = zit->second;
        uint32_t run = 0, len = 0, dist = 0;
        if (zp && zp->at(At, run, len, dist)) { T[0] = run; T[1] = len; T[2] = dist; predictedAny = true; return true; }
        if (!zp || At < zp->kept()) {                                      // none yet, or At behind what it keeps: from the start
            const uint8_t *mem = mode == kDecode ? X.w : X.mem; ByteSource *src = X.src;
            zp = std::make_unique<ZlibParser>(Knob, Lo, Hi, [mem, src](uint64_t P, uint8_t *B, size_t N) {
                if (mem) { memcpy(B, mem + P, N); return true; }
                return src && src->preadAll(B, N, P); });
        }
        const uint64_t from = zp->reached(), before = psteps;
        //what this run may spend: its own progress, plus ONE catch-up from the stream's start (a reader restored mid-stream
        //parses up to where it stands, once; any other parse is paid by progress or, on new ground, by the stream's account)
        if (!zCatchUp) { zCatchUp = true; zCaught = At - Lo; }           // granted once, and kept for the rest of the run
        const uint64_t budget = WorkPerByte(kFamilyZlib, Knob) * (progress() - std::min(prog0, progress()) + zCaught + kLz4hcMaxBlock);
        const bool fresh = from >= pcache->zFurthest(Lo, Hi, Knob);       // new ground: the stream's account pays
        const uint64_t shared = pcache->steps.load();
        const uint64_t room = fresh ? (pcache->streamBudget > shared ? pcache->streamBudget - shared : 0) : UINT64_MAX;
        const bool ok = zp->ensure(At, psteps, room == UINT64_MAX ? budget : std::min(budget, before + room));
        if (fresh) pcache->steps += psteps - before;
        pcache->zReached(Lo, Hi, Knob, zp->reached());
        if (!ok) { zp.reset(); return fail("a description that parses without making progress"); }
        if (zp->at(At, run, len, dist)) { T[0] = run; T[1] = len; T[2] = dist; predictedAny = true; }
        return true;
    }
    void record(uint32_t val) { decOut->push_back(val); }

    // ---- run: 1 done (RET at the entry's depth, or END), 2 paused at a MARK (stopAt reached), 0 refused
    template <int M> int runT(int entry, bool resume) {
        // pc and the call stack are kept as ORIGINAL op numbers outside a run (checkpoints store those); inside, as this
        // mode's instruction numbers
        const Prog &P = S.prog[M]; const Ins *I0 = P.ins.data(); const uint32_t nins = (uint32_t)P.ins.size();
        if (!resume) { pc = entry; stk.clear(); }
        const size_t depth0 = resume ? 0 : stk.size();
        uint32_t ip_ = P.from[(size_t)std::min<size_t>((size_t)pc, D.ops.size())];
        for (int &s2 : stk) s2 = (int)P.from[(size_t)std::min<size_t>((size_t)s2, D.ops.size())];
        auto leave = [&](int r) { pc = ip_ < nins ? (int)I0[ip_].orig : (int)D.ops.size();   // (the sentinel's orig is the end)
            for (int &s2 : stk) s2 = (uint32_t)s2 < nins ? (int)I0[s2].orig : (int)D.ops.size();
            return r; };
        uint32_t tick = 0, val = 0; const Ins *op_ = nullptr;
        // DIRECT THREADING: every handler ends with its own jump to the next one (computed goto), so the branch predictor
        // learns per-instruction patterns instead of one shared switch. Table order = OpCode order, then the fused ones.
        static const void *const J[] = { &&L_OP_BIT, &&L_OP_TREE, &&L_OP_RTREE, &&L_OP_DIRECT, &&L_OP_MLIT, &&L_OP_RAW, &&L_OP_HUFF, &&L_OP_BUILD, &&L_OP_STA, &&L_OP_SET, &&L_OP_DEC, &&L_OP_OUTLIT, &&L_OP_OUTCOPY, &&L_OP_HMTF, &&L_OP_HPUSH, &&L_OP_JZ, &&L_OP_JMP, &&L_OP_CALL, &&L_OP_RET, &&L_OP_ASSERT, &&L_OP_FLUSH, &&L_OP_MARK, &&L_OP_END, &&L_OP_HUFFRUN, &&L_OP_BYTERUN, &&L_OP_PREDICT, &&L_OP_RAWBYTES, &&L_OP_E8FRAME, &&L_OP_E8END, &&L_OP_NEAREST, &&L_OP_LZXFOLDER, &&L_OP_LZXEND, &&L_OP_LZXSIZE, &&L_OP_LZXEMIT, &&L_F_BITJZ, &&L_F_SETBITJZ, &&L_F_DECN, &&L_F_OFFEND };
        static_assert(sizeof(J) / sizeof(J[0]) == F_OFFEND + 1, "dispatch table out of step with the opcodes");
        #define NEXT() do { if (__builtin_expect(!(++tick & 0xFFFF), 0)) { fuel += 0x10000; \
                if (overBudget() || X.err) { fail(X.err ? "the content does not read" : "a description that works without making progress"); return 0; } X.workMark = X.work; } \
            op_ = &I0[ip_]; ip_ = op_->fall; val = 0; goto *J[op_->op]; } while (0)
        #define CHECK_NEXT() do { if (why) return 0; NEXT(); } while (0)
        // a coding op's value: the decision (CODE, FREE), else its expression; DECODE learns it from the stream
        #define VALUE() do { if (M != kDecode) { if ((op_->flags & kFree) && M == kCode) { if (!Dc.get(val)) { fail("out of decisions"); return 0; } } else val = opnd<M>(op_->v); } } while (0)
        #define GIVE() do { v[op_->tgt] = val; if ((op_->flags & kFree) && M == kDecode) record(val); } while (0)
        NEXT();
            L_F_SETBITJZ: { const uint32_t b0 = opnd<M>(op_->v) & 1, sl = opnd<M>(op_->x); if (why || !slots(sl, 1)) return 0;
                const uint32_t b = rbitT<M>(slot[sl], b0); v[op_->tgt] = b; if (!b) ip_ = op_->target; NEXT(); }
            L_F_BITJZ: { const uint32_t b0 = M == kDecode ? 0 : opnd<M>(op_->v) & 1, sl = opnd<M>(op_->x); if (why || !slots(sl, 1)) return 0;
                const uint32_t b = rbitT<M>(slot[sl], b0); v[op_->tgt] = b; if (!b) ip_ = op_->target; NEXT(); }
            L_F_DECN:
                if (M == kCode) { for (uint32_t q = 0; q < op_->nb; ++q) { uint32_t x; if (!Dc.get(x)) { fail("out of decisions"); return 0; } v[op_->regs[q]] = x; } }
                else if (M == kDecode) for (uint32_t q = 0; q < op_->nb; ++q) record(v[op_->regs[q]]);
                NEXT();
            L_F_OFFEND: fail("the program runs off its end"); return 0;
            L_OP_BIT: { VALUE(); const uint32_t s = opnd<M>(op_->x); if (!slots(s, 1)) return 0; val = rbitT<M>(slot[s], val & 1); GIVE(); NEXT(); }
            L_OP_TREE: L_OP_RTREE: { VALUE();
                const uint32_t s = opnd<M>(op_->x); const int nb = op_->nb ? op_->nb : (int)opnd<M>(op_->m);
                if (nb > 24 || !slots(s, 1u << nb)) { fail("a tree out of range"); return 0; }
                uint32_t m = 1, r = 0;
                if (op_->op == OP_TREE) { for (int i = nb - 1; i >= 0; --i) { const uint32_t b = rbitT<M>(slot[s + m], (val >> i) & 1); m = (m << 1) | b; } r = m - (1u << nb); }
                else { for (int i = 0; i < nb; ++i) { const uint32_t b = rbitT<M>(slot[s + m], (val >> i) & 1); m = (m << 1) | b; r |= b << i; } }
                val = r; GIVE(); NEXT(); }
            L_OP_DIRECT: { VALUE();
                const uint32_t n = opnd<M>(op_->x); if (n > 32) { fail("too many direct bits"); return 0; }
                if (M == kPrice) { price += n << 4; GIVE(); NEXT(); }
                if (M == kDecode) { uint32_t r = 0; for (uint32_t k = 0; k < n; ++k) { range >>= 1; code -= range; const uint32_t t = 0u - (code >> 31); code += range & t;
                        if (range < (1u << 24)) { range <<= 8; code = (code << 8) | inByte(); } r = (r << 1) + t + 1; } val = r; GIVE(); NEXT(); }
                for (uint32_t k = n; k-- > 0;) { range >>= 1; low += range & (0u - ((val >> k) & 1)); if (range < (1u << 24)) { range <<= 8; rcShift(); } }
                GIVE(); NEXT(); }
            L_OP_MLIT: { VALUE();
                const uint32_t s = opnd<M>(op_->x); if (!slots(s, 0x300)) return 0;
                uint32_t mb = opnd<M>(op_->m), offs = 0x100, ds = 1;
                for (int i = 7; i >= 0; --i) { mb <<= 1; const uint32_t idx = offs + (mb & offs) + ds; const uint32_t b = rbitT<M>(slot[s + (idx & 0x3FF)], (val >> i) & 1); ds = (ds << 1) | b; offs &= ~(mb ^ (ds << 8)); }
                val = ds & 0xFF; GIVE(); NEXT(); }
            L_OP_RAW: { VALUE();
                const uint32_t n = opnd<M>(op_->x); if (n > 32) { fail("too many raw bits"); return 0; }
                if (M == kDecode) val = bget((int)n);
                else if (M == kPrice) price += n << 4;
                else bput(val, (int)n);
                if (why) return 0;
                GIVE(); NEXT(); }
            L_OP_HUFF: VALUE(); val = huff((int)op_->imm, val); if (why) return 0; GIVE(); NEXT();
            L_OP_HUFFRUN: {
                Huff &h = hf[op_->imm]; uint32_t p = place(), n = 0;
                const bool bounded = (op_->flags & kBounded) != 0; const uint32_t most = bounded ? opnd<M>(op_->v) : 0;   // ISA 7
                if (M == kDecode) {
                    const uint32_t lim = opnd<M>(op_->m);
                    for (;;) { if (bounded && n >= most) { v[op_->nb] = 0xFFFFFFFFu; break; }
                        const uint32_t sym = huff((int)op_->imm, 0); if (why) return 0;
                        if (sym >= lim || sym > 255) { v[op_->nb] = sym; break; }
                        if (p >= X.cap) { fail("more content than expected"); return 0; }
                        X.w[p++] = (uint8_t)sym; ++n; }
                } else {
                    n = opnd<M>(op_->x);
                    for (uint32_t i = 0; i < n; ++i) { const uint8_t c = X.at((uint64_t)p + i);
                        if (c >= h.nsym || !h.len[c]) { fail("a symbol its code cannot say"); return 0; }
                        if (M == kPrice) price += (uint32_t)h.len[c] << 4; else bput(D.coder == kBits16M ? h.mcode[c] : h.code[c], h.len[c]); }
                    p += n; if (!(bounded && n == most)) huff((int)op_->imm, v[op_->nb]); if (why) return 0;   // (ran out: no end symbol)
                }
                v[op_->tgt] = n; v[kRegPlace] = p; CHECK_NEXT(); }
            L_OP_BYTERUN: {
                if (D.coder == kRange) { fail("a byte run outside the bit coder"); return 0; }
                const uint32_t n = opnd<M>(op_->x), p = place();
                if (D.coder == kBits16M && ((M == kDecode && !bytesMode && ((bipos - wb) & 15)) || (M == kCode && bn))) { fail("a byte run off a word boundary"); return 0; }
                if (M == kDecode) {
                    if ((uint64_t)p + n > X.cap) { fail("more content than expected"); return 0; }
                    if (!(bipos & 7)) { const uint64_t q = bipos >> 3; if (q + n > inn) { fail("the stream ends early"); return 0; } if (n) memcpy(X.w + p, in + q, n); bipos += 8ull * n; }
                    else for (uint32_t i = 0; i < n; ++i) { X.w[p + i] = (uint8_t)bget(8); if (why) return 0; }
                    if (D.coder == kBits16M) bytesMode = true;
                } else if (M == kPrice) price += n << 7;
                else if (!bn && X.viewed(p, n)) {                               // through a translated frame: the encoder's
                    for (uint32_t i = 0; i < n; ++i) out->push_back(X.at((uint64_t)p + i));   // bytes, as they are (either coder)
                }
                else if (!bn) {
                    if (runs && n >= kRunMin) {
                        if ((uint64_t)p + n > X.size) { fail("a copy run past the content"); return 0; }
                        runs->push_back({out->size() + copied, p, out->size(), n}); copied += n;
                    } else if (!X.copyTo(*out, p, n)) { fail("a copy run past the content"); return 0; }
                }
                else for (uint32_t i = 0; i < n; ++i) bput(X.at((uint64_t)p + i), 8);
                v[kRegPlace] = p + n; CHECK_NEXT(); }
            L_OP_RAWBYTES: { VALUE();
                const uint32_t n = opnd<M>(op_->x);
                if (n < 1 || n > 4) { fail("rawbytes takes 1 to 4 bytes"); return 0; }
                if (D.coder == kRange) { fail("bytes outside the bit coder"); return 0; }
                if (M == kDecode) {
                    if (D.coder == kBits16M ? (!bytesMode && ((bipos - wb) & 15)) : (bipos & 7) != 0) { fail("bytes off a byte boundary"); return 0; }
                    const uint64_t q = bipos >> 3; if (q + n > inn) { fail("the stream ends early"); return 0; }
                    val = 0; for (uint32_t k = 0; k < n; ++k) val |= (uint32_t)in[q + k] << (8 * k);
                    bipos += 8ull * n; if (D.coder == kBits16M) bytesMode = true;
                } else if (M == kPrice) price += n << 7;
                else { if (bn) { fail("bytes off a byte boundary"); return 0; } for (uint32_t k = 0; k < n; ++k) out->push_back((uint8_t)(val >> (8 * k))); }
                GIVE(); NEXT(); }
            L_OP_E8FRAME: {                                              // ISA 8: frame [x, x+v), first byte at stream position m, filesize in tgt
                const uint32_t at = opnd<M>(op_->x), n = opnd<M>(op_->v), cur = opnd<M>(op_->m), fs = v[op_->tgt];
                if (!n || n > (1u << 20)) { fail("an E8 frame of no size, or over 1 MiB"); return 0; }
                if ((uint64_t)at + n > (1ull << 32) || (uint64_t)cur + n > (1ull << 32) || fs > 0x7FFFFFFFu) { fail("an E8 frame out of range"); return 0; }
                if (M == kDecode) {
                    if (e8open.open) { fail("an E8 frame opened inside another"); return 0; }
                    if (!e8done.empty() && at < e8done.back().first + e8done.back().second.n) { fail("E8 frames out of order"); return 0; }
                    if ((uint64_t)at + n > X.cap) { fail("an E8 frame past the content"); return 0; }
                    e8open.at = at; e8open.f = {n, cur, fs}; e8open.slot = decOut->size(); e8open.open = true; record(0);   // its decision: filled at E8END
                } else if (M == kCode) {
                    uint32_t t; if (!Dc.get(t)) { fail("out of decisions"); return 0; }
                    if (t > 1) { fail("an E8 frame's decision is 0 or 1"); return 0; }
                    if (t) {
                        if (!X.vframes.empty() && at < X.vframes.rbegin()->first + X.vframes.rbegin()->second.n) { fail("E8 frames out of order"); return 0; }
                        //what the window no longer reaches goes (the rule a checkpoint keeps), and at most 4096 frames stay
                        const uint64_t keep = place() > D.window ? place() - D.window : 0;
                        while (!X.vframes.empty() && X.vframes.begin()->first + X.vframes.begin()->second.n <= keep) {
                            X.wcache.erase(X.vframes.begin()->first); X.vframes.erase(X.vframes.begin()); }
                        X.wbytes = 0; for (const auto &kv : X.wcache) X.wbytes += kv.second.second.size();
                        X.wAt = UINT64_MAX; X.wEnd = 0; X.wcur = nullptr;             // (the frame at hand may have gone)
                        if (X.vframes.size() >= 4096) { fail("more than 4096 E8 frames in the window"); return 0; }
                        X.vframes[at] = {n, cur, fs};                         // (frames never overlap: the cache stands)
                    }
                }
                CHECK_NEXT(); }
            L_OP_E8END: {                                                // ISA 8: the frame opened is translated or not (v)
                if (M == kDecode) {
                    if (!e8open.open) { fail("an E8 frame ended that was not opened"); return 0; }
                    const uint32_t t = opnd<M>(op_->v) ? 1 : 0;
                    (*decOut)[e8open.slot] = t; e8open.open = false;
                    if (t) e8done.push_back({e8open.at, e8open.f});
                }
                CHECK_NEXT(); }
            L_OP_NEAREST: {                                              // ISA 8
                uint32_t d = kNoPrediction;
                if (M != kPrice && !noPredict && (M != kDecode || wholeContent)) {
                    const uint32_t maxd = opnd<M>(op_->m);
                    if (maxd > D.window) { fail("NEAREST reaching past the description's WINDOW"); return 0; }
                    d = nearest(place(), opnd<M>(op_->x), opnd<M>(op_->v), maxd);
                    if (d != kNoPrediction) predictedAny = true;
                }
                v[op_->tgt] = d; CHECK_NEXT(); }
            L_OP_LZXFOLDER: {                                            // ISA 9
                const uint32_t at = opnd<M>(op_->x), n = opnd<M>(op_->v), e8 = opnd<M>(op_->m);
                const uint64_t have = M == kDecode ? X.cap : X.size;
                if (!n || (uint64_t)at + n > have) { fail("an LZX folder past the content"); return 0; }
                if (!lzxList.empty() && at < lzxList.back().at + lzxList.back().n) { fail("LZX folders out of order"); return 0; }
                if (lzxList.size() >= 4096) { fail("more than 4096 LZX folders"); return 0; }
                lzxList.push_back({at, n, e8, op_->imm}); lzxCur = (int)lzxList.size() - 1;
                uint32_t r = kNoPrediction;
                if (M == kDecode) {
                    if (lzxOpen) { fail("an LZX folder opened inside another"); return 0; }
                    lzxSlot = decOut->size(); lzxOpen = true; record(0);       // its decision: filled at LZXEND
                    lzxAvail = !noPredict && wholeContent; lzxBad = false;
                    if (lzxAvail) r = 1;
                } else if (M == kCode) {
                    uint32_t t; if (!Dc.get(t)) { fail("out of decisions"); return 0; }
                    if (t > 1) { fail("an LZX folder's decision is 0 or 1"); return 0; }
                    if (t && noPredict) { fail("a plain record takes no family's frames"); return 0; }
                    lzxUse = t; if (t) r = 1;
                }
                v[op_->tgt] = r; CHECK_NEXT(); }
            L_OP_LZXEND: {
                if (M == kDecode) {
                    if (!lzxOpen) { fail("an LZX folder ended that was not opened"); return 0; }
                    if (e8open.open) { fail("an E8 frame open at LZXEND"); return 0; }
                    //the family's only when the description says so AND the family made every frame it was asked for
                    const uint32_t t = opnd<M>(op_->v) && lzxAvail && !lzxBad ? 1 : 0;
                    (*decOut)[lzxSlot] = t; lzxOpen = false;
                    if (t) decOut->resize(lzxSlot + 1);                  // the folder is the family's: nothing else of it is kept
                } else if (M == kCode) lzxUse = 0;
                CHECK_NEXT(); }
            L_OP_LZXSIZE: {
                uint32_t r = kNoPrediction; const uint32_t k = opnd<M>(op_->x);
                if ((M == kDecode && lzxOpen && lzxAvail) || (M == kCode && lzxUse)) {
                    const int q = lzxFrame(lzxCur, k, [&](const std::vector<uint8_t> &fr) { r = (uint32_t)fr.size(); });
                    if (q == -2) return 0;
                    if (q == -1) { if (M == kDecode) lzxBad = true;
                                   else { fail(pcache->lzxFamily()->over ? "a description that parses without making progress" : "the LZX family no longer makes this folder"); return 0; } }
                }
                v[op_->tgt] = r; CHECK_NEXT(); }
            L_OP_LZXEMIT: {
                const uint32_t k = opnd<M>(op_->x); uint32_t r = 0;
                if (M == kCode) {
                    if (!lzxUse) { fail("LZXEMIT in a folder that is not the family's"); return 0; }
                    if (bn) { fail("LZXEMIT off a byte boundary"); return 0; }
                    const int q = lzxFrame(lzxCur, k, [&](const std::vector<uint8_t> &fr) { out->insert(out->end(), fr.begin(), fr.end()); }, true);
                    if (q == -2) return 0;
                    if (q == 0) { fail("no such LZX frame"); return 0; }
                    if (q == -1) { fail(pcache->lzxFamily()->over ? "a description that parses without making progress" : "the LZX family no longer makes this folder"); return 0; }
                    r = 1;
                } else if (M == kDecode && lzxOpen && lzxAvail && !(bipos & 7)) {
                    const uint64_t q0 = bipos >> 3;
                    const int q = lzxFrame(lzxCur, k, [&](const std::vector<uint8_t> &fr) {
                        r = q0 <= inn && fr.size() <= inn - q0 && memcmp(in + q0, fr.data(), fr.size()) == 0 ? 1 : 0; });
                    if (q == -2) return 0;
                    if (q == -1) lzxBad = true;
                }
                v[op_->tgt] = r; CHECK_NEXT(); }
            L_OP_PREDICT: {
                uint32_t t[3] = {0, kNoPrediction, 0};
                if (M != kPrice && !noPredict && (M != kDecode || wholeContent)) {
                    if (op_->nb == kFamilyZlib) { if (!predictZ(opnd<M>(op_->x), opnd<M>(op_->v), opnd<M>(op_->m), op_->imm, t)) return 0; }
                    else if (!predict(opnd<M>(op_->x), opnd<M>(op_->v), opnd<M>(op_->m), op_->imm, t)) return 0;
                }
                v[op_->tgt] = t[0]; v[op_->tgt + 1u] = t[1]; v[op_->tgt + 2u] = t[2]; CHECK_NEXT(); }
            L_OP_BUILD: {
                const uint32_t a = opnd<M>(op_->x), n = opnd<M>(op_->v); const auto &t = arr[op_->nb];
                if ((uint64_t)a + n > t.size()) { fail("a code past its array"); return 0; }
                if (!build((int)op_->imm, t.data() + a, n)) return 0;
                CHECK_NEXT(); }
            L_OP_STA: { const uint32_t i = opnd<M>(op_->x); auto &t = arr[op_->nb]; if (i >= t.size()) { fail("an array write out of range"); return 0; } t[i] = opnd<M>(op_->v); CHECK_NEXT(); }
            L_OP_SET: v[op_->tgt] = opnd<M>(op_->v); NEXT();
            L_OP_DEC:
                if (M == kCode) { uint32_t x; if (!Dc.get(x)) { fail("out of decisions"); return 0; } v[op_->tgt] = x; }
                else if (M == kDecode) record(v[op_->tgt]);
                NEXT();
            L_OP_OUTLIT: {
                const uint32_t p = place();
                if (M == kDecode) { if (p >= X.cap) { fail("more content than expected"); return 0; } X.w[p] = (uint8_t)opnd<M>(op_->v); }
                v[kRegPlace] = p + 1; NEXT(); }
            L_OP_OUTCOPY: {
                const uint32_t p = place(), len = opnd<M>(op_->x), dist = opnd<M>(op_->v);
                if (M == kDecode) {
                    if (!dist || dist > p) { fail("a copy from before the start"); return 0; }
                    if ((uint64_t)p + len > X.cap) { fail("more content than expected"); return 0; }
                    for (uint32_t i = 0; i < len; ++i) X.w[p + i] = X.w[p + i - dist];
                }
                v[kRegPlace] = p + len; NEXT(); }
            L_OP_HMTF: { const uint32_t s = opnd<M>(op_->v); if (s >= op_->nb) { fail("no such history slot"); return 0; } const uint32_t h = v[op_->tgt + s];
                for (uint32_t j = s; j > 0; --j) v[op_->tgt + j] = v[op_->tgt + j - 1];
                v[op_->tgt] = h; NEXT(); }
            L_OP_HPUSH: { const uint32_t x = opnd<M>(op_->v); for (int j = op_->nb - 1; j > 0; --j) v[(size_t)(op_->tgt + j)] = v[(size_t)(op_->tgt + j - 1)]; v[op_->tgt] = x; NEXT(); }
            L_OP_JZ: if (!opnd<M>(op_->v)) ip_ = op_->target; if (why) return 0; NEXT();
            L_OP_JMP: if (why) return 0; ip_ = op_->target; NEXT();
            L_OP_CALL: if (why) return 0; if (stk.size() >= kMaxStack) { fail("calls too deep"); return 0; } stk.push_back((int)ip_); ip_ = op_->target; NEXT();
            L_OP_RET: if (why) return 0; if (stk.size() == depth0) return leave(1); ip_ = (uint32_t)stk.back(); stk.pop_back(); NEXT();
            L_OP_ASSERT: if (!opnd<M>(op_->v)) { failOp = (int)op_->orig; fail("the stream breaks a rule of its format"); return 0; } CHECK_NEXT();
            L_OP_FLUSH: if (M == kCode) { if (D.coder == kRange) for (int i = 0; i < 5; ++i) rcShift(); else if (bn) bput(0, (D.coder == kBits16M ? 16 : 8) - bn); } CHECK_NEXT();
            L_OP_MARK: if (why) return 0; if (M == kCode && out && out->size() + copied >= stopAt) return leave(2); NEXT();
            L_OP_END: if (why) return 0; return leave(1);
        #undef NEXT
        #undef CHECK_NEXT
        #undef VALUE
        #undef GIVE
    }

    int run(int entry, bool resume = false) { return mode == kDecode ? runT<kDecode>(entry, resume) : mode == kPrice ? runT<kPrice>(entry, resume) : runT<kCode>(entry, resume); }

    // ---- checkpoints: everything a CODE run needs to resume at a MARK
    std::vector<uint8_t> snapshot() const {
        std::vector<uint8_t> o;
        PutVar(o, (uint64_t)pc); PutVar(o, stk.size()); for (int s : stk) PutVar(o, (uint64_t)s);
        for (int i = 0; i < kRegs; ++i) PutVar(o, v[(size_t)i]);
        PutVar(o, low); PutVar(o, range); o.push_back(cache); PutVar(o, cacheSize); PutVar(o, acc); PutVar(o, (uint64_t)bn);
        for (uint16_t s : slot) PutVar(o, s);
        for (const auto &a : arr) for (uint32_t x : a) PutVar(o, x);
        for (int t = 0; t < D.nhuff; ++t) { PutVar(o, hlens[t].size()); o.insert(o.end(), hlens[t].begin(), hlens[t].end()); }
        if (UsesE8(D)) {                                                  // (ISA 8 only: other descriptions' records are unchanged)
            //as RUNS: frames back to back, each as long as the first (the last may be shorter), stream positions advancing
            //with them, one filesize — LZX's frames are, so a checkpoint carries a few numbers, not a table
            std::vector<std::array<uint64_t, 6>> runs;                    // at, n, cur, fs, count, the last frame's n
            for (const auto &[at, f] : X.vframes) {
                if (!runs.empty()) {
                    auto &r = runs.back(); const uint64_t end = r[0] + r[1] * (r[4] - 1) + r[5];
                    if (r[5] == r[1] && at == end && f.cur == r[2] + (end - r[0]) && f.fs == r[3] && f.n <= r[1]) { ++r[4]; r[5] = f.n; continue; }
                }
                runs.push_back({at, f.n, f.cur, f.fs, 1, f.n});
            }
            PutVar(o, runs.size());
            for (const auto &r : runs) for (uint64_t x : r) PutVar(o, x);
        }
        if (UsesLzx(D)) {                                                 // (ISA 9 only)
            PutVar(o, lzxList.size()); for (const auto &L : lzxList) { PutVar(o, L.at); PutVar(o, L.n); PutVar(o, L.e8); PutVar(o, L.knob); }
            PutVar(o, (uint64_t)(lzxCur + 1)); PutVar(o, lzxUse);
        }
        return o;
    }
    bool restore(const uint8_t *p, size_t n) {
        Rd r{p, n};
        pc = (int)r.var(); const uint64_t ns = r.var(); if (r.bad || ns > kMaxStack || (uint64_t)pc >= D.ops.size()) return fail("a malformed checkpoint");
        stk.resize((size_t)ns); for (auto &s : stk) { s = (int)r.var(); if ((uint64_t)s >= D.ops.size()) return fail("a malformed checkpoint"); }
        for (int i = 0; i < kRegs; ++i) v[(size_t)i] = (uint32_t)r.var();
        low = r.var(); range = (uint32_t)r.var(); cache = r.u8(); cacheSize = r.var(); acc = r.var(); bn = (int)r.var();
        for (auto &s : slot) { const uint64_t x = r.var(); if (!x || x >= 2048) return fail("a malformed checkpoint"); s = (uint16_t)x; }
        for (auto &a : arr) for (auto &x : a) x = (uint32_t)r.var();
        for (int t = 0; t < D.nhuff; ++t) {
            const uint64_t k = r.var(); if (r.bad || k > kMaxSym || r.at + k > n) return fail("a malformed checkpoint");
            std::vector<uint32_t> l(p + r.at, p + r.at + k); r.at += (size_t)k;
            if (k && !build(t, l.data(), (uint32_t)k)) return false;
            if (!k) hf[t].nsym = 0;
        }
        X.vframes.clear(); X.wAt = UINT64_MAX; X.wEnd = 0; X.wcur = nullptr; X.wcache.clear(); X.wbytes = 0;
        if (UsesE8(D)) {
            const uint64_t nr = r.var(); if (r.bad || nr > 4096) return fail("a malformed checkpoint");
            uint64_t end = 0, frames = 0;
            for (uint64_t k = 0; k < nr; ++k) {
                const uint64_t at = r.var(), fn = r.var(), cur = r.var(), fs = r.var(), count = r.var(), last = r.var();
                if (r.bad || !fn || fn > (1u << 20) || !last || last > fn || !count || (frames += count) > 4096 || at < end ||
                    at + fn * (count - 1) + last > (1ull << 32) || cur + fn * (count - 1) + last > (1ull << 32) || fs > 0x7FFFFFFFu) return fail("a malformed checkpoint");
                for (uint64_t j = 0; j < count; ++j)
                    X.vframes[at + j * fn] = {(uint32_t)(j + 1 == count ? last : fn), (uint32_t)(cur + j * fn), (uint32_t)fs};
                end = at + fn * (count - 1) + last;
            }
        }
        lzxList.clear(); lzxCur = -1; lzxUse = 0;
        if (UsesLzx(D)) {
            const uint64_t nl = r.var(); if (r.bad || nl > 4096) return fail("a malformed checkpoint");
            uint64_t end = 0;
            for (uint64_t k = 0; k < nl; ++k) {
                const uint64_t at = r.var(), ln = r.var(), e8 = r.var(), kn = r.var();
                if (r.bad || !ln || ln > 0xFFFFFFFFu || at > 0xFFFFFFFFu || at < end || at + ln > (1ull << 32) || e8 > 0xFFFFFFFFu || kn > 0xFFFFFFFFu || !LzxKnob((uint32_t)kn)) return fail("a malformed checkpoint");
                lzxList.push_back({at, ln, (uint32_t)e8, (uint32_t)kn}); end = at + ln;
            }
            const uint64_t cur = r.var(), use = r.var();
            if (r.bad || cur > nl || use > 1) return fail("a malformed checkpoint");
            lzxCur = (int)cur - 1; lzxUse = (uint32_t)use;
        }
        if (r.bad || r.at != n || bn < 0 || bn > (D.coder == kBits16M ? 15 : 7) || cacheSize > maxCache) return fail("a malformed checkpoint");
        return true;
    }
};

bool Unzstd(const std::vector<uint8_t> &z, std::vector<uint8_t> &o) {
    const unsigned long long n = ZSTD_getFrameContentSize(z.data(), z.size());
    if (n == ZSTD_CONTENTSIZE_ERROR || n == ZSTD_CONTENTSIZE_UNKNOWN || n > (256ull << 20)) return false;
    o.resize((size_t)n); return ZSTD_decompress(o.data(), o.size(), z.data(), z.size()) == n;
}
std::vector<uint8_t> Zstd(const std::vector<uint8_t> &x) {
    std::vector<uint8_t> z(ZSTD_compressBound(x.size())); z.resize(ZSTD_compress(z.data(), z.size(), x.data(), x.size(), 9)); return z;
}

} // namespace

// ================================================================================================ mint
uint64_t SuggestedSpacing(const Description &D, uint64_t Shipped, bool Plain) {
    // a PREDICTED record is for keeping and sending, not reading (a machine reads its plain twin): a checkpoint every 8 MiB
    // shipped, so each segment is about one family block (segments decode in parallel, one parse per block) and the
    // record is decisions, not snapshots
    if (!Plain && UsesPrediction(D)) return 8u << 20;
    // SPEED FIRST (USER 2026-11-26): segments decode in parallel and a random read starts at most one segment back, so
    // adaptive coders checkpoint every 512 KiB shipped (a snapshot is ~10 KB of slots: ~2% of a big record) and a small
    // stream still splits into ~32 segments, down to 64 KiB
    const uint64_t most = D.nslots ? (512u << 10) : (64u << 10), least = D.nslots ? (64u << 10) : (16u << 10);
    if (!Shipped) return most;
    return std::max<uint64_t>(least, std::min<uint64_t>(most, Shipped / 32));     // ~32 segments, within the class's bounds
}

// Record: "VGCR" (plain) or "VGCQ" (it takes predictions: a run needs the description's families) | varint shipped size |
// varint total decisions | varint checkpoints | per checkpoint: varint shipped offset, varint decisions before it, varint
// payload length (VGCQ: then a varint, the FNV-1a 64 of the segment's shipped bytes: a family that predicts otherwise
// than at the mint, another reader's or a hostile record's, is refused per segment, never served) | payloads. A payload
// is one zstd frame: varint snapshot length, snapshot, varint decision count, the segment's decisions as varints.
bool UsesPrediction(const Description &D) { for (const Op &o : D.ops) if (o.op == OP_PREDICT || o.op == OP_NEAREST || o.op == OP_LZXFOLDER) return true; return false; }
// The work a family's parse may take a byte: LZ4HC 128 (real archives take 4, 73 at worst); zlib twice its chain length and
// a little (zlib itself walks up to its chain at a search, about twice a byte: level 9 takes thousands on degenerate data)
uint64_t WorkPerByte(uint8_t Family, uint32_t Knob) {
    static const uint32_t kChain[10] = {0, 4, 8, 32, 16, 32, 128, 256, 1024, 4096};
    if (Family == kFamilyZlib) return 2ull * kChain[(Knob & 0xFF) < 10 ? (Knob & 0xFF) : 9] + 64;
    return 128;
}
uint64_t MaxWorkPerByte(const Description &D) { uint64_t w = 128; for (const Op &o : D.ops) if (o.op == OP_PREDICT) w = std::max(w, WorkPerByte(o.nb, o.imm)); return w; }
namespace { uint64_t SegmentHash(const uint8_t *p, size_t n, uint64_t h = 1469598103934665603ull) { for (size_t i = 0; i < n; ++i) { h ^= p[i]; h *= 1099511628211ull; } return h; } }

bool MintInto(const Description &D, const uint8_t *Shipped, size_t N, size_t ContentSize, uint8_t *Buf, size_t ContentCap, uint64_t Spacing,
              size_t &ContentLen, std::vector<uint8_t> &Record, std::string &Err, bool Predict) {
    if (ContentCap > 0xFFFFFFFFu || ContentSize > ContentCap) { Err = "content over 4 GiB is not supported"; return false; }
    Spec S(D);
    if (!S.ok) { Err = "a description too complex to run"; return false; }
    bool predicted = Predict && UsesPrediction(D);
    std::vector<uint32_t> dec;
    std::vector<std::pair<uint64_t, ViewFrame>> e8first;                 // the first pass's translated frames (LZX family input)
    std::shared_ptr<PredictCache::LzxFamily> lzx2;
    // DECODE, plain: the content, and the decisions as the stream has them
    // (predicted: DECODE again over the whole content, every token checked against the family's)
    for (int pass = 0; pass < (predicted ? 2 : 1); ++pass) {
        dec.clear();
        Machine m(D, S, kDecode); m.in = Shipped; m.inn = N; m.X.w = Buf; m.decOut = &dec; m.e8prev = pass ? &e8first : nullptr;
        m.X.cap = pass ? ContentLen : ContentSize ? ContentSize : ContentCap; m.noPredict = !pass; m.wholeContent = pass == 1;
        if (pass) { m.pcache = std::make_shared<PredictCache>(); m.pcache->streamBudget = MaxWorkPerByte(D) * ((uint64_t)N + ContentLen + 2 * kLz4hcMaxBlock); }
        if (D.coder == kRange) { m.ip = 1; for (int i = 0; i < 4; ++i) m.code = (m.code << 8) | m.inByte(); }
        if (m.run(D.entryStream) != 1) { Err = std::string("decode: ") + (m.why ? m.why : "refused") + (m.failOp >= 0 ? " (op " + std::to_string(m.failOp) + ", content place " + std::to_string(m.place()) + ")" : std::string()); return false; }
        if (m.e8open.open) { Err = "decode: an E8 frame left open"; return false; }
        //(the LZX family's work so far: the coding goes on from it, when it read what a reader will: the second decode's E8
        //frames are the first's, so the real bytes it compressed are the content's)
        if (pass && m.pcache) {
            bool same = m.e8done.size() == e8first.size();
            for (size_t q = 0; same && q < e8first.size(); ++q) {
                const auto &a = e8first[q], &b = m.e8done[q];
                same = a.first == b.first && a.second.n == b.second.n && a.second.cur == b.second.cur && a.second.fs == b.second.fs; }
            if (same) lzx2 = m.pcache->lzx;
        }
        if (pass + 1 == (predicted ? 2 : 1)) m.e8finish();               // after the LAST decode only (a second one reads
        else { e8first = std::move(m.e8done); m.e8done.clear(); }        // ahead what the encoder saw): the real bytes
        if (ContentSize && m.place() != ContentSize) { Err = "decode: the content is not the size expected"; return false; }
        if (pass && m.place() != ContentLen) { Err = "decode: the content is not the size expected"; return false; }
        ContentLen = m.place();
        if (pass && !m.predictedAny) predicted = false;   // nothing the family made (an archive of stored members): a plain record
    }
    // code it back, taking checkpoints at MARKs every Spacing shipped bytes; what it codes is compared and dropped segment by
    // segment (`copied` counts what is out and gone), so a stream of gigabytes needs no second copy of itself
    std::vector<uint8_t> out; out.reserve((size_t)std::min<uint64_t>(N + 64, Spacing * 2 + (1u << 20)));
    struct C { uint64_t out, dec; std::vector<uint8_t> snap; };
    std::vector<C> cks;
    Machine m(D, S, kCode); m.out = &out; m.X.mem = Buf; m.X.size = ContentLen; m.Dc.setMem(dec.data(), dec.size()); m.Dc.total = dec.size();
    m.noPredict = !predicted; m.pc = D.entryStream;
    const uint64_t streamBudget = MaxWorkPerByte(D) * ((uint64_t)N + ContentLen + 2 * kLz4hcMaxBlock);   // what a reader will allow the stream
    m.pcache = std::make_shared<PredictCache>(); m.pcache->streamBudget = streamBudget;
    if (predicted && lzx2) { m.pcache->lzx = lzx2; m.pcache->steps = lzx2->paid; }   // (its work paid as the decode paid it)
    cks.push_back({0, 0, m.snapshot()});
    for (bool first = true;; first = false) {
        m.stopAt = cks.back().out + Spacing;                 // from the LAST checkpoint: a long run (one token) does not leave a burst of tiny segments behind it
        const int r = m.run(D.entryStream, !first);
        if (r == 0) { Err = std::string("code: ") + (m.why ? m.why : "refused"); return false; }
        if (m.copied + out.size() > N || (!out.empty() && memcmp(out.data(), Shipped + m.copied, out.size()) != 0)) { Err = "the stream does not code back to its own bytes"; return false; }
        m.copied += out.size(); out.clear();
        if (r == 1) break;
        m.e8prune();                                                      // (as a reader restored here: what the checkpoint carries)
        cks.push_back({m.copied, m.Dc.consumed(), m.snapshot()});
        //from here on, as a reader restored at this checkpoint runs: its own parse budget and no parse at hand (a record
        //no reader could read is refused here, never minted)
        m.prog0 = m.progress(); m.fuelBase = m.fuel + m.X.work; m.psteps = 0; m.pseqs.reset(); m.zCatchUp = false; m.zCaught = 0; m.zown.clear();
        m.nidx = Machine::NIdx();                                         // (a reader restored here builds its own NEAREST index)
        {   //a fresh parse cache (a reader there has none at hand), the stream's account carried over
            auto fresh = std::make_shared<PredictCache>(); fresh->steps = m.pcache->steps.load(); fresh->streamBudget = streamBudget;
            { std::lock_guard<std::mutex> l(m.pcache->mu); fresh->charged = m.pcache->charged; fresh->zfurthest = m.pcache->zfurthest; fresh->lzx = m.pcache->lzx; }
            m.pcache = std::move(fresh); }
    }
    if (m.copied != N) { Err = "the stream does not code back to its own bytes"; return false; }
    if (m.Dc.consumed() != dec.size()) { Err = "decisions left over"; return false; }
    // the record
    std::vector<std::vector<uint8_t>> pay;
    for (size_t k = 0; k < cks.size(); ++k) {
        std::vector<uint8_t> p; PutVar(p, cks[k].snap.size()); p.insert(p.end(), cks[k].snap.begin(), cks[k].snap.end());
        const uint64_t e = k + 1 < cks.size() ? cks[k + 1].dec : dec.size();
        PutVar(p, e - cks[k].dec); for (uint64_t i = cks[k].dec; i < e; ++i) PutVar(p, dec[(size_t)i]);
        pay.push_back(Zstd(p));
    }
    Record = {'V', 'G', 'C', (uint8_t)(predicted ? 'Q' : 'R')}; PutVar(Record, N); PutVar(Record, dec.size()); PutVar(Record, cks.size());
    for (size_t k = 0; k < cks.size(); ++k) {
        PutVar(Record, cks[k].out); PutVar(Record, cks[k].dec); PutVar(Record, pay[k].size());
        if (predicted) { const uint64_t e = k + 1 < cks.size() ? cks[k + 1].out : N; PutVar(Record, SegmentHash(Shipped + cks[k].out, (size_t)(e - cks[k].out))); }
    }
    for (const auto &p : pay) Record.insert(Record.end(), p.begin(), p.end());
    return true;
}

bool Mint(const Description &D, const uint8_t *Shipped, size_t N, size_t ContentSize, size_t ContentCap, uint64_t Spacing,
          std::vector<uint8_t> &Content, std::vector<uint8_t> &Record, std::string &Err, bool Predict) {
    if (ContentCap > 0xFFFFFFFFu || ContentSize > ContentCap) { Err = "content over 4 GiB is not supported"; return false; }
    Content.assign(ContentCap, 0); size_t len = 0;
    if (!MintInto(D, Shipped, N, ContentSize, Content.data(), ContentCap, Spacing, len, Record, Err, Predict)) return false;
    Content.resize(len); return true;
}

// ================================================================================================ the read side
namespace {
// A paused CODE run and what it produced since `base`: the next read that continues where this one stopped continues
// the run instead of replaying from a checkpoint. RAM only, one per source.
// A decoded segment: its generated bytes and its copy runs (axiom 10), `len` output bytes in all.
struct Seg { std::vector<uint8_t> pool; std::vector<CopyRun> runs; uint64_t len = 0; };
// One part of a read: `n` bytes for `dst`, from the pool (`mem`) or handed down to the content at `from`.
struct Piece { uint8_t *dst; const uint8_t *mem; uint64_t from; size_t n; };

struct Cursor { std::vector<uint8_t> out; uint64_t base = 0; size_t seg = 0; bool done = false; std::unique_ptr<Machine> m; };

// One pool of decoding threads for every coded stream of the process (a mount serves many): jobs hold their stream
// weakly, so a stream that goes away drops its queued segments.
class Pool {
public:
    static Pool &Get() { static Pool *P = new Pool(); return *P; }   // never destroyed: workers outlive static teardown
    size_t size() const { return W; }
    // LOWER LAYERS FIRST: a segment of a layer waits on segments of the layer below it, so a worker that takes an upper
    // job before the lower ones it needs only blocks; jobs run by depth (0: over plain content), then in the order asked
    void Post(uint32_t Depth, std::function<void()> F) { { std::lock_guard<std::mutex> g(Mu); Q.push(Job{Depth, ++Seq, std::move(F)}); } Cv.notify_one(); }
private:
    // half the machine's threads, 2 to 8 (a game is running too); VGFS_CODING_THREADS overrides (benchmarks, a Deck's 4)
    static size_t Workers() { if (const char *e = std::getenv("VGFS_CODING_THREADS")) { const long n = std::atol(e); if (n >= 1 && n <= 64) return (size_t)n; }
        return std::max<size_t>(2, std::min<size_t>(8, std::thread::hardware_concurrency() / 2)); }
    Pool() : W(Workers()) {
        for (size_t i = 0; i < W; ++i) std::thread([this] { for (;;) { std::function<void()> F;
            { std::unique_lock<std::mutex> l(Mu); Cv.wait(l, [this] { return !Q.empty(); }); F = std::move(const_cast<Job &>(Q.top()).F); Q.pop(); }
            F(); } }).detach();
    }
    struct Job { uint32_t depth; uint64_t seq; std::function<void()> F;
        bool operator<(const Job &o) const { return depth != o.depth ? depth > o.depth : seq > o.seq; } };   // top: least depth, first asked
    size_t W; std::mutex Mu; std::condition_variable Cv; std::priority_queue<Job> Q; uint64_t Seq = 0;
};
} // namespace

struct CodedByteSource::Impl : std::enable_shared_from_this<CodedByteSource::Impl> {
    Description D; std::unique_ptr<Spec> S; uint64_t total = 0, payloadAt = 0, size = 0;
    std::vector<Ck> cks; std::shared_ptr<ByteSource> rec, content;
    std::mutex mu;
    struct Waiters { std::condition_variable cv; int n = 0; };
    std::map<size_t, Waiters> waits;                                        // readers waiting on a segment being decoded: only they are woken
    std::map<size_t, std::shared_ptr<const Seg>> segs;                      // decoded segments, shared by every reader
    std::map<size_t, uint64_t> used; uint64_t clock = 0;                    // when each was last read (least recently used goes)
    uint64_t ends[8] = {0}; int nend = 0;                                   // where recent reads ended (readers going front to back)
    std::atomic<uint64_t> decodes{0}, generated{0};
    std::set<size_t> queued, running, bad;                                  // asked of the pool, not started; being decoded; failed
    bool dropOnWake = false;                                                // (tests) the next woken reader loses its segment
    uint32_t depth = 0;                                                     // coded layers under this one (the pool runs lower ones first)
    bool predicted = false;                                                 // a VGCQ record: its runs take the families' predictions
    std::shared_ptr<PredictCache> pcache = std::make_shared<PredictCache>();

    uint64_t segEnd(size_t k) const { return k + 1 < cks.size() ? cks[k + 1].out : size; }
    size_t segOf(uint64_t off) const { size_t lo = 0, hi = cks.size(); while (hi - lo > 1) { const size_t m = (lo + hi) / 2; if (cks[m].out <= off) lo = m; else hi = m; } return lo; }
    bool payload(size_t j, std::vector<uint8_t> &p) const {
        std::vector<uint8_t> z((size_t)cks[j].recLen);
        return rec->preadAll(z.data(), z.size(), payloadAt + cks[j].rec) && Unzstd(z, p);
    }
    // segment j's decisions, from its payload q after the snapshot (at `at`)
    bool chunk(size_t j, const std::vector<uint8_t> &q, size_t at, std::vector<uint32_t> &c, uint64_t &base) const {
        Rd r{q.data(), q.size()}; r.at = at; const uint64_t n = r.var(); if (r.bad || n > q.size() - r.at) return false;
        c.resize((size_t)n); for (auto &x : c) x = (uint32_t)r.var();
        base = cks[j].dec; return !r.bad && r.at == q.size() && base + n == (j + 1 < cks.size() ? cks[j + 1].dec : total);
    }
    // a machine paused at checkpoint k, its decisions loading segment by segment as the run reaches them
    std::unique_ptr<Cursor> start(size_t k) {
        std::vector<uint8_t> p; if (!payload(k, p)) return nullptr;
        Rd r{p.data(), p.size()}; const uint64_t sn = r.var(); if (r.bad || r.at + sn > p.size()) return nullptr;
        auto c = std::make_unique<Cursor>(); c->base = cks[k].out; c->seg = k;
        c->m = std::make_unique<Machine>(D, *S, kCode); Machine &m = *c->m; m.out = &c->out; m.maxCache = size + 1; m.outBase = cks[k].out;
        if (!m.restore(p.data() + r.at, (size_t)sn)) return nullptr;
        m.X.src = content.get(); m.X.size = content->size(); m.X.window = D.window;
        m.noPredict = !predicted; m.pcache = pcache; m.prog0 = m.progress();
        if (!chunk(k, p, r.at + (size_t)sn, m.Dc.chunk, m.Dc.base)) return nullptr;
        m.Dc.setChunk(); m.Dc.total = total;
        Cursor *cp = c.get();
        m.Dc.next = [this, cp](std::vector<uint32_t> &ch, uint64_t &base) {
            if (cp->seg + 1 >= cks.size()) return false;
            std::vector<uint8_t> q; if (!payload(++cp->seg, q)) return false;
            Rd rr{q.data(), q.size()}; const uint64_t s2 = rr.var(); if (rr.bad || rr.at + s2 > q.size()) return false;
            return chunk(cp->seg, q, rr.at + (size_t)s2, ch, base);
        };
        return c;
    }
    // decode segment k whole: exactly the bytes between its checkpoint and the next (both taken at the same MARKs)
    std::shared_ptr<const Seg> decode(size_t k) {
        auto c = start(k); if (!c) return nullptr;
        auto g = std::make_shared<Seg>(); Machine &m = *c->m; m.runs = &g->runs;
        const uint64_t len = segEnd(k) - cks[k].out;
        m.stopAt = k + 1 < cks.size() ? len : UINT64_MAX;
        const int res = m.run(D.entryStream, true);
        if (res == 0 || m.X.err || c->out.size() + m.copied < len) return nullptr;
        // exactly `len` bytes: a run (or generated bytes) past the segment's end belong to the next one
        uint64_t kept = 0; auto &R = g->runs;
        while (!R.empty() && R.back().at >= len) R.pop_back();
        if (!R.empty() && R.back().at + R.back().n > len) R.back().n = (uint32_t)(len - R.back().at);
        for (const auto &r : R) kept += r.n;
        c->out.resize((size_t)(len - kept)); g->pool = std::move(c->out); g->len = len;
        if (predicted) {                                                  // the segment's bytes, against the mint's
            uint64_t h = 1469598103934665603ull, pos = 0, pool = 0; std::vector<uint8_t> b;
            for (const auto &r : g->runs) {
                h = SegmentHash(g->pool.data() + pool, (size_t)(r.at - pos), h); pool += r.at - pos;
                b.resize(r.n); if (!content->preadAll(b.data(), b.size(), r.from)) return nullptr;
                h = SegmentHash(b.data(), b.size(), h); pos = r.at + r.n;
            }
            h = SegmentHash(g->pool.data() + pool, g->pool.size() - pool, h);
            if (h != cks[k].hash) return nullptr;
        }
        return g;
    }
    // the pieces of [from, from+n) of segment g, for dst (caller holds a reference to g while they are used)
    static void pieces(const Seg &g, uint64_t from, size_t n, uint8_t *dst, std::vector<Piece> &P) {
        const uint64_t end = from + n; uint64_t pos = from;
        auto it = std::partition_point(g.runs.begin(), g.runs.end(), [&](const CopyRun &r) { return r.at + r.n <= pos; });
        while (pos < end) {
            if (it != g.runs.end() && it->at <= pos) {                       // inside a copy run: handed down
                const uint64_t m = std::min<uint64_t>(end, it->at + it->n) - pos;
                P.push_back({dst + (pos - from), nullptr, it->from + (pos - it->at), (size_t)m}); pos += m; ++it; continue;
            }
            const uint64_t stop = it == g.runs.end() ? end : std::min<uint64_t>(end, it->at);   // generated bytes up to the next run
            const uint64_t at = it == g.runs.end() ? g.pool.size() - (g.len - pos) : it->pool - (it->at - pos);
            P.push_back({dst + (pos - from), g.pool.data() + at, 0, (size_t)(stop - pos)}); pos = stop;
        }
    }
    // decode segment k in this thread (caller holds mu through `l`, which is released while decoding)
    void run(size_t k, std::unique_lock<std::mutex> &l) {
        queued.erase(k); running.insert(k);
        l.unlock(); auto out = decode(k); ++decodes; l.lock();
        running.erase(k);
        if (out) { generated += out->pool.size(); segs[k] = std::move(out); used[k] = ++clock; } else bad.insert(k);
        const size_t cap = 4 * Pool::Get().size() + 8;                       // keep a few: the least recently read go
        while (segs.size() > cap) {
            size_t victim = SIZE_MAX; uint64_t oldest = UINT64_MAX;
            //never one a reader is waiting for: it was decoded for that reader, who has not taken it yet
            for (const auto &[j, t] : used) if (t < oldest && j != k && !waits.count(j)) { oldest = t; victim = j; }
            if (victim == SIZE_MAX) break;
            segs.erase(victim); used.erase(victim);
        }
        if (auto w = waits.find(k); w != waits.end()) w->second.cv.notify_all();
    }
    // ask the pool for segments [from, to) not decoded, queued or underway (caller holds mu)
    void ahead(size_t from, size_t to) {
        to = std::min(to, cks.size());
        for (size_t k = from; k < to; ++k) {
            if (segs.count(k) || queued.count(k) || running.count(k) || bad.count(k)) continue;
            queued.insert(k);
            std::weak_ptr<Impl> w = shared_from_this();
            Pool::Get().Post(depth, [w, k] {
                auto self = w.lock(); if (!self) return;
                std::unique_lock<std::mutex> l(self->mu);
                if (!self->queued.count(k)) return;                          // a reader took it over
                self->run(k, l);
            });
        }
    }
    // wait for segment j: decode it here if it is only queued (WORK STEALING: a reader never waits on a job that has not
    // started, so readers nested at any depth, inside pool workers or not, cannot deadlock the pool)
    void await(size_t j, std::unique_lock<std::mutex> &l) {
        while (!segs.count(j) && !bad.count(j)) {
            if (queued.count(j)) { run(j, l); continue; }
            //neither decoded, queued nor underway: decoded and gone again before this reader woke (read-ahead filled
            //the cache under a slow content read) — decode it once more, here
            if (!running.count(j)) { queued.insert(j); run(j, l); continue; }
            Waiters &w = waits[j]; ++w.n; w.cv.wait(l); if (--w.n == 0) waits.erase(j);
            if (dropOnWake && segs.count(j)) { dropOnWake = false; segs.erase(j); used.erase(j); }   // (tests)
        }
    }
};

std::shared_ptr<CodedByteSource> CodedByteSource::Create(std::shared_ptr<ByteSource> Desc, std::shared_ptr<ByteSource> Record,
                                                         std::shared_ptr<ByteSource> Content, uint64_t ShippedSize, std::string &Err) {
    if (!Desc || !Record || !Content) { Err = "no description, record or content"; return nullptr; }
    auto S = std::shared_ptr<CodedByteSource>(new CodedByteSource());
    S->I = std::make_shared<Impl>();
    std::vector<uint8_t> d(Desc->size());
    if (d.size() > (64u << 20) || (!d.empty() && !Desc->preadAll(d.data(), d.size(), 0))) { Err = "the description does not read"; return nullptr; }
    if (!Parse(d.data(), d.size(), S->I->D, Err)) return nullptr;
    S->I->S = std::make_unique<Spec>(S->I->D);
    if (!S->I->S->ok) { Err = "a description too complex to run"; return nullptr; }
    if (Content->size() > 0xFFFFFFFFu) { Err = "content over 4 GiB is not supported"; return nullptr; }
    // the record's index
    const uint64_t rn = Record->size(); std::vector<uint8_t> h((size_t)std::min<uint64_t>(rn, 1u << 16));
    if (h.size() < 4 || !Record->preadAll(h.data(), h.size(), 0) || memcmp(h.data(), "VGC", 3) != 0 || (h[3] != 'R' && h[3] != 'Q')) { Err = "not a coding record"; return nullptr; }
    S->I->predicted = h[3] == 'Q';
    for (;;) {
        Rd r{h.data(), h.size()}; r.at = 4; S->Cks.clear();
        const uint64_t shipped = r.var(); S->I->total = r.var(); const uint64_t nck = r.var();
        if (!r.bad && ShippedSize && shipped != ShippedSize) { Err = "the record is for a stream of another size"; return nullptr; }
        if (!r.bad) ShippedSize = shipped;
        uint64_t off = 0, lastOut = 0, lastDec = 0;
        bool ok = !r.bad && nck >= 1 && nck <= (1u << 24);
        for (uint64_t k = 0; ok && k < nck; ++k) {
            Ck c; c.out = r.var(); c.dec = r.var(); c.recLen = r.var(); c.rec = off;
            if (S->I->predicted) c.hash = r.var();
            if (r.bad) break;
            if (c.recLen > rn || off + c.recLen > rn) { ok = false; break; }
            off += c.recLen;
            if ((k == 0 && (c.out || c.dec)) || (k && (c.out < lastOut || c.dec < lastDec)) || c.dec > S->I->total || c.out > ShippedSize) { ok = false; break; }
            lastOut = c.out; lastDec = c.dec; S->Cks.push_back(c);
        }
        if (r.bad && h.size() < rn) { h.resize((size_t)std::min<uint64_t>(rn, h.size() * 4)); if (!Record->preadAll(h.data(), h.size(), 0)) { Err = "the record does not read"; return nullptr; } continue; }
        if (!ok || r.bad) { Err = "a malformed coding record"; return nullptr; }
        S->I->payloadAt = r.at;
        if (r.at + off != rn) { Err = "the record is not the size its index says"; return nullptr; }
        break;
    }
    if (auto below = std::dynamic_pointer_cast<CodedByteSource>(Content)) S->I->depth = below->I->depth + 1;
    S->Rec = Record; S->Content = Content; S->Size = ShippedSize;
    S->I->pcache->streamBudget = MaxWorkPerByte(S->I->D) * (ShippedSize + Content->size() + 2 * kLz4hcMaxBlock);
    S->I->cks = S->Cks; S->I->rec = std::move(Record); S->I->content = std::move(Content); S->I->size = ShippedSize;
    return S;
}

uint64_t CodedByteSource::segmentsDecoded() const { return I->decodes.load(); }
bool CodedByteSource::predicted() const { return I->predicted; }

bool ExpandInto(std::shared_ptr<ByteSource> Desc, std::shared_ptr<ByteSource> Record, std::shared_ptr<ByteSource> Content,
                uint8_t *ShippedBuf, size_t ShippedCap, uint8_t *ContentBuf, size_t ContentCap, uint64_t Spacing,
                std::vector<uint8_t> &Plain, std::string &Err) {
    auto C = CodedByteSource::Create(Desc, Record, Content, 0, Err);
    if (!C) return false;
    const uint64_t n = C->size(), cn = Content->size();
    //what a record says the stream's size is, the content must account for (a stream is its content coded, plus framing)
    if (n > cn + cn / 8 + Record->size() + (1u << 20)) { Err = "the record claims a stream far bigger than its content"; return false; }
    if (n > ShippedCap || cn > ContentCap) { Err = "the buffers are too small for this stream"; return false; }
    // the shipped bytes, through the predicted record (read front to back: segments decode ahead in the pool)
    for (uint64_t at = 0; at < n;) {
        const size_t k = (size_t)std::min<uint64_t>(n - at, 8u << 20);
        C->prefetch(at + k, std::min<uint64_t>(n - at - k, 64u << 20));
        if (!C->preadAll(ShippedBuf + at, k, at)) { Err = "the stream does not read through its record"; return false; }
        at += k;
    }
    const Description &D = C->I->D;
    size_t len = 0;
    if (!MintInto(D, ShippedBuf, (size_t)n, (size_t)cn, ContentBuf, ContentCap, Spacing, len, Plain, Err, false)) return false;
    // the plain mint's content is the stream's own: it must be the content the record was minted over
    std::vector<uint8_t> b(1u << 20);
    for (uint64_t at = 0; at < cn;) {
        const size_t k = (size_t)std::min<uint64_t>(cn - at, b.size());
        if (!Content->preadAll(b.data(), k, at)) { Err = "the content does not read"; return false; }
        if (memcmp(b.data(), ContentBuf + at, k) != 0) { Err = "the stream codes from other content than its own"; return false; }
        at += k;
    }
    return true;
}
void CodedByteSource::debugHoldWaiter(uint64_t Off, bool On) {
    std::lock_guard<std::mutex> g(I->mu);
    const size_t j = I->segOf(Off);
    if (On) ++I->waits[j].n; else if (I->waits.count(j) && --I->waits[j].n <= 0) I->waits.erase(j);
}
bool CodedByteSource::debugCached(uint64_t Off) const { std::lock_guard<std::mutex> g(I->mu); return I->segs.count(I->segOf(Off)) > 0; }
void CodedByteSource::debugStreamBudget(uint64_t Steps) { I->pcache->streamBudget = Steps; }
void CodedByteSource::debugLzxKept(uint64_t Bytes) { I->pcache->lzxKept = Bytes; }
void CodedByteSource::debugDropOnNextWake() { std::lock_guard<std::mutex> g(I->mu); I->dropOnWake = true; }
uint64_t CodedByteSource::bytesGenerated() const { return I->generated.load(); }

void CodedByteSource::prefetch(uint64_t Off, uint64_t N) {
    if (Off >= Size || !N) return;
    std::lock_guard<std::mutex> g(I->mu);
    //at most half the segments kept: asking further ahead only decodes what is evicted before it is read
    const size_t From = I->segOf(Off), Cap = (4 * Pool::Get().size() + 8) / 2;
    I->ahead(From, std::min<size_t>(I->segOf(std::min<uint64_t>(Size - 1, Off + N - 1)) + 1, From + Cap));
}

ssize_t CodedByteSource::pread(void *Buf, size_t N, uint64_t Off) {
    if (Off >= Size || !N) return 0;
    if (N > Size - Off) N = (size_t)(Size - Off);
    Impl &M = *I; uint8_t *dst = static_cast<uint8_t *>(Buf);
    // Every read is served from whole decoded segments, shared by every reader (a layer above reads this one from many
    // pool workers at once, each front to back in its own region): a segment is decoded once however many read it.
    // A read that continues where a recent one ended asks the pool for the segments after it (read-ahead).
    std::unique_lock<std::mutex> l(M.mu);
    bool continues = Off == 0;
    for (int e = 0; e < M.nend && !continues; ++e) continues = Off >= M.ends[e] ? Off - M.ends[e] <= (256u << 10) : M.ends[e] - Off <= (256u << 10);
    uint64_t at = Off; size_t done = 0;
    std::vector<std::shared_ptr<const Seg>> hold; std::vector<Piece> P;
    while (done < N) {
        const size_t j = M.segOf(at);
        M.ahead(j, j + 1 + (continues ? Pool::Get().size() : 0));
        M.await(j, l);
        auto it = M.segs.find(j);
        if (it == M.segs.end()) return -EIO;                                 // it does not decode
        M.used[j] = ++M.clock;
        const uint64_t from = at - M.cks[j].out, n = std::min<uint64_t>(N - done, it->second->len - from);
        Impl::pieces(*it->second, from, (size_t)n, dst + done, P); hold.push_back(it->second); done += (size_t)n; at += n;
    }
    remember(M, Off, N);
    l.unlock();
    // the pieces, outside the lock: generated bytes copied, copy runs handed down to the content (which serves its own
    // copy runs the same way, so the bytes are written once, by the layer that holds them)
    for (const Piece &p : P) {
        if (p.mem) memcpy(p.dst, p.mem, p.n);
        else if (!Content->preadAll(p.dst, p.n, p.from)) return -EIO;
    }
    return (ssize_t)N;
}

void CodedByteSource::remember(Impl &M, uint64_t Off, size_t N) {
    int slot = 0; for (int e = 1; e < M.nend; ++e) if (M.ends[e] < M.ends[slot]) slot = e;   // remember this end (replacing the oldest-placed)
    if (M.nend < 8) slot = M.nend++;
    for (int e = 0; e < M.nend; ++e) if (M.ends[e] == Off) { slot = e; break; }           // a reader moving on replaces its own end
    M.ends[slot] = Off + N;
}

} // namespace coding
