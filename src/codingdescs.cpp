// Descriptions of the formats VidyaGod knows how to WRITE, built with a small assembler. The reader never runs any
// of this: it parses whatever description data a package carries. These exist so the packer can mint.
#include "coding.h"

#include <cstring>

namespace coding {

namespace {

struct Asm {
    Description d;
    std::vector<int> lab = std::vector<int>(128, -1);
    std::vector<std::pair<size_t, int>> fix;
    uint8_t mode = 0;
    uint16_t e(uint8_t op, uint16_t a, uint16_t b, uint32_t imm) { d.ex.push_back(Ex{op, a, b, imm}); return (uint16_t)(d.ex.size() - 1); }
    uint16_t C(uint32_t v) { return e(EX_CONST, 0, 0, v); }
    uint16_t R(int r) { return e(EX_REG, 0, 0, (uint32_t)r); }
    uint16_t X(uint8_t op, uint16_t a, uint16_t b) { return e(op, a, b, 0); }
    uint16_t X1(uint8_t op, uint16_t a) { return e(op, a, 0, 0); }
    uint16_t TB(int t, uint16_t a) { return e(EX_TABLE, a, 0, (uint32_t)t); }
    uint16_t AR(int t, uint16_t a) { return e(EX_ARR, a, 0, (uint32_t)t); }
    uint16_t Z() { return C(0); }
    void op(uint8_t o, uint8_t flags, uint8_t nb, uint8_t tgt, uint16_t x, uint16_t v, uint16_t m, uint32_t imm, int l = -1) {
        if (l >= 0) fix.push_back({d.ops.size(), l});
        Op p; p.op = o; p.modes = mode; p.flags = flags; p.nb = nb; p.tgt = tgt; p.x = x; p.v = v; p.m = m; p.imm = imm; d.ops.push_back(p);
    }
    void Mode(uint8_t m) { mode = m; }
    void Label(int l) { lab[(size_t)l] = (int)d.ops.size(); }
    void link() { for (auto &f : fix) d.ops[f.first].target = (uint16_t)lab[(size_t)f.second]; }
    // ops
    void Bit(uint16_t slot, uint16_t v, int t) { op(OP_BIT, 0, 0, (uint8_t)t, slot, v, Z(), 0); }
    void Tree(uint16_t slot, int nb, uint16_t v, int t) { op(OP_TREE, 0, (uint8_t)nb, (uint8_t)t, slot, v, Z(), 0); }
    void RTree(uint16_t slot, int nb, uint16_t v, int t) { op(OP_RTREE, 0, (uint8_t)nb, (uint8_t)t, slot, v, Z(), 0); }
    void RTreeN(uint16_t slot, uint16_t n, uint16_t v, int t) { op(OP_RTREE, 0, 0, (uint8_t)t, slot, v, n, 0); }
    void Direct(uint16_t n, uint16_t v, int t) { op(OP_DIRECT, 0, 0, (uint8_t)t, n, v, Z(), 0); }
    void MLit(uint16_t slot, uint16_t v, uint16_t mb, int t) { op(OP_MLIT, 0, 0, (uint8_t)t, slot, v, mb, 0); }
    void Raw(uint16_t n, uint16_t v, int t) { op(OP_RAW, 0, 0, (uint8_t)t, n, v, Z(), 0); }
    void RawF(uint16_t n, int t) { op(OP_RAW, kFree, 0, (uint8_t)t, n, Z(), Z(), 0); }
    void Huff(int tab, uint16_t v, int t) { op(OP_HUFF, 0, 0, (uint8_t)t, Z(), v, Z(), (uint32_t)tab); }
    void HuffF(int tab, int t) { op(OP_HUFF, kFree, 0, (uint8_t)t, Z(), Z(), Z(), (uint32_t)tab); }
    void Build(int tab, int arr, uint16_t x, uint16_t n) { op(OP_BUILD, 0, (uint8_t)arr, 0, x, n, Z(), (uint32_t)tab); }
    void Sta(int arr, uint16_t i, uint16_t v) { op(OP_STA, 0, (uint8_t)arr, 0, i, v, Z(), 0); }
    void Set(int t, uint16_t v) { op(OP_SET, 0, 0, (uint8_t)t, Z(), v, Z(), 0); }
    void Dec(int t) { op(OP_DEC, 0, 0, (uint8_t)t, Z(), Z(), Z(), 0); }
    void OutLit(uint16_t v) { op(OP_OUTLIT, 0, 0, 0, Z(), v, Z(), 0); }
    void OutCopy(uint16_t len, uint16_t dist) { op(OP_OUTCOPY, 0, 0, 0, len, dist, Z(), 0); }
    void HMtf(int base, int n, uint16_t s) { op(OP_HMTF, 0, (uint8_t)n, (uint8_t)base, Z(), s, Z(), 0); }
    void HPush(int base, int n, uint16_t v) { op(OP_HPUSH, 0, (uint8_t)n, (uint8_t)base, Z(), v, Z(), 0); }
    void Jz(uint16_t v, int l) { op(OP_JZ, 0, 0, 0, Z(), v, Z(), 0, l); }
    void Jmp(int l) { op(OP_JMP, 0, 0, 0, Z(), Z(), Z(), 0, l); }
    void Call(int l) { op(OP_CALL, 0, 0, 0, Z(), Z(), Z(), 0, l); }
    void Ret() { op(OP_RET, 0, 0, 0, Z(), Z(), Z(), 0); }
    void Assert(uint16_t v) { op(OP_ASSERT, 0, 0, 0, Z(), v, Z(), 0); }
    void Flush() { op(OP_FLUSH, 0, 0, 0, Z(), Z(), Z(), 0); }
    void Mark() { op(OP_MARK, 0, 0, 0, Z(), Z(), Z(), 0); }
    void HuffRun(int tab, uint16_t n, int runReg, int termReg, uint16_t lim) { op(OP_HUFFRUN, 0, (uint8_t)termReg, (uint8_t)runReg, n, Z(), lim, (uint32_t)tab); }
    void ByteRun(uint16_t n) { op(OP_BYTERUN, 0, 0, 0, n, Z(), Z(), 0); }
    void Predict(int family, uint32_t knob, int tgt, uint16_t at, uint16_t lo, uint16_t hi) { op(OP_PREDICT, 0, (uint8_t)family, (uint8_t)tgt, at, lo, hi, knob); }
    void End() { op(OP_END, 0, 0, 0, Z(), Z(), Z(), 0); }
    uint16_t ADD(uint16_t a, uint16_t b) { return X(EX_ADD, a, b); }
    uint16_t SUB(uint16_t a, uint16_t b) { return X(EX_SUB, a, b); }
    uint16_t MUL(uint16_t a, uint16_t b) { return X(EX_MUL, a, b); }
    uint16_t SHL(uint16_t a, uint16_t b) { return X(EX_SHL, a, b); }
    uint16_t SHR(uint16_t a, uint16_t b) { return X(EX_SHR, a, b); }
    uint16_t AND(uint16_t a, uint16_t b) { return X(EX_AND, a, b); }
    uint16_t OR(uint16_t a, uint16_t b) { return X(EX_OR, a, b); }
    uint16_t XOR(uint16_t a, uint16_t b) { return X(EX_XOR, a, b); }
    uint16_t LT(uint16_t a, uint16_t b) { return X(EX_LT, a, b); }
    uint16_t EQ(uint16_t a, uint16_t b) { return X(EX_EQ, a, b); }
    uint16_t NE(uint16_t a, uint16_t b) { return X(EX_NE, a, b); }
    uint16_t GE(uint16_t a, uint16_t b) { return X(EX_GE, a, b); }
};

// ---- LZMA
enum { LR_K = 1, LR_L, LR_D, LR_SL, LR_S, LR_H0, LR_H1, LR_H2, LR_H3, LR_B, LR_V, LR_T0, LR_T1, LR_T2, LR_CUR, LR_PS, LR_FB, LR_BASE };
const uint32_t kLitNext[12] = {0,0,0,0,1,2,3,4,5,6,4,5}, kMatchNext[12] = {7,7,7,7,7,7,7,10,10,10,10,10},
               kRepNext[12] = {8,8,8,8,8,8,8,11,11,11,11,11}, kShortNext[12] = {9,9,9,9,9,9,9,11,11,11,11,11};
enum : uint32_t { S_ISMATCH = 0, S_ISREP = 192, S_REPG0 = 204, S_REPG1 = 216, S_REPG2 = 228, S_REP0LONG = 240, S_POSSLOT = 432,
                  S_POSENC = 688, S_ALIGN = 802, S_LEN = 818, S_REPLEN = 818 + 514, S_LIT = 818 + 1028 };
enum { Z_STREAM, Z_LOOP, Z_ENDC, Z_ENDD, Z_TOK, Z_SLOT1, Z_REP0, Z_MTF, Z_REPLEN, Z_SHORT, Z_MATCH, Z_ALIGN, Z_SMALL, Z_PUSH, Z_ENDTOK,
       Z_LIT, Z_PLAIN, Z_LE, Z_LEN0 };
void LzLen(Asm &a, uint32_t base, int l0, uint16_t PS) {
    const uint16_t V = a.R(LR_V), B = a.R(LR_B);
    a.Mode(kCodePrice); a.Set(LR_B, a.GE(V, a.C(8))); a.Mode(0); a.Bit(a.C(base), B, LR_B); a.Jz(B, l0);
    a.Mode(kCodePrice); a.Set(LR_B, a.GE(V, a.C(16))); a.Mode(0); a.Bit(a.C(base + 1), B, LR_B); a.Jz(B, l0 + 1);
    a.Mode(kCodePrice); a.Set(LR_T2, a.SUB(V, a.C(16))); a.Mode(0); a.Tree(a.C(base + 2 + 256), 8, a.R(LR_T2), LR_T2);
    a.Mode(kDecode); a.Set(LR_V, a.ADD(a.R(LR_T2), a.C(16))); a.Mode(0); a.Jmp(l0 + 2);
    a.Label(l0 + 1);
    a.Mode(kCodePrice); a.Set(LR_T2, a.SUB(V, a.C(8))); a.Mode(0); a.Tree(a.ADD(a.C(base + 2 + 128), a.SHL(PS, a.C(3))), 3, a.R(LR_T2), LR_T2);
    a.Mode(kDecode); a.Set(LR_V, a.ADD(a.R(LR_T2), a.C(8))); a.Mode(0); a.Jmp(l0 + 2);
    a.Label(l0);
    a.Tree(a.ADD(a.C(base + 2), a.SHL(PS, a.C(3))), 3, V, LR_V);
    a.Label(l0 + 2);
}

// ---- deflate
enum { DR_K = 1, DR_L, DR_D, DR_BF, DR_BT, DR_SYM, DR_C, DR_E, DR_DC, DR_N, DR_I, DR_HLIT, DR_HDIST, DR_HCLEN, DR_R, DR_T, DR_LEN, DR_NLEN, DR_B, DR_RUN };
enum { DA_LENS, DA_CL, DA_FIXL, DA_FIXD };
enum { DT_LBASE, DT_LEXT, DT_DBASE, DT_DEXT, DT_CLORDER, DT_LSYM };
enum { G_STREAM, G_BLOCK, G_DYN, G_TOKENS, G_BEND, G_STORED, G_SLOOP, G_DYNHDR, G_CLCLR, G_CLGO, G_CLRD, G_CLB, G_LL, G_RLE, G_Z, G_Z18,
       G_FILL, G_FL, G_LLDONE, G_TOK, G_TEOB, G_TLIT, G_TCODE, G_LIT, G_EOB };

// ---- LZ4
enum { QR_LIT = 1, QR_ML, QR_OFF, QR_TK, QR_R, QR_B, QR_I };
enum { QR_A = 40, QR_PL, QR_PM, QR_PO, QR_F };                       // with a family: the anchor, the predicted token, the flag
enum { Q_STREAM, Q_SEQ, Q_LX, Q_LITS, Q_LL, Q_LDONE, Q_LAST, Q_MX, Q_COPY, Q_ENDC, Q_TOKEN, Q_PRED, Q_GOT, Q_RECORD, Q_RECDONE };
// An LZ4 block's encoder family: its parse of the block [lo, hi) (registers) predicts every sequence
struct Lz4Family { uint32_t attempts; int lo, hi; };

} // namespace

Description LzmaDescription(int lc, int lp, int pb, uint32_t dict, bool hasEnd) {
    Asm a;
    const uint16_t P = a.R(kRegPlace), K = a.R(LR_K), L = a.R(LR_L), D = a.R(LR_D), SL = a.R(LR_SL), S = a.R(LR_S), B = a.R(LR_B), H0 = a.R(LR_H0), T0 = a.R(LR_T0);
    const uint16_t PS = a.AND(P, a.C((1u << pb) - 1)), FB = a.R(LR_FB), BASE = a.R(LR_BASE);   // the position state: an expression
    // the stream: tokens until the end marker (a copy no stream can reach) or, without one, the content's end.
    // Decisions per token: its kind; a copy adds length, history slot, distance - 1 (a literal needs nothing more).
    a.Label(Z_STREAM); a.Label(Z_LOOP); a.Mark();
    if (!hasEnd) a.Jz(a.X1(EX_XLEFT, 0), Z_ENDC);
    a.Mode(kCode); a.Dec(LR_K); a.Mode(0);
    a.Call(Z_TOK);
    a.Jz(a.NE(K, a.C(2)), Z_ENDC);
    a.Jmp(Z_LOOP);
    a.Label(Z_ENDC); a.Mode(kCode); a.Flush(); a.Mode(0);
    a.Label(Z_ENDD); a.End();
    // one token
    a.Label(Z_TOK);
    a.Bit(a.ADD(a.C(S_ISMATCH), a.ADD(a.SHL(S, a.C(4)), PS)), K, LR_K);
    a.Mode(kDecode); a.Dec(LR_K); a.Mode(0);
    a.Jz(K, Z_LIT);
    a.Mode(kCode); a.Dec(LR_L); a.Dec(LR_SL); a.Dec(LR_D); a.Mode(0);
    a.Mode(kCodePrice); a.Set(LR_B, a.NE(SL, a.C(kNoSlot))); a.Mode(0); a.Bit(a.ADD(a.C(S_ISREP), S), B, LR_B); a.Jz(B, Z_MATCH);
    a.Mode(kCodePrice); a.Set(LR_B, a.NE(SL, a.C(0))); a.Mode(0); a.Bit(a.ADD(a.C(S_REPG0), S), B, LR_B); a.Jz(B, Z_REP0);
    a.Mode(kCodePrice); a.Set(LR_B, a.NE(SL, a.C(1))); a.Mode(0); a.Bit(a.ADD(a.C(S_REPG1), S), B, LR_B); a.Jz(B, Z_SLOT1);
    a.Mode(kCodePrice); a.Set(LR_B, a.SUB(SL, a.C(2))); a.Mode(0); a.Bit(a.ADD(a.C(S_REPG2), S), B, LR_B);
    a.Mode(kDecode); a.Set(LR_SL, a.ADD(B, a.C(2))); a.Mode(0); a.Jmp(Z_MTF);
    a.Label(Z_SLOT1); a.Mode(kDecode); a.Set(LR_SL, a.C(1)); a.Mode(0); a.Jmp(Z_MTF);
    a.Label(Z_REP0); a.Mode(kDecode); a.Set(LR_SL, a.C(0)); a.Mode(0);
    a.Mode(kCodePrice); a.Set(LR_B, a.NE(L, a.C(1))); a.Mode(0); a.Bit(a.ADD(a.C(S_REP0LONG), a.ADD(a.SHL(S, a.C(4)), PS)), B, LR_B); a.Jz(B, Z_SHORT); a.Jmp(Z_REPLEN);
    a.Label(Z_MTF); a.HMtf(LR_H0, 4, SL);
    a.Label(Z_REPLEN);
    a.Mode(kCodePrice); a.Set(LR_V, a.SUB(L, a.C(2))); a.Mode(0); LzLen(a, S_REPLEN, Z_LEN0, PS);
    a.Mode(kDecode); a.Set(LR_L, a.ADD(a.R(LR_V), a.C(2))); a.Set(LR_D, a.C(0)); a.Dec(LR_L); a.Dec(LR_SL); a.Dec(LR_D); a.Mode(0);
    a.Set(LR_S, a.TB(2, S)); a.OutCopy(L, a.ADD(H0, a.C(1))); a.Ret();
    a.Label(Z_SHORT); a.Mode(kDecode); a.Set(LR_L, a.C(1)); a.Set(LR_D, a.C(0)); a.Dec(LR_L); a.Dec(LR_SL); a.Dec(LR_D); a.Mode(0);
    a.Set(LR_S, a.TB(3, S)); a.OutCopy(a.C(1), a.ADD(H0, a.C(1))); a.Ret();
    a.Label(Z_MATCH); a.Mode(kDecode); a.Set(LR_SL, a.C(kNoSlot)); a.Mode(0); a.Set(LR_S, a.TB(1, S));
    a.Mode(kCodePrice); a.Set(LR_V, a.SUB(L, a.C(2))); a.Mode(0); LzLen(a, S_LEN, Z_LEN0 + 3, PS);
    a.Mode(kDecode); a.Set(LR_L, a.ADD(a.R(LR_V), a.C(2))); a.Mode(0);
    const uint16_t LTPS = a.TB(4, L);                                    // min(L - 2, 3): a table, so the slot index is affine
    a.Mode(kCodePrice); a.Set(LR_T0, a.X1(EX_LOG2SLOT, D)); a.Mode(0);
    a.Tree(a.ADD(a.C(S_POSSLOT), a.SHL(LTPS, a.C(6))), 6, T0, LR_T0);
    a.Jz(a.GE(T0, a.C(4)), Z_SMALL);
    a.Set(LR_FB, a.SUB(a.SHR(T0, a.C(1)), a.C(1))); a.Set(LR_BASE, a.SHL(a.OR(a.C(2), a.AND(T0, a.C(1))), FB));
    a.Jz(a.LT(T0, a.C(14)), Z_ALIGN);
    a.RTreeN(a.SUB(a.SUB(a.ADD(a.C(S_POSENC), BASE), T0), a.C(1)), FB, a.SUB(D, BASE), LR_T1);
    a.Mode(kDecode); a.Set(LR_D, a.ADD(BASE, a.R(LR_T1))); a.Mode(0); a.Jmp(Z_PUSH);
    a.Label(Z_ALIGN);
    a.Direct(a.SUB(FB, a.C(4)), a.SHR(a.SUB(D, BASE), a.C(4)), LR_T1); a.RTree(a.C(S_ALIGN), 4, a.AND(a.SUB(D, BASE), a.C(15)), LR_T2);
    a.Mode(kDecode); a.Set(LR_D, a.ADD(BASE, a.ADD(a.SHL(a.R(LR_T1), a.C(4)), a.R(LR_T2)))); a.Mode(0); a.Jmp(Z_PUSH);
    a.Label(Z_SMALL); a.Mode(kDecode); a.Set(LR_D, T0); a.Mode(0);
    a.Label(Z_PUSH); a.Mode(kDecode); a.Dec(LR_L); a.Dec(LR_SL); a.Dec(LR_D); a.Mode(0);
    a.Jz(a.NE(D, a.C(0xFFFFFFFFu)), Z_ENDTOK);
    a.HPush(LR_H0, 4, D); a.OutCopy(L, a.ADD(D, a.C(1))); a.Ret();
    a.Label(Z_ENDTOK); a.Set(LR_K, a.C(2)); a.Ret();
    a.Label(Z_LIT);
    a.Mode(kCodePrice); a.Set(LR_CUR, a.X1(EX_BYTE, P)); a.Mode(0);
    const uint16_t LITCTX = a.ADD(a.C(S_LIT), a.MUL(a.C(0x300), a.ADD(a.SHL(a.AND(P, a.C((1u << lp) - 1)), a.C((uint32_t)lc)),
                                                                   a.SHR(a.X1(EX_BYTE, a.SUB(P, a.C(1))), a.C(8u - (uint32_t)lc)))));
    a.Jz(a.GE(S, a.C(7)), Z_PLAIN);
    a.MLit(LITCTX, a.R(LR_CUR), a.X1(EX_BYTE, a.SUB(a.SUB(P, H0), a.C(1))), LR_CUR); a.Jmp(Z_LE);
    a.Label(Z_PLAIN); a.Tree(LITCTX, 8, a.R(LR_CUR), LR_CUR);
    a.Label(Z_LE); a.Set(LR_S, a.TB(0, S));
    a.OutLit(a.R(LR_CUR)); a.Ret();
    a.link();
    Description d = std::move(a.d);
    d.name = "LZMA"; d.coder = kRange; d.shift = 5; d.nslots = S_LIT + (0x300u << (lc + lp));
    std::vector<uint32_t> ltps(274); for (uint32_t l = 0; l < 274; ++l) ltps[l] = l < 2 ? 0 : std::min<uint32_t>(l - 2, 3);
    d.tables = {std::vector<uint32_t>(kLitNext, kLitNext + 12), std::vector<uint32_t>(kMatchNext, kMatchNext + 12),
                std::vector<uint32_t>(kRepNext, kRepNext + 12), std::vector<uint32_t>(kShortNext, kShortNext + 12), ltps};
    d.entryStream = (uint16_t)a.lab[Z_STREAM]; d.entryToken = a.lab[Z_TOK];
    d.window = dict; d.maxlen = 273; d.len1slot = 0; d.histbase = LR_H0; d.histlen = 4; d.tokK = LR_K; d.tokL = LR_L; d.tokSL = LR_SL; d.tokD = LR_D;
    return d;
}

Description DeflateDescription() {
    static const uint32_t LBASE[29] = {3,4,5,6,7,8,9,10,11,13,15,17,19,23,27,31,35,43,51,59,67,83,99,115,131,163,195,227,258};
    static const uint32_t LEXT[29] = {0,0,0,0,0,0,0,0,1,1,1,1,2,2,2,2,3,3,3,3,4,4,4,4,5,5,5,5,0};
    static const uint32_t DBASE[30] = {1,2,3,4,5,7,9,13,17,25,33,49,65,97,129,193,257,385,513,769,1025,1537,2049,3073,4097,6145,8193,12289,16385,24577};
    static const uint32_t DEXT[30] = {0,0,0,0,1,1,2,2,3,3,4,4,5,5,6,6,7,7,8,8,9,9,10,10,11,11,12,12,13,13};
    static const uint32_t CLORDER[19] = {16,17,18,0,8,7,9,6,10,5,11,4,12,3,13,2,14,1,15};
    std::vector<uint32_t> lsym(256), fixl(288), fixd(30, 5);
    for (int v = 0; v < 256; ++v) { int s = 28; while ((uint32_t)(v + 3) < LBASE[s]) --s; lsym[(size_t)v] = (uint32_t)s; }
    for (int k = 0; k < 288; ++k) fixl[(size_t)k] = k < 144 ? 8 : k < 256 ? 9 : k < 280 ? 7 : 8;
    Asm a;
    const uint16_t K = a.R(DR_K), L = a.R(DR_L), D = a.R(DR_D), BF = a.R(DR_BF), BT = a.R(DR_BT), SYM = a.R(DR_SYM), Cc = a.R(DR_C), E = a.R(DR_E), DC = a.R(DR_DC);
    const uint16_t N = a.R(DR_N), I = a.R(DR_I), HLIT = a.R(DR_HLIT), HDIST = a.R(DR_HDIST), HCLEN = a.R(DR_HCLEN), Rr = a.R(DR_R), T = a.R(DR_T), LEN = a.R(DR_LEN), NLEN = a.R(DR_NLEN);
    const uint16_t PAD = a.AND(a.SUB(a.C(8), a.X1(EX_BITPOS, 0)), a.C(7)), ONE = a.C(1);
    a.Label(G_STREAM); a.Label(G_BLOCK); a.Mark();
    a.RawF(a.C(1), DR_BF); a.RawF(a.C(2), DR_BT); a.Assert(a.NE(BT, a.C(3)));
    a.Jz(BT, G_STORED); a.Jz(a.EQ(BT, a.C(1)), G_DYN);
    a.Build(0, DA_FIXL, a.C(0), a.C(288)); a.Build(1, DA_FIXD, a.C(0), a.C(30)); a.Jmp(G_TOKENS);
    a.Label(G_DYN); a.Call(G_DYNHDR);
    a.Label(G_TOKENS); a.Mark();
    a.Mode(kCode); a.Dec(DR_RUN); a.Dec(DR_K); a.Dec(DR_L); a.Dec(DR_D); a.Mode(0);
    a.Call(G_TOK);
    a.Mode(kDecode); a.Dec(DR_RUN); a.Dec(DR_K); a.Dec(DR_L); a.Dec(DR_D); a.Mode(0);
    a.Jz(a.EQ(K, a.C(2)), G_TOKENS);
    a.Label(G_BEND); a.Jz(BF, G_BLOCK);
    a.Set(DR_N, PAD); a.RawF(N, DR_T); a.Mode(kDecode); a.Assert(a.EQ(a.X1(EX_INLEFT, 0), a.C(0))); a.Mode(0); a.Flush(); a.End();
    a.Label(G_STORED);
    a.Set(DR_N, PAD); a.RawF(N, DR_T); a.RawF(a.C(16), DR_LEN);
    a.Mode(kCodePrice); a.Set(DR_NLEN, a.XOR(LEN, a.C(0xFFFF))); a.Mode(0); a.Raw(a.C(16), NLEN, DR_NLEN); a.Assert(a.EQ(NLEN, a.XOR(LEN, a.C(0xFFFF))));
    a.ByteRun(LEN); a.Jmp(G_BEND);
    a.Label(G_DYNHDR);
    a.RawF(a.C(5), DR_HLIT); a.RawF(a.C(5), DR_HDIST); a.RawF(a.C(4), DR_HCLEN); a.Assert(a.LT(HLIT, a.C(30))); a.Assert(a.LT(HDIST, a.C(30)));
    a.Set(DR_I, a.C(0));
    a.Label(G_CLCLR); a.Jz(a.LT(I, a.C(19)), G_CLGO); a.Sta(DA_CL, I, a.C(0)); a.Set(DR_I, a.ADD(I, ONE)); a.Jmp(G_CLCLR);
    a.Label(G_CLGO); a.Set(DR_I, a.C(0));
    a.Label(G_CLRD); a.Jz(a.LT(I, a.ADD(HCLEN, a.C(4))), G_CLB); a.RawF(a.C(3), DR_T); a.Sta(DA_CL, a.TB(DT_CLORDER, I), T); a.Set(DR_I, a.ADD(I, ONE)); a.Jmp(G_CLRD);
    a.Label(G_CLB); a.Build(2, DA_CL, a.C(0), a.C(19));
    a.Set(DR_N, a.ADD(a.ADD(HLIT, a.C(257)), a.ADD(HDIST, ONE))); a.Set(DR_I, a.C(0));
    a.Label(G_LL); a.Jz(a.LT(I, N), G_LLDONE);
    a.HuffF(2, DR_SYM); a.Jz(a.LT(SYM, a.C(16)), G_RLE);
    a.Sta(DA_LENS, I, SYM); a.Set(DR_I, a.ADD(I, ONE)); a.Jmp(G_LL);
    a.Label(G_RLE); a.Jz(a.EQ(SYM, a.C(16)), G_Z);
    a.Assert(a.GE(I, ONE)); a.RawF(a.C(2), DR_R); a.Set(DR_T, a.AR(DA_LENS, a.SUB(I, ONE))); a.Set(DR_R, a.ADD(Rr, a.C(3))); a.Jmp(G_FILL);
    a.Label(G_Z); a.Jz(a.EQ(SYM, a.C(17)), G_Z18);
    a.RawF(a.C(3), DR_R); a.Set(DR_R, a.ADD(Rr, a.C(3))); a.Set(DR_T, a.C(0)); a.Jmp(G_FILL);
    a.Label(G_Z18); a.RawF(a.C(7), DR_R); a.Set(DR_R, a.ADD(Rr, a.C(11))); a.Set(DR_T, a.C(0));
    a.Label(G_FILL); a.Assert(a.GE(N, a.ADD(I, Rr)));
    a.Label(G_FL); a.Jz(Rr, G_LL); a.Sta(DA_LENS, I, T); a.Set(DR_I, a.ADD(I, ONE)); a.Set(DR_R, a.SUB(Rr, ONE)); a.Jmp(G_FL);
    a.Label(G_LLDONE); a.Assert(a.NE(a.AR(DA_LENS, a.C(256)), a.C(0)));
    a.Build(0, DA_LENS, a.C(0), a.ADD(HLIT, a.C(257))); a.Build(1, DA_LENS, a.ADD(HLIT, a.C(257)), a.ADD(HDIST, ONE)); a.Ret();
    a.Label(G_TOK);
    // a run of literals, then what ends it: kind 1 a copy, 2 the end of the block, 3 a copy of 258 spelled 284 + 31
    // (deflate's one non-canonical spelling: a true choice, so a decision)
    a.Mode(kCodePrice); a.Jz(a.NE(K, a.C(2)), G_TEOB);
    a.Set(DR_SYM, a.ADD(a.MUL(a.EQ(K, a.C(3)), a.C(284)), a.MUL(a.NE(K, a.C(3)), a.ADD(a.C(257), a.TB(DT_LSYM, a.SUB(L, a.C(3))))))); a.Jmp(G_TCODE);
    a.Label(G_TEOB); a.Set(DR_SYM, a.C(256));
    a.Mode(0); a.Label(G_TCODE);
    a.HuffRun(0, a.R(DR_RUN), DR_RUN, DR_SYM, a.C(256));
    a.Jz(a.NE(SYM, a.C(256)), G_EOB);
    a.Assert(a.LT(SYM, a.C(286)));
    a.Set(DR_C, a.SUB(SYM, a.C(257)));
    a.Mode(kCodePrice); a.Set(DR_E, a.SUB(L, a.TB(DT_LBASE, Cc))); a.Mode(0);
    a.Raw(a.TB(DT_LEXT, Cc), E, DR_E);
    a.Mode(kDecode); a.Set(DR_L, a.ADD(a.TB(DT_LBASE, Cc), E)); a.Mode(0);
    a.Mode(kCodePrice); a.Set(DR_DC, a.X1(EX_LOG2SLOT, a.SUB(D, ONE))); a.Mode(0);
    a.Huff(1, DC, DR_DC); a.Assert(a.LT(DC, a.C(30)));
    a.Mode(kCodePrice); a.Set(DR_E, a.SUB(D, a.TB(DT_DBASE, DC))); a.Mode(0);
    a.Raw(a.TB(DT_DEXT, DC), E, DR_E);
    a.Mode(kDecode); a.Set(DR_D, a.ADD(a.TB(DT_DBASE, DC), E)); a.Set(DR_K, a.ADD(ONE, a.MUL(a.C(2), a.AND(a.EQ(Cc, a.C(27)), a.EQ(L, a.C(258)))))); a.Mode(0);
    a.OutCopy(L, D); a.Ret();
    a.Label(G_EOB); a.Mode(kDecode); a.Set(DR_K, a.C(2)); a.Set(DR_L, a.C(0)); a.Set(DR_D, a.C(0)); a.Mode(0); a.Ret();
    a.link();
    Description d = std::move(a.d);
    d.name = "deflate"; d.coder = kBits;
    d.tables = {std::vector<uint32_t>(LBASE, LBASE + 29), std::vector<uint32_t>(LEXT, LEXT + 29), std::vector<uint32_t>(DBASE, DBASE + 30),
                std::vector<uint32_t>(DEXT, DEXT + 30), std::vector<uint32_t>(CLORDER, CLORDER + 19), lsym};
    d.arrays = {std::vector<uint32_t>(320), std::vector<uint32_t>(19), fixl, fixd};
    d.nhuff = 3; d.entryStream = (uint16_t)a.lab[G_STREAM]; d.entryToken = a.lab[G_TOK];
    d.window = 32768; d.maxlen = 258; d.tokK = DR_K; d.tokL = DR_L; d.tokSL = DR_T; d.tokD = DR_D;
    return d;
}

// One LZ4 block's sequences, from Q_SEQ to Q_ENDC (the caller ends the stream or returns). DECODE: `atEnd` is 0 once the
// block's input is consumed (after a literal run: that run was the last sequence). CODE: the last sequence is the one
// whose match length decision is 0, or the decisions run out.
// With a family (`Fam`), a sequence's decisions are a flag: 0 the family's token, else 1 and the token as it is.
static void Lz4Body(Asm &a, uint16_t atEnd, const Lz4Family *Fam = nullptr) {
    const uint16_t LIT = a.R(QR_LIT), ML = a.R(QR_ML), OFF = a.R(QR_OFF), TK = a.R(QR_TK), Rr = a.R(QR_R), B = a.R(QR_B);
    const uint16_t F15 = a.C(15), B255 = a.C(255);
    auto MIN15 = [&](uint16_t x) { return a.SUB(x, a.MUL(a.GE(x, a.C(16)), a.SUB(x, F15))); };
    auto MIN255 = [&](uint16_t x) { return a.SUB(x, a.MUL(a.GE(x, a.C(256)), a.SUB(x, B255))); };
    auto predict = [&] { a.Predict(kFamilyLz4hc, Fam->attempts, QR_PL, a.R(QR_A), a.R(Fam->lo), a.R(Fam->hi)); };
    // DECODE, a sequence read: its decisions (with a family: whether it is the family's, and if not, itself)
    // (falls: `next` is the label right after it: no jump, so a description without a family is op for op what it was)
    auto record = [&](int next, bool falls = false) {
        a.Mode(kDecode);
        if (!Fam) { a.Dec(QR_LIT); a.Dec(QR_ML); a.Dec(QR_OFF); a.Mode(0); if (!falls) a.Jmp(next); return; }
        predict();
        a.Set(QR_F, a.OR(a.OR(a.NE(LIT, a.R(QR_PL)), a.NE(ML, a.R(QR_PM))), a.NE(OFF, a.R(QR_PO))));
        a.Dec(QR_F); a.Jz(a.R(QR_F), next); a.Dec(QR_LIT); a.Dec(QR_ML); a.Dec(QR_OFF); a.Mode(0); if (!falls) a.Jmp(next);
    };
    a.Label(Q_SEQ); a.Mark();
    if (Fam) a.Set(QR_A, a.R(kRegPlace));
    a.Mode(kCode); a.Jz(a.X1(EX_DLEFT, 0), Q_ENDC);
    if (!Fam) { a.Dec(QR_LIT); a.Dec(QR_ML); a.Dec(QR_OFF); }
    else {
        a.Dec(QR_F); a.Jz(a.R(QR_F), Q_PRED); a.Dec(QR_LIT); a.Dec(QR_ML); a.Dec(QR_OFF); a.Jmp(Q_GOT);
        a.Label(Q_PRED); predict(); a.Assert(a.NE(a.R(QR_PM), a.C(kNoPrediction)));      // a record whose flag the family cannot back
        a.Set(QR_LIT, a.R(QR_PL)); a.Set(QR_ML, a.R(QR_PM)); a.Set(QR_OFF, a.R(QR_PO));
        a.Label(Q_GOT);
    }
    a.Mode(kCode); a.Set(QR_TK, a.OR(a.SHL(MIN15(LIT), a.C(4)), a.MUL(a.NE(ML, a.C(0)), MIN15(a.SUB(ML, a.C(4))))));
    a.Mode(0); a.Raw(a.C(8), TK, QR_TK);
    a.Mode(kDecode); a.Set(QR_LIT, a.SHR(TK, a.C(4))); a.Mode(0);
    a.Jz(a.EQ(a.SHR(TK, a.C(4)), F15), Q_LITS);
    a.Mode(kCodePrice); a.Set(QR_R, a.SUB(LIT, F15)); a.Mode(0);
    a.Label(Q_LX);
    a.Mode(kCodePrice); a.Set(QR_B, MIN255(Rr)); a.Set(QR_R, a.SUB(Rr, B)); a.Mode(0);
    a.Raw(a.C(8), B, QR_B);
    a.Mode(kDecode); a.Set(QR_LIT, a.ADD(LIT, B)); a.Mode(0);
    a.Jz(a.EQ(B, B255), Q_LITS); a.Jmp(Q_LX);
    a.Label(Q_LITS); a.ByteRun(LIT);
    a.Mode(kDecode); a.Jz(atEnd, Q_LAST);
    a.Mode(kCode); a.Jz(ML, Q_ENDC);
    a.Mode(0);
    a.Raw(a.C(16), OFF, QR_OFF); a.Assert(a.NE(OFF, a.C(0)));
    a.Mode(kDecode); a.Set(QR_ML, a.ADD(a.AND(TK, F15), a.C(4))); a.Mode(0);
    a.Jz(a.EQ(a.AND(TK, F15), F15), Q_COPY);
    a.Mode(kCodePrice); a.Set(QR_R, a.SUB(a.SUB(ML, a.C(4)), F15)); a.Mode(0);
    a.Label(Q_MX);
    a.Mode(kCodePrice); a.Set(QR_B, MIN255(Rr)); a.Set(QR_R, a.SUB(Rr, B)); a.Mode(0);
    a.Raw(a.C(8), B, QR_B);
    a.Mode(kDecode); a.Set(QR_ML, a.ADD(ML, B)); a.Mode(0);
    a.Jz(a.EQ(B, B255), Q_COPY); a.Jmp(Q_MX);
    a.Label(Q_COPY); a.OutCopy(ML, OFF);
    record(Q_SEQ);
    a.Label(Q_LAST); a.Mode(kDecode); a.Set(QR_ML, a.C(0)); a.Set(QR_OFF, a.C(0)); a.Mode(0);
    record(Q_ENDC, true);
    a.Label(Q_ENDC);
}

Description Lz4BlockDescription() {
    Asm a;
    a.Label(Q_STREAM);
    Lz4Body(a, a.X1(EX_INLEFT, 0));
    a.End();
    a.link();
    Description d = std::move(a.d);
    d.name = "LZ4 block"; d.coder = kBits; d.entryStream = (uint16_t)a.lab[Q_STREAM]; d.entryToken = -1; d.window = 65535; d.maxlen = 0xFFFFFFFFu;
    return d;
}

// ---- BSA (Bethesda archive, version 105: Skyrim Special Edition)
// The CONTENT is the archive's header region as it is (header, folder records, folder names + file records, file names)
// followed by every member's decoded bytes in data order (an embedded name, when the archive embeds them, stays with its
// member). Members are uncompressed (copied: a copy run of the content) or a 4-byte original size + an LZ4 frame whose
// blocks are LZ4 blocks or stored. Everything the archive's own header says is read back from the content, so the
// header steers the walk and the decisions hold only what the encoder chose: frame flags, block sizes, sequences.
enum { BR_FLAGS = 10, BR_NF, BR_FI, BR_Q, BR_CNT, BR_SZ, BR_LEN, BR_END, BR_ORIG, BR_CEND, BR_MAG, BR_FLG, BR_BD, BR_HC, BR_BS, BR_BEND, BR_X, BR_COMP,
       BR_LEFT, BR_RQ, BR_BLO, BR_BHI };
enum { B_STREAM = 40, B_FOLD, B_FILE, B_NEXTF, B_DONE, B_MEMBER, B_RAWMEM, B_NONAME, B_CS, B_DI, B_BLK, B_CBLK, B_BCK, B_BCS, B_FEND, B_FDONE, B_LZ4,
       B_LOOP, B_HAVE, B_SCAN, B_NEXT, B_NEXTFOLD, B_NONE };
Description BsaDescription(uint32_t Attempts) {
    Asm a;
    auto R = [&](int r) { return a.R(r); };
    auto BYTE = [&](uint16_t at) { return a.X1(EX_BYTE, at); };
    auto U32 = [&](uint16_t at) { return a.OR(a.OR(BYTE(at), a.SHL(BYTE(a.ADD(at, a.C(1))), a.C(8))),
                                              a.OR(a.SHL(BYTE(a.ADD(at, a.C(2))), a.C(16)), a.SHL(BYTE(a.ADD(at, a.C(3))), a.C(24)))); };
    auto SPOS = [&] { return a.X1(EX_STREAMPOS, 0); };
    auto BIT = [&](uint16_t x, int b) { return a.AND(a.SHR(x, a.C((uint32_t)b)), a.C(1)); };
    const uint16_t PLACE = a.R(kRegPlace);
    a.Label(B_STREAM);
    // the header: 36 bytes as they are, then the rest of the header region, whose size the header gives
    a.ByteRun(a.C(36));
    a.Assert(a.EQ(U32(a.C(0)), a.C(0x00415342)));                       // "BSA\0"
    a.Assert(a.EQ(U32(a.C(4)), a.C(105)));
    a.Set(BR_FLAGS, U32(a.C(12))); a.Set(BR_NF, U32(a.C(16)));
    {   const uint16_t F = R(BR_NF), N = U32(a.C(20)), TFN = U32(a.C(24)), TFIN = U32(a.C(28));
        const uint16_t H = a.ADD(a.ADD(a.ADD(a.C(36), a.MUL(F, a.C(24))), a.MUL(BIT(R(BR_FLAGS), 0), a.ADD(TFN, F))),
                                 a.ADD(a.MUL(N, a.C(16)), a.MUL(BIT(R(BR_FLAGS), 1), TFIN)));
        a.Set(BR_X, H); }
    a.Assert(a.GE(R(BR_X), a.C(36)));
    a.ByteRun(a.SUB(R(BR_X), a.C(36)));
    // every member in DATA order (the order the archive stores them): the record whose offset is where the stream
    // stands. Usually the record after the last one taken (a cursor walking folders and their file records, in the
    // content now); where the archive stores members in another order than it lists them (Skyrim SE's 2021 Misc.bsa:
    // 5,582 breaks among 21,474 files), the records are searched from the first, and the cursor continues from the match.
    a.Set(BR_LEFT, U32(a.C(20)));                                          // members left: the archive's file count
    a.Set(BR_Q, a.ADD(a.C(36), a.MUL(R(BR_NF), a.C(24)))); a.Set(BR_FI, a.C(0)); a.Set(BR_CNT, a.C(0));
    a.Label(B_LOOP); a.Jz(R(BR_LEFT), B_DONE);
    a.Call(B_NEXT);
    a.Jz(a.AND(a.NE(R(BR_RQ), a.C(0)), a.EQ(U32(a.ADD(R(BR_RQ), a.C(12))), SPOS())), B_SCAN);
    a.Label(B_HAVE);
    a.Set(BR_SZ, U32(a.ADD(R(BR_RQ), a.C(8))));
    a.Call(B_MEMBER); a.Mark();
    a.Set(BR_LEFT, a.SUB(R(BR_LEFT), a.C(1))); a.Jmp(B_LOOP);
    a.Label(B_SCAN);                                                       // from the first record
    a.Set(BR_Q, a.ADD(a.C(36), a.MUL(R(BR_NF), a.C(24)))); a.Set(BR_FI, a.C(0)); a.Set(BR_CNT, a.C(0));
    a.Label(B_FILE);
    a.Call(B_NEXT);
    a.Assert(a.NE(R(BR_RQ), a.C(0)));                                      // no member starts here: not this format
    a.Jz(a.EQ(U32(a.ADD(R(BR_RQ), a.C(12))), SPOS()), B_FILE);
    a.Jmp(B_HAVE);
    a.Label(B_DONE); a.Mode(kDecode); a.Assert(a.EQ(a.X1(EX_INLEFT, 0), a.C(0))); a.Mode(0); a.End();
    // the cursor's next file record (its address in BR_RQ; 0 after the last): through the folders, past each one's name
    a.Label(B_NEXT);
    a.Label(B_FOLD); a.Jz(R(BR_CNT), B_NEXTFOLD);
    a.Set(BR_RQ, R(BR_Q)); a.Set(BR_Q, a.ADD(R(BR_Q), a.C(16))); a.Set(BR_CNT, a.SUB(R(BR_CNT), a.C(1))); a.Ret();
    a.Label(B_NEXTFOLD); a.Jz(a.LT(R(BR_FI), R(BR_NF)), B_NONE);
    a.Set(BR_CNT, U32(a.ADD(a.ADD(a.C(36), a.MUL(R(BR_FI), a.C(24))), a.C(8))));
    a.Set(BR_Q, a.ADD(R(BR_Q), a.MUL(BIT(R(BR_FLAGS), 0), a.ADD(a.C(1), BYTE(R(BR_Q))))));   // the folder's name (when named)
    a.Set(BR_FI, a.ADD(R(BR_FI), a.C(1))); a.Jmp(B_FOLD);
    a.Label(B_NONE); a.Set(BR_RQ, a.C(0)); a.Ret();
    // one member: its record's size (bit 30 flips the archive's default compression)
    a.Label(B_MEMBER);
    a.Set(BR_COMP, a.XOR(BIT(R(BR_FLAGS), 2), BIT(R(BR_SZ), 30)));
    a.Set(BR_LEN, a.AND(R(BR_SZ), a.C(0x3FFFFFFFu))); a.Set(BR_END, a.ADD(SPOS(), R(BR_LEN)));
    a.Jz(BIT(R(BR_FLAGS), 8), B_NONAME);                                   // an embedded name: its length byte, then the name
    a.ByteRun(a.C(1)); a.ByteRun(BYTE(a.SUB(PLACE, a.C(1))));
    a.Label(B_NONAME);
    a.Jz(R(BR_COMP), B_RAWMEM);
    a.RawF(a.C(32), BR_ORIG); a.Set(BR_CEND, a.ADD(PLACE, R(BR_ORIG)));
    a.Raw(a.C(32), a.C(0x184D2204u), BR_MAG); a.Assert(a.EQ(R(BR_MAG), a.C(0x184D2204u)));
    a.RawF(a.C(8), BR_FLG); a.RawF(a.C(8), BR_BD);
    a.Assert(a.EQ(a.AND(R(BR_FLG), a.C(0xC2)), a.C(0x40)));             // version 01, reserved bit clear
    a.Jz(BIT(R(BR_FLG), 3), B_CS); a.RawF(a.C(32), BR_X); a.RawF(a.C(32), BR_X);   // the content size
    a.Label(B_CS); a.Jz(BIT(R(BR_FLG), 0), B_DI); a.RawF(a.C(32), BR_X);            // a dictionary id
    a.Label(B_DI); a.RawF(a.C(8), BR_HC);
    a.Label(B_BLK); a.RawF(a.C(32), BR_BS); a.Jz(R(BR_BS), B_FEND);
    a.Jz(BIT(R(BR_BS), 31), B_CBLK);
    a.ByteRun(a.AND(R(BR_BS), a.C(0x7FFFFFFFu))); a.Jmp(B_BCK);            // a stored block
    a.Label(B_CBLK); a.Set(BR_BEND, a.ADD(SPOS(), R(BR_BS)));
    if (Attempts) {                                                       // the block's content: the frame's block size, or what is left
        const uint16_t BMAX = a.SHL(a.C(1), a.ADD(a.MUL(a.AND(a.SHR(R(BR_BD), a.C(4)), a.C(7)), a.C(2)), a.C(8)));
        const uint16_t END = a.ADD(PLACE, BMAX);
        a.Set(BR_BLO, PLACE); a.Set(BR_BHI, a.SUB(END, a.MUL(a.GE(END, R(BR_CEND)), a.SUB(END, R(BR_CEND)))));
    }
    a.Call(B_LZ4);
    a.Mode(kDecode); a.Assert(a.EQ(SPOS(), R(BR_BEND))); a.Mode(0);
    a.Label(B_BCK); a.Jz(BIT(R(BR_FLG), 4), B_BLK); a.RawF(a.C(32), BR_X); a.Jmp(B_BLK);   // a block checksum
    a.Label(B_FEND); a.Jz(BIT(R(BR_FLG), 2), B_FDONE); a.RawF(a.C(32), BR_X);             // the content checksum
    a.Label(B_FDONE); a.Assert(a.EQ(PLACE, R(BR_CEND))); a.Assert(a.EQ(SPOS(), R(BR_END))); a.Ret();
    a.Label(B_RAWMEM); a.ByteRun(a.SUB(R(BR_END), SPOS())); a.Ret();
    // an LZ4 block, ending at BR_BEND (DECODE) or its last sequence (CODE)
    a.Label(B_LZ4);
    const Lz4Family fam{Attempts, BR_BLO, BR_BHI};
    Lz4Body(a, a.NE(SPOS(), R(BR_BEND)), Attempts ? &fam : nullptr);
    a.Ret();
    a.link();
    Description d = std::move(a.d);
    if (Attempts) d.isa = 5;
    d.name = Attempts ? "BSA 105 (Skyrim Special Edition), LZ4HC " + std::to_string(Attempts) : "BSA 105 (Skyrim Special Edition)"; d.coder = kBits; d.entryStream = (uint16_t)a.lab[B_STREAM]; d.entryToken = -1;
    d.window = 65535; d.maxlen = 0xFFFFFFFFu;
    return d;
}

} // namespace coding
