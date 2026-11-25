#include "deflatelayer.h"

#include <array>
#include <cstring>

namespace deflatelayer {

namespace {

// ---- the tables deflate itself defines (RFC 1951, 3.2.5) ----------------------------------------
constexpr uint16_t LBASE[29] = {3,4,5,6,7,8,9,10,11,13,15,17,19,23,27,31,35,43,51,59,67,83,99,115,131,163,195,227,258};
constexpr uint8_t  LEXT[29]  = {0,0,0,0,0,0,0,0,1,1,1,1,2,2,2,2,3,3,3,3,4,4,4,4,5,5,5,5,0};
constexpr uint16_t DBASE[30] = {1,2,3,4,5,7,9,13,17,25,33,49,65,97,129,193,257,385,513,769,1025,1537,2049,3073,4097,6145,
                                8193,12289,16385,24577};
constexpr uint8_t  DEXT[30]  = {0,0,0,0,1,1,2,2,3,3,4,4,5,5,6,6,7,7,8,8,9,9,10,10,11,11,12,12,13,13};
constexpr uint8_t  CLORDER[19] = {16,17,18,0,8,7,9,6,10,5,11,4,12,3,13,2,14,1,15};

// The length symbol (0..28) and distance symbol (0..29) of a value, by table: a read emits one per match.
struct SymTables {
    std::array<uint8_t, 259> lsym{};
    std::array<uint8_t, 32769> dsym{};
    SymTables() {
        for (int L = 3; L <= 258; ++L) { int s = 28; while (L < LBASE[s]) --s; lsym[L] = (uint8_t)s; }
        for (int D = 1; D <= 32768; ++D) { int s = 29; while (D < DBASE[s]) --s; dsym[D] = (uint8_t)s; }
    }
};
const SymTables &Syms() { static const SymTables T; return T; }

// ---- bits, LSB first --------------------------------------------------------------------------
struct BitIn {
    const uint8_t *p; uint64_t nbits; uint64_t at = 0; bool over = false;
    BitIn(const uint8_t *d, uint64_t nbytes) : p(d), nbits(nbytes * 8) {}
    uint32_t Bits(int n) {
        uint32_t v = 0;
        for (int i = 0; i < n; ++i) {
            if (at >= nbits) { over = true; return 0; }
            v |= (uint32_t)((p[at >> 3] >> (at & 7)) & 1) << i; ++at;
        }
        return v;
    }
};
struct BitOut {
    std::vector<uint8_t> &o; uint64_t acc = 0; int n = 0;
    explicit BitOut(std::vector<uint8_t> &out, int lead = 0) : o(out), n(lead) {}
    void Put(uint64_t v, int bits) {
        acc |= v << n; n += bits;
        while (n >= 8) { o.push_back((uint8_t)acc); acc >>= 8; n -= 8; }
    }
    void PutLong(uint64_t v, int bits) { if (bits > 32) { Put(v & 0xFFFFFFFFu, 32); Put(v >> 32, bits - 32); } else Put(v, bits); }
    void Pad() { if (n) Put(0, 8 - n); }
};

// ---- canonical Huffman: decoding (counts per length) and encoding (codes, bit-reversed for an LSB-first writer) --
struct Huff { std::array<int16_t, 16> count{}; std::array<int16_t, 320> sym{}; };
// False when the lengths over-subscribe the code space (no valid deflate stream has them).
bool HuffBuild(Huff &h, const uint8_t *len, int n) {
    h.count.fill(0);
    for (int s = 0; s < n; ++s) h.count[len[s]]++;
    h.count[0] = 0;
    int left = 1;
    for (int l = 1; l < 16; ++l) { left <<= 1; left -= h.count[l]; if (left < 0) return false; }
    std::array<int16_t, 16> offs{}; for (int l = 1; l < 15; ++l) offs[l + 1] = (int16_t)(offs[l] + h.count[l]);
    for (int s = 0; s < n; ++s) if (len[s]) h.sym[offs[len[s]]++] = (int16_t)s;
    return true;
}
int HuffDec(BitIn &b, const Huff &h) {
    int code = 0, first = 0, index = 0;
    for (int l = 1; l < 16; ++l) {
        code |= (int)b.Bits(1); if (b.over) return -1;
        const int c = h.count[l];
        if (code - c < first) return h.sym[index + (code - first)];
        index += c; first += c; first <<= 1; code <<= 1;
    }
    return -1;
}
struct Enc { std::array<uint16_t, 288> code{}; std::array<uint8_t, 288> len{}; };
void EncBuild(Enc &e, const uint8_t *len, int n) {
    std::array<int, 16> blc{}, next{};
    for (int s = 0; s < n; ++s) blc[len[s]]++;
    blc[0] = 0;
    int code = 0; for (int l = 1; l < 16; ++l) { code = (code + blc[l - 1]) << 1; next[l] = code; }
    for (int s = 0; s < n; ++s) {
        e.len[s] = len[s];
        if (!len[s]) continue;
        int c = next[len[s]]++, r = 0;
        for (int i = 0; i < len[s]; ++i) { r = (r << 1) | (c & 1); c >>= 1; }
        e.code[s] = (uint16_t)r;
    }
}
void FixedLengths(uint8_t *ll, uint8_t *dl) {
    for (int k = 0; k < 288; ++k) ll[k] = k < 144 ? 8 : k < 256 ? 9 : k < 280 ? 7 : 8;
    for (int k = 0; k < 32; ++k) dl[k] = 5;
}
// A dynamic block's code lengths, from its header bits (positioned after BFINAL/BTYPE). False on a malformed header.
bool DynamicLengths(BitIn &b, uint8_t *ll, uint8_t *dl) {
    const int nlen = (int)b.Bits(5) + 257, ndist = (int)b.Bits(5) + 1, ncode = (int)b.Bits(4) + 4;
    if (b.over || nlen > 286 || ndist > 30) return false;
    uint8_t cl[19] = {0};
    for (int i = 0; i < ncode; ++i) cl[CLORDER[i]] = (uint8_t)b.Bits(3);
    Huff ch; if (!HuffBuild(ch, cl, 19)) return false;
    uint8_t lens[320] = {0}; int k = 0;
    while (k < nlen + ndist) {
        const int sy = HuffDec(b, ch);
        if (sy < 0) return false;
        if (sy < 16) { lens[k++] = (uint8_t)sy; continue; }
        int rep = 0; uint8_t v = 0;
        if (sy == 16) { if (!k) return false; v = lens[k - 1]; rep = 3 + (int)b.Bits(2); }
        else if (sy == 17) rep = 3 + (int)b.Bits(3);
        else rep = 11 + (int)b.Bits(7);
        if (b.over || k + rep > nlen + ndist) return false;
        while (rep--) lens[k++] = v;
    }
    std::memset(ll, 0, 288); std::memset(dl, 0, 32);
    std::memcpy(ll, lens, (size_t)nlen); std::memcpy(dl, lens + nlen, (size_t)ndist);
    return ll[256] != 0;                                   // a block that cannot end is not a block
}

void PutVar(std::vector<uint8_t> &o, uint64_t v) { while (v >= 0x80) { o.push_back((uint8_t)(v | 0x80)); v >>= 7; } o.push_back((uint8_t)v); }
bool GetVar(const uint8_t *p, size_t n, size_t &at, uint64_t &v) {
    v = 0;
    for (int sh = 0; sh < 64; sh += 7) {
        if (at >= n) return false;
        const uint8_t x = p[at++]; v |= (uint64_t)(x & 0x7F) << sh;
        if (!(x & 0x80)) return true;
    }
    return false;
}

} // namespace

// ================================================================================================= mint side
bool DeflateDecisions(const uint8_t *Stream, size_t N, std::vector<uint8_t> &Decisions, std::vector<uint8_t> &Content,
                      std::string &Err) {
    Decisions.clear(); Content.clear();
    BitIn b(Stream, N);
    std::vector<uint8_t> tok;
    bool final = false;
    while (!final) {
        const uint64_t from = b.at;
        final = b.Bits(1) != 0;
        const uint32_t type = b.Bits(2);
        if (b.over) { Err = "the stream ends inside a block header"; return false; }
        if (type == 3) { Err = "a block of the reserved type 3"; return false; }
        uint8_t ll[288], dl[32];
        uint64_t storedLen = 0;
        if (type == 0) {
            b.at = (b.at + 7) & ~7ull;
            const uint32_t len = b.Bits(16), nlen = b.Bits(16);
            if (b.over) { Err = "the stream ends inside a stored block's lengths"; return false; }
            if ((len ^ 0xFFFF) != nlen) { Err = "a stored block whose length and its complement disagree"; return false; }
            storedLen = len;
        } else if (type == 1) FixedLengths(ll, dl);
        else if (!DynamicLengths(b, ll, dl)) { Err = "a dynamic block whose code-length header is malformed"; return false; }
        const uint64_t headerBits = b.at - from;
        if (headerBits > 0xFFFF) { Err = "a block header too long"; return false; }
        // the header, as it was
        std::vector<uint8_t> hdr; { BitIn h(Stream, N); h.at = from; BitOut w(hdr); uint64_t left = headerBits;
            while (left) { const int k = left > 24 ? 24 : (int)left; w.Put(h.Bits(k), k); left -= (uint64_t)k; } w.Pad(); }
        tok.clear();
        if (type == 0) {
            if (b.at / 8 + storedLen > N) { Err = "the stream ends inside a stored block"; return false; }
            Content.insert(Content.end(), Stream + b.at / 8, Stream + b.at / 8 + storedLen);
            b.at += storedLen * 8;
        } else {
            Huff lh, dh;
            if (!HuffBuild(lh, ll, 288) || !HuffBuild(dh, dl, 32)) { Err = "a block whose code lengths over-subscribe"; return false; }
            uint64_t run = 0;
            for (;;) {
                const int sy = HuffDec(b, lh);
                if (sy < 0) { Err = b.over ? "the stream ends inside a block" : "a literal/length code no table has"; return false; }
                if (sy < 256) { Content.push_back((uint8_t)sy); ++run; continue; }
                if (sy == 256) { PutVar(tok, run); PutVar(tok, 0); break; }
                if (sy > 285) { Err = "a length symbol deflate does not define"; return false; }
                const int s = sy - 257; const uint32_t len = LBASE[s] + b.Bits(LEXT[s]);
                const int ds = HuffDec(b, dh);
                if (ds < 0 || ds > 29) { Err = b.over ? "the stream ends inside a match" : "a distance code no table has"; return false; }
                const uint32_t dist = DBASE[ds] + b.Bits(DEXT[ds]);
                if (b.over) { Err = "the stream ends inside a match"; return false; }
                if (dist > Content.size()) { Err = "a match reaching back before the stream's start"; return false; }
                const size_t at = Content.size();
                for (uint32_t i = 0; i < len; ++i) Content.push_back(Content[at - dist + i]);
                PutVar(tok, run); PutVar(tok, len - 2); PutVar(tok, dist - 1); run = 0;
            }
        }
        Decisions.push_back((uint8_t)type);
        PutVar(Decisions, final ? 0 : b.at - from);
        PutVar(Decisions, headerBits);
        Decisions.insert(Decisions.end(), hdr.begin(), hdr.end());
        if (type == 0) PutVar(Decisions, storedLen);
        else { PutVar(Decisions, tok.size()); Decisions.insert(Decisions.end(), tok.begin(), tok.end()); }
    }
    if ((b.at + 7) / 8 != N) { Err = "bytes after the final block"; return false; }
    // Verified, never assumed: the record and the content must give back every byte of the stream.
    auto src = DeflateByteSource::Create(std::make_shared<MemByteSource>(Decisions), std::make_shared<MemByteSource>(Content), N, Err);
    if (!src) return false;
    std::vector<uint8_t> back(N);
    if (N && !src->preadAll(back.data(), N, 0)) { Err = "the rebuilt stream does not read"; return false; }
    if (std::memcmp(back.data(), Stream, N) != 0) { Err = "the rebuilt stream differs from the original"; return false; }
    return true;
}

// ================================================================================================= read side
std::shared_ptr<DeflateByteSource> DeflateByteSource::Create(std::shared_ptr<ByteSource> Decisions, std::shared_ptr<ByteSource> Content,
                                                             uint64_t StreamSize, std::string &Err) {
    if (!Decisions || !Content) { Err = "no decisions or no content"; return nullptr; }
    // One pass over the record makes the index; the record itself stays where it is.
    std::vector<uint8_t> d(Decisions->size());
    if (!d.empty() && !Decisions->preadAll(d.data(), d.size(), 0)) { Err = "the decisions record does not read"; return nullptr; }
    auto S = std::shared_ptr<DeflateByteSource>(new DeflateByteSource());
    S->Dec = std::move(Decisions); S->Content = std::move(Content); S->Size = StreamSize;
    size_t at = 0; uint64_t bit = 0, cpos = 0; bool last = false;
    while (at < d.size()) {
        if (last) { Err = "the decisions record goes on after its last block"; return nullptr; }
        Block B; B.type = d[at++];
        uint64_t blockBits, headerBits;
        if (B.type > 2 || !GetVar(d.data(), d.size(), at, blockBits) || !GetVar(d.data(), d.size(), at, headerBits) || headerBits > 0xFFFF || headerBits < 3)
        { Err = "a malformed block in the decisions record"; return nullptr; }
        B.bit = bit; B.content = cpos; B.headerBits = (uint16_t)headerBits; B.header = at;
        at += (headerBits + 7) / 8;
        if (at > d.size()) { Err = "the decisions record ends inside a header"; return nullptr; }
        if (B.type == 0) {
            uint64_t len; if (!GetVar(d.data(), d.size(), at, len)) { Err = "a stored block without its length"; return nullptr; }
            B.contentLen = len;
        } else {
            uint64_t tl; if (!GetVar(d.data(), d.size(), at, tl) || at + tl > d.size()) { Err = "a block whose tokens run past the record"; return nullptr; }
            B.tokens = at; B.tokenLen = (uint32_t)tl;
            size_t q = at; const size_t qe = at + tl; uint64_t run, len, dist;
            for (;;) {                                           // its content length: the literal runs and the matches
                if (!GetVar(d.data(), qe, q, run)) { Err = "a block's tokens end without an end of block"; return nullptr; }
                B.contentLen += run;
                if (!GetVar(d.data(), qe, q, len)) { Err = "a block's tokens end without an end of block"; return nullptr; }
                if (!len) break;
                if (len > 256 || !GetVar(d.data(), qe, q, dist) || dist >= 32768) { Err = "a malformed match in the decisions record"; return nullptr; }
                B.contentLen += len + 2;
            }
            if (q != qe) { Err = "tokens after a block's end"; return nullptr; }
            at = qe;
        }
        cpos += B.contentLen;
        if (!blockBits) last = true; else bit += blockBits;
        S->Blocks.push_back(B);
    }
    if (S->Blocks.empty() || !last) { Err = "a decisions record without its last block"; return nullptr; }
    if (cpos != S->Content->size()) { Err = "the content is not the size the decisions record says"; return nullptr; }
    if (S->Blocks.back().bit + S->Blocks.back().headerBits > StreamSize * 8) { Err = "the stream is shorter than the decisions record says"; return nullptr; }
    return S;
}

namespace {
// One block made ready to replay: its header, tokens, content and code tables.
struct Ready {
    std::vector<uint8_t> header, tokens, content;
    Enc le, de;
};
bool Load(ByteSource &Dec, ByteSource &Content, const DeflateByteSource::Block &B, Ready &R) {
    R.header.resize((B.headerBits + 7) / 8);
    if (!R.header.empty() && !Dec.preadAll(R.header.data(), R.header.size(), B.header)) return false;
    R.content.resize(B.contentLen);
    if (B.contentLen && !Content.preadAll(R.content.data(), B.contentLen, B.content)) return false;
    if (B.type == 0) return true;
    R.tokens.resize(B.tokenLen);
    if (B.tokenLen && !Dec.preadAll(R.tokens.data(), B.tokenLen, B.tokens)) return false;
    uint8_t ll[288], dl[32];
    if (B.type == 1) FixedLengths(ll, dl);
    else { BitIn h(R.header.data(), R.header.size()); h.at = 3; if (!DynamicLengths(h, ll, dl)) return false; }
    EncBuild(R.le, ll, 288); EncBuild(R.de, dl, 32);
    return true;
}
// A match's codes: length symbol and extra bits, distance symbol and extra bits.
inline int MatchBits(const Ready &R, uint32_t len, uint32_t dist, uint64_t &v) {
    const SymTables &T = Syms();
    const int s = T.lsym[len], ds = T.dsym[dist];
    int n = R.le.len[257 + s]; v = R.le.code[257 + s];
    v |= (uint64_t)(len - LBASE[s]) << n; n += LEXT[s];
    v |= (uint64_t)R.de.code[ds] << n; n += R.de.len[ds];
    v |= (uint64_t)(dist - DBASE[ds]) << n; n += DEXT[ds];
    return n;
}
} // namespace

ssize_t DeflateByteSource::pread(void *Buf, size_t N, uint64_t Off) {
    if (Off >= Size || !N) return 0;
    if (N > Size - Off) N = (size_t)(Size - Off);
    // Start at the last item boundary at or before the read's first bit: everything from there on is produced whole, and
    // only the byte holding that boundary (when it is not Off's own first bit) comes out partial — a byte before Off.
    const uint64_t T = 8 * Off;
    size_t lo = 0, hi = Blocks.size();
    while (hi - lo > 1) { const size_t m = (lo + hi) / 2; if (Blocks[m].bit <= T) lo = m; else hi = m; }
    Ready R; if (!Load(*Dec, *Content, Blocks[lo], R)) return -EIO;
    const Block *B = &Blocks[lo];
    size_t tp = 0;
    // Create checked every block's tokens, so a token that does not read means the record changed under us: an error.
    auto next = [&](uint64_t &v) { return GetVar(R.tokens.data(), R.tokens.size(), tp, v); };
    // walk the first block's items silently up to the boundary
    uint64_t start = B->bit, cp = 0; int phase = 0; uint64_t run = 0, len = 0, dist = 0; bool skipped = false;
    if (B->type && B->bit + B->headerBits <= T) {
        uint64_t bit = B->bit + B->headerBits; skipped = true; start = bit;
        for (;;) {
            if (!next(run)) return -EIO;
            uint64_t k = 0;
            while (k < run) { const int b = R.le.len[R.content[cp + k]]; if (bit + (uint64_t)b > T) break; bit += (uint64_t)b; ++k; }
            cp += k; start = bit;
            if (k < run) { run -= k; phase = 1; break; }
            if (!next(len)) return -EIO;
            if (!len) { phase = 3; break; }
            if (!next(dist)) return -EIO;
            len += 2; dist += 1;
            uint64_t v; const int b = MatchBits(R, (uint32_t)len, (uint32_t)dist, v);
            if (bit + (uint64_t)b > T) { phase = 2; break; }
            bit += (uint64_t)b; cp += len; start = bit;
        }
    }
    std::vector<uint8_t> out; out.reserve(N + 1024);
    BitOut w(out, (int)(start & 7));
    const uint64_t sb = start >> 3, need = Off + N - sb;
    for (size_t i = lo; i < Blocks.size() && out.size() < need; ++i) {
        if (i != lo) { B = &Blocks[i]; if (!Load(*Dec, *Content, *B, R)) return -EIO; }
        if (!(i == lo && skipped)) {
            BitIn h(R.header.data(), R.header.size()); uint64_t left = B->headerBits;
            while (left) { const int k = left > 24 ? 24 : (int)left; w.Put(h.Bits(k), k); left -= (uint64_t)k; }
            if (B->type == 0) { for (uint64_t k = 0; k < B->contentLen && out.size() < need; ++k) w.Put(R.content[k], 8); continue; }
            cp = 0; tp = 0; phase = 0;
        }
        for (;;) {
            if (phase == 0) { if (!next(run)) return -EIO; phase = 1; }
            if (phase == 1) {
                uint64_t k = 0;                              // a run can fill a block: stop once the read is covered
                for (; k < run && out.size() < need; ++k) { const uint8_t c = R.content[cp + k]; w.Put(R.le.code[c], R.le.len[c]); }
                cp += k;
                if (k < run) break;
                if (!next(len)) return -EIO;
                if (!len) { w.Put(R.le.code[256], R.le.len[256]); phase = 0; break; }
                if (!next(dist)) return -EIO;
                len += 2; dist += 1; phase = 2;
            }
            if (phase == 3) { w.Put(R.le.code[256], R.le.len[256]); phase = 0; break; }
            uint64_t v; const int b = MatchBits(R, (uint32_t)len, (uint32_t)dist, v); w.PutLong(v, b);
            cp += len; phase = 0;
            if (out.size() >= need) break;
        }
    }
    if (out.size() < need) w.Pad();
    if (out.size() < need) return -EIO;                     // a record that does not cover the stream
    std::memcpy(Buf, out.data() + (Off - sb), N);
    return (ssize_t)N;
}

} // namespace deflatelayer
