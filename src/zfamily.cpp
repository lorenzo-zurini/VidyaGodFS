#include "zfamily.h"

#include <algorithm>
#include <cstring>

namespace coding {

namespace {
constexpr unsigned kMinMatch = 3, kMaxMatch = 258, kMinLookahead = kMaxMatch + kMinMatch + 1, kTooFar = 4096, kWinInit = kMaxMatch;
struct Cfg { int good, lazy, nice, chain; };
const Cfg kCfg[10] = {{0, 0, 0, 0}, {4, 4, 8, 4}, {4, 5, 16, 8}, {4, 6, 32, 32}, {4, 4, 16, 16}, {8, 16, 32, 32},
                      {8, 16, 128, 128}, {8, 32, 128, 256}, {32, 128, 258, 1024}, {32, 258, 258, 4096}};
constexpr size_t kKeepTokens = 1u << 20;               // tokens kept behind the parse (24 bytes each: 24 MiB at most)
} // namespace

bool ZlibParser::ValidKnob(uint32_t K) {
    const unsigned L = K & 0xFF, M = (K >> 8) & 0xFF, W = (K >> 16) & 0xFF;
    return L >= 4 && L <= 9 && M >= 1 && M <= 9 && W >= 9 && W <= 15 && (K >> 24) == 0;   // levels 1-3 (deflate_fast): not yet
}

ZlibParser::ZlibParser(uint32_t K, uint64_t L, uint64_t H, ReadFn R) : Lo(L), Hi(H), Next(L), Read(std::move(R)), Base(L), Done(L) {
    const Cfg &C = kCfg[K & 0xFF];
    Good = C.good; Lazy = C.lazy; Nice = C.nice; Chain = C.chain;
    WBits = (K >> 16) & 0xFF; WSize = 1u << WBits; WMask = WSize - 1;
    HBits = ((K >> 8) & 0xFF) + 7; HSize = 1u << HBits; HMask = HSize - 1; HShift = (HBits + kMinMatch - 1) / kMinMatch;
    Window.assign(2 * (size_t)WSize, 0); Prev.assign(WSize, 0); Head.assign(HSize, 0); WindowSize = 2ul * WSize;
    MatchLength = PrevLength = kMinMatch - 1;
}

unsigned ZlibParser::insertString(unsigned Str) {
    InsH = ((InsH << HShift) ^ Window[Str + kMinMatch - 1]) & HMask;
    const unsigned M = Prev[Str & WMask] = Head[InsH];
    Head[InsH] = (uint16_t)Str;
    return M;
}

void ZlibParser::fillWindow() {
    const unsigned MaxDist = WSize - kMinLookahead;
    unsigned More;
    do {
        More = (unsigned)(WindowSize - Lookahead - StrStart);
        if (StrStart >= WSize + MaxDist) {                // slide: the upper half down
            memcpy(Window.data(), Window.data() + WSize, WSize - More);
            MatchStart -= WSize; StrStart -= WSize; Base += WSize;
            if (Insert > StrStart) Insert = StrStart;
            for (auto &X : Head) X = X >= WSize ? (uint16_t)(X - WSize) : 0;
            for (auto &X : Prev) X = X >= WSize ? (uint16_t)(X - WSize) : 0;
            More += WSize;
        }
        if (Next >= Hi) break;
        const unsigned N = (unsigned)std::min<uint64_t>(More, Hi - Next);
        if (!Read(Next, Window.data() + StrStart + Lookahead, N)) { Bad = true; return; }
        Next += N; Lookahead += N;
        if (Lookahead + Insert >= kMinMatch) {
            unsigned Str = StrStart - Insert;
            InsH = Window[Str]; InsH = ((InsH << HShift) ^ Window[Str + 1]) & HMask;
            while (Insert) {
                InsH = ((InsH << HShift) ^ Window[Str + kMinMatch - 1]) & HMask;
                Prev[Str & WMask] = Head[InsH]; Head[InsH] = (uint16_t)Str;
                ++Str; --Insert;
                if (Lookahead + Insert < kMinMatch) break;
            }
        }
    } while (Lookahead < kMinLookahead && Next < Hi);
    //zlib zeroes what lies past the input (the match compares may read there; the length is capped after)
    if (HighWater < WindowSize) {
        const unsigned long Curr = StrStart + (unsigned long)Lookahead;
        if (HighWater < Curr) {
            const unsigned long Init = std::min<unsigned long>(WindowSize - Curr, kWinInit);
            memset(Window.data() + Curr, 0, Init); HighWater = Curr + Init;
        } else if (HighWater < Curr + kWinInit) {
            const unsigned long Init = std::min<unsigned long>(Curr + kWinInit - HighWater, WindowSize - HighWater);
            memset(Window.data() + HighWater, 0, Init); HighWater += Init;
        }
    }
}

unsigned ZlibParser::longestMatch(unsigned Cur) {
    const unsigned MaxDist = WSize - kMinLookahead;
    unsigned ChainLength = (unsigned)Chain; const uint8_t *Scan = Window.data() + StrStart; int BestLen = (int)PrevLength, NiceMatch = Nice;
    const unsigned Limit = StrStart > MaxDist ? StrStart - MaxDist : 0;
    uint8_t ScanEnd1 = Scan[BestLen - 1], ScanEnd = Scan[BestLen];
    if (PrevLength >= (unsigned)Good) ChainLength >>= 2;
    if ((unsigned)NiceMatch > Lookahead) NiceMatch = (int)Lookahead;
    do {
        if (++*StepsP > MaxSteps) { Over = true; break; }
        const uint8_t *M = Window.data() + Cur;
        if (M[BestLen] != ScanEnd || M[BestLen - 1] != ScanEnd1 || M[0] != Scan[0] || M[1] != Scan[1]) continue;
        int Len = 2; while (Len < (int)kMaxMatch && Scan[Len] == M[Len]) ++Len;
        if (Len > BestLen) { MatchStart = Cur; BestLen = Len; if (Len >= NiceMatch) break; ScanEnd1 = Scan[BestLen - 1]; ScanEnd = Scan[BestLen]; }
    } while ((Cur = Prev[Cur & WMask]) > Limit && --ChainLength != 0);
    return (unsigned)BestLen <= Lookahead ? (unsigned)BestLen : Lookahead;
}

// tokens as the decisions see them: a run of literals, then the copy that ends it
void ZlibParser::emitLit(unsigned At) {
    const uint64_t P = Base + At;
    if (Toks.empty() || Toks.back().len) Toks.push_back({P, 1, 0, 0}); else ++Toks.back().lit;
}
void ZlibParser::emitCopy(unsigned At, unsigned Dist, unsigned Len) {
    const uint64_t P = Base + At;
    if (Toks.empty() || Toks.back().len) Toks.push_back({P, 0, Len, Dist});
    else { Toks.back().len = Len; Toks.back().dist = Dist; }
    Done = P + Len;
    if (Toks.size() > kKeepTokens) Toks.pop_front();
}

bool ZlibParser::ensure(uint64_t At, uint64_t &Steps, uint64_t Max) {
    if (Bad) return false;
    StepsP = &Steps; MaxSteps = Max;
    const unsigned MaxDist = WSize - kMinLookahead;
    while (!Finished && Done <= At) {
        if (Lookahead < kMinLookahead) {
            fillWindow(); if (Bad) return false;
            if (Lookahead == 0) {                          // the input's end: the last literal, then the run ends the stream
                if (MatchAvailable) { emitLit(StrStart - 1); MatchAvailable = 0; }
                if (!Toks.empty() && !Toks.back().len) Done = Toks.back().pos + Toks.back().lit; else Done = Hi;
                if (Done < Hi) Done = Hi;
                Finished = true; break;
            }
        }
        unsigned HashHead = 0;
        if (Lookahead >= kMinMatch) HashHead = insertString(StrStart);
        PrevLength = MatchLength; PrevMatch = MatchStart; MatchLength = kMinMatch - 1;
        if (HashHead != 0 && PrevLength < (unsigned)Lazy && StrStart - HashHead <= MaxDist) {
            MatchLength = longestMatch(HashHead);
            if (Over) return false;
            if (MatchLength <= 5 && MatchLength == kMinMatch && StrStart - MatchStart > kTooFar) MatchLength = kMinMatch - 1;
        }
        if (PrevLength >= kMinMatch && MatchLength <= PrevLength) {
            const unsigned MaxInsert = StrStart + Lookahead - kMinMatch;
            emitCopy(StrStart - 1, StrStart - 1 - PrevMatch, PrevLength);
            Lookahead -= PrevLength - 1; PrevLength -= 2;
            do { if (++StrStart <= MaxInsert) insertString(StrStart); } while (--PrevLength != 0);
            MatchAvailable = 0; MatchLength = kMinMatch - 1; ++StrStart;
        } else if (MatchAvailable) { emitLit(StrStart - 1); ++StrStart; --Lookahead; }
        else { MatchAvailable = 1; ++StrStart; --Lookahead; }
    }
    return true;
}

bool ZlibParser::at(uint64_t At, uint32_t &Run, uint32_t &Len, uint32_t &Dist) const {
    if (Toks.empty() || At < Toks.front().pos || At >= Done) return false;
    auto It = std::upper_bound(Toks.begin(), Toks.end(), At, [](uint64_t X, const ZTok &T) { return X < T.pos; });
    if (It == Toks.begin()) return false;
    const ZTok &T = *--It;
    if (At > T.pos + T.lit) return false;                 // inside the copy: no token starts there
    Run = (uint32_t)(T.pos + T.lit - At); Len = T.len; Dist = T.dist;
    return true;
}

} // namespace coding
