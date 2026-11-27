#ifndef VIDYAGODFS_ZFAMILY_H
#define VIDYAGODFS_ZFAMILY_H

#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <vector>

// ---------------------------------------------------------------------------
// An ENCODER FAMILY of the coding algebra (MetaPackageFormat 22.15.4): zlib's deflate parse (deflate_slow: hash chains
// over 3-byte hashes, lazy matching, TOO_FAR; levels 4 to 9), written from the algorithm. It reproduces zlib's tokens
// exactly (verified token for token against zlib, GOG's Inno installers included: they are zlib level 6).
//
// It is INCREMENTAL: a deflate stream can be gigabytes, so the parse advances only as far as it is asked and keeps a
// window of tokens behind it, never all of them. A PREDICTOR, never a requirement (what it predicts is checked at mint).
// ---------------------------------------------------------------------------

namespace coding {

constexpr uint8_t kFamilyZlib = 2;

// One token: `lit` literals from `pos` (absolute content position), then a copy of `len` bytes from `dist` back
// (len 0: the stream's last literals).
struct ZTok { uint64_t pos = 0; uint32_t lit = 0, len = 0, dist = 0; };

class ZlibParser {
public:
    // Knob: level (4..9) | memLevel << 8 (1..9) | windowBits << 16 (9..15). Read(pos, buf, n): content bytes from pos.
    using ReadFn = std::function<bool(uint64_t, uint8_t *, size_t)>;
    static bool ValidKnob(uint32_t Knob);
    ZlibParser(uint32_t Knob, uint64_t Lo, uint64_t Hi, ReadFn Read);
    // Advance until the token covering content position At is known (At in [Lo, Hi)). False: the input did not read, or
    // the work (chain steps, counted on in Steps) would pass MaxSteps.
    bool ensure(uint64_t At, uint64_t &Steps, uint64_t MaxSteps);
    // The token covering At, as the stream's decisions see it: the literals left from At to the copy (the run), the copy
    // (len 0: none before the stream's end). False when At is behind the tokens kept (ask a fresh parser).
    bool at(uint64_t At, uint32_t &Run, uint32_t &Len, uint32_t &Dist) const;
    uint64_t reached() const { return Done; }          // positions below this are covered by known tokens
    uint64_t lo() const { return Lo; }
    uint64_t kept() const { return Toks.empty() ? Done : Toks.front().pos; }
    size_t tokens() const { return Toks.size(); }

private:
    void fillWindow();
    unsigned longestMatch(unsigned Cur);
    void emitLit(unsigned At);
    void emitCopy(unsigned At, unsigned Dist, unsigned Len);
    unsigned insertString(unsigned Str);
    uint64_t Lo, Hi, Next;                              // the stream's content; where the input continues
    ReadFn Read;
    bool Bad = false, Finished = false;
    int Good, Lazy, Nice, Chain;
    unsigned WBits, WSize, WMask, HBits, HSize, HMask, HShift;
    std::vector<uint8_t> Window; std::vector<uint16_t> Prev, Head; unsigned long WindowSize;
    unsigned StrStart = 0, Lookahead = 0, Insert = 0, InsH = 0, MatchStart = 0, MatchLength, PrevLength, PrevMatch = 0, MatchAvailable = 0;
    unsigned long HighWater = 0; uint64_t Base;         // content position of Window[0]
    uint64_t *StepsP = nullptr, MaxSteps = 0; bool Over = false;
    std::deque<ZTok> Toks; uint64_t Done;               // tokens kept (a window behind the parse); covered up to Done
};

} // namespace coding

#endif
