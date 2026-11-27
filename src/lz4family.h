#ifndef VIDYAGODFS_LZ4FAMILY_H
#define VIDYAGODFS_LZ4FAMILY_H

#include <cstddef>
#include <cstdint>
#include <memory>
#include <vector>

// ---------------------------------------------------------------------------
// An ENCODER FAMILY of the coding algebra (MetaPackageFormat 22.15.4): LZ4's high-compression parse as lz4 1.7 made it
// (hash chain over 4-byte hashes, the three-match lookahead), written from the algorithm. With `Attempts` = 32768 (lz4
// 1.7's level 16, its maximum) it reproduces Bethesda's Skyrim SE archives block for block.
//
// It is a PREDICTOR, never a requirement: what it predicts is checked against the stream at mint, and a sequence it
// gets wrong is stored as it is. It runs in the reader (code), never in a description (data): a description names the
// family and its knobs through the PREDICT op (ISA 5).
// ---------------------------------------------------------------------------

namespace coding {

// One sequence of an LZ4 block: `lit` literals from `anchor` (block-relative), then a copy of `ml` bytes from `off` back
// (ml 0: the last sequence, literals only).
struct Lz4Seq { uint32_t anchor = 0, lit = 0, ml = 0, off = 0; };

constexpr uint32_t kLz4hcMaxAttempts = 1u << 16;
constexpr size_t kLz4hcMaxBlock = 4u << 20;            // LZ4 frames' largest block

class Lz4hcParser {
public:
    Lz4hcParser();
    ~Lz4hcParser();
    // The sequences of one block, in order. N at most kLz4hcMaxBlock, Attempts 1..kLz4hcMaxAttempts.
    void parse(const uint8_t *Src, size_t N, uint32_t Attempts, std::vector<Lz4Seq> &Out);
private:
    struct Ctx;
    std::unique_ptr<Ctx> C;
};

} // namespace coding

#endif
