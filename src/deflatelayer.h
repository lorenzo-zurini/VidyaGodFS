#ifndef VIDYAGODFS_DEFLATELAYER_H
#define VIDYAGODFS_DEFLATELAYER_H

#include "bytesource.h"

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

// ---------------------------------------------------------------------------
// The deflate layer: a raw deflate stream (a zip or .pak member, the inside of a zlib/gzip wrapper) served from its
// DECODED content plus a small record of what its encoder decided, never from the stream's own bytes.
//
// Why: a game's archive changes a few files per update, but a deflate stream re-encodes wholesale — one changed byte
// moves every bit after it. So a delta of the shipped bytes costs the whole stream, while a delta of the content costs
// the change. The content is the lineage; this layer is what turns it back into the shipped bytes, exactly.
//
// How: inside a deflate block the code tables are fixed, so the stream is a pure function of position: the block's
// header bits as they were, then each literal through the block's table and each match as its codes. What the encoder
// decided — where blocks start, their headers, which spans are matches — is the DECISIONS record DeflateDecisions makes.
// Nothing is searched for at read time: reads replay those decisions over the content.
//
// Decisions record, per block (varints are LEB128):
//   u8 type (0 stored, 1 fixed, 2 dynamic) | varint bits of the whole block (0 for the last) | varint header bits |
//   the header bits as they were, packed LSB-first | type 0: varint stored length;
//   else varint token bytes, then tokens: varint literal run, varint (match length - 2, 0 = end of block),
//   varint (distance - 1) when a match.
// Every offset a read needs (a block's bit position, its content, its tokens) is a prefix sum over this record, made
// once when the source is created. Only that index is kept; the tokens and the content are read per block.
// ---------------------------------------------------------------------------

namespace deflatelayer {

// Splits a raw deflate stream into its decoded content and its decisions. False (Err says why) when the bytes are not
// exactly one complete raw deflate stream: a bad code, a distance before the start, a stream cut short, or bytes after
// the final block. A successful split is verified: rebuilding the stream from what it returns gives every byte back.
bool DeflateDecisions(const uint8_t *Stream, size_t N, std::vector<uint8_t> &Decisions, std::vector<uint8_t> &Content,
                      std::string &Err);

// A raw deflate stream rebuilt from its decisions and its content: random access, safe to read from many threads at
// once, nothing resident but the per-block index. A read searches for nothing; it replays the blocks it covers.
class DeflateByteSource : public ByteSource {
public:
    // `Decisions` as DeflateDecisions made it; `Content` the decoded bytes (any source: a file, a delta's view);
    // `StreamSize` the stream's length. nullptr (Err says why) when the record does not parse, or its blocks do not
    // add up to `StreamSize` bits or to `Content`'s size.
    static std::shared_ptr<DeflateByteSource> Create(std::shared_ptr<ByteSource> Decisions, std::shared_ptr<ByteSource> Content,
                                                     uint64_t StreamSize, std::string &Err);

    ssize_t  pread(void *Buf, size_t N, uint64_t Off) override;
    uint64_t size() const override { return Size; }
    size_t   blocks() const { return Blocks.size(); }   // (tests)

    struct Block {
        uint64_t bit = 0;        // where the block starts in the stream, in bits
        uint64_t content = 0;    // where its decoded bytes start in the content
        uint64_t contentLen = 0;
        uint64_t header = 0;     // where its header bytes start in the decisions record
        uint64_t tokens = 0;     // where its tokens start in the decisions record
        uint32_t tokenLen = 0;
        uint16_t headerBits = 0;
        uint8_t  type = 0;
    };

private:
    std::shared_ptr<ByteSource> Dec, Content;
    std::vector<Block>          Blocks;
    uint64_t                    Size = 0;
};

} // namespace deflatelayer

#endif // VIDYAGODFS_DEFLATELAYER_H
