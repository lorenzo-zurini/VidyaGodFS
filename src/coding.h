#ifndef VIDYAGODFS_CODING_H
#define VIDYAGODFS_CODING_H

#include "bytesource.h"

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

// ---------------------------------------------------------------------------
// The coding algebra (MetaPackageFormat chapter 22.15): a compressed stream (LZMA, deflate, LZ4, ...) served from its
// DECODED content plus the DECISIONS its encoder made, through a DESCRIPTION of the format.
//
// A description is DATA, never code (USER 2026-11-26: "we shall never ship compiled code"; "no opaque blocks, if
// there's no ops, invent them"): ops and expressions over a fixed, versioned set of primitives - adaptive binary
// slots with a range coder, an LSB-first bit coder with canonical Huffman codes, registers, arrays, a copy history,
// content and decision ops. ONE description runs in three modes:
//   DECODE  shipped bytes -> content + decisions   (the mint's parse)
//   CODE    content + decisions -> shipped bytes   (the read)
//   PRICE   the cost of a candidate decision       (prediction)
// This engine knows no format and no encoder. Descriptions come from peers, so they are untrusted: Parse validates
// every index, expressions may only refer to earlier expressions (no cycles, no recursion), every slot, table and
// array access is bounds-checked, and a run is metered (fuel per byte), so a hostile description is refused, never
// obeyed.
// ---------------------------------------------------------------------------

namespace coding {

constexpr uint32_t kIsa = 2;          // the instruction set a description may use; newer is refused
constexpr int kRegs = 64;
constexpr int kRegPlace = 0;          // register 0: the place in the content
constexpr uint32_t kNoSlot = 255;

enum Mode : uint8_t { kCode = 1, kDecode = 2, kPrice = 4, kAll = 7, kCodePrice = 5 };
enum Coder : uint8_t { kRange = 0, kBits = 1 };

enum ExOp : uint8_t {
    EX_CONST, EX_REG, EX_ADD, EX_SUB, EX_MUL, EX_SHL, EX_SHR, EX_AND, EX_OR, EX_XOR, EX_LT, EX_EQ, EX_NE, EX_GE,
    EX_BYTE,      // content byte at a (0 outside what exists)
    EX_TABLE,     // constant table imm [a]
    EX_ARR,       // array imm [a]
    EX_LOG2SLOT,  // 2*floor(log2 a) + the next bit; a below 4
    EX_BITPOS,    // the bit coder's position within its byte
    EX_DLEFT,     // decisions not yet consumed (CODE)
    EX_XLEFT,     // content bytes after the place
    EX_INLEFT,    // DECODE: shipped bits not yet read by the bit coder
    EX_COUNT
};
enum OpCode : uint8_t {
    OP_BIT, OP_TREE, OP_RTREE, OP_DIRECT, OP_MLIT,   // the range coder through adaptive slots
    OP_RAW, OP_HUFF,                              // the bit coder: raw bits, a symbol through a built code
    OP_BUILD,    // code imm from array nb [x, x+v) of code lengths: canonical; over-subscription refused
    OP_STA,      // array nb [x] = v
    OP_SET,      // register tgt = v
    OP_DEC,      // decision <-> register tgt
    OP_OUTLIT,   // content byte v at the place (DECODE writes it), place + 1
    OP_OUTCOPY,  // content: x bytes from distance v (DECODE copies), place + x
    OP_HMTF,     // history registers tgt .. tgt+nb: move slot v to the front
    OP_HPUSH,    // history: push v at the front
    OP_JZ, OP_JMP, OP_CALL, OP_RET,
    OP_ASSERT,   // v must hold, else the stream is refused
    OP_FLUSH,    // the coder writes out what it holds
    OP_MARK,     // a place where a checkpoint may be taken (between whole decisions)
    OP_END,
    OP_COUNT
};
constexpr uint8_t kFree = 1;          // op flag: its value is a decision

struct Ex { uint8_t op = 0; uint16_t a = 0, b = 0; uint32_t imm = 0; };
struct Op { uint8_t op = 0, modes = 0, flags = 0, nb = 0, tgt = 0; uint16_t x = 0, v = 0, m = 0, target = 0; uint32_t imm = 0; };

struct Description {
    std::string name;
    uint32_t isa = kIsa;
    uint8_t coder = kRange;
    std::vector<Op> ops;
    std::vector<Ex> ex;
    uint32_t nslots = 0;
    uint8_t shift = 5;                                  // adaptive slots move 1/2^shift of the way
    std::vector<std::vector<uint32_t>> tables;          // constant
    std::vector<std::vector<uint32_t>> arrays;          // initial contents (their sizes are the arrays' sizes)
    uint8_t nhuff = 0;
    uint16_t entryStream = 0;
    int32_t entryToken = -1;
    // what the generic predictor needs to know (22.15.2, axioms 4 and 6)
    uint32_t window = 0, maxlen = 0;
    int8_t len1slot = -1;
    uint8_t histbase = 0, histlen = 0, tokK = 0, tokL = 0, tokSL = 0, tokD = 0;
};

std::vector<uint8_t> Serialize(const Description &D);
// False (Err says why) for anything that is not a valid description this engine can run.
bool Parse(const uint8_t *Data, size_t N, Description &D, std::string &Err);

// Descriptions of the formats this repository knows how to WRITE (the reader never needs these: it reads any
// description).
Description LzmaDescription(int Lc, int Lp, int Pb, uint32_t Dict, bool EndMarker);
Description DeflateDescription();
Description Lz4BlockDescription();

// Mint: decode `Shipped` with `D` into its content and a RECORD (the decisions, plus checkpoints every `Spacing`
// shipped bytes at the description's MARK points), then code it back and refuse unless every byte matches.
// `ContentSize` is the expected content size (0: unknown, at most `ContentCap`).
bool Mint(const Description &D, const uint8_t *Shipped, size_t N, size_t ContentSize, size_t ContentCap, uint64_t Spacing,
          std::vector<uint8_t> &Content, std::vector<uint8_t> &Record, std::string &Err);

// A shipped stream served from a description, its content and its record: random access through the record's
// checkpoints, safe for concurrent reads, nothing resident but the parsed description and the checkpoint index.
class CodedByteSource : public ByteSource {
public:
    static std::shared_ptr<CodedByteSource> Create(std::shared_ptr<ByteSource> Desc, std::shared_ptr<ByteSource> Record,
                                                   std::shared_ptr<ByteSource> Content, uint64_t ShippedSize, std::string &Err);
    ssize_t  pread(void *Buf, size_t N, uint64_t Off) override;
    uint64_t size() const override { return Size; }
    size_t   checkpoints() const { return Cks.size(); }       // (tests)
    struct Ck { uint64_t out = 0, rec = 0, recLen = 0, dec = 0; };
    struct Impl;
private:
    std::shared_ptr<Impl> I;
    std::shared_ptr<ByteSource> Rec, Content;
    std::vector<Ck> Cks;
    uint64_t Size = 0;
};

} // namespace coding

#endif // VIDYAGODFS_CODING_H
