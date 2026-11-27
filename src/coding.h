#ifndef VIDYAGODFS_CODING_H
#define VIDYAGODFS_CODING_H

#include "bytesource.h"

#include <cstdint>
#include <memory>
#include <map>
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

constexpr uint32_t kIsa = 9;          // the instruction set a description may use; newer is refused (3: HUFFRUN, BYTERUN; 4: STREAMPOS; 5: PREDICT; 6: U16 U32 U16BE U32BE;
                                      // 7: the BITS16M coder, RAWBYTES, DIV MOD, a bounded HUFFRUN; 8: E8FRAME E8END NEAREST;
                                      // 9: the LZX family: LZXFOLDER LZXEND LZXSIZE LZXEMIT)
constexpr int kRegs = 64;
constexpr int kRegPlace = 0;          // register 0: the place in the content
constexpr uint32_t kNoSlot = 255;
constexpr uint32_t kNoPrediction = 0xFFFFFFFFu;
constexpr uint8_t kFamilyLz4hc = 1;

enum Mode : uint8_t { kCode = 1, kDecode = 2, kPrice = 4, kAll = 7, kCodePrice = 5 };
// kBits: bits LSB-first (deflate). kBits16M (ISA 7): bits MSB-first from 16-bit little-endian words (LZX), the words
// counted from where the bits begin (after bytes, the next bits start a new run of words where they stand: a container's
// bitstream begins wherever its block does); byte runs and RAWBYTES at word boundaries of the bits before them.
enum Coder : uint8_t { kRange = 0, kBits = 1, kBits16M = 2 };

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
    EX_STREAMPOS, // ISA 4: the shipped stream's byte position: read so far (DECODE), written so far (CODE); 0 in PRICE
    // ---- ISA 6: integers in the content, as containers store them (one value, not four byte reads and their shifts)
    EX_U16,       // the little-endian 16-bit integer at content place a (bytes outside what exists read as 0, as EX_BYTE)
    EX_U32,       // the little-endian 32-bit integer at a
    EX_U16BE,     // big-endian 16 bits at a
    EX_U32BE,     // big-endian 32 bits at a
    // ---- ISA 7
    EX_DIV,       // a / b (b 0: the run is refused)
    EX_MOD,       // a % b (b 0: the run is refused)
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
    // ---- ISA 3: runs (22.12 flattening: a run of literals is one op, not one program per byte)
    OP_HUFFRUN,  // a run of literals through code imm: CODE emits x content bytes then the terminating symbol in register nb;
                 // DECODE reads symbols below m as literals (into the content) until one is not, which goes to register nb;
                 // register tgt gets the run's length either way. ISA 7, flag kBounded: v BOUNDS the run (LZX: no end
                 // symbol): DECODE stops after v literals (register nb then 0xFFFFFFFF: "the count ran out"), and CODE
                 // writes no terminating symbol when the run's length is v
    OP_BYTERUN,  // x content bytes through the bit coder as they are (byte-aligned: copied whole)
    // ---- ISA 5: encoder families (22.15.4: a family predicts the encoder's decisions, so a record holds corrections)
    OP_PREDICT,  // registers tgt, tgt+1, tgt+2 = family nb's predicted token anchored at content place x, from its parse of
                 // the content [v, m) (a block), knob imm. Family 1: LZ4 high compression (lz4family.h), imm = its attempts;
                 // the token is (literals, copy length, distance), copy length 0 the block's last; no prediction at x (or a
                 // run that predicts nothing: PRICE, a plain mint) gives copy length kNoPrediction
    // ---- ISA 7
    OP_RAWBYTES, // x (1..4) stream bytes as a little-endian integer, at a byte boundary (BITS16M: a word boundary of the bits
                 // before it, or after bytes); a coding op (`free` makes it a decision)
    // ---- ISA 8: a TRANSLATED VIEW (LZX's E8: the encoder translated x86 CALL operands before compressing). The format's code
    // works on what the encoder saw; the content is the real bytes (so it dedups with the installed files)
    OP_E8FRAME,  // frame [x, x+v) of the content, its first byte at stream position m, filesize in register tgt: if the frame
                 // turns out translated (E8END), the code reads it translated (one decision: CODE learns it here)
    OP_E8END,    // the frame opened is translated if v (DECODE decides; the content becomes the real bytes when the run ends)
    OP_NEAREST,  // register tgt = the NEAREST distance d (1..m, never before content place v) at which the content repeats the x
                 // bytes at the place (an LZ copy's distance as match finders hand it out; x >= 2), or 0xFFFFFFFF: none
                 // found within 128 candidates, or no content ahead to look at (PRICE; the first, plain DECODE of a mint).
                 // A predictor like PREDICT: what it says is checked when minted, never trusted
    // ---- ISA 9: the LZX ENCODER FAMILY (MAKECAB 1.00's compressor, lzxmakecab.h): a whole CAB folder reproduced from its
    // content. Folders go through ONE compressor in stream order (state survives between folders of one knob, as in
    // MAKECAB), fed only as far as the frames asked for
    OP_LZXFOLDER,// folder [x, x+v) of the content, E8 filesize m, knob imm (window bits | second partition / 32 KiB << 8): one
                 // decision, the folder is the family's (DECODE decides at LZXEND); register tgt = 1 when the family is
                 // at hand (CODE: the decision says so; DECODE: a mint's second pass), else 0xFFFFFFFF
    OP_LZXEND,   // the folder opened is the family's if v AND the family made every frame asked for: DECODE drops every
                 // decision recorded since LZXFOLDER's (CODE makes the folder from the family's frames instead); closes it
    OP_LZXSIZE,  // register tgt = the byte size of the open folder's frame x (its CFDATA payload), or 0xFFFFFFFF (no such
                 // frame: past the folder's last, or the family not at hand)
    OP_LZXEMIT,  // frame x's payload at the stream's byte position: CODE writes it; DECODE compares (register tgt = 1 if the
                 // stream holds it there, else 0; nothing is read)
    OP_COUNT
};
constexpr uint8_t kFree = 1;          // op flag: its value is a decision
constexpr uint8_t kBounded = 2;       // op flag (HUFFRUN, ISA 7): v bounds the run (0 too: a run of no literals)

struct Ex { uint8_t op = 0; uint16_t a = 0, b = 0; uint32_t imm = 0; };
struct Op { uint8_t op = 0, modes = 0, flags = 0, nb = 0, tgt = 0; uint16_t x = 0, v = 0, m = 0, target = 0; uint32_t imm = 0; };

struct Description {
    std::string name;
    uint32_t isa = 4;                                   // the instruction set it needs (a builder using newer ops says so)
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

// A description is KEPT as readable data in a node (chapter 22 §22.16: JSON, one instruction a string; codingtext.cpp),
// never as a binary. False (Err says why) for anything that is not a valid description this engine can run.
bool Validate(const Description &D, std::string &Err);
// Names a printed description uses for what it numbers (registers, labels at op indices, tables, arrays, codes);
// anything unnamed prints as r5, L12, t0, a0, h0.
struct TextNames {
    std::map<int, std::string> regs, labels;
    std::vector<std::string> tables, arrays, huffs;
};
// Print: the description's text (canonical: Read(Print(D)) runs as D does, and prints the same). False if it is not
// valid, or sets a field its text form cannot say.
bool Print(const Description &D, std::string &Out, std::string &Err, const TextNames *Names = nullptr);
// Read: a description's text, or a node whose CODED layers carry one (inline); validated. Names: what the text called things
// (Print(D, …, Names) gives the text back in canonical form with them).
bool Read(const std::string &Text, Description &D, std::string &Err, TextNames *Names = nullptr);
// The same as bytes (the text, UTF-8): what a ByteSource of a description holds. Serialize is empty if Print fails.
std::vector<uint8_t> Serialize(const Description &D);
bool Parse(const uint8_t *Data, size_t N, Description &D, std::string &Err);


// The checkpoint spacing a description suits: a coder without adaptive state (static codes, raw bytes) checkpoints
// cheaply, so often (every block or so: a read starts at most that far back, and segments decode in parallel); one
// with adaptive slots carries them in every checkpoint, so less often.
// `Shipped` (the stream's size, 0 unknown) lets a small stream still split into enough segments to decode in parallel.
// Plain: the spacing for a plain record of a description with families (an expansion's).
uint64_t SuggestedSpacing(const Description &D, uint64_t Shipped = 0, bool Plain = false);

// Mint: decode `Shipped` with `D` into its content and a RECORD (the decisions, plus checkpoints every `Spacing`
// shipped bytes at the description's MARK points), then code it back and refuse unless every byte matches.
// `ContentSize` is the expected content size (0: unknown, at most `ContentCap`).
// A description with PREDICT ops (ISA 5) mints a PREDICTED record ("VGCQ": its decisions are corrections against the
// families' predictions, so it is small, and a run of it runs the families); `Predict` false mints a PLAIN one ("VGCR":
// every decision as the stream has it; fast to run, larger).
bool UsesPrediction(const Description &D);
bool Mint(const Description &D, const uint8_t *Shipped, size_t N, size_t ContentSize, size_t ContentCap, uint64_t Spacing,
          std::vector<uint8_t> &Content, std::vector<uint8_t> &Record, std::string &Err, bool Predict = true);
// The same into a caller's buffer of ContentCap bytes (a tool maps a big one lazily, so a stream of gigabytes costs only the
// pages its content fills); the content's length is returned in ContentLen.
bool MintInto(const Description &D, const uint8_t *Shipped, size_t N, size_t ContentSize, uint8_t *Buf, size_t ContentCap, uint64_t Spacing,
              size_t &ContentLen, std::vector<uint8_t> &Record, std::string &Err, bool Predict = true);

// A shipped stream served from a description, its content and its record: random access through the record's
// checkpoints, safe for concurrent reads. A reader going front to back (a game loading a bundle) is served by
// READ-AHEAD: every checkpoint segment decodes on its own, so a shared pool of threads decodes the segments after the
// one being read while it is read; decoded segments are kept in a small RAM ring, a few per stream, never on disk.
class CodedByteSource : public ByteSource {
public:
    // ShippedSize: the size the caller expects (0: the record's own, which is always checked against it).
    static std::shared_ptr<CodedByteSource> Create(std::shared_ptr<ByteSource> Desc, std::shared_ptr<ByteSource> Record,
                                                   std::shared_ptr<ByteSource> Content, uint64_t ShippedSize, std::string &Err);
    ssize_t  pread(void *Buf, size_t N, uint64_t Off) override;
    // [Off, Off+N) will be read soon: its segments are asked of the pool now, so a layer above that reads this one front
    // to back finds them decoded (layers PIPELINE: every layer decodes ahead of the one reading it)
    void     prefetch(uint64_t Off, uint64_t N) override;
    uint64_t size() const override { return Size; }
    size_t   checkpoints() const { return Cks.size(); }       // (tests)
    uint64_t segmentsDecoded() const;                          // (tests, benchmarks: work done, against checkpoints())
    bool     predicted() const;                                // a VGCQ record (its reads run the families: slower; see ExpandInto)
    uint64_t bytesGenerated() const;                           // (tests: bytes segments generated; copy runs are handed down, not counted)
    // (tests) the interleavings of a busy pool, forced: hold a reader's place on the segment holding Off (as a waiting
    // reader does: the segment is not evicted), ask whether that segment is decoded and kept, and have the next reader
    // woken from waiting lose its segment at that moment (as if read-ahead had evicted it while it woke).
    void     debugHoldWaiter(uint64_t Off, bool On);
    bool     debugCached(uint64_t Off) const;
    void     debugStreamBudget(uint64_t Steps);                // (tests) what the families may spend, the whole stream's
    void     debugLzxKept(uint64_t Bytes);                     // (tests) the LZX family's frames kept (64 MiB)
    void     debugDropOnNextWake();
    struct Ck { uint64_t out = 0, rec = 0, recLen = 0, dec = 0, hash = 0; };   // hash: a predicted record's, of the segment's shipped bytes
    struct Impl;
private:
    static void remember(Impl &M, uint64_t Off, size_t N);   // where a read ended (read-ahead for readers going front to back)
    std::shared_ptr<Impl> I;
    std::shared_ptr<ByteSource> Rec, Content;
    std::vector<Ck> Cks;
    uint64_t Size = 0;
    friend bool ExpandInto(std::shared_ptr<ByteSource>, std::shared_ptr<ByteSource>, std::shared_ptr<ByteSource>, uint8_t *, size_t,
                           uint8_t *, size_t, uint64_t, std::vector<uint8_t> &, std::string &);
};

// EXPAND a predicted record into the plain one (the same stream, the same description, every decision stored: a machine
// keeps this beside the content so its reads run at plain speed, never the families). The shipped bytes are generated
// into ShippedBuf (the stream's size) and minted plain over ContentBuf (the content's size): a tool maps both lazily.
// Refused unless the plain mint reproduces the stream and its content is the content given.
bool ExpandInto(std::shared_ptr<ByteSource> Desc, std::shared_ptr<ByteSource> Record, std::shared_ptr<ByteSource> Content,
                uint8_t *ShippedBuf, size_t ShippedCap, uint8_t *ContentBuf, size_t ContentCap, uint64_t Spacing,
                std::vector<uint8_t> &Plain, std::string &Err);

} // namespace coding

#endif // VIDYAGODFS_CODING_H
