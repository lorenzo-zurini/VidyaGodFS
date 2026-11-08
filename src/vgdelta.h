#ifndef VIDYAGODFS_VGDELTA_H
#define VIDYAGODFS_VGDELTA_H

#include "bytesource.h"

#include <cstdint>
#include <functional>
#include <deque>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

// ---------------------------------------------------------------------------
// .vgdelta — a random-access, layerable, compressed binary delta of one whole (zip) byte-stream against a
// "base" byte-stream (the reconstructed view of the layer below). It reconstructs a target T from a base B
// as a gap-free sequence of segments covering [0, target_size): COPY(base_off, len) — served by a pure
// pread on B — or ADD(add_off, len) — literal new bytes kept as independently-decompressible zstd blocks.
// No file is ever materialized: reads touch only the byte ranges they need. Deltas compose (a COPY's base
// may itself be a DeltaByteSource), so stacking deltas chains versions (v1.zip -> d2 -> d3).
//
// On-disk layout (all little-endian):
//   Header:  magic "VGD1"(4) | u32 version | u32 block_size | u64 target_size | u64 base_size |
//            u64 base_hash(FNV-1a-64 of B) | u32 num_segments | u32 num_blocks
//   Segments (compressed): u32 clen | u32 ulen | zstd(segment records)
//            each record: u8 kind | u64 len | u64 src_off   (target_off is the running prefix sum)
//   Blocks index (compressed): u32 clen | u32 ulen | zstd(block records)
//            each record: u64 comp_off (rel. to add-region start) | u32 comp_len | u32 uncomp_len
//   ADD region: the concatenated per-block zstd frames (read + decompressed on demand)
// ---------------------------------------------------------------------------

namespace vgdelta {

constexpr char     MAGIC[4]         = { 'V', 'G', 'D', '1' };
constexpr uint32_t VERSION          = 1;
constexpr uint32_t DEFAULT_BLOCK    = 262144;   // 256K: bigger ADD frames compress ~3% better than 64K while keeping
                                                // per-read decompression bounded (the reader decompresses one block per read)
constexpr uint8_t  KIND_COPY        = 0;
constexpr uint8_t  KIND_ADD         = 1;

// FNV-1a-64 over a buffer — the base-identity hash stored in the header (cheap "is this the right base?").
uint64_t Fnv1a64(const uint8_t *p, size_t n);

struct BlockRec {
    uint64_t compOff   = 0;   // offset of this block's zstd frame, relative to the add-region start
    uint32_t compLen   = 0;
    uint32_t uncompLen = 0;
};

// One .vgdelta file's ADD-block store — the literal bytes it introduced. A flattened DeltaByteSource keeps one
// per delta file in the collapsed chain, so its ADD segments read straight from the original file (no copy).
struct AddSource {
    std::shared_ptr<ByteSource> file;       // the .vgdelta file
    uint64_t                    regionOff = 0;
    uint32_t                    blockSize = DEFAULT_BLOCK;
    std::vector<BlockRec>       blocks;
};

// A resolved segment in the FLAT map: COPY reads the ultimate base; ADD reads addSources[addSrc].
struct FlatSeg {
    uint64_t targetOff = 0;   // prefix sum (in-memory)
    uint64_t len       = 0;
    uint64_t srcOff    = 0;   // COPY: byte offset into the ultimate base; ADD: logical offset into that AddSource
    uint32_t addSrc    = 0;   // ADD only: index into addSources
    uint8_t  kind      = KIND_COPY;
};

// A ByteSource that reconstructs T on the fly. CRUCIAL: it is ALWAYS FLAT — its segments reference the
// ULTIMATE non-delta base directly (COPY) or a specific delta file's ADD blocks (ADD). When Create()'s base
// is itself a DeltaByteSource, the two are COMPOSED (segment-map merge, no re-diffing) so a chain of N deltas
// collapses to ONE flat map: reads stay O(log n) no matter how deep the chain (hundreds of versions). The
// on-disk incremental deltas are unchanged — they are the summands; flattening forms their "sum" at build time.
class DeltaByteSource : public ByteSource {
public:
    // Parses the .vgdelta from `delta` and applies it over `base`. If `base` is itself a DeltaByteSource, the
    // result is the composition (a single flat map over base's ultimate base). nullptr on bad magic/format.
    // verifyBase (single-level authoring check only) hashes the whole base against the header's base_hash.
    static std::shared_ptr<DeltaByteSource> Create(std::shared_ptr<ByteSource> delta,
                                                   std::shared_ptr<ByteSource> base,
                                                   std::string &err, bool verifyBase = false);

    ssize_t  pread(void *buf, size_t n, uint64_t off) override;
    uint64_t size() const override { return TargetSize; }

private:
    int readAdd(uint32_t addSrc, const AddSource &A, uint8_t *buf, size_t n, uint64_t addOff);
    // Decompressed ADD block, cached. Reads (esp. zip enumeration: thousands of small scattered reads) otherwise
    // re-decompress the same block over and over — expensive once blocks are large. FIFO-capped, mutex-guarded
    // (pread is a concurrent-safe contract). Key = (addSrc << 40) ^ blockIdx.
    std::shared_ptr<std::vector<uint8_t>> GetAddBlock(uint32_t addSrc, const AddSource &A, uint64_t blk);

    std::shared_ptr<ByteSource>              BaseSrc;    // the ULTIMATE (non-delta) base — for COPY
    std::vector<std::shared_ptr<AddSource>>  AddSources; // one per delta file surviving in the flattened chain
    std::vector<FlatSeg>                     Segs;       // flat, sorted by targetOff, gap-free over [0,TargetSize)
    uint64_t                                 TargetSize = 0;

    std::mutex                                                        CacheMu;
    std::unordered_map<uint64_t, std::shared_ptr<std::vector<uint8_t>>> BlockCache;
    std::deque<uint64_t>                                             CacheFifo;
    static constexpr size_t                                          CacheCap = 64;   // 64 blocks (~16 MB at 256K)
};

// Generates a .vgdelta reconstructing `target` from `base` (both addressable as flat memory — mmap them; the target is
// read once, sequentially). Uses a rolling-hash + greedy-extend matcher; literal runs are stored as per-block zstd.
//
// Memory is bounded whatever the target or delta size: the base index (~12 bytes per 256 bytes of base: a 57 GB base
// is ~2.7 GB) plus O(block). The literal stream, the segment records and the compressed ADD region are SPILLED to
// scratch files as they are produced, and the delta is streamed into `outPath` — never resident. `scratchDir` says
// where the scratch goes; empty = the system temp dir — pass a real on-disk directory when that is a tmpfs (spilling
// to RAM-backed /tmp would defeat the whole point). It needs about the delta's size plus the new literals, free.
// Progress + cancellation. Called periodically while the delta is built; return FALSE to ABORT: the generation then
// fails with Err "cancelled" (its scratch files and `outPath` are removed on that path like any other).
// `stage` is 0 while scanning the target for matches and 1 while compressing the literal stream — two passes
// with independent totals, so a caller renders them as two halves of one bar rather than a number that jumps.
// Multi-GB archives are the normal case here (a 3.7GB Minecraft chain), which is why this is not optional
// decoration: without it a conversion cannot be interrupted and shows nothing for minutes.
using ProgressFn = std::function<bool(int stage, uint64_t done, uint64_t total)>;

// False (outPath removed) on any failure or a cancel; Err says why.
bool GenerateDeltaToFile(const uint8_t *base, size_t baseLen, const uint8_t *target, size_t targetLen,
                         const std::string &outPath, std::string &Err, uint32_t blockSize = DEFAULT_BLOCK,
                         const std::string &scratchDir = std::string(), const ProgressFn &progress = {});
// The same delta, returned in memory — for small ones (the tests, a fixture, the editor's single archive). Empty on
// failure or a cancel. A delta of gigabytes goes to a file.
std::vector<uint8_t> GenerateDelta(const uint8_t *base, size_t baseLen,
                                   const uint8_t *target, size_t targetLen,
                                   uint32_t blockSize = DEFAULT_BLOCK,
                                   const std::string &scratchDir = std::string(),
                                   const ProgressFn &progress = {});

// Byte-verifies a delta: composes it over `base`, then streams the reconstruction and compares it against
// `target` chunk-by-chunk. True only on an exact byte-for-byte match; on failure Err says what diverged
// (create/size/read/mismatch). THE one verify used by both the app's --convert-delta-chain and the tests —
// production converts and the test suite must never hand-roll (and drift) their own reconstruct-compare.
//
// `progress` is the SAME contract as GenerateDelta's, with stage 2 ("verifying"): this pass streams the whole
// reconstruction a second time, so on a multi-GB archive it is minutes during which the caller would otherwise
// show a finished bar and a Cancel button that does nothing. Return false to abort (VerifyDelta then returns
// false with Err "cancelled").
// `delta` is read through a ByteSource (mmap the file): only the tables and one ADD block at a time are resident.
bool VerifyDelta(const std::shared_ptr<ByteSource> &delta, const std::shared_ptr<ByteSource> &base,
                 ByteSource &target, std::string &Err, const ProgressFn &progress = {});
bool VerifyDelta(const std::vector<uint8_t> &delta, const std::shared_ptr<ByteSource> &base,
                 ByteSource &target, std::string &Err, const ProgressFn &progress = {});

} // namespace vgdelta

#endif // VIDYAGODFS_VGDELTA_H
