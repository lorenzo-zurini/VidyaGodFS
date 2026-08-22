#ifndef VIDYAGODFS_VGDELTA_H
#define VIDYAGODFS_VGDELTA_H

#include "bytesource.h"

#include <cstdint>
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

// Generates a .vgdelta reconstructing `target` from `base` (both addressable as flat memory — mmap them, they
// are read once and sequentially). Uses a rolling-hash + greedy-extend matcher; literal runs are stored as
// per-block zstd.
//
// Memory: the matched-literal stream and the compressed ADD region are SPILLED to two scratch files instead of
// being accumulated in RAM — on a big archive the literals alone can be several GB, and holding them plus the
// compressed copy plus the returned buffer used to blow past the machine's RAM. Only the returned delta (and the
// base index) stay resident. `scratchDir` says where those files go; empty = the system temp dir — pass a real
// on-disk directory when that is a tmpfs (spilling to RAM-backed /tmp would defeat the whole point).
std::vector<uint8_t> GenerateDelta(const uint8_t *base, size_t baseLen,
                                   const uint8_t *target, size_t targetLen,
                                   uint32_t blockSize = DEFAULT_BLOCK,
                                   const std::string &scratchDir = std::string());

// Byte-verifies a delta: composes it over `base`, then streams the reconstruction and compares it against
// `target` chunk-by-chunk. True only on an exact byte-for-byte match; on failure Err says what diverged
// (create/size/read/mismatch). THE one verify used by both the app's --convert-delta-chain and the tests —
// production converts and the test suite must never hand-roll (and drift) their own reconstruct-compare.
bool VerifyDelta(const std::vector<uint8_t> &delta, const std::shared_ptr<ByteSource> &base,
                 ByteSource &target, std::string &Err);

} // namespace vgdelta

#endif // VIDYAGODFS_VGDELTA_H
