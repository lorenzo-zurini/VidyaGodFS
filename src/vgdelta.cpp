#include "vgdelta.h"

#include <zstd.h>

#include <algorithm>
#include <cerrno>
#include <atomic>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <string>
#include <memory>
#include <unordered_map>

#ifndef _WIN32
#include <fcntl.h>      // SpillFile: open/posix_fadvise
#include <unistd.h>     //   … write/fdatasync/close, and getpid for the scratch-name salt
#else
#include <process.h>    // _getpid — unistd.h does not exist here
#endif

namespace vgdelta {

// ---- gentle spill file --------------------------------------------------------------------------
// A sequential scratch writer that FORCES its own writeback in small increments. Naively streaming
// gigabytes through the page cache lets dirty pages pile up to vm.dirty_ratio (~20% of RAM), at which
// point the kernel stalls the WHOLE machine in synchronous flushing — that froze a desktop while this
// generator spilled its literal stream. Every FLUSH_EVERY bytes we fdatasync the window and then drop
// it from the cache (POSIX_FADV_DONTNEED), so at any instant only ~one window of dirty data exists and
// the rest of the system never feels the spill. Windows: plain buffered writes (its conversions are
// small; no equivalent stall mechanism in play).
class SpillFile {
    static constexpr uint64_t FLUSH_EVERY = 64ull << 20;   // 64 MB windows
public:
    bool Open(const std::filesystem::path &p) {
#ifndef _WIN32
        fd_ = ::open(p.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
        return fd_ >= 0;
#else
        f_.open(p, std::ios::binary | std::ios::trunc);
        return (bool)f_;
#endif
    }
    bool Write(const void *b, size_t n) {
#ifndef _WIN32
        const uint8_t *q = (const uint8_t *)b;
        while (n) {
            ssize_t w = ::write(fd_, q, n);
            if (w < 0) { if (errno == EINTR) continue; return false; }  // retry signal-interrupted writes
            if (w == 0) return false;
            q += w; n -= (size_t)w; off_ += (uint64_t)w;
        }
        if (off_ - synced_ >= FLUSH_EVERY) Drain();
        return true;
#else
        f_.write((const char *)b, (std::streamsize)n); off_ += n; return (bool)f_;
#endif
    }
    bool Close() {   // final drain + close; returns false on any write error
#ifndef _WIN32
        if (fd_ < 0) return false;
        Drain();
        return ::close(fd_) == 0 ? (fd_ = -1, true) : (fd_ = -1, false);
#else
        f_.flush(); bool ok = (bool)f_; f_.close(); return ok;
#endif
    }
    uint64_t Size() const { return off_; }
    ~SpillFile() {
#ifndef _WIN32
        if (fd_ >= 0) ::close(fd_);
#endif
    }
private:
#ifndef _WIN32
    void Drain() {
        ::fdatasync(fd_);
        ::posix_fadvise(fd_, 0, (off_t)off_, POSIX_FADV_DONTNEED);
        synced_ = off_;
    }
    int fd_ = -1;
    uint64_t synced_ = 0;
#else
    std::ofstream f_;
#endif
    uint64_t off_ = 0;
};

// ---- little-endian (de)serialization ------------------------------------------------------------

static void put32(std::vector<uint8_t> &v, uint32_t x) { for (int i = 0; i < 4; ++i) v.push_back((x >> (8 * i)) & 0xff); }
static void put64(std::vector<uint8_t> &v, uint64_t x) { for (int i = 0; i < 8; ++i) v.push_back((x >> (8 * i)) & 0xff); }
static uint32_t rd32(const uint8_t *p) { uint32_t x = 0; for (int i = 0; i < 4; ++i) x |= (uint32_t)p[i] << (8 * i); return x; }
static uint64_t rd64(const uint8_t *p) { uint64_t x = 0; for (int i = 0; i < 8; ++i) x |= (uint64_t)p[i] << (8 * i); return x; }

uint64_t Fnv1a64(const uint8_t *p, size_t n) {
    uint64_t h = 1469598103934665603ULL;
    for (size_t i = 0; i < n; ++i) { h ^= p[i]; h *= 1099511628211ULL; }
    return h;
}

// ---- zstd helpers -------------------------------------------------------------------------------

static std::vector<uint8_t> ZCompress(const uint8_t *p, size_t n, int level = 19) {
    std::vector<uint8_t> out(ZSTD_compressBound(n));
    size_t r = ZSTD_compress(out.data(), out.size(), p, n, level);
    if (ZSTD_isError(r)) return {};
    out.resize(r);
    return out;
}

// Decompresses exactly `ulen` bytes. Empty on error.
static std::vector<uint8_t> ZDecompress(const uint8_t *p, size_t clen, size_t ulen) {
    std::vector<uint8_t> out(ulen);
    size_t r = ZSTD_decompress(out.data(), ulen, p, clen);
    if (ZSTD_isError(r) || r != ulen) return {};
    return out;
}

// =================================================================================================
// DeltaByteSource — parse + read
// =================================================================================================

static constexpr uint64_t HEADER_SIZE = 4 + 4 + 4 + 8 + 8 + 8 + 4 + 4;   // 44

namespace {
struct RawSeg { uint8_t kind; uint64_t len; uint64_t srcOff; };
struct Parsed {
    uint64_t targetSize = 0, baseSize = 0, baseHash = 0;
    std::vector<RawSeg>        segs;       // this delta's segments, over its IMMEDIATE base
    std::shared_ptr<AddSource> add;        // this file's ADD-block store
};

// Parse one .vgdelta file (header + segment table + block index). ADD blocks stay on disk (read on demand).
bool ParseDelta(const std::shared_ptr<ByteSource> &delta, Parsed &P, std::string &err) {
    uint8_t hdr[HEADER_SIZE];
    if (!delta->preadAll(hdr, HEADER_SIZE, 0)) { err = "vgdelta: short header"; return false; }
    if (std::memcmp(hdr, MAGIC, 4) != 0)       { err = "vgdelta: bad magic";    return false; }
    if (rd32(hdr + 4) != VERSION)              { err = "vgdelta: unsupported version"; return false; }
    uint32_t blockSize = rd32(hdr + 8);
    P.targetSize = rd64(hdr + 12);
    P.baseSize   = rd64(hdr + 20);
    P.baseHash   = rd64(hdr + 28);
    uint32_t numSeg = rd32(hdr + 36), numBlk = rd32(hdr + 40);
    if (blockSize == 0) { err = "vgdelta: zero block size"; return false; }
    uint64_t off = HEADER_SIZE;

    {   // segment table (clen/ulen u64 — a pathologically fragmented delta can't overflow)
        uint8_t lens[16];
        if (!delta->preadAll(lens, 16, off)) { err = "vgdelta: short seg lens"; return false; }
        uint64_t clen = rd64(lens), ulen = rd64(lens + 8);
        if (ulen != (uint64_t)numSeg * 17) { err = "vgdelta: seg table size mismatch"; return false; }
        std::vector<uint8_t> comp(clen);
        if (clen && !delta->preadAll(comp.data(), clen, off + 16)) { err = "vgdelta: short seg table"; return false; }
        std::vector<uint8_t> raw = ZDecompress(comp.data(), clen, ulen);
        if (raw.size() != ulen) { err = "vgdelta: seg table corrupt"; return false; }
        P.segs.reserve(numSeg); uint64_t tpos = 0;
        for (uint32_t i = 0; i < numSeg; ++i) {
            const uint8_t *r = raw.data() + (size_t)i * 17;
            RawSeg s{ r[0], rd64(r + 1), rd64(r + 9) };
            tpos += s.len; P.segs.push_back(s);
        }
        if (tpos != P.targetSize) { err = "vgdelta: segments do not cover target"; return false; }
        off += 16 + clen;
    }

    P.add = std::make_shared<AddSource>(); P.add->file = delta; P.add->blockSize = blockSize;
    {   // block index
        uint8_t lens[16];
        if (!delta->preadAll(lens, 16, off)) { err = "vgdelta: short blk lens"; return false; }
        uint64_t clen = rd64(lens), ulen = rd64(lens + 8);
        if (ulen != (uint64_t)numBlk * 16) { err = "vgdelta: blk index size mismatch"; return false; }
        std::vector<uint8_t> comp(clen);
        if (clen && !delta->preadAll(comp.data(), clen, off + 16)) { err = "vgdelta: short blk index"; return false; }
        std::vector<uint8_t> raw = ZDecompress(comp.data(), clen, ulen);
        if (raw.size() != ulen) { err = "vgdelta: blk index corrupt"; return false; }
        P.add->blocks.reserve(numBlk);
        for (uint32_t i = 0; i < numBlk; ++i) {
            const uint8_t *r = raw.data() + (size_t)i * 16;
            P.add->blocks.push_back({ rd64(r), rd32(r + 8), rd32(r + 12) });
        }
        off += 16 + clen;
    }
    P.add->regionOff = off;   // ADD block frames follow the block index
    return true;
}

// Largest flat segment with targetOff <= o.
size_t SegAt(const std::vector<FlatSeg> &segs, uint64_t o) {
    size_t i = (size_t)(std::upper_bound(segs.begin(), segs.end(), o,
                   [](uint64_t v, const FlatSeg &s) { return v < s.targetOff; }) - segs.begin());
    return i ? i - 1 : 0;
}
} // namespace

std::shared_ptr<DeltaByteSource> DeltaByteSource::Create(std::shared_ptr<ByteSource> delta,
                                                         std::shared_ptr<ByteSource> base,
                                                         std::string &err, bool verifyBase) {
    Parsed P;
    if (!ParseDelta(delta, P, err)) return nullptr;
    if (!base) { err = "vgdelta: null base"; return nullptr; }
    if (base->size() != P.baseSize) { err = "vgdelta: base size mismatch"; return nullptr; }

    auto D = std::shared_ptr<DeltaByteSource>(new DeltaByteSource());
    D->TargetSize = P.targetSize;

    if (auto *bd = dynamic_cast<DeltaByteSource *>(base.get())) {
        // COMPOSE: rewrite this delta's COPY-from-M ranges through the base's flat map (M over the ultimate
        // base). A chain of N deltas thus collapses to ONE flat map — reads never walk the chain.
        D->BaseSrc    = bd->BaseSrc;
        D->AddSources = bd->AddSources;                 // indices preserved; this file appended
        uint32_t thisAdd = (uint32_t)D->AddSources.size();
        D->AddSources.push_back(P.add);
        const std::vector<FlatSeg> &B = bd->Segs;
        D->Segs.reserve(P.segs.size());
        for (const RawSeg &s : P.segs) {
            if (s.kind == KIND_ADD) { D->Segs.push_back({ 0, s.len, s.srcOff, thisAdd, KIND_ADD }); continue; }
            uint64_t m = s.srcOff, rem = s.len; size_t bi = SegAt(B, m);
            while (rem > 0 && bi < B.size()) {
                const FlatSeg &bs = B[bi];
                uint64_t bsEnd = bs.targetOff + bs.len;
                if (m < bs.targetOff || m >= bsEnd) { err = "vgdelta: compose gap"; return nullptr; }
                uint64_t take = std::min(bsEnd, m + rem) - m;
                D->Segs.push_back({ 0, take, bs.srcOff + (m - bs.targetOff), bs.addSrc, bs.kind });
                m += take; rem -= take; ++bi;
            }
            if (rem > 0) { err = "vgdelta: compose out of range"; return nullptr; }
        }
    } else {
        // Base is the ultimate (non-delta) source: this delta's segments map directly onto it.
        if (verifyBase) {
            std::vector<uint8_t> b(P.baseSize);
            if (!base->preadAll(b.data(), P.baseSize, 0) || Fnv1a64(b.data(), b.size()) != P.baseHash)
            { err = "vgdelta: base hash mismatch"; return nullptr; }
        }
        D->BaseSrc = std::move(base);
        D->AddSources.push_back(P.add);
        D->Segs.reserve(P.segs.size());
        for (const RawSeg &s : P.segs) D->Segs.push_back({ 0, s.len, s.srcOff, 0, s.kind });
    }

    uint64_t t = 0; for (FlatSeg &s : D->Segs) { s.targetOff = t; t += s.len; }
    if (t != D->TargetSize) { err = "vgdelta: flat segments do not cover target"; return nullptr; }
    return D;
}

std::shared_ptr<std::vector<uint8_t>> DeltaByteSource::GetAddBlock(uint32_t addSrc, const AddSource &A, uint64_t blk) {
    uint64_t key = ((uint64_t)addSrc << 40) ^ blk;
    {
        std::lock_guard<std::mutex> g(CacheMu);
        auto it = BlockCache.find(key);
        if (it != BlockCache.end()) return it->second;
    }
    const BlockRec &b = A.blocks[blk];                          // decompress outside the lock
    std::vector<uint8_t> comp(b.compLen);
    if (b.compLen && !A.file->preadAll(comp.data(), b.compLen, A.regionOff + b.compOff)) return nullptr;
    auto raw = std::make_shared<std::vector<uint8_t>>(ZDecompress(comp.data(), b.compLen, b.uncompLen));
    if (raw->size() != b.uncompLen) return nullptr;
    {
        std::lock_guard<std::mutex> g(CacheMu);
        if (BlockCache.emplace(key, raw).second) {             // first insert of this key → track for eviction
            CacheFifo.push_back(key);
            if (CacheFifo.size() > CacheCap) { BlockCache.erase(CacheFifo.front()); CacheFifo.pop_front(); }
        }
    }
    return raw;
}

int DeltaByteSource::readAdd(uint32_t addSrc, const AddSource &A, uint8_t *buf, size_t n, uint64_t addOff) {
    while (n > 0) {
        uint64_t b = addOff / A.blockSize;
        uint32_t intra = (uint32_t)(addOff % A.blockSize);
        if (b >= A.blocks.size()) return -EIO;
        auto raw = GetAddBlock(addSrc, A, b);
        if (!raw || intra > raw->size()) return -EIO;
        size_t avail = raw->size() - intra;
        size_t take  = n < avail ? n : avail;
        std::memcpy(buf, raw->data() + intra, take);
        buf += take; n -= take; addOff += take;
    }
    return 0;
}

ssize_t DeltaByteSource::pread(void *buf, size_t n, uint64_t off) {
    if (off >= TargetSize || Segs.empty()) return 0;
    size_t want = n < (size_t)(TargetSize - off) ? n : (size_t)(TargetSize - off);
    size_t idx = SegAt(Segs, off);

    uint8_t *out = (uint8_t *)buf;
    size_t done = 0;
    uint64_t pos = off;
    while (done < want && idx < Segs.size()) {
        const FlatSeg &s = Segs[idx];
        uint64_t segEnd = s.targetOff + s.len;
        if (pos < s.targetOff || pos >= segEnd) return -EIO;      // gap/ordering guard
        uint64_t reqEnd = off + want;
        size_t chunk = (size_t)((segEnd < reqEnd ? segEnd : reqEnd) - pos);

        if (s.kind == KIND_COPY) {
            uint64_t bsrc = s.srcOff + (pos - s.targetOff);
            size_t got = 0;
            while (got < chunk) {
                ssize_t r = BaseSrc->pread(out + done + got, chunk - got, bsrc + got);
                if (r < 0) return r;
                if (r == 0) return -EIO;
                got += (size_t)r;
            }
        } else {
            uint64_t asrc = s.srcOff + (pos - s.targetOff);
            if (int e = readAdd(s.addSrc, *AddSources[s.addSrc], out + done, chunk, asrc)) return e;
        }
        done += chunk; pos += chunk; ++idx;
    }
    return (ssize_t)done;
}

// =================================================================================================
// GenerateDelta — rolling-hash + greedy-extend matcher
// =================================================================================================

static constexpr uint32_t ANCHOR = 256;    // min match seed; runs >= ~2*ANCHOR are reliably found. 256 (not 1024)
                                           // so the matcher recovers the sub-KB scattered COPYs that per-version
                                           // reobfuscation churn produces — the dominant delta-size lever (~27%).
static constexpr uint64_t RK_R    = 131;

static uint64_t PowR(uint64_t exp) { uint64_t r = 1, b = RK_R; while (exp) { if (exp & 1) r *= b; b *= b; exp >>= 1; } return r; }
static uint64_t HashWin(const uint8_t *p) { uint64_t h = 0; for (uint32_t i = 0; i < ANCHOR; ++i) h = h * RK_R + p[i]; return h; }

// The base index: one entry per ANCHOR-aligned window, the first offset winning per hash — open addressing at ~2/3
// load, 8 bytes a slot: the hash's high half as a check, and the window's number + 1 (0 = empty). An unordered_map
// node per window was ~40 bytes plus its bucket: a 57 GB base's 222 M windows took ~9 GB and OOM-killed the desktop
// on a big jump; this is ~2.7 GB. A check collision drops a window from the index (a match not found: a bigger
// delta, never a wrong one — every candidate is byte-compared before it is used).
class BaseIndex {
public:
    bool Build(const uint8_t *base, size_t len) {
        const uint64_t n = len >= ANCHOR ? (uint64_t)(len - ANCHOR) / ANCHOR + 1 : 0;
        if (n >= UINT32_MAX) return false;                      // > 1 TiB of base: windows no longer fit 32 bits
        Cap = std::max<uint64_t>(16, n + n / 2);
        Slots.assign(Cap, 0);
        for (uint64_t w = 0; w < n; ++w) Insert(HashWin(base + w * ANCHOR), (uint32_t)w);
        return true;
    }
    // The base offset of the first window hashing to h, or -1. A candidate: the caller compares the bytes.
    int64_t Find(uint64_t h) const {
        if (!Cap) return -1;
        const uint32_t Check = (uint32_t)(h >> 32);
        for (uint64_t i = Home(h);; i = i + 1 == Cap ? 0 : i + 1) {
            const uint64_t S = Slots[i];
            if (!S) return -1;
            if ((uint32_t)(S >> 32) == Check) return (int64_t)((S & 0xffffffffu) - 1) * ANCHOR;
        }
    }
private:
    uint64_t Home(uint64_t h) const {
        h ^= h >> 33; h *= 0xff51afd7ed558ccdULL; h ^= h >> 33;  // spread the rolling hash over the table
        return (uint64_t)(((unsigned __int128)h * Cap) >> 64);
    }
    void Insert(uint64_t h, uint32_t w) {
        const uint32_t Check = (uint32_t)(h >> 32);
        for (uint64_t i = Home(h);; i = i + 1 == Cap ? 0 : i + 1) {
            uint64_t &S = Slots[i];
            if (!S) { S = ((uint64_t)Check << 32) | ((uint64_t)w + 1); return; }
            if ((uint32_t)(S >> 32) == Check) return;           // first wins
        }
    }
    std::vector<uint64_t> Slots;
    uint64_t Cap = 0;
};

// One scratch file, removed on every exit path.
struct Scratch {
    std::filesystem::path path;
    ~Scratch() { std::error_code e; if (!path.empty()) std::filesystem::remove(path, e); }
};

// Copies `n` bytes of the file at `from` onto `out`, a buffer at a time.
static bool Append(SpillFile &out, const std::filesystem::path &from, uint64_t n) {
    std::ifstream in(from, std::ios::binary);
    if (!in) return false;
    std::vector<char> buf(size_t(4) << 20);
    while (n) {
        const size_t k = (size_t)std::min<uint64_t>(n, buf.size());
        in.read(buf.data(), (std::streamsize)k);
        if ((size_t)in.gcount() != k || !out.Write(buf.data(), k)) return false;
        n -= k;
    }
    return true;
}

// Compresses the file at `from` (`n` bytes) into `to` as ONE zstd frame (the reader decompresses a table in one
// call), streaming: a block of input and its output resident at a time. Returns the compressed size, or -1.
static int64_t CompressFile(const std::filesystem::path &from, uint64_t n, const std::filesystem::path &to, int level) {
    std::unique_ptr<ZSTD_CCtx, size_t (*)(ZSTD_CCtx *)> c(ZSTD_createCCtx(), ZSTD_freeCCtx);
    if (!c || ZSTD_isError(ZSTD_CCtx_setParameter(c.get(), ZSTD_c_compressionLevel, level))
           || ZSTD_isError(ZSTD_CCtx_setPledgedSrcSize(c.get(), n))) return -1;
    std::ifstream in(from, std::ios::binary);
    SpillFile out;
    if (!in || !out.Open(to)) return -1;
    std::vector<char> ib(ZSTD_CStreamInSize()), ob(ZSTD_CStreamOutSize());
    uint64_t left = n;
    for (;;) {
        const size_t k = (size_t)std::min<uint64_t>(left, ib.size());
        in.read(ib.data(), (std::streamsize)k);
        if ((size_t)in.gcount() != k) return -1;
        left -= k;
        const ZSTD_EndDirective mode = left ? ZSTD_e_continue : ZSTD_e_end;
        ZSTD_inBuffer I{ ib.data(), k, 0 };
        for (bool more = true; more;) {
            ZSTD_outBuffer O{ ob.data(), ob.size(), 0 };
            const size_t r = ZSTD_compressStream2(c.get(), &O, &I, mode);
            if (ZSTD_isError(r) || !out.Write(ob.data(), O.pos)) return -1;
            more = mode == ZSTD_e_end ? r != 0 : I.pos < I.size;
        }
        if (!left) break;
    }
    const uint64_t size = out.Size();
    return out.Close() ? (int64_t)size : -1;
}

bool GenerateDeltaToFile(const uint8_t *base, size_t baseLen, const uint8_t *target, size_t targetLen,
                         const std::string &outPath, std::string &Err, uint32_t blockSize,
                         const std::string &scratchDir, const ProgressFn &progress) {
    if (blockSize == 0) blockSize = DEFAULT_BLOCK;
    //outPath is removed on a failure only once this call opened it: a file already there (the delta it would replace,
    //or a base or target named by mistake) is never taken by a generation that failed before writing.
    bool Opened = false;
    const auto Fail = [&](const std::string &why) { Err = why; std::error_code e; if (Opened) std::filesystem::remove(outPath, e); return false; };

    // Scratch files (see the header): the literal stream, the segment records, then their compressed forms — each
    // written as it is produced, so none is ever resident.
    std::error_code sec;
    const std::filesystem::path scratch =
        scratchDir.empty() ? std::filesystem::temp_directory_path(sec) : std::filesystem::path(scratchDir);
    // Clock alone is not unique: two concurrent generations landing in the same tick shared these files and
    // corrupted each other, and whichever finished first deleted the other's scratch. Mix in the pid and a
    // process-wide counter so concurrent callers cannot collide.
    static std::atomic<uint64_t> ScratchSeq{0};
#ifdef _WIN32
    const uint64_t pid = (uint64_t)::_getpid();
#else
    const uint64_t pid = (uint64_t)::getpid();
#endif
    const auto uniq = std::to_string((uint64_t)std::chrono::steady_clock::now().time_since_epoch().count())
                    + "_" + std::to_string(pid)
                    + "_" + std::to_string(ScratchSeq.fetch_add(1));
    Scratch litPath{ scratch / ("vgdelta_lit_" + uniq + ".tmp") }, cmpPath{ scratch / ("vgdelta_cmp_" + uniq + ".tmp") },
            segPath{ scratch / ("vgdelta_seg_" + uniq + ".tmp") }, segcPath{ scratch / ("vgdelta_segc_" + uniq + ".tmp") };

    SpillFile lit, seg;
    if (!lit.Open(litPath.path) || !seg.Open(segPath.path)) return Fail("cannot write scratch files in " + scratch.string());
    bool spillOk = true;
    uint64_t numSegs = 0;
    // Segment records: kind(1) len(8) srcOff(8) = 17 bytes each.
    auto emitSeg = [&](uint8_t kind, uint64_t len, uint64_t srcOff) {
        uint8_t r[17] = { kind };
        for (int i = 0; i < 8; ++i) { r[1 + i] = (uint8_t)(len >> (8 * i)); r[9 + i] = (uint8_t)(srcOff >> (8 * i)); }
        spillOk = seg.Write(r, sizeof r) && spillOk;
        ++numSegs;
    };
    auto emitAdd = [&](size_t from, size_t to) {
        if (to <= from) return;
        emitSeg(KIND_ADD, (uint64_t)(to - from), lit.Size());
        spillOk = lit.Write(target + from, to - from) && spillOk;
    };

    BaseIndex index;
    if (!index.Build(base, baseLen)) return Fail("the base is over 1 TiB");

    const uint64_t Rhi = PowR(ANCHOR - 1);
    size_t p = 0, litStart = 0;
    // Poll sparsely: `p` advances one byte per miss, so a callback per iteration would cost more than the
    // matching itself. Track the NEXT threshold rather than testing p's alignment — on a near-identical
    // archive p leaps over whole boundaries on every COPY, so an alignment test fires once and never again,
    // freezing the bar and making Cancel unreachable for the entire scan.
    constexpr size_t kPollEvery = 4u << 20;
    size_t nextPoll = 0;
    if (targetLen >= ANCHOR) {
        uint64_t h = HashWin(target);
        while (p + ANCHOR <= targetLen) {
            if (progress && p >= nextPoll) {
                if (!progress(0, (uint64_t)p, (uint64_t)targetLen)) return Fail("cancelled");
                nextPoll = p + kPollEvery;
            }
            bool matched = false;
            if (const int64_t at = index.Find(h); at >= 0) {
                size_t o = (size_t)at;
                if (o + ANCHOR <= baseLen && std::memcmp(base + o, target + p, ANCHOR) == 0) {
                    size_t len = ANCHOR;
                    while (o + len < baseLen && p + len < targetLen && base[o + len] == target[p + len]) ++len;
                    size_t back = 0;
                    while (back < p - litStart && o > back && base[o - 1 - back] == target[p - 1 - back]) ++back;
                    emitAdd(litStart, p - back);
                    emitSeg(KIND_COPY, (uint64_t)(len + back), (uint64_t)(o - back));
                    p += len; litStart = p;
                    matched = true;
                    if (p + ANCHOR <= targetLen) h = HashWin(target + p);
                }
            }
            if (!matched) {
                if (p + ANCHOR < targetLen) h = (h - (uint64_t)target[p] * Rhi) * RK_R + target[p + ANCHOR];
                ++p;
            }
        }
    }
    emitAdd(litStart, targetLen);   // tail literals
    { BaseIndex done; std::swap(index, done); }   // the index is the encoder's one big allocation: free it now

    // ---- serialize ----
    // ADD region: stream the literal file back in blockSize chunks, zstd each, and write the compressed bytes
    // straight to the second scratch file. Only ONE uncompressed block (blockSize) and its compressed form are
    // resident at a time, so this scales to any archive size.
    const uint64_t addTotal = lit.Size(), segBytes = seg.Size();
    if (!lit.Close() || !seg.Close() || !spillOk) return Fail("writing the scratch files failed (disk full?)");
    if (numSegs > UINT32_MAX) return Fail("too many segments");
    std::vector<BlockRec> blocks;
    uint64_t addRegionSize = 0;
    {
        std::ifstream in(litPath.path, std::ios::binary);
        SpillFile out;
        if (!in || !out.Open(cmpPath.path)) return Fail("cannot write scratch files in " + scratch.string());
        std::vector<uint8_t> buf(blockSize);
        for (uint64_t o = 0; o < addTotal; o += blockSize) {
            if (progress && !progress(1, o, addTotal)) return Fail("cancelled");
            const uint32_t ul = (uint32_t)std::min<uint64_t>(blockSize, addTotal - o);
            in.read(reinterpret_cast<char *>(buf.data()), (std::streamsize)ul);
            if ((uint64_t)in.gcount() != ul) return Fail("reading the literals back failed");
            std::vector<uint8_t> c = ZCompress(buf.data(), ul, 19);   // ADD blocks + tables both at 19 (decode
                                                                     // cost is level-independent, so max the ratio)
            if (c.empty()) return Fail("zstd failed");
            blocks.push_back({ addRegionSize, (uint32_t)c.size(), ul });
            if (!out.Write(c.data(), c.size())) return Fail("writing the scratch files failed (disk full?)");
            addRegionSize += c.size();
        }
        if (!out.Close()) return Fail("writing the scratch files failed (disk full?)");
    }
    std::filesystem::remove(litPath.path, sec);   // literals no longer needed — free the space before the output

    const int64_t segComp = CompressFile(segPath.path, segBytes, segcPath.path, 19);
    if (segComp < 0) return Fail("compressing the segment table failed");
    std::filesystem::remove(segPath.path, sec);

    // Block records: compOff(8) compLen(4) uncompLen(4) = 16 bytes each — 16 bytes per 256K of new content.
    std::vector<uint8_t> blkRaw;
    blkRaw.reserve(blocks.size() * 16);
    for (const BlockRec &b : blocks) { put64(blkRaw, b.compOff); put32(blkRaw, b.compLen); put32(blkRaw, b.uncompLen); }
    std::vector<uint8_t> blkComp = ZCompress(blkRaw.data(), blkRaw.size());

    SpillFile out;
    if (!out.Open(outPath)) return Fail("cannot write " + outPath);
    Opened = true;
    std::vector<uint8_t> head;
    head.insert(head.end(), MAGIC, MAGIC + 4);
    put32(head, VERSION);
    put32(head, blockSize);
    put64(head, targetLen);
    put64(head, baseLen);
    put64(head, Fnv1a64(base, baseLen));
    put32(head, (uint32_t)numSegs);
    put32(head, (uint32_t)blocks.size());
    put64(head, (uint64_t)segComp); put64(head, segBytes);
    bool ok = out.Write(head.data(), head.size()) && Append(out, segcPath.path, (uint64_t)segComp);
    head.clear();
    put64(head, blkComp.size()); put64(head, blkRaw.size());
    ok = ok && out.Write(head.data(), head.size()) && out.Write(blkComp.data(), blkComp.size())
            && Append(out, cmpPath.path, addRegionSize);   // the compressed ADD region, straight from its scratch file
    if (!out.Close() || !ok) return Fail("writing " + outPath + " failed (disk full?)");
    return true;
}

std::vector<uint8_t> GenerateDelta(const uint8_t *base, size_t baseLen,
                                   const uint8_t *target, size_t targetLen,
                                   uint32_t blockSize, const std::string &scratchDir,
                                   const ProgressFn &progress) {
    std::error_code sec;
    const std::filesystem::path scratch =
        scratchDir.empty() ? std::filesystem::temp_directory_path(sec) : std::filesystem::path(scratchDir);
    static std::atomic<uint64_t> OutSeq{0};
    Scratch outPath{ scratch / ("vgdelta_out_" + std::to_string((uint64_t)std::chrono::steady_clock::now().time_since_epoch().count())
                                + "_" + std::to_string(OutSeq.fetch_add(1)) + ".tmp") };
    std::string err;
    if (!GenerateDeltaToFile(base, baseLen, target, targetLen, outPath.path.string(), err, blockSize, scratchDir, progress)) return {};
    std::ifstream in(outPath.path, std::ios::binary | std::ios::ate);
    if (!in) return {};
    std::vector<uint8_t> out((size_t)in.tellg());
    in.seekg(0);
    in.read(reinterpret_cast<char *>(out.data()), (std::streamsize)out.size());
    if ((size_t)in.gcount() != out.size()) return {};
    return out;
}

} // namespace vgdelta

bool vgdelta::VerifyDelta(const std::vector<uint8_t> &delta, const std::shared_ptr<ByteSource> &base,
                          ByteSource &target, std::string &Err, const ProgressFn &progress)
{
    return VerifyDelta(std::make_shared<MemByteSource>(delta), base, target, Err, progress);
}

bool vgdelta::VerifyDelta(const std::shared_ptr<ByteSource> &delta, const std::shared_ptr<ByteSource> &base,
                          ByteSource &target, std::string &Err, const ProgressFn &progress)
{
    std::string derr;
    auto ds = DeltaByteSource::Create(delta, base, derr, false);
    if (!ds) { Err = "compose failed: " + derr; return false; }
    const uint64_t N = target.size();
    if (ds->size() != N)
    {
        Err = "size mismatch: reconstructed " + std::to_string(ds->size()) + " vs target " + std::to_string(N);
        return false;
    }
    constexpr size_t CH = size_t(8) << 20;
    std::vector<uint8_t> a(CH), b(CH);
    for (uint64_t off = 0; off < N;)
    {
        //Every 8MiB chunk is already a coarse enough tick for a progress bar, so no threshold bookkeeping here.
        if (progress && !progress(2, off, N)) { Err = "cancelled"; return false; }
        const size_t want = (size_t)std::min<uint64_t>(CH, N - off);
        if (!ds->preadAll(a.data(), want, off))     { Err = "reconstruction read failed at " + std::to_string(off); return false; }
        if (!target.preadAll(b.data(), want, off))  { Err = "target read failed at " + std::to_string(off); return false; }
        if (std::memcmp(a.data(), b.data(), want) != 0) { Err = "byte mismatch in chunk at " + std::to_string(off); return false; }
        off += want;
    }
    //Report the finish. Polling only at the TOP of the loop meant the bar stopped one chunk short of 100%
    //and simply vanished — the operation looked stalled at the moment it succeeded.
    if (progress) (void)progress(2, N, N);
    return true;
}
