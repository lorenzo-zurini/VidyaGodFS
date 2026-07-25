#include "vgdelta.h"

#include <zstd.h>

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <unordered_map>

namespace vgdelta {

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

int DeltaByteSource::readAdd(const AddSource &A, uint8_t *buf, size_t n, uint64_t addOff) {
    while (n > 0) {
        uint64_t b = addOff / A.blockSize;
        uint32_t intra = (uint32_t)(addOff % A.blockSize);
        if (b >= A.blocks.size()) return -EIO;
        const BlockRec &blk = A.blocks[b];
        std::vector<uint8_t> comp(blk.compLen);
        if (blk.compLen && !A.file->preadAll(comp.data(), blk.compLen, A.regionOff + blk.compOff)) return -EIO;
        std::vector<uint8_t> raw = ZDecompress(comp.data(), blk.compLen, blk.uncompLen);
        if (raw.size() != blk.uncompLen || intra > blk.uncompLen) return -EIO;
        size_t avail = blk.uncompLen - intra;
        size_t take  = n < avail ? n : avail;
        std::memcpy(buf, raw.data() + intra, take);
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
            if (int e = readAdd(*AddSources[s.addSrc], out + done, chunk, asrc)) return e;
        }
        done += chunk; pos += chunk; ++idx;
    }
    return (ssize_t)done;
}

// =================================================================================================
// GenerateDelta — rolling-hash + greedy-extend matcher
// =================================================================================================

static constexpr uint32_t ANCHOR = 1024;   // min match seed; runs >= ~2*ANCHOR are reliably found
static constexpr uint64_t RK_R    = 131;

static uint64_t PowR(uint64_t exp) { uint64_t r = 1, b = RK_R; while (exp) { if (exp & 1) r *= b; b *= b; exp >>= 1; } return r; }
static uint64_t HashWin(const uint8_t *p) { uint64_t h = 0; for (uint32_t i = 0; i < ANCHOR; ++i) h = h * RK_R + p[i]; return h; }

std::vector<uint8_t> GenerateDelta(const uint8_t *base, size_t baseLen,
                                   const uint8_t *target, size_t targetLen,
                                   uint32_t blockSize) {
    if (blockSize == 0) blockSize = DEFAULT_BLOCK;

    struct Seg { uint8_t kind; uint64_t len; uint64_t srcOff; };
    std::vector<Seg> segs;
    std::vector<uint8_t> addStream;

    auto emitAdd = [&](size_t from, size_t to) {
        if (to <= from) return;
        segs.push_back({ KIND_ADD, (uint64_t)(to - from), (uint64_t)addStream.size() });
        addStream.insert(addStream.end(), target + from, target + to);
    };

    // Index the base at ANCHOR-aligned windows (first offset wins per hash). u64 offset: bases can be >4 GB.
    std::unordered_map<uint64_t, uint64_t> index;
    if (baseLen >= ANCHOR) {
        index.reserve(baseLen / ANCHOR + 1);
        for (size_t o = 0; o + ANCHOR <= baseLen; o += ANCHOR)
            index.emplace(HashWin(base + o), (uint64_t)o);
    }

    const uint64_t Rhi = PowR(ANCHOR - 1);
    size_t p = 0, litStart = 0;
    if (targetLen >= ANCHOR) {
        uint64_t h = HashWin(target);
        while (p + ANCHOR <= targetLen) {
            bool matched = false;
            auto it = index.find(h);
            if (it != index.end()) {
                size_t o = it->second;
                if (o + ANCHOR <= baseLen && std::memcmp(base + o, target + p, ANCHOR) == 0) {
                    size_t len = ANCHOR;
                    while (o + len < baseLen && p + len < targetLen && base[o + len] == target[p + len]) ++len;
                    size_t back = 0;
                    while (back < p - litStart && o > back && base[o - 1 - back] == target[p - 1 - back]) ++back;
                    emitAdd(litStart, p - back);
                    segs.push_back({ KIND_COPY, (uint64_t)(len + back), (uint64_t)(o - back) });
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

    // ---- serialize ----
    // ADD region: split addStream into blockSize chunks, zstd each.
    std::vector<BlockRec> blocks;
    std::vector<uint8_t>  addRegion;
    for (size_t o = 0; o < addStream.size(); o += blockSize) {
        uint32_t ul = (uint32_t)std::min<size_t>(blockSize, addStream.size() - o);
        std::vector<uint8_t> c = ZCompress(addStream.data() + o, ul, 12);   // ADD blocks: fast level, tables use 19
        blocks.push_back({ (uint64_t)addRegion.size(), (uint32_t)c.size(), ul });
        addRegion.insert(addRegion.end(), c.begin(), c.end());
    }

    // Segment records: kind(1) len(8) srcOff(8) = 17 bytes each.
    std::vector<uint8_t> segRaw;
    segRaw.reserve(segs.size() * 17);
    for (const Seg &s : segs) { segRaw.push_back(s.kind); put64(segRaw, s.len); put64(segRaw, s.srcOff); }
    std::vector<uint8_t> segComp = ZCompress(segRaw.data(), segRaw.size());

    // Block records: compOff(8) compLen(4) uncompLen(4) = 16 bytes each.
    std::vector<uint8_t> blkRaw;
    blkRaw.reserve(blocks.size() * 16);
    for (const BlockRec &b : blocks) { put64(blkRaw, b.compOff); put32(blkRaw, b.compLen); put32(blkRaw, b.uncompLen); }
    std::vector<uint8_t> blkComp = ZCompress(blkRaw.data(), blkRaw.size());

    std::vector<uint8_t> out;
    out.insert(out.end(), MAGIC, MAGIC + 4);
    put32(out, VERSION);
    put32(out, blockSize);
    put64(out, targetLen);
    put64(out, baseLen);
    put64(out, Fnv1a64(base, baseLen));
    put32(out, (uint32_t)segs.size());
    put32(out, (uint32_t)blocks.size());
    put64(out, segComp.size()); put64(out, segRaw.size());
    out.insert(out.end(), segComp.begin(), segComp.end());
    put64(out, blkComp.size()); put64(out, blkRaw.size());
    out.insert(out.end(), blkComp.begin(), blkComp.end());
    out.insert(out.end(), addRegion.begin(), addRegion.end());
    return out;
}

} // namespace vgdelta
