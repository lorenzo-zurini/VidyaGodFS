#include "zipscan.h"
#include "layerspec.h"   // NormalizeVPath

#include <algorithm>
#include <vector>
#include <ctime>
#include <string>

namespace zipscan {

uint16_t Rd16(const uint8_t *p) { return (uint16_t)(p[0] | (p[1] << 8)); }
uint32_t Rd32(const uint8_t *p) { return (uint32_t)(p[0] | (p[1] << 8) | (p[2] << 16) | ((uint32_t)p[3] << 24)); }
uint64_t Rd64(const uint8_t *p) { uint64_t v = 0; for (int i = 7; i >= 0; --i) v = (v << 8) | p[i]; return v; }

namespace {
// The directory read a window at a time: one read per megabyte of records rather than two per member (a call each,
// and through a delta's view a lookup of its runs each).
struct Window {
    ByteSource &src;
    uint64_t at = 0;
    std::vector<uint8_t> buf;
    bool read(void *dst, size_t n, uint64_t off) {
        if (off < at || off + n > at + buf.size()) {
            const uint64_t left = off < src.size() ? src.size() - off : 0;
            buf.resize((size_t)std::min<uint64_t>(left, std::max<size_t>(n, 1u << 20)));
            at = off;
            if (buf.size() < n || !src.preadAll(buf.data(), buf.size(), off)) { buf.clear(); return false; }
        }
        std::copy_n(buf.data() + (off - at), n, static_cast<uint8_t *>(dst));
        return true;
    }
};
} // namespace

namespace {
uint32_t Crc32(const std::string &S)
{
    uint32_t C = 0xFFFFFFFFu;
    for (unsigned char B : S)
    {
        C ^= B;
        for (int K = 0; K < 8; ++K) C = (C >> 1) ^ (0xEDB88320u & (0u - (C & 1u)));
    }
    return ~C;
}

bool ValidUtf8(const std::string &S)
{
    for (size_t I = 0; I < S.size();)
    {
        const unsigned char C = (unsigned char)S[I];
        const int N = C < 0x80 ? 1 : (C >> 5) == 6 ? 2 : (C >> 4) == 14 ? 3 : (C >> 3) == 30 ? 4 : 0;
        if (!N || I + N > S.size()) return false;
        for (int K = 1; K < N; ++K) if (((unsigned char)S[I + K] >> 6) != 2) return false;
        I += N;
    }
    return true;
}

//CP437 → UTF-8 for bytes 0x80..0xFF (what libzip turns a name neither flagged nor valid UTF-8 into).
std::string Cp437(const std::string &S)
{
    static const uint16_t Hi[128] = {
        0x00C7,0x00FC,0x00E9,0x00E2,0x00E4,0x00E0,0x00E5,0x00E7,0x00EA,0x00EB,0x00E8,0x00EF,0x00EE,0x00EC,0x00C4,0x00C5,
        0x00C9,0x00E6,0x00C6,0x00F4,0x00F6,0x00F2,0x00FB,0x00F9,0x00FF,0x00D6,0x00DC,0x00A2,0x00A3,0x00A5,0x20A7,0x0192,
        0x00E1,0x00ED,0x00F3,0x00FA,0x00F1,0x00D1,0x00AA,0x00BA,0x00BF,0x2310,0x00AC,0x00BD,0x00BC,0x00A1,0x00AB,0x00BB,
        0x2591,0x2592,0x2593,0x2502,0x2524,0x2561,0x2562,0x2556,0x2555,0x2563,0x2551,0x2557,0x255D,0x255C,0x255B,0x2510,
        0x2514,0x2534,0x252C,0x251C,0x2500,0x253C,0x255E,0x255F,0x255A,0x2554,0x2569,0x2566,0x2560,0x2550,0x256C,0x2567,
        0x2568,0x2564,0x2565,0x2559,0x2558,0x2552,0x2553,0x256B,0x256A,0x2518,0x250C,0x2588,0x2584,0x258C,0x2590,0x2580,
        0x03B1,0x00DF,0x0393,0x03C0,0x03A3,0x03C3,0x00B5,0x03C4,0x03A6,0x0398,0x03A9,0x03B4,0x221E,0x03C6,0x03B5,0x2229,
        0x2261,0x00B1,0x2265,0x2264,0x2320,0x2321,0x00F7,0x2248,0x00B0,0x2219,0x00B7,0x221A,0x207F,0x00B2,0x25A0,0x00A0 };
    std::string Out;
    for (unsigned char B : S)
    {
        if (B < 0x80) { Out += (char)B; continue; }
        const uint16_t U = Hi[B - 0x80];
        if (U < 0x800) { Out += (char)(0xC0 | (U >> 6)); Out += (char)(0x80 | (U & 0x3F)); }
        else { Out += (char)(0xE0 | (U >> 12)); Out += (char)(0x80 | ((U >> 6) & 0x3F)); Out += (char)(0x80 | (U & 0x3F)); }
    }
    return Out;
}

time_t DosTime(uint16_t T, uint16_t D)
{
    struct tm Tm {};
    Tm.tm_isdst = -1;
    Tm.tm_year = ((D >> 9) & 127) + 1980 - 1900;
    Tm.tm_mon  = ((D >> 5) & 15) - 1;
    Tm.tm_mday = D & 31;
    Tm.tm_hour = (T >> 11) & 31;
    Tm.tm_min  = (T >> 5) & 63;
    Tm.tm_sec  = (T << 1) & 62;
    return mktime(&Tm);
}
} // namespace

bool WalkCentralDirFull(ByteSource &src, const FullCb &cb)
{
    uint64_t fsize = src.size();
    if (fsize < 22) return false;

    // Locate the End Of Central Directory by scanning the tail for its signature.
    uint64_t tail = std::min<uint64_t>(fsize, 22 + 65535);
    std::vector<uint8_t> buf(tail);
    if (!src.preadAll(buf.data(), tail, fsize - tail)) return false;
    long eocd = -1;
    for (long i = (long)tail - 22; i >= 0; --i)
        if (Rd32(&buf[i]) == 0x06054b50u) { eocd = i; break; }
    if (eocd < 0) return false;

    const uint8_t *E = &buf[eocd];
    uint64_t totalEntries = Rd16(E + 10);
    uint64_t cdSize       = Rd32(E + 12);
    uint64_t cdOffset     = Rd32(E + 16);
    uint64_t eocdFileOff  = fsize - tail + (uint64_t)eocd;

    // ZIP64: the 32-bit fields are sentinels (>4 GB archive). Follow the locator → ZIP64 EOCD.
    if (cdOffset == 0xFFFFFFFFu || totalEntries == 0xFFFFu || cdSize == 0xFFFFFFFFu)
    {
        if (eocdFileOff < 20) return false;
        uint8_t loc[20];
        if (!src.preadAll(loc, 20, eocdFileOff - 20) || Rd32(loc) != 0x07064b50u) return false;
        uint64_t z64off = Rd64(loc + 8);
        uint8_t z64[56];
        if (!src.preadAll(z64, 56, z64off) || Rd32(z64) != 0x06064b50u) return false;
        totalEntries = Rd64(z64 + 32);
        cdSize       = Rd64(z64 + 40);
        cdOffset     = Rd64(z64 + 48);
    }
    //The whole directory asked for at once: through a delta its records are scattered over the base, and the first
    //read of each would wait in turn.
    if (cdOffset < fsize) src.prefetch(cdOffset, std::min<uint64_t>(cdSize, fsize - cdOffset));

    Window cd{ src, 0, {} };
    uint64_t pos = cdOffset;
    for (uint64_t i = 0; i < totalEntries; ++i)
    {
        uint8_t rec[46];
        if (!cd.read(rec, 46, pos) || Rd32(rec) != 0x02014b50u) return false;
        CdEntry Ent;
        Ent.index = i;
        Ent.madeBy  = Rd16(rec + 4);
        Ent.flags   = Rd16(rec + 8);
        Ent.method  = Rd16(rec + 10);
        const uint16_t dosTime = Rd16(rec + 12), dosDate = Rd16(rec + 14);
        uint16_t nameLen  = Rd16(rec + 28);
        uint16_t extraLen = Rd16(rec + 30);
        uint16_t commLen  = Rd16(rec + 32);
        uint32_t compSize32   = Rd32(rec + 20);
        uint32_t uncompSize32 = Rd32(rec + 24);
        Ent.extAttr  = Rd32(rec + 38);
        Ent.compSize = compSize32; Ent.uncompSize = uncompSize32;
        Ent.lhOffset = Rd32(rec + 42);
        Ent.mtime = DosTime(dosTime, dosDate);

        Ent.rawName.resize(nameLen);
        if (nameLen && !cd.read(Ent.rawName.data(), nameLen, pos + 46)) return false;
        std::string unicodePath;

        std::vector<uint8_t> extra(extraLen);
        if (extraLen && cd.read(extra.data(), extraLen, pos + 46 + nameLen))
        {
            size_t e = 0;
            while (e + 4 <= (size_t)extraLen)
            {
                uint16_t id = Rd16(&extra[e]); uint16_t sz = Rd16(&extra[e + 2]);
                if (e + 4 + sz > (size_t)extraLen) break;
                const size_t f0 = e + 4, end = e + 4 + sz;
                if (id == 0x0001) // ZIP64 extended info: present fields appear in order for each sentinel
                {
                    size_t f = f0;
                    if (uncompSize32 == 0xFFFFFFFFu && f + 8 <= end) { Ent.uncompSize = Rd64(&extra[f]); f += 8; }
                    if (compSize32   == 0xFFFFFFFFu && f + 8 <= end) { Ent.compSize   = Rd64(&extra[f]); f += 8; }
                    if (Ent.lhOffset == 0xFFFFFFFFu && f + 8 <= end) Ent.lhOffset = Rd64(&extra[f]);
                }
                else if (id == 0x7075 && sz >= 5 && extra[f0] == 1 && Rd32(&extra[f0 + 1]) == Crc32(Ent.rawName))
                    unicodePath.assign((const char *)&extra[f0 + 5], sz - 5);   // Info-ZIP Unicode path, for this name
                e += 4 + sz;
            }
        }
        if (!unicodePath.empty() && !(Ent.flags & 0x800) && ValidUtf8(unicodePath)) Ent.utf8Name = unicodePath;
        else if ((Ent.flags & 0x800) || ValidUtf8(Ent.rawName)) Ent.utf8Name = Ent.rawName;
        else Ent.utf8Name = Cp437(Ent.rawName);

        if (!cb(Ent)) return true; // caller stopped
        pos += 46u + nameLen + extraLen + commLen;
    }
    //Walked as many records as the end record counts: they fill the directory exactly, or the count is wrong (a writer
    //that wrapped it past 65,535 without ZIP64) — the walk would leave members out, unseen. libzip decides then.
    if (pos - cdOffset != cdSize) return false;
    return true;
}

bool WalkCentralDir(ByteSource &src, const EntryCb &cb)
{
    return WalkCentralDirFull(src, [&](const CdEntry &E) { return cb(E.rawName, E.method, E.lhOffset); });
}

std::unordered_map<std::string, uint64_t> CentralDirOffsets(ByteSource &src)
{
    std::unordered_map<std::string, uint64_t> out;
    WalkCentralDir(src, [&](const std::string &raw, uint16_t, uint64_t lhOffset) {
        const std::string vrel = CleanMemberName(raw);   // the name the mount serves it by
        if (!vrel.empty()) out[vrel] = lhOffset;
        return true;
    });
    return out;
}

std::string FirstCompressedEntry(ByteSource &src)
{
    std::string result;
    WalkCentralDir(src, [&](const std::string &raw, uint16_t method, uint64_t) {
        if (method == 0) return true;                       // STORE — keep walking
        result = raw.empty() ? "(entry)" : raw;
        return false;                                       // found one — stop
    });
    return result;
}

uint64_t LocalDataOffset(ByteSource &src, uint64_t lhOffset)
{
    uint8_t lh[30];
    if (!src.preadAll(lh, 30, lhOffset) || Rd32(lh) != 0x04034b50u) return UINT64_MAX;
    // The LOCAL header's name/extra lengths (which can differ from the central ones) set where data starts.
    return lhOffset + 30 + Rd16(lh + 26) + Rd16(lh + 28);
}

} // namespace zipscan
