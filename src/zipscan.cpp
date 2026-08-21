#include "zipscan.h"
#include "layerspec.h"   // NormalizeVPath

#include <algorithm>
#include <vector>

namespace zipscan {

uint16_t Rd16(const uint8_t *p) { return (uint16_t)(p[0] | (p[1] << 8)); }
uint32_t Rd32(const uint8_t *p) { return (uint32_t)(p[0] | (p[1] << 8) | (p[2] << 16) | ((uint32_t)p[3] << 24)); }
uint64_t Rd64(const uint8_t *p) { uint64_t v = 0; for (int i = 7; i >= 0; --i) v = (v << 8) | p[i]; return v; }

std::unordered_map<std::string, uint64_t> CentralDirOffsets(ByteSource &src)
{
    std::unordered_map<std::string, uint64_t> out;
    uint64_t fsize = src.size();
    if (fsize < 22) return out;

    // Locate the End Of Central Directory by scanning the tail for its signature.
    uint64_t tail = std::min<uint64_t>(fsize, 22 + 65535);
    std::vector<uint8_t> buf(tail);
    if (!src.preadAll(buf.data(), tail, fsize - tail)) return out;
    long eocd = -1;
    for (long i = (long)tail - 22; i >= 0; --i)
        if (Rd32(&buf[i]) == 0x06054b50u) { eocd = i; break; }
    if (eocd < 0) return out;

    const uint8_t *E = &buf[eocd];
    uint64_t totalEntries = Rd16(E + 10);
    uint64_t cdOffset     = Rd32(E + 16);
    uint64_t eocdFileOff  = fsize - tail + (uint64_t)eocd;

    // ZIP64: the 32-bit fields are sentinels (>4 GB archive). Follow the locator → ZIP64 EOCD.
    if (cdOffset == 0xFFFFFFFFu || totalEntries == 0xFFFFu)
    {
        if (eocdFileOff < 20) return out;
        uint8_t loc[20];
        if (!src.preadAll(loc, 20, eocdFileOff - 20) || Rd32(loc) != 0x07064b50u) return out;
        uint64_t z64off = Rd64(loc + 8);
        uint8_t z64[56];
        if (!src.preadAll(z64, 56, z64off) || Rd32(z64) != 0x06064b50u) return out;
        totalEntries = Rd64(z64 + 32);
        cdOffset     = Rd64(z64 + 48);
    }

    uint64_t pos = cdOffset;
    for (uint64_t i = 0; i < totalEntries; ++i)
    {
        uint8_t rec[46];
        if (!src.preadAll(rec, 46, pos) || Rd32(rec) != 0x02014b50u) break;
        uint16_t nameLen  = Rd16(rec + 28);
        uint16_t extraLen = Rd16(rec + 30);
        uint16_t commLen  = Rd16(rec + 32);
        uint32_t compSize32   = Rd32(rec + 20);
        uint32_t uncompSize32 = Rd32(rec + 24);
        uint64_t lhOffset     = Rd32(rec + 42);

        std::vector<uint8_t> name(nameLen);
        if (nameLen && !src.preadAll(name.data(), nameLen, pos + 46)) break;

        // Pull the 64-bit local-header offset from the ZIP64 extra when the 32-bit field is a sentinel.
        if (lhOffset == 0xFFFFFFFFu)
        {
            std::vector<uint8_t> extra(extraLen);
            if (extraLen && src.preadAll(extra.data(), extraLen, pos + 46 + nameLen))
            {
                size_t e = 0;
                while (e + 4 <= (size_t)extraLen)
                {
                    uint16_t id = Rd16(&extra[e]); uint16_t sz = Rd16(&extra[e + 2]);
                    if (e + 4 + sz > (size_t)extraLen) break;
                    if (id == 0x0001) // ZIP64 extended info: present fields appear in order for each sentinel
                    {
                        size_t f = e + 4, end = e + 4 + sz;
                        if (uncompSize32 == 0xFFFFFFFFu && f + 8 <= end) f += 8;
                        if (compSize32   == 0xFFFFFFFFu && f + 8 <= end) f += 8;
                        if (f + 8 <= end) lhOffset = Rd64(&extra[f]);
                        break;
                    }
                    e += 4 + sz;
                }
            }
        }

        std::string vrel = NormalizeVPath(std::string((const char *)name.data(), nameLen));
        if (!vrel.empty()) out[vrel] = lhOffset;
        pos += 46u + nameLen + extraLen + commLen;
    }
    return out;
}

uint64_t LocalDataOffset(ByteSource &src, uint64_t lhOffset)
{
    uint8_t lh[30];
    if (!src.preadAll(lh, 30, lhOffset) || Rd32(lh) != 0x04034b50u) return UINT64_MAX;
    // The LOCAL header's name/extra lengths (which can differ from the central ones) set where data starts.
    return lhOffset + 30 + Rd16(lh + 26) + Rd16(lh + 28);
}

} // namespace zipscan
