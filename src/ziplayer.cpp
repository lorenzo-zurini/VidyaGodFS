#include "ziplayer.h"
#include "layerspec.h"   // NormalizeVPath

#include <cstring>
#include <cerrno>
#include <algorithm>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <iostream>

ZipIndex::~ZipIndex()
{
    if (archive) zip_close(archive);
    if (rawFd >= 0) ::close(rawFd);
}

// ---- little-endian readers + pread helper --------------------------------

static uint16_t rd16(const uint8_t *p) { return (uint16_t)(p[0] | (p[1] << 8)); }
static uint32_t rd32(const uint8_t *p) { return (uint32_t)(p[0] | (p[1] << 8) | (p[2] << 16) | ((uint32_t)p[3] << 24)); }
static uint64_t rd64(const uint8_t *p) { uint64_t v = 0; for (int i = 7; i >= 0; --i) v = (v << 8) | p[i]; return v; }

static bool PreadAll(int fd, void *buf, size_t n, uint64_t off)
{
    uint8_t *p = (uint8_t *)buf; size_t done = 0;
    while (done < n) { ssize_t r = ::pread(fd, p + done, n - done, (off_t)(off + done)); if (r <= 0) return false; done += (size_t)r; }
    return true;
}

// ---- zip central-directory parsing (for STORED data offsets) --------------

//Walks the central directory and returns normalized-name → local-header offset (ZIP64-aware).
//Empty on any parse failure (callers then fall back to libzip extraction — no STORED zero-copy).
static std::unordered_map<std::string, uint64_t> ParseCentralDirOffsets(int fd)
{
    std::unordered_map<std::string, uint64_t> out;
    struct stat stt; if (::fstat(fd, &stt) != 0) return out;
    uint64_t fsize = (uint64_t)stt.st_size;
    if (fsize < 22) return out;

    // Locate the End Of Central Directory by scanning the tail for its signature.
    uint64_t tail = std::min<uint64_t>(fsize, 22 + 65535);
    std::vector<uint8_t> buf(tail);
    if (!PreadAll(fd, buf.data(), tail, fsize - tail)) return out;
    long eocd = -1;
    for (long i = (long)tail - 22; i >= 0; --i)
        if (rd32(&buf[i]) == 0x06054b50u) { eocd = i; break; }
    if (eocd < 0) return out;

    const uint8_t *E = &buf[eocd];
    uint64_t totalEntries = rd16(E + 10);
    uint64_t cdOffset     = rd32(E + 16);
    uint64_t eocdFileOff  = fsize - tail + (uint64_t)eocd;

    // ZIP64: the 32-bit fields are sentinels (>4 GB archive). Follow the locator → ZIP64 EOCD.
    if (cdOffset == 0xFFFFFFFFu || totalEntries == 0xFFFFu)
    {
        if (eocdFileOff < 20) return out;
        uint8_t loc[20];
        if (!PreadAll(fd, loc, 20, eocdFileOff - 20) || rd32(loc) != 0x07064b50u) return out;
        uint64_t z64off = rd64(loc + 8);
        uint8_t z64[56];
        if (!PreadAll(fd, z64, 56, z64off) || rd32(z64) != 0x06064b50u) return out;
        totalEntries = rd64(z64 + 32);
        cdOffset     = rd64(z64 + 48);
    }

    uint64_t pos = cdOffset;
    for (uint64_t i = 0; i < totalEntries; ++i)
    {
        uint8_t rec[46];
        if (!PreadAll(fd, rec, 46, pos) || rd32(rec) != 0x02014b50u) break;
        uint16_t nameLen  = rd16(rec + 28);
        uint16_t extraLen = rd16(rec + 30);
        uint16_t commLen  = rd16(rec + 32);
        uint16_t diskStart16  = rd16(rec + 34);
        uint32_t compSize32   = rd32(rec + 20);
        uint32_t uncompSize32 = rd32(rec + 24);
        uint64_t lhOffset     = rd32(rec + 42);

        std::vector<uint8_t> name(nameLen);
        if (nameLen && !PreadAll(fd, name.data(), nameLen, pos + 46)) break;

        // Pull the 64-bit local-header offset from the ZIP64 extra when the 32-bit field is a sentinel.
        if (lhOffset == 0xFFFFFFFFu)
        {
            std::vector<uint8_t> extra(extraLen);
            if (extraLen && PreadAll(fd, extra.data(), extraLen, pos + 46 + nameLen))
            {
                size_t e = 0;
                while (e + 4 <= (size_t)extraLen)
                {
                    uint16_t id = rd16(&extra[e]); uint16_t sz = rd16(&extra[e + 2]);
                    if (e + 4 + sz > (size_t)extraLen) break;
                    if (id == 0x0001) // ZIP64 extended info: present fields appear in order for each sentinel
                    {
                        size_t f = e + 4, end = e + 4 + sz;
                        if (uncompSize32 == 0xFFFFFFFFu && f + 8 <= end) f += 8;
                        if (compSize32   == 0xFFFFFFFFu && f + 8 <= end) f += 8;
                        if (f + 8 <= end) lhOffset = rd64(&extra[f]);
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

//Returns the absolute data offset of the entry whose local header is at lhOffset, or UINT64_MAX.
static uint64_t LocalDataOffset(int fd, uint64_t lhOffset)
{
    uint8_t lh[30];
    if (!PreadAll(fd, lh, 30, lhOffset) || rd32(lh) != 0x04034b50u) return UINT64_MAX;
    // The LOCAL header's name/extra lengths (which can differ from the central ones) set where data starts.
    return lhOffset + 30 + rd16(lh + 26) + rd16(lh + 28);
}

// ---- index ---------------------------------------------------------------

static void RegisterParents(ZipIndex &Z, const std::string &vrel)
{
    std::string cur = vrel;
    while (true)
    {
        size_t slash = cur.find_last_of('/');
        std::string parent = (slash == std::string::npos) ? std::string() : cur.substr(0, slash);
        std::string child  = (slash == std::string::npos) ? cur : cur.substr(slash + 1);
        if (child.empty()) break;
        Z.dirChildren[parent].insert(child);
        if (parent.empty()) break;
        cur = parent;
    }
}

std::shared_ptr<ZipIndex> BuildZipIndex(const std::string &ArchivePath)
{
    int err = 0;
    zip_t *za = zip_open(ArchivePath.c_str(), ZIP_RDONLY, &err);
    if (!za)
    {
        std::cerr << "[vidyagodfs] zip_open failed for " << ArchivePath << " (err " << err << ")\n";
        return nullptr;
    }

    auto Z = std::make_shared<ZipIndex>();
    Z->archivePath = ArchivePath;
    Z->archive = za;
    Z->rawFd = ::open(ArchivePath.c_str(), O_RDONLY);

    // Local-header offsets for STORED zero-copy (empty if the raw fd or CD parse is unavailable).
    auto lhOffsets = (Z->rawFd >= 0) ? ParseCentralDirOffsets(Z->rawFd)
                                     : std::unordered_map<std::string, uint64_t>();

    zip_int64_t n = zip_get_num_entries(za, 0);
    for (zip_int64_t i = 0; i < n; ++i)
    {
        zip_stat_t st;
        zip_stat_init(&st);
        if (zip_stat_index(za, i, 0, &st) != 0) continue;
        if (!(st.valid & ZIP_STAT_NAME) || st.name == nullptr) continue;

        std::string raw = st.name;
        bool isDir = (!raw.empty() && raw.back() == '/');
        std::string vrel = NormalizeVPath(raw);
        if (vrel.empty()) continue; // skip a root entry

        ZipEntry e; e.name = vrel; e.index = (uint64_t)i; e.isDir = isDir;
        if (st.valid & ZIP_STAT_MTIME) e.mtime = st.mtime;

        if (isDir)
        {
            Z->byName[vrel] = e;
            Z->dirChildren.try_emplace(vrel);
        }
        else
        {
            if (st.valid & ZIP_STAT_SIZE) e.size = st.size;

            // STORED + unencrypted → resolve the data offset for zero-copy pread.
            bool storeMethod = (st.valid & ZIP_STAT_COMP_METHOD) && st.comp_method == ZIP_CM_STORE;
            bool encrypted   = (st.valid & ZIP_STAT_ENCRYPTION_METHOD) && st.encryption_method != ZIP_EM_NONE;
            if (storeMethod && !encrypted && Z->rawFd >= 0)
            {
                auto it = lhOffsets.find(vrel);
                if (it != lhOffsets.end())
                {
                    uint64_t doff = LocalDataOffset(Z->rawFd, it->second);
                    if (doff != UINT64_MAX) { e.stored = true; e.dataOffset = doff; }
                }
            }
            Z->byName[vrel] = e;
        }
        RegisterParents(*Z, vrel);
    }
    return Z;
}

// ---- open / read ---------------------------------------------------------

int OpenZipEntry(ZipIndex &Z, const ZipEntry &E, ZipReader &Out)
{
    Out.size = E.size;

    // Only STORED entries are servable — zero-copy pread directly on the archive (no materialization).
    if (E.stored)
    {
        Out.stored = true;
        Out.storedFd = Z.rawFd;
        Out.dataOffset = E.dataOffset;
        return 0;
    }

    // Compressed entry: unsupported. The app blocks non-STORE zips before mounting (with a re-zip
    // dialog); this only fires if one slips through.
    std::cerr << "[vidyagodfs] refusing compressed zip entry '" << E.name << "' in " << Z.archivePath
              << " — re-zip the package with 'zip -0' (STORE)\n";
    return -EIO;
}

int ReadZipEntry(ZipReader &R, char *Buf, size_t Size, off_t Off)
{
    if (Off < 0) return -EINVAL;
    if (!R.stored) return -EIO;
    if ((uint64_t)Off >= R.size) return 0;
    size_t avail = (size_t)(R.size - (uint64_t)Off);
    size_t want = Size < avail ? Size : avail;

    ssize_t got = ::pread(R.storedFd, Buf, want, (off_t)(R.dataOffset + (uint64_t)Off));
    return got < 0 ? -errno : (int)got;
}
