#include "ziplayer.h"
#include "layerspec.h"   // NormalizeVPath

#include <zip.h>
#include <cstring>
#include <cerrno>
#include <algorithm>
#include <sys/stat.h>
#include <iostream>

// ---- little-endian readers -----------------------------------------------

static uint16_t rd16(const uint8_t *p) { return (uint16_t)(p[0] | (p[1] << 8)); }
static uint32_t rd32(const uint8_t *p) { return (uint32_t)(p[0] | (p[1] << 8) | (p[2] << 16) | ((uint32_t)p[3] << 24)); }
static uint64_t rd64(const uint8_t *p) { uint64_t v = 0; for (int i = 7; i >= 0; --i) v = (v << 8) | p[i]; return v; }

// ---- zip central-directory parsing (for STORED data offsets) --------------
// Reads through a ByteSource so a delta-backed archive parses exactly like a plain file.

//Walks the central directory and returns normalized-name → local-header offset (ZIP64-aware).
//Empty on any parse failure (callers then fall back to libzip extraction — no STORED zero-copy).
static std::unordered_map<std::string, uint64_t> ParseCentralDirOffsets(ByteSource &src)
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
        if (!src.preadAll(loc, 20, eocdFileOff - 20) || rd32(loc) != 0x07064b50u) return out;
        uint64_t z64off = rd64(loc + 8);
        uint8_t z64[56];
        if (!src.preadAll(z64, 56, z64off) || rd32(z64) != 0x06064b50u) return out;
        totalEntries = rd64(z64 + 32);
        cdOffset     = rd64(z64 + 48);
    }

    uint64_t pos = cdOffset;
    for (uint64_t i = 0; i < totalEntries; ++i)
    {
        uint8_t rec[46];
        if (!src.preadAll(rec, 46, pos) || rd32(rec) != 0x02014b50u) break;
        uint16_t nameLen  = rd16(rec + 28);
        uint16_t extraLen = rd16(rec + 30);
        uint16_t commLen  = rd16(rec + 32);
        uint32_t compSize32   = rd32(rec + 20);
        uint32_t uncompSize32 = rd32(rec + 24);
        uint64_t lhOffset     = rd32(rec + 42);

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
static uint64_t LocalDataOffset(ByteSource &src, uint64_t lhOffset)
{
    uint8_t lh[30];
    if (!src.preadAll(lh, 30, lhOffset) || rd32(lh) != 0x04034b50u) return UINT64_MAX;
    // The LOCAL header's name/extra lengths (which can differ from the central ones) set where data starts.
    return lhOffset + 30 + rd16(lh + 26) + rd16(lh + 28);
}

// ---- libzip custom source over a ByteSource -------------------------------
// Lets libzip enumerate entries of an archive whose bytes are not a plain file (a delta view). Read-only,
// seekable; the actual STORED data reads still bypass libzip via the manual CD offsets above.

namespace {
struct ZipSrcUD {
    std::shared_ptr<ByteSource> src;
    uint64_t   pos = 0;
    zip_error_t err;
};

zip_int64_t ZipSrcCb(void *ud0, void *data, zip_uint64_t len, zip_source_cmd_t cmd)
{
    auto *ud = static_cast<ZipSrcUD *>(ud0);
    switch (cmd)
    {
        case ZIP_SOURCE_OPEN:  ud->pos = 0; return 0;
        case ZIP_SOURCE_CLOSE: return 0;
        case ZIP_SOURCE_READ: {
            ssize_t r = ud->src->pread(data, (size_t)len, ud->pos);
            if (r < 0) { zip_error_set(&ud->err, ZIP_ER_READ, EIO); return -1; }
            ud->pos += (uint64_t)r;
            return r;
        }
        case ZIP_SOURCE_SEEK: {
            zip_int64_t off = zip_source_seek_compute_offset(ud->pos, ud->src->size(), data, len, &ud->err);
            if (off < 0) return -1;
            ud->pos = (uint64_t)off;
            return 0;
        }
        case ZIP_SOURCE_TELL: return (zip_int64_t)ud->pos;
        case ZIP_SOURCE_STAT: {
            auto *st = static_cast<zip_stat_t *>(data);
            if (len < sizeof(zip_stat_t)) return -1;
            zip_stat_init(st);
            st->size        = ud->src->size();
            st->comp_size   = ud->src->size();
            st->comp_method = ZIP_CM_STORE;
            st->valid       = ZIP_STAT_SIZE | ZIP_STAT_COMP_SIZE | ZIP_STAT_COMP_METHOD;
            return sizeof(zip_stat_t);
        }
        case ZIP_SOURCE_ERROR:    return zip_error_to_data(&ud->err, data, len);
        case ZIP_SOURCE_SUPPORTS: return zip_source_make_command_bitmap(
            ZIP_SOURCE_OPEN, ZIP_SOURCE_READ, ZIP_SOURCE_CLOSE, ZIP_SOURCE_STAT, ZIP_SOURCE_SEEK,
            ZIP_SOURCE_TELL, ZIP_SOURCE_SUPPORTS, ZIP_SOURCE_ERROR, ZIP_SOURCE_FREE, -1);
        case ZIP_SOURCE_FREE:     delete ud; return 0;
        default:                  zip_error_set(&ud->err, ZIP_ER_OPNOTSUPP, 0); return -1;
    }
}
} // namespace

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

std::shared_ptr<ZipIndex> BuildZipIndex(std::shared_ptr<ByteSource> Src, const std::string &Name)
{
    if (!Src) return nullptr;

    zip_error_t ze; zip_error_init(&ze);
    auto *ud = new ZipSrcUD{ Src, 0, {} };
    zip_error_init(&ud->err);
    zip_source_t *zs = zip_source_function_create(ZipSrcCb, ud, &ze);
    if (!zs) { delete ud; std::cerr << "[vidyagodfs] zip_source_create failed for " << Name << "\n"; return nullptr; }

    zip_t *za = zip_open_from_source(zs, ZIP_RDONLY, &ze);
    if (!za)
    {
        std::cerr << "[vidyagodfs] zip_open failed for " << Name << " (" << zip_error_strerror(&ze) << ")\n";
        zip_source_free(zs);   // invokes ZIP_SOURCE_FREE → deletes ud
        return nullptr;
    }

    auto Z = std::make_shared<ZipIndex>();
    Z->archivePath = Name;
    Z->src = Src;

    // Local-header offsets for STORED zero-copy (empty if the CD parse is unavailable).
    auto lhOffsets = ParseCentralDirOffsets(*Src);

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

            // Unix symlink? The mode lives in the high 16 bits of the central-dir external attributes.
            // Check the S_IFLNK bits directly (0170000 mask, 0120000 = symlink) — no POSIX S_ISLNK macro,
            // which doesn't exist on the MinGW/Windows toolchain.
            zip_uint8_t opsys = 0; zip_uint32_t extAttr = 0;
            if (zip_file_get_external_attributes(za, i, 0, &opsys, &extAttr) == 0 &&
                opsys == ZIP_OPSYS_UNIX && (((extAttr >> 16) & 0170000u) == 0120000u))
                e.symlink = true;

            // STORED + unencrypted → resolve the data offset for zero-copy pread.
            bool storeMethod = (st.valid & ZIP_STAT_COMP_METHOD) && st.comp_method == ZIP_CM_STORE;
            bool encrypted   = (st.valid & ZIP_STAT_ENCRYPTION_METHOD) && st.encryption_method != ZIP_EM_NONE;
            if (storeMethod && !encrypted)
            {
                auto it = lhOffsets.find(vrel);
                if (it != lhOffsets.end())
                {
                    uint64_t doff = LocalDataOffset(*Src, it->second);
                    if (doff != UINT64_MAX) { e.stored = true; e.dataOffset = doff; }
                }
            }
            Z->byName[vrel] = e;
        }
        RegisterParents(*Z, vrel);
    }

    zip_close(za);   // frees the source → ZIP_SOURCE_FREE → deletes ud (Z->src keeps the ByteSource alive)
    return Z;
}

// ---- open / read ---------------------------------------------------------

int OpenZipEntry(ZipIndex &Z, const ZipEntry &E, ZipReader &Out)
{
    Out.size = E.size;

    // Only STORED entries are servable — zero-copy through the ByteSource (no materialization).
    if (E.stored)
    {
        Out.stored = true;
        Out.src = Z.src.get();
        Out.dataOffset = E.dataOffset;
        return 0;
    }

    // Compressed entry: unsupported. The app blocks non-STORE zips before mounting (with a re-zip dialog);
    // this only fires if one slips through.
    std::cerr << "[vidyagodfs] refusing compressed zip entry '" << E.name << "' in " << Z.archivePath
              << " — re-zip the package with 'zip -0' (STORE)\n";
    return -EIO;
}

int ReadZipEntry(ZipReader &R, char *Buf, size_t Size, off_t Off)
{
    if (Off < 0) return -EINVAL;
    if (!R.stored || !R.src) return -EIO;
    if ((uint64_t)Off >= R.size) return 0;
    size_t avail = (size_t)(R.size - (uint64_t)Off);
    size_t want = Size < avail ? Size : avail;

    ssize_t got = R.src->pread(Buf, want, R.dataOffset + (uint64_t)Off);
    return (int)got;   // >=0 bytes, or a negative -errno propagated from the ByteSource
}

// ---- symlink flattening --------------------------------------------------

// Joins `base` (a directory path, internal zip name) with a relative `target`, normalizing "." / "..".
// Returns false when the walk escapes the archive root (more ".." than segments).
static bool JoinNormalized(const std::string &base, const std::string &target, std::string &out)
{
    std::vector<std::string> segs;
    auto push = [&](const std::string &p) {
        size_t s = 0;
        while (s <= p.size())
        {
            size_t e = p.find('/', s);
            std::string seg = p.substr(s, e == std::string::npos ? std::string::npos : e - s);
            if (seg == "..") { if (segs.empty()) return false; segs.pop_back(); }
            else if (!seg.empty() && seg != ".") segs.push_back(seg);
            if (e == std::string::npos) break;
            s = e + 1;
        }
        return true;
    };
    if (!push(base) || !push(target)) return false;
    out.clear();
    for (const std::string &s : segs) { if (!out.empty()) out += '/'; out += s; }
    return true;
}

const ZipEntry *ResolveZipSymlink(ZipIndex &Z, const ZipEntry &E)
{
    const ZipEntry *cur = &E;
    for (int hop = 0; hop < 8 && cur->symlink; ++hop)
    {
        // The link target IS the entry content (STORE archives keep it contiguous — plain pread).
        if (!cur->stored || cur->size == 0 || cur->size > 4096) return nullptr;
        std::string tgt(cur->size, '\0');
        if (Z.src->pread(tgt.data(), tgt.size(), cur->dataOffset) != (ssize_t)tgt.size()) return nullptr;
        if (!tgt.empty() && tgt[0] == '/') return nullptr;      // absolute → leaves the archive

        std::string dir = cur->name.substr(0, cur->name.find_last_of('/') == std::string::npos
                                                  ? 0 : cur->name.find_last_of('/'));
        std::string resolved;
        if (!JoinNormalized(dir, tgt, resolved)) return nullptr; // escapes the archive root
        auto it = Z.byName.find(resolved);
        if (it == Z.byName.end()) return nullptr;                // dangling
        cur = &it->second;
    }
    if (cur->symlink || cur->isDir) return nullptr;              // loop guard hit, or a directory target
    return cur;
}
