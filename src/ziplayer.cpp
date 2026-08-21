#include "ziplayer.h"
#include "layerspec.h"   // NormalizeVPath
#include "zipscan.h"     // CentralDirOffsets / LocalDataOffset (the shared ZIP64 CD walker)

#include <zip.h>
#include <cstring>
#include <cerrno>
#include <algorithm>
#include <sys/stat.h>
#include <iostream>

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
    auto lhOffsets = zipscan::CentralDirOffsets(*Src);

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
                    uint64_t doff = zipscan::LocalDataOffset(*Src, it->second);
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
