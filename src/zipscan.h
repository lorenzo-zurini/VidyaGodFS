#ifndef VIDYAGODFS_ZIPSCAN_H
#define VIDYAGODFS_ZIPSCAN_H

#include "bytesource.h"

#include <cstdint>
#include <functional>
#include <string>
#include <unordered_map>

// Hand-rolled ZIP64-aware central-directory walker, shared between the FS (STORED zero-copy offsets)
// and the parent app (STORE-validation / first-compressed-entry check). Reads through a ByteSource so a
// delta-backed archive parses exactly like a plain file. This is the single authoritative zip-CD parser;
// the parent links this TU (see the parent CMake) instead of keeping its own near-identical copy.
namespace zipscan {

// Little-endian readers (also useful to callers doing their own record parsing).
uint16_t Rd16(const uint8_t *p);
uint32_t Rd32(const uint8_t *p);
uint64_t Rd64(const uint8_t *p);

// The one central-directory walk everything else wraps: invokes cb(rawName, compressionMethod,
// localHeaderOffset) per record (lhOffset already ZIP64-resolved); cb returning false stops the walk.
// Returns false when the archive can't be parsed as a zip at all.
using EntryCb = std::function<bool(const std::string &, uint16_t, uint64_t)>;
bool WalkCentralDir(ByteSource &src, const EntryCb &cb);

// Everything one central-directory record says about its member (ZIP64 sizes and offset resolved): what a mount's
// index is built from, in the one walk — libzip's own read of the directory made two small reads per member, and the
// index then walked it again for the offsets.
struct CdEntry {
    std::string rawName;               // as stored
    std::string utf8Name;              // as libzip names it: the Unicode path extra, else UTF-8 as is, else CP437
    uint16_t    method = 0, flags = 0, madeBy = 0;
    uint32_t    extAttr = 0;
    uint64_t    compSize = 0, uncompSize = 0, lhOffset = 0, index = 0;
    time_t      mtime = 0;             // as libzip gives it: the DOS time, in local time (an extended timestamp unread)
};
using FullCb = std::function<bool(const CdEntry &)>;
// The walk, every record whole. The directory is asked for at once first (a read hint), then read a window at a time.
bool WalkCentralDirFull(ByteSource &src, const FullCb &cb);

// Walks the central directory → normalized-name → local-header offset (ZIP64-aware).
// Empty on any parse failure (callers fall back to libzip — no STORED zero-copy).
std::unordered_map<std::string, uint64_t> CentralDirOffsets(ByteSource &src);

// Name of the first COMPRESSED (non-STORE) entry, or "" when every entry is STORED (or unparseable).
// The app uses this to block compressed zip layers before mounting (zero-copy serving requires STORE).
std::string FirstCompressedEntry(ByteSource &src);

// Absolute data offset of the entry whose local header is at lhOffset, or UINT64_MAX on a bad header.
uint64_t LocalDataOffset(ByteSource &src, uint64_t lhOffset);

} // namespace zipscan

#endif // VIDYAGODFS_ZIPSCAN_H
