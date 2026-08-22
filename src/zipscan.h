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
