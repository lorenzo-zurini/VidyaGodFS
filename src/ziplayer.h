#ifndef VIDYAGODFS_ZIPLAYER_H
#define VIDYAGODFS_ZIPLAYER_H

#include "bytesource.h"

#include <string>
#include <unordered_map>
#include <set>
#include <memory>
#include <cstdint>
#include <ctime>

//One file entry inside a zip layer, captured at index time.
struct ZipEntry {
    std::string name;            // normalized, no leading/trailing '/'
    uint64_t    index = 0;       // zip entry index (index-time only)
    uint64_t    size = 0;        // uncompressed size
    time_t      mtime = 0;
    bool        isDir = false;
    // A Unix symlink entry (S_IFLNK in the central-directory external attrs). Its content IS the link
    // target string, so getattr reports S_IFLNK and readlink reads `size` bytes of content.
    bool        symlink = false;
    // STORED (uncompressed, unencrypted) entries are served zero-copy: their bytes sit contiguously in the
    // archive after their local header, so reads are a direct ByteSource::pread (no decompression, no
    // materialization). Where the bytes start is read from that header when the entry is first used
    // (ZipDataOffset), not when the archive is indexed: a mount reads the central directory only — one read per
    // member was minutes on a disk that seeks, for an archive of thousands (or a delta's view of one).
    bool        stored = false;
    uint64_t    localHeader = 0;               // offset of the entry's local header within the archive stream
    mutable uint64_t dataOffset = UINT64_MAX;  // learned on first use; UINT64_MAX = not yet
    // A link's resolution (ResolveZipSymlink), learned on its first lookup: null = not yet, the marker
    // kNoZipTarget = no file inside the archive, else that file's entry.
    mutable const ZipEntry *linkTo = nullptr;
};

//A whole zip archive indexed for the FS lifetime, read through a ByteSource — so the archive bytes may be a
//plain file (FdByteSource) OR a binary delta over the layer below (DeltaByteSource), transparently. Only
//STORED entries are servable; they are read zero-copy via `src->pread` at ZipEntry::dataOffset. Compressed
//(DEFLATE/etc.) entries are NOT served: package layers must be `zip -0` (STORE). The app validates this
//before mounting (ContainerWrapper) and shows a re-zip dialog; this is the fallback.
struct ZipIndex {
    std::string                 archivePath;  // for diagnostics only
    std::shared_ptr<ByteSource> src;          // the archive byte stream (file or delta view)
    std::unordered_map<std::string, ZipEntry>              byName;      // files + explicit dir entries
    std::unordered_map<std::string, std::set<std::string>> dirChildren; // parent vrel → child segment names
};

//What a link that leads to no file inside its archive resolves to, once worked out (ZipEntry::linkTo).
extern const ZipEntry kNoZipTarget;

//Indexes every entry of the zip served by `Src` (synthesizing missing parent dirs). `Name` is used only for
//diagnostics. nullptr on failure.
std::shared_ptr<ZipIndex> BuildZipIndex(std::shared_ptr<ByteSource> Src, const std::string &Name);

//Per-open reader for a STORED entry — serves reads via `src->pread` (the shared ZipIndex::src, borrowed —
//NOT owned). There is no materialization (no memory buffer, no temp file).
struct ZipReader {
    bool        stored = false;
    ByteSource *src    = nullptr;  // borrowed (ZipIndex::src.get())
    uint64_t    dataOffset = 0;
    uint64_t    size = 0;
};

//Where a STORED entry's bytes start, from its local header (read once, then remembered); UINT64_MAX when the entry
//is not stored or its header does not read. Safe to call concurrently.
uint64_t ZipDataOffset(const ZipIndex &Z, const ZipEntry &E);

//Prepares Out to serve entry E. STORED → zero-copy reader. A compressed entry returns -EIO (the app blocks
//non-STORE zips up front; this guards the fallback path).
int OpenZipEntry(ZipIndex &Z, const ZipEntry &E, ZipReader &Out);

//Symlink flattening: chases a symlink entry to its final NON-symlink target WITHIN the same archive
//(targets resolve against the entry's own directory, using the zip's INTERNAL names — i.e. the tree as
//authored, before any submount re-rooting; that is the namespace the links were written for). Returns the
//final entry, or nullptr when the chain leaves the archive (e.g. "-> /"), targets a directory, dangles, or
//exceeds the hop limit — callers then serve the link itself, as stored. A link either becomes its target file
//(it was authored for the archive's own tree) or stays the link it is. Worked out once per link (a prefix's links
//are looked up over and over); a link whose bytes did not read is tried again next time.
const ZipEntry *ResolveZipSymlink(ZipIndex &Z, const ZipEntry &E);

//Serves a read from an opened ZipReader. Returns bytes read (>=0) or -errno.
int ReadZipEntry(ZipReader &R, char *Buf, size_t Size, off_t Off);

#endif // VIDYAGODFS_ZIPLAYER_H
