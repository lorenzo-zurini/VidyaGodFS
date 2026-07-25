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
    // archive at `dataOffset`, so reads are a direct ByteSource::pread (no decompression, no materialization).
    bool        stored = false;
    uint64_t    dataOffset = 0;  // absolute byte offset of the entry data within the archive stream
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

//Prepares Out to serve entry E. STORED → zero-copy reader. A compressed entry returns -EIO (the app blocks
//non-STORE zips up front; this guards the fallback path).
int OpenZipEntry(ZipIndex &Z, const ZipEntry &E, ZipReader &Out);

//Serves a read from an opened ZipReader. Returns bytes read (>=0) or -errno.
int ReadZipEntry(ZipReader &R, char *Buf, size_t Size, off_t Off);

#endif // VIDYAGODFS_ZIPLAYER_H
