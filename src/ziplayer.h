#ifndef VIDYAGODFS_ZIPLAYER_H
#define VIDYAGODFS_ZIPLAYER_H

#include <string>
#include <vector>
#include <unordered_map>
#include <set>
#include <memory>
#include <mutex>
#include <cstdint>
#include <ctime>
#include <zip.h>

//One file entry inside a zip layer, captured at index time.
struct ZipEntry {
    std::string name;            // normalized, no leading/trailing '/'
    uint64_t    index = 0;       // zip entry index, for zip_fopen_index
    uint64_t    size = 0;        // uncompressed size
    time_t      mtime = 0;
    bool        isDir = false;
    // STORED (uncompressed, unencrypted) entries are served zero-copy: their bytes sit contiguously
    // in the archive at `dataOffset`, so reads are a direct pread (no decompression, no materialization).
    bool        stored = false;
    uint64_t    dataOffset = 0;  // absolute byte offset of the entry data within the archive
};

//A whole zip archive indexed for the FS lifetime. Only STORED (uncompressed) entries are servable —
//they are read zero-copy via pread on `rawFd` at ZipEntry::dataOffset (any size, bounded by nothing).
//Compressed (DEFLATE/etc.) entries are NOT served: package layers must be `zip -0` (STORE). The app
//validates this before mounting (ContainerWrapper) and shows a re-zip dialog; this is the fallback.
struct ZipIndex {
    std::string archivePath;
    zip_t*      archive = nullptr;  // libzip handle, used only to build the entry list at index time
    int         rawFd = -1;         // plain O_RDONLY fd for STORED pread (thread-safe, no shared offset)
    std::unordered_map<std::string, ZipEntry>              byName;      // files + explicit dir entries
    std::unordered_map<std::string, std::set<std::string>> dirChildren; // parent vrel → child segment names
    ~ZipIndex();
};

//Opens ArchivePath and indexes every entry (synthesizing missing parent dirs). nullptr on failure.
std::shared_ptr<ZipIndex> BuildZipIndex(const std::string &ArchivePath);

//Per-open reader for a STORED entry — serves reads via pread on the shared archive fd (`storedFd`,
//not owned). There is no materialization (no memory buffer, no temp file).
struct ZipReader {
    bool     stored = false;
    int      storedFd = -1;    // shared ZipIndex::rawFd — NOT closed
    uint64_t dataOffset = 0;
    uint64_t size = 0;
};

//Prepares Out to serve entry E. STORED → zero-copy reader. A compressed entry returns -EIO (the app
//blocks non-STORE zips up front; this guards the fallback path).
int OpenZipEntry(ZipIndex &Z, const ZipEntry &E, ZipReader &Out);

//Serves a read from an opened ZipReader. Returns bytes read (>=0) or -errno.
int ReadZipEntry(ZipReader &R, char *Buf, size_t Size, off_t Off);

#endif // VIDYAGODFS_ZIPLAYER_H
