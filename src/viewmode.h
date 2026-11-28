#ifndef VIDYAGODFS_VIEWMODE_H
#define VIDYAGODFS_VIEWMODE_H

#include "bytesource.h"
#include "coding.h"

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

// ---------------------------------------------------------------------------
// VIEW mode (ISA 10, MetaPackageFormat 22.17): a description run over a CONTENT (a disc image, an archive) that lists the
// files in it, the content's FILE TABLE. No coder, no stream, no decisions: control flow, 64-bit registers and arrays,
// reads of the content, and the entry ops (ENAME ECHAR ETAB EDIR EFINISH ESTRIDE EPART EFIN). Descriptions come from
// peers, so a run is bounded: at most kViewMaxEntries entries, names of at most kViewMaxName bytes, every extent inside
// the content, fuel per op and per byte, a call stack of kViewMaxCalls.
//
// The table a run gives is kept as a LISTING (ViewListing): canonical text, its CID the VIEW layer's identity. A mount
// serves the listing (no description runs at a mount); a mint makes it, and `view verify` checks it against a run.
// ---------------------------------------------------------------------------

namespace coding {

constexpr size_t kViewMaxEntries = 1u << 20;
constexpr size_t kViewMaxName = 4096;          // bytes of a name as built (before it is read as text)
constexpr size_t kViewMaxExtents = 1u << 22;   // every file's together
constexpr size_t kViewMaxCalls = 1024;

struct ViewEntry {
    std::string path;                                     // UTF-8, '/' between parts; no empty, "." or ".." part
    bool dir = false;
    std::vector<std::pair<uint64_t, uint64_t>> extents;   // a file's bytes: (offset, length) ranges of the content, in order
    uint64_t size() const { uint64_t n = 0; for (const auto &e : extents) n += e.second; return n; }
};

// Run a VIEW description over Content. Out: every folder and file, sorted by path (bytewise), a folder for every
// path's ancestors too. False (Err says why) for a run that is refused: an assert that fails, a name that is not text in
// the description's NAMES, a path listed twice, an extent outside the content, a limit passed.
bool RunView(const Description &D, ByteSource &Content, std::vector<ViewEntry> &Out, std::string &Err, uint64_t Fuel = 1ull << 34);

// A name as built (bytes in the description's NAMES encoding) read to UTF-8.
bool DecodeViewName(uint8_t Names, const std::string &Raw, std::string &Utf8, std::string &Err);

// The canonical listing of a file table (the .vgview file): "VGVIEW 1\n", then one line per entry in path order:
//   "d\t<path>\n"  or  "f\t<path>\t<size>\t<off>+<len>,<off>+<len>…\n"   (numbers decimal; a file of no bytes: "-")
// Entries must be as RunView gives them (sorted, ancestors present). Paths hold no tab, newline or NUL.
std::string ViewListing(const std::vector<ViewEntry> &Entries);
// Read a listing back, refusing anything ViewListing would not write. ContentSize > 0: every extent must lie inside it.
bool ReadViewListing(const std::string &Text, std::vector<ViewEntry> &Out, std::string &Err, uint64_t ContentSize = 0);

} // namespace coding

#endif // VIDYAGODFS_VIEWMODE_H
