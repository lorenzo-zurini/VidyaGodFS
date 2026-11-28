#ifndef VIDYAGODFS_TREELAYER_H
#define VIDYAGODFS_TREELAYER_H

#include "bytesource.h"

#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <string>
#include <vector>

// ---------------------------------------------------------------------------
// A TREE (.vgtz, MetaPackageFormat 04 / 22.18): an install as files read from its BASES — the original media through
// VIEWs, archives, other trees, single files — plus only the bytes no base has. READABLE first (USER 2026-11-28: "as
// human readable as possible, while keeping all the other achievements"): a .vgtz is a STORE zip any tool opens:
//     TREE.txt                the table, one line a path, in words
//     patch/<path>.patch      a changed text file: a unified diff over its base file (patch(1), git apply)
//     add/<path>.add          a file's new bytes, text: raw
//     add/<path>.add.zst      a file's new bytes, binary: zstd's seekable format (zstd -d reads it; random access)
// TREE.txt ("VGTZ 1"; fields by tab; a..b is [a, b) of the base file):
//     base   <i>  <cid>
//     dir    <path>
//     link   <path>  <target>
//     same   <path>  <size>  <mode>  from <i>  <base path>               the base file, whole
//     range  <path>  <size>  <mode>  from <i>  <base path>  <a>..<b>     a part of it
//     patch  <path>  <size>  <mode>  from <i>  <base path>               text: its patch over the base file
//     pieces <path>  <size>  <mode>  from <i>  <base path>  <pieces>     "keep a..b", "new n" (its add's next n bytes),
//                                                                        "zero n", joined by ", "
//     new    <path>  <size>  <mode>                                      its add, whole (a 0-byte file: none)
// <mode> octal permission bits or "-". A tree lists its whole tree: a path absent is a file absent.
// ---------------------------------------------------------------------------

namespace vgtree {

constexpr size_t kMaxEntries = 1u << 21;
constexpr size_t kMaxPieces = 1u << 22;          // every file's together
constexpr size_t kMaxBases = 1u << 16;
constexpr uint64_t kMaxTable = 64ull << 20;      // TREE.txt
constexpr uint64_t kMaxPatch = 16ull << 20;      // a patch, the text file it is applied to, and the file it makes
constexpr uint64_t kMaxPatches = 256ull << 20;   // every patch of a tree together
constexpr size_t kMaxPatchLines = 1u << 20;      // a file a patch is made of (and its base): at most these lines
constexpr size_t kMaxDiffSteps = 4096;           // the line diff's edit steps (its memory: their square, in words)
constexpr uint32_t kZstdFrame = 256u << 10;      // a binary add's seekable frames (decompressed)
constexpr int kZstdLevel = 3;                    // speed first (USER 2026-11-26: speed > ratio)

struct Piece { enum Kind : uint8_t { Keep, New, Zero }; Kind kind = Keep; uint64_t off = 0, len = 0; };   // Keep: [off, off+len)
struct Entry {
    enum Kind : uint8_t { Dir, File, Link };
    enum Op : uint8_t { Same, Range, Patch, Pieces, New };
    std::string path;            // UTF-8, '/' between parts (a VIEW's path rules)
    Kind kind = File;
    std::string link;            // Link: its target
    uint64_t size = 0;
    uint32_t mode = 0;           // permission bits; 0 = not said ("-")
    Op op = Same;
    uint32_t base = 0;           // Same, Range, Patch, Pieces: which base
    std::string basePath;        // its file there ("" a single-file base itself)
    uint64_t off = 0, len = 0;   // Range
    std::vector<Piece> pieces;   // Pieces
};
struct Table {
    std::vector<std::string> bases;   // CIDs, in BASE_SOURCES order
    std::vector<Entry> entries;       // path order (bytewise), every parent a folder listed before it
};

// The canonical TREE.txt (refused otherwise: one form, so one CID) and its strict reader.
bool TableText(const Table &T, std::string &Out, std::string &Err);
bool ReadTable(const std::string &Text, Table &Out, std::string &Err);

// What a file's new bytes are, for writing: text goes raw (readable), anything else to seekable zstd.
struct AddBytes { const uint8_t *p = nullptr; size_t n = 0; bool text = false; };
// Write a .vgtz: the table, each file's add (by path) and each text file's patch (by path). Deterministic.
bool WriteTree(const std::string &OutPath, const Table &T, const std::map<std::string, AddBytes> &Adds,
               const std::map<std::string, std::string> &Patches, std::string &Err);

// An opened .vgtz: its table, and its members (a file's add as bytes of the size the table says, a patch's text).
// Mounting reads the table and every patch (checked whole: 22.18.4); an add, and a base archive's member, are opened
// when first read (a mount of thousands of files makes no read per file), and a bad one then reads as -EIO.
struct Opened {
    Table table;
    std::function<std::shared_ptr<ByteSource>(const std::string &Path, uint64_t Size)> add;   // nullptr: none
    std::function<bool(const std::string &Path, std::string &Patch)> patch;
};
bool OpenTree(std::shared_ptr<ByteSource> File, Opened &Out, std::string &Err);

// A file of the tree as bytes. BaseFile(i, path) gives base i's file (nullptr: none such). Refused (nullptr, Err): a
// base file missing or of another size than the op says, a range past it, a patch that does not fit its table. A
// patched file is applied when first read (a byte-bounded cache for the process holds what was applied).
using BaseFileFn = std::function<std::shared_ptr<ByteSource>(uint32_t Base, const std::string &Path)>;
std::shared_ptr<ByteSource> EntryBytes(const Entry &E, const BaseFileFn &BaseFile, const Opened &Tree, std::string &Err);

// Bytes of a known size opened when first read (Open once; a failure, or another size, logged once as What, then
// every read -EIO).
std::shared_ptr<ByteSource> Lazily(uint64_t Size, std::function<std::shared_ptr<ByteSource>(std::string &Err)> Open, std::string What);

// A link's target inside the tree (22.18.2): relative, never above the tree's top from the link's folder, no empty part.
bool InsideLink(const std::string &Path, const std::string &Target);

// Text: how bytes are text ("" as they are, "utf-16-le", "utf-16-be" behind their mark), or false.
bool TextEncoding(const uint8_t *P, size_t N, std::string &Enc);
// A unified diff rebuilding New from Old byte for byte (a UTF-16 file: over its text as UTF-8, its first line
// "# text <encoding>"); deterministic (line Myers diff, 3 lines of context). False if none (not text, too large, a diff
// too long to be worth it).
bool MakePatch(const std::string &Old, const std::string &New, const std::string &OldName, const std::string &NewName, std::string &Patch);
bool ApplyPatch(const std::string &Old, const std::string &Patch, std::string &New, std::string &Err);
// A patch's grammar checked whole without its base (22.18.4): the files it names, and the bytes it removes and adds
// (in its file's encoding: a UTF-16 file's in UTF-16).
bool PatchInfo(const std::string &Patch, std::string &OldName, std::string &NewName, uint64_t &Removed, uint64_t &Added, std::string &Err);

// zstd's seekable format (zstd contrib/seekable_format): frames of kZstdFrame, a seek table in a skippable frame.
// Sink takes it a frame at a time (false: stop); SeekableZstd gathers it whole (small inputs, tests).
bool SeekableZstdTo(const uint8_t *P, size_t N, const std::function<bool(const void *, size_t)> &Sink, std::string &Err);
std::string SeekableZstd(const uint8_t *P, size_t N, std::string &Err);
std::shared_ptr<ByteSource> SeekableZstdSource(std::shared_ptr<ByteSource> Compressed, std::string &Err);

} // namespace vgtree

#endif // VIDYAGODFS_TREELAYER_H
