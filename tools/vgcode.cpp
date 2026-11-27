// vgcode: the coding algebra from the command line (authoring and verification; the mount reads coded layers itself).
// A <description> is a node holding one in its DESCRIPTION, or the description's own JSON (chapter 22 §22.16).
//   vgcode check <description> [canonical-out]
//       read and validate a description; write its canonical text (the same names, values laid out canonically)
//   vgcode mint [--plain] <description> <shipped> <content-out> <record-out> [spacing]
//       decode the shipped file into its content and a record, code it back and refuse unless every byte matches
//       (a description with a family mints a PREDICTED record, small; --plain mints every decision: larger, fast to read)
//   vgcode expand <description> <record> <content> <plain-record-out> [spacing]
//       a predicted record's plain twin (what a machine keeps beside the content, so reads never run the family)
//   vgcode verify <description> <record> <content> <shipped>
//       rebuild the shipped bytes through the read path (segments, copy runs, the pool) and compare them to the file
//   vgcode cat <description> <record> <content> <out>
//       rebuild the shipped bytes into a file
// Exit 0 = done and verified; 1 = refused or different; 2 = usage.
#include "coding.h"
#include "bytesource.h"

#include <chrono>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iostream>
#include <string>
#include <sys/mman.h>
#include <vector>

static bool Slurp(const std::string &p, std::vector<uint8_t> &o) {
    std::ifstream f(p, std::ios::binary); if (!f) return false;
    o.assign(std::istreambuf_iterator<char>(f), {}); return true;
}
static bool Spit(const std::string &p, const uint8_t *b, size_t n) {
    std::ofstream f(p, std::ios::binary | std::ios::trunc); if (!f) return false;
    f.write((const char *)b, (std::streamsize)n); return (bool)f;
}
static double Now() { return std::chrono::duration<double>(std::chrono::steady_clock::now().time_since_epoch()).count(); }
static std::shared_ptr<ByteSource> Map(const std::string &p) {
    auto m = std::make_shared<MmapByteSource>(); if (!m->Map(p)) { std::cerr << "cannot read " << p << "\n"; return nullptr; } return m;
}
static std::shared_ptr<coding::CodedByteSource> Open(char **a) {
    auto d = Map(a[0]), r = Map(a[1]), c = Map(a[2]); if (!d || !r || !c) return nullptr;
    std::string err; auto s = coding::CodedByteSource::Create(d, r, c, 0, err);
    if (!s) std::cerr << "refused: " << err << "\n";
    return s;
}

int main(int argc, char **argv) {
    const std::string cmd = argc > 1 ? argv[1] : "";
    if (cmd == "check" && (argc == 3 || argc == 4)) {
        std::vector<uint8_t> db; std::string err, text; coding::Description d;
        if (!Slurp(argv[2], db)) { std::cerr << "cannot read " << argv[2] << "\n"; return 1; }
        coding::TextNames names;
        if (!coding::Read(std::string(db.begin(), db.end()), d, err, &names) || !coding::Print(d, text, err, &names)) { std::cerr << "refused: " << err << "\n"; return 1; }
        if (argc == 4 && !Spit(argv[3], (const uint8_t *)text.data(), text.size())) { std::cerr << "cannot write\n"; return 1; }
        std::cout << "valid: " << d.name << " (ISA " << d.isa << ", " << d.ops.size() << " instructions, " << d.ex.size() << " values)\n";
        return 0;
    }
    bool plain = false;
    if (cmd == "mint" && argc > 2 && std::string(argv[2]) == "--plain") { plain = true; for (int i = 2; i + 1 < argc; ++i) argv[i] = argv[i + 1]; --argc; }
    if (cmd == "mint" && (argc == 6 || argc == 7)) {
        std::vector<uint8_t> db; std::string err; coding::Description d;
        if (!Slurp(argv[2], db) || !coding::Parse(db.data(), db.size(), d, err)) { std::cerr << "description: " << err << "\n"; return 1; }
        MmapByteSource s; if (!s.Map(argv[3])) { std::cerr << "cannot read " << argv[3] << "\n"; return 1; }
        // the content buffer: 4 GiB reserved, paid for only as the decode fills it
        const size_t cap = 0xFFFFFFFFu;
        void *buf = mmap(nullptr, cap, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
        if (buf == MAP_FAILED) { std::cerr << "cannot reserve the content buffer\n"; return 1; }
        const uint64_t spacing = argc == 7 ? std::stoull(argv[6]) : coding::SuggestedSpacing(d, s.n, plain);
        size_t len = 0; std::vector<uint8_t> rec; const double t0 = Now();
        if (!coding::MintInto(d, s.p, (size_t)s.n, 0, (uint8_t *)buf, cap, spacing, len, rec, err, !plain)) { std::cerr << "refused: " << err << "\n"; return 1; }
        const double dt = Now() - t0;
        if (!Spit(argv[4], (const uint8_t *)buf, len) || !Spit(argv[5], rec.data(), rec.size())) { std::cerr << "cannot write\n"; return 1; }
        std::cout << "minted " << s.n << " shipped -> " << len << " content + " << rec.size() << (rec[3] == 'Q' ? " predicted" : " plain") << " record (" << d.name << ", spacing "
                  << spacing << ") in " << dt << " s; codes back bit-exact\n";
        return 0;
    }
    if (cmd == "expand" && (argc == 6 || argc == 7)) {
        auto d = Map(argv[2]), r = Map(argv[3]), c = Map(argv[4]); if (!d || !r || !c) return 1;
        std::string err; auto src = coding::CodedByteSource::Create(d, r, c, 0, err); if (!src) { std::cerr << "refused: " << err << "\n"; return 1; }
        const size_t sn = (size_t)src->size(), cn = (size_t)c->size();
        void *sb = mmap(nullptr, sn + 1, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
        void *cb = mmap(nullptr, cn + 1, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
        if (sb == MAP_FAILED || cb == MAP_FAILED) { std::cerr << "cannot reserve the buffers\n"; return 1; }
        std::vector<uint8_t> db; coding::Description dd; Slurp(argv[2], db); coding::Parse(db.data(), db.size(), dd, err);
        const uint64_t spacing = argc == 7 ? std::stoull(argv[6]) : coding::SuggestedSpacing(dd, sn, true);
        std::vector<uint8_t> plainRec; const double t0 = Now();
        if (!coding::ExpandInto(d, r, c, (uint8_t *)sb, sn, (uint8_t *)cb, cn, spacing, plainRec, err)) { std::cerr << "refused: " << err << "\n"; return 1; }
        if (!Spit(argv[5], plainRec.data(), plainRec.size())) { std::cerr << "cannot write\n"; return 1; }
        std::cout << "expanded " << r->size() << " -> " << plainRec.size() << " plain record (" << sn << " shipped) in " << Now() - t0 << " s\n";
        return 0;
    }
    if ((cmd == "verify" || cmd == "cat") && argc == 6) {
        auto src = Open(argv + 2); if (!src) return 1;
        std::unique_ptr<MmapByteSource> want; std::FILE *out = nullptr;
        if (cmd == "verify") { want = std::make_unique<MmapByteSource>(); if (!want->Map(argv[5])) { std::cerr << "cannot read " << argv[5] << "\n"; return 1; }
            if (want->n != src->size()) { std::cerr << "DIFFERENT: " << src->size() << " bytes, the file has " << want->n << "\n"; return 1; } }
        else if (!(out = std::fopen(argv[5], "wb"))) { std::cerr << "cannot write " << argv[5] << "\n"; return 1; }
        std::vector<uint8_t> b(8u << 20); const double t0 = Now();
        for (uint64_t o = 0; o < src->size(); o += b.size()) {
            const size_t n = (size_t)std::min<uint64_t>(b.size(), src->size() - o);
            if (!src->preadAll(b.data(), n, o)) { std::cerr << "read failed at " << o << "\n"; return 1; }
            if (want && memcmp(b.data(), want->p + o, n)) { std::cerr << "DIFFERENT in [" << o << ", " << o + n << ")\n"; return 1; }
            if (out && std::fwrite(b.data(), 1, n, out) != n) { std::cerr << "cannot write\n"; return 1; }
        }
        const double dt = Now() - t0;
        if (out) std::fclose(out);
        std::cout << (want ? "identical: " : "wrote ") << src->size() << " bytes in " << dt << " s (" << src->size() / dt / 1e6 << " MB/s, "
                  << src->segmentsDecoded() << "/" << src->checkpoints() << " segments)\n";
        return 0;
    }
    std::cerr << "usage:\n  vgcode check <description> [canonical-out]\n  vgcode mint [--plain] <description> <shipped> <content-out> <record-out> [spacing]\n"
                 "  vgcode expand <description> <record> <content> <plain-record-out> [spacing]\n"
                 "  vgcode verify <description> <record> <content> <shipped>\n  vgcode cat <description> <record> <content> <out>\n";
    return 2;
}
