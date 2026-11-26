// vgcode: the coding algebra from the command line (authoring and verification; the mount reads coded layers itself).
//   vgcode describe <lz4|deflate|bsa|lzma:lc,lp,pb,dict[,end]> <out.vgcd>
//   vgcode mint <description> <shipped> <content-out> <record-out> [spacing]
//       decode the shipped file into its content and a record, code it back and refuse unless every byte matches
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
    if (cmd == "describe" && argc == 4) {
        const std::string n = argv[2]; coding::Description d;
        if (n == "lz4") d = coding::Lz4BlockDescription();
        else if (n == "deflate") d = coding::DeflateDescription();
        else if (n == "bsa") d = coding::BsaDescription();
        else if (n.rfind("lzma:", 0) == 0) {
            unsigned lc, lp, pb, end = 1; unsigned long dict;
            if (std::sscanf(n.c_str() + 5, "%u,%u,%u,%lu,%u", &lc, &lp, &pb, &dict, &end) < 4) { std::cerr << "lzma:lc,lp,pb,dict[,end]\n"; return 2; }
            d = coding::LzmaDescription((int)lc, (int)lp, (int)pb, (uint32_t)dict, end != 0);
        } else { std::cerr << "no description named " << n << "\n"; return 2; }
        const auto b = coding::Serialize(d);
        return Spit(argv[3], b.data(), b.size()) ? 0 : 1;
    }
    if (cmd == "mint" && (argc == 6 || argc == 7)) {
        std::vector<uint8_t> db; std::string err; coding::Description d;
        if (!Slurp(argv[2], db) || !coding::Parse(db.data(), db.size(), d, err)) { std::cerr << "description: " << err << "\n"; return 1; }
        MmapByteSource s; if (!s.Map(argv[3])) { std::cerr << "cannot read " << argv[3] << "\n"; return 1; }
        // the content buffer: 4 GiB reserved, paid for only as the decode fills it
        const size_t cap = 0xFFFFFFFFu;
        void *buf = mmap(nullptr, cap, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
        if (buf == MAP_FAILED) { std::cerr << "cannot reserve the content buffer\n"; return 1; }
        const uint64_t spacing = argc == 7 ? std::stoull(argv[6]) : coding::SuggestedSpacing(d, s.n);
        size_t len = 0; std::vector<uint8_t> rec; const double t0 = Now();
        if (!coding::MintInto(d, s.p, (size_t)s.n, 0, (uint8_t *)buf, cap, spacing, len, rec, err)) { std::cerr << "refused: " << err << "\n"; return 1; }
        const double dt = Now() - t0;
        if (!Spit(argv[4], (const uint8_t *)buf, len) || !Spit(argv[5], rec.data(), rec.size())) { std::cerr << "cannot write\n"; return 1; }
        std::cout << "minted " << s.n << " shipped -> " << len << " content + " << rec.size() << " record (" << d.name << ", spacing "
                  << spacing << ") in " << dt << " s; codes back bit-exact\n";
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
    std::cerr << "usage:\n  vgcode describe <lz4|deflate|bsa|lzma:lc,lp,pb,dict[,end]> <out>\n  vgcode mint <description> <shipped> <content-out> <record-out> [spacing]\n"
                 "  vgcode verify <description> <record> <content> <shipped>\n  vgcode cat <description> <record> <content> <out>\n";
    return 2;
}
