#include "lz4family.h"

#include <cstring>

namespace coding {

namespace {
constexpr int kMinMatch = 4, kMfLimit = 12, kLastLiterals = 5, kMlMask = 15, kOptimalMl = kMlMask - 1 + kMinMatch;
constexpr uint32_t kMaxDistance = 65535, kHashLog = 15, kDictSize = 1u << 16;
inline uint32_t Rd32(const uint8_t *p) { uint32_t v; memcpy(&v, p, 4); return v; }   // little-endian hosts only (all we build)
inline uint32_t HashOf(const uint8_t *p) { return (Rd32(p) * 2654435761u) >> (32 - kHashLog); }
inline int Count(const uint8_t *a, const uint8_t *b, const uint8_t *lim) { const uint8_t *s = a; while (a < lim && *a == *b) { ++a; ++b; } return (int)(a - s); }
} // namespace

// Positions are indices from `base` = the block's start - 64 KiB, as lz4 1.7 counts them (index 64 KiB is the block's
// first byte, so an empty hash slot, 0, is out of the window).
struct Lz4hcParser::Ctx {
    uint32_t ht[1u << kHashLog];
    uint16_t ct[kDictSize];
    const uint8_t *src = nullptr; uint32_t next = 0;
    const uint8_t *at(uint32_t i) const { return src + i - kDictSize; }
    uint32_t idx(const uint8_t *p) const { return (uint32_t)(p - src) + kDictSize; }
    uint32_t lowLimit(const uint8_t *ip) const { const uint32_t x = idx(ip); return kDictSize + kDictSize > x ? kDictSize : x - (kDictSize - 1); }
    void insert(const uint8_t *ip) {                  // the chains up to ip (excluded)
        const uint32_t t = idx(ip);
        for (uint32_t i = next; i < t; ++i) { const uint32_t h = HashOf(at(i)); uint32_t d = i - ht[h]; if (d > kMaxDistance) d = kMaxDistance; ct[(uint16_t)i] = (uint16_t)d; ht[h] = i; }
        if (t > next) next = t;
    }
    int best(const uint8_t *ip, const uint8_t *lim, const uint8_t *&mp, uint32_t att) {
        const uint32_t lo = lowLimit(ip); insert(ip); uint32_t mi = ht[HashOf(ip)]; int ml = 0;
        while (mi >= lo && att) { --att; const uint8_t *m = at(mi);
            if (m[ml] == ip[ml] && Rd32(m) == Rd32(ip)) { const int t = Count(ip + kMinMatch, m + kMinMatch, lim) + kMinMatch; if (t > ml) { ml = t; mp = m; } }
            mi -= ct[(uint16_t)mi]; }
        return ml;
    }
    int wider(const uint8_t *ip, const uint8_t *ilow, const uint8_t *ihigh, int longest, const uint8_t *&mp, const uint8_t *&sp, uint32_t att) {
        const uint32_t lo = lowLimit(ip); insert(ip); uint32_t mi = ht[HashOf(ip)]; const int delta = (int)(ip - ilow);
        while (mi >= lo && att) { --att; const uint8_t *m = at(mi);
            if (ilow[longest] == (m - delta)[longest] && Rd32(m) == Rd32(ip)) {
                int t = kMinMatch + Count(ip + kMinMatch, m + kMinMatch, ihigh), back = 0;
                while (ip + back > ilow && m + back > src && ip[back - 1] == m[back - 1]) --back;
                t -= back;
                if (t > longest) { longest = t; mp = m + back; sp = ip + back; } }
            mi -= ct[(uint16_t)mi]; }
        return longest;
    }
};

Lz4hcParser::Lz4hcParser() : C(new Ctx) {}
Lz4hcParser::~Lz4hcParser() = default;

void Lz4hcParser::parse(const uint8_t *Src, size_t N, uint32_t Att, std::vector<Lz4Seq> &Out) {
    Out.clear();
    Ctx &c = *C;
    memset(c.ht, 0, sizeof c.ht); memset(c.ct, 0xFF, sizeof c.ct);
    c.src = Src; c.next = kDictSize;
    const uint8_t *ip = Src, *anchor = ip, *const iend = ip + N;
    auto seq = [&](int ml, const uint8_t *ref) {
        Out.push_back({(uint32_t)(anchor - Src), (uint32_t)(ip - anchor), (uint32_t)ml, (uint32_t)(ip - ref)});
        ip += ml; anchor = ip;
    };
    if (N >= (size_t)kMfLimit + 1) {
        const uint8_t *const mflimit = iend - kMfLimit, *const mlimit = iend - kLastLiterals;
        int ml, ml2, ml3, ml0; const uint8_t *ref = nullptr, *s2 = nullptr, *r2 = nullptr, *s3 = nullptr, *r3 = nullptr, *s0, *r0;
        ++ip;
        while (ip < mflimit) {
            ml = c.best(ip, mlimit, ref, Att);
            if (!ml) { ++ip; continue; }
            s0 = ip; r0 = ref; ml0 = ml;
        search2:
            if (ip + ml < mflimit) ml2 = c.wider(ip + ml - 2, ip, mlimit, ml, r2, s2, Att); else ml2 = ml;
            if (ml2 == ml) { seq(ml, ref); continue; }
            if (s0 < ip && s2 < ip + ml0) { ip = s0; ref = r0; ml = ml0; }
            if (s2 - ip < 3) { ml = ml2; ip = s2; ref = r2; goto search2; }
        search3:
            if (s2 - ip < kOptimalMl) {
                int nm = ml; if (nm > kOptimalMl) nm = kOptimalMl;
                if (ip + nm > s2 + ml2 - kMinMatch) nm = (int)(s2 - ip) + ml2 - kMinMatch;
                const int cor = nm - (int)(s2 - ip); if (cor > 0) { s2 += cor; r2 += cor; ml2 -= cor; }
            }
            if (s2 + ml2 < mflimit) ml3 = c.wider(s2 + ml2 - 3, s2, mlimit, ml2, r3, s3, Att); else ml3 = ml2;
            if (ml3 == ml2) {                         // no better third match: two sequences
                if (s2 < ip + ml) ml = (int)(s2 - ip);
                seq(ml, ref); ip = s2; seq(ml2, r2); continue;
            }
            if (s3 < ip + ml + 3) {                   // no room for the second: it goes
                if (s3 >= ip + ml) {
                    if (s2 < ip + ml) { const int cor = (int)(ip + ml - s2); s2 += cor; r2 += cor; ml2 -= cor; if (ml2 < kMinMatch) { s2 = s3; r2 = r3; ml2 = ml3; } }
                    seq(ml, ref); ip = s3; ref = r3; ml = ml3; s0 = s2; r0 = r2; ml0 = ml2; goto search2;
                }
                s2 = s3; r2 = r3; ml2 = ml3; goto search3;
            }
            if (s2 < ip + ml) {                       // three ascending matches: write the first
                if (s2 - ip < kMlMask) {
                    if (ml > kOptimalMl) ml = kOptimalMl;
                    if (ip + ml > s2 + ml2 - kMinMatch) ml = (int)(s2 - ip) + ml2 - kMinMatch;
                    const int cor = ml - (int)(s2 - ip); if (cor > 0) { s2 += cor; r2 += cor; ml2 -= cor; }
                } else ml = (int)(s2 - ip);
            }
            seq(ml, ref);
            ip = s2; ref = r2; ml = ml2; s2 = s3; r2 = r3; ml2 = ml3; goto search3;
        }
    }
    Out.push_back({(uint32_t)(anchor - Src), (uint32_t)(iend - anchor), 0, 0});
}

} // namespace coding
