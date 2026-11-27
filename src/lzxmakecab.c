/*
 * lzxmakecab.c -- the LZX compressor of Microsoft Cabinet Maker 1.00.0601 (MAKECAB.EXE, 1997-03-19), reimplemented
 * from analysis of the binary for interoperability (no Microsoft code is contained or executed here). It is the
 * coding algebra's LZX ENCODER FAMILY (MetaPackageFormat 22.15.4): given a CAB folder's bytes it produces the folder's
 * CFDATA payloads exactly as MAKECAB 1.00 did (all four AoE2 cabinets: 21,112 / 21,112 CFDATA byte for byte).
 *
 * Origin and evidence: the analysis notes and the verified standalone tool (lzxenc.c, NOTES.md: every function below
 * names the address of the routine it mirrors, image base 0x400000; "ctx+0x.." the field's offset in the compressor
 * context). This file is that tool's encoder, unchanged but for its edges: output goes to a callback instead of a file,
 * errors return instead of exiting, E8 translation can be left to the caller (the engine hands it the translated
 * window), and the original's match-buffer overflow — where its output depends on its heap layout — ends the run as
 * "not this encoder" instead of emulating it.
 */
#include "lzxmakecab.h"

#include <setjmp.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef int32_t i32;

#define MAX_MATCH 257          /* 0x101 */
#define MIN_MATCH 2
#define BREAK_LENGTH 50        /* 0x32: "good enough" match, ends tree searches and optimal passes */
#define LOOK 0xefd             /* optimal pass never reaches further than start+LOOK */
#define NUM_NODES 4110         /* 0x18150 / 24 */
#define MAX_LITERAL_ITEMS 65536
#define MAX_DIST_ITEMS 32768
#define NUM_SECONDARY 249      /* 0xf9 */
#define MAX_MAIN (256 + 8 * 51)
#define OUTBUF_SIZE 0x9800
#define OUTBUF_LIMIT 0x97c0

/* 0x41e5a8: extra bits per position slot */
static const u8 extra_bits[52] = {
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13, 14, 14,
    15, 15, 16, 16, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 0};
/* 0x41e7a8: bit length of 0..255 (0 -> 0, 1 -> 1, 2..3 -> 2, ...) -- built at start-up here */
static inline u32 bitlen8(u32 v) { u32 b = 0; for (; v; v >>= 1) b++; return b; }   /* (the tool computed these into a table) */
/* 0x41e760: squares 0..16 */
static const u32 square_table[17] = {0, 1, 4, 9, 16, 25, 36, 49, 64, 81, 100, 121, 144, 169, 196, 225, 256};

typedef struct {       /* 24 bytes in the binary (decision_data, ctx+0x253c) */
    u32 link;          /* +0  formatted match position that arrives at this node */
    u32 path;          /* +4  position the best path comes from (later reversed: goes to) */
    u32 rep[3];        /* +8  repeated offsets after arriving here by the best path */
    u32 numbits;       /* +14 cost of the best path to here */
} node_t;

typedef struct lzx_ctx {
    /* window ------------------------------------------------------------------------------- */
    u32 window_size;                 /* ctx+0x4 */
    u32 second_partition;            /* ctx+0x988 (MAKECAB passes 0x10000) */
    u8 *real_window;                 /* ctx+0x4330, window_size + second_partition + 0x1101 bytes */
    u32 *real_left, *real_right;     /* ctx+0x4334 / 0x4338, (window_size+second_partition)*4 + 0x4404 bytes each */
    u32 bias;                        /* position p lives at real_window[p - bias]; the binary keeps biased
                                        pointers instead (ctx+0x0 window, ctx+0xc / ctx+0x10 trees) */
    u32 *root;                       /* ctx+0x8: 65536 tree roots, indexed by the first two bytes */
    u32 BufPos;                      /* ctx+0x458, absolute, starts at window_size */
    /* parser ------------------------------------------------------------------------------- */
    u32 R[3];                        /* ctx+0x44..0x4c: repeated offsets of the parser */
    u32 S[3];                        /* ctx+0x38..0x40: repeated offsets at the last output block boundary */
    u32 matchpos_table[MAX_MATCH + 2]; /* ctx+0x50: [len] = formatted position of the nearest match of that length */
    u8 slot_table[1024];             /* ctx+0x45c */
    node_t *dd;                      /* ctx+0x253c */
    u32 next_tree_create;            /* ctx+0x2530 */
    u32 last_literals, last_distances; /* ctx+0x2534 / 0x2538: tallied so far into the cost statistics */
    /* token buffer ------------------------------------------------------------------------- */
    u32 literals, distances;         /* ctx+0x24 / 0x28 */
    u32 *DistData;                   /* ctx+0x2c, 0x8000 entries */
    u8 *LitData;                     /* ctx+0x30, 0x10000 entries: literal byte, or match length - 2 */
    u8 *ItemType;                    /* ctx+0x34, 0x2000 bytes: bit set = match */
    /* trees -------------------------------------------------------------------------------- */
    u32 num_position_slots;          /* ctx+0x870 */
    u8 main_len[MAX_MAIN + 8];       /* ctx+0x2540 (+1 for the sentinel of the tree writer) */
    u8 secondary_len[NUM_SECONDARY + 1]; /* ctx+0x27fd */
    u16 main_freq[2 * MAX_MAIN];     /* ctx+0x28f8 (the tree builder keeps inner-node sums behind the leaves) */
    u16 main_code[MAX_MAIN];         /* ctx+0x33e8 */
    u8 main_prev_len[MAX_MAIN];      /* ctx+0x3960 */
    u16 secondary_freq[2 * NUM_SECONDARY]; /* ctx+0x3c1e */
    u16 secondary_code[NUM_SECONDARY]; /* ctx+0x4002 */
    u8 secondary_prev_len[NUM_SECONDARY]; /* ctx+0x41f4 */
    u16 aligned_freq[16];            /* ctx+0x42ee */
    u16 aligned_code[8];             /* ctx+0x430e */
    u8 aligned_len[8];               /* ctx+0x431e */
    /* tree builder scratch (ctx+0x9a0..0x252e) */
    int mt_n; u16 *mt_freq; u8 *mt_len; u16 *mt_sort;
    i32 mt_heap[MAX_MAIN + 2]; int mt_heapsize;
    u16 mt_left[2 * MAX_MAIN], mt_right[2 * MAX_MAIN];
    u16 mt_len_cnt[17]; int mt_depth;
    /* bit output --------------------------------------------------------------------------- */
    u32 bitbuf;                      /* ctx+0x14 */
    int bitcount;                    /* ctx+0x18 (char), 32 = empty */
    int output_overflow;             /* ctx+0x1c */
    u8 *outbuf, *outptr;             /* ctx+0x85c / 0x860 */
    u32 frame_bytes;                 /* ctx+0x868: uncompressed bytes encoded into the current frame */
    /* state -------------------------------------------------------------------------------- */
    u32 block_start;                 /* ctx+0x86c: BufPos where the token buffer starts (first-block redo) */
    u32 file_size;                   /* ctx+0x874: E8 translation size (MAKECAB: constant 12000000) */
    u8 num_block_splits;             /* ctx+0x87c: statistical splits found in the current frame (max 4) */
    u8 popcount[256];                /* ctx+0x87d */
    u8 first_block;                  /* ctx+0x97d: nothing output yet since the reset */
    u32 need_full_stats;             /* ctx+0x980: next cost update re-tallies the whole token buffer */
    u32 first_time;                  /* ctx+0x984: stream header not written yet */
    u32 pos_last_call;               /* ctx+0x98c: BufPos - window_size at the end of the last compress call */
    u32 pos_block_start;             /* ctx+0x990: absolute position where the next output block starts */
    const u8 *in; i32 in_size;       /* ctx+0x994 / 0x998 */
    u32 instr_pos;                   /* ctx+0x99c: E8 translator position */
    u32 num_calls;                   /* ctx+0x433c: compress calls since reset (E8 only for the first 32768) */
    /* host ----------------------------------------------------------------------------------- */
    u32 nframes;
    int translate;                   /* the engine: 0 = the input is already the translated window */
    LzxFrameSink sink; void *sink_arg;
    uint64_t steps, limit;           /* the match finder's tree steps (one per node visited, one per position), and their
                                        bound: its trees have no depth limit of their own, so crafted input could make it
                                        slow; past the bound the run stops (LZXMK_OVER) */
    jmp_buf stop;                    /* an error or "not this encoder": back to the API call */
} lzx_ctx;

#define MW(c) ((const u8 *)((uintptr_t)(c)->real_window - (uintptr_t)(c)->bias))
#define LEFT(c) ((u32 *)((uintptr_t)(c)->real_left - (uintptr_t)(c)->bias * 4))
#define RIGHT(c) ((u32 *)((uintptr_t)(c)->real_right - (uintptr_t)(c)->bias * 4))

#define die(c, m) longjmp((c)->stop, 1)
#define STEP(c) do { if (++(c)->steps > (c)->limit) longjmp((c)->stop, 4); } while (0)

/* MP_SLOT: inlined everywhere in the binary (e.g. 0x41af47) */
static void undefined_behaviour(const lzx_ctx *c);
static inline u32 mp_slot(const lzx_ctx *c, u32 mpos)
{
    u32 s;
    if (mpos < 0x400) return c->slot_table[mpos];
    if (mpos < 0x80000) return c->slot_table[mpos >> 9] + 18u;
    s = (mpos >> 17) + 34u;
    if (s >= c->num_position_slots) undefined_behaviour(c); /* only reachable through the match buffer overflow */
    return s;
}

/* The original would index its tables with a garbage position slot here (out-of-bounds reads and writes that
 * depend on the whole heap image): there is nothing left to reproduce: "not this encoder". */
static void undefined_behaviour(const lzx_ctx *c)
{
    longjmp(((lzx_ctx *)c)->stop, 2);
}

/* ------------------------------------------------------------------------------------------ */
/* bit output                                                                                   */

/* 0x41d3b0 flush_frame: pad to 16 bits, hand the frame to the host (the FCI callback 0x417a60) */
static void output_bits(lzx_ctx *c, int n, u32 v);
static void flush_frame(lzx_ctx *c)
{
    if (c->bitcount < 32) output_bits(c, c->bitcount - 16, 0); /* 0x41ad20 */
    long n = (long)(c->outptr - c->outbuf);
    if (n > 0) {
        if (n > 0xffff) die(c, "frame too large");
        if (c->sink && c->sink(c->sink_arg, c->outbuf, (uint32_t)n, c->frame_bytes)) longjmp(c->stop, 3);
        c->nframes++;
    }
    c->frame_bytes = 0;
    c->outptr = c->outbuf;
    c->bitcount = 32;
    c->bitbuf = 0;
}

/* 0x41b8f0 output_bits (also inlined in the block encoders): MSB first, 16-bit little-endian words */
static void output_bits(lzx_ctx *c, int n, u32 v)
{
    c->bitcount -= n;
    c->bitbuf |= v << c->bitcount;
    while (c->bitcount <= 16) {
        if (c->outptr >= c->outbuf + OUTBUF_LIMIT) { c->output_overflow = 1; c->outptr = c->outbuf; }
        *c->outptr++ = (u8)(c->bitbuf >> 16);
        *c->outptr++ = (u8)(c->bitbuf >> 24);
        c->bitbuf <<= 16;
        c->bitcount += 16;
    }
}

/* ------------------------------------------------------------------------------------------ */
/* Huffman tree construction: 0x41d9d0 make_tree, 0x41db30 (heap + merge), 0x41de40 make_len,     */
/* 0x41df10 count_len, 0x41dac0 make_code.  (The classic heap construction with the "len_cnt"    */
/* overflow repair that limits code lengths to 16.)                                              */

static void downheap(lzx_ctx *c, int i) /* inlined three times in 0x41db30 */
{
    int j, k = c->mt_heap[i];
    const u16 *freq = c->mt_freq;
    while ((j = 2 * i) <= c->mt_heapsize) {
        if (j < c->mt_heapsize && freq[c->mt_heap[j]] > freq[c->mt_heap[j + 1]]) j++;
        if (freq[c->mt_heap[j]] >= freq[k]) break;
        c->mt_heap[i] = c->mt_heap[j];
        i = j;
    }
    c->mt_heap[i] = k;
}

static void count_len(lzx_ctx *c, int i) /* 0x41df10 */
{
    if (i < c->mt_n) c->mt_len_cnt[c->mt_depth < 16 ? c->mt_depth : 16]++;
    else {
        c->mt_depth++;
        count_len(c, c->mt_left[i]);
        count_len(c, c->mt_right[i]);
        c->mt_depth--;
    }
}

static void make_len(lzx_ctx *c, int root) /* 0x41de40 */
{
    int i, k;
    u16 cum = 0;
    for (i = 0; i <= 16; i++) c->mt_len_cnt[i] = 0;
    count_len(c, root);
    for (i = 16; i > 0; i--) cum = (u16)(cum + (u16)(c->mt_len_cnt[i] << (16 - i)));
    while (cum != 0) {
        c->mt_len_cnt[16]--;
        for (i = 15; i > 0; i--)
            if (c->mt_len_cnt[i] != 0) { c->mt_len_cnt[i]--; c->mt_len_cnt[i + 1] += 2; break; }
        cum--;
    }
    for (i = 16; i > 0; i--) {
        k = c->mt_len_cnt[i];
        while (--k >= 0) c->mt_len[*c->mt_sort++] = (u8)i;
    }
}

static void make_code(lzx_ctx *c, int n, const u8 *len, u16 *code) /* 0x41dac0 */
{
    u16 start[18];
    int i;
    start[0] = 0; /* never used for a coded symbol */
    start[1] = 0;
    for (i = 1; i <= 16; i++) start[i + 1] = (u16)((start[i] + c->mt_len_cnt[i]) << 1);
    for (i = 0; i < n; i++) code[i] = start[len[i]]++;
}

/* 0x41d9d0.  freq must have room for 2n-1 entries; code[] doubles as the sort buffer.
 * A tree with one used symbol gets a second one forced in (freq[] is MODIFIED and stays modified). */
static void make_tree(lzx_ctx *c, int n, u16 *freq, u8 *len, u16 *code, int gen_codes)
{
    int i, j, k, avail;
    for (;;) {
        c->mt_n = n; c->mt_freq = freq; c->mt_len = len;
        c->mt_depth = 0; c->mt_heapsize = 0; c->mt_heap[1] = 0;
        for (i = 0; i < n; i++) {
            len[i] = 0;
            if (freq[i]) c->mt_heap[++c->mt_heapsize] = i;
        }
        if (c->mt_heapsize >= 2) break;
        if (c->mt_heapsize == 0) { code[c->mt_heap[1]] = 0; return; }
        if (c->mt_heap[1] == 0) freq[1] = 1; else freq[0] = 1;
    }
    /* 0x41db30 */
    for (i = c->mt_heapsize / 2; i >= 1; i--) downheap(c, i);
    c->mt_sort = code;
    avail = n;
    do {
        i = c->mt_heap[1];
        if (i < n) *c->mt_sort++ = (u16)i;
        c->mt_heap[1] = c->mt_heap[c->mt_heapsize--];
        downheap(c, 1);
        j = c->mt_heap[1];
        if (j < n) *c->mt_sort++ = (u16)j;
        k = avail++;
        freq[k] = (u16)(freq[i] + freq[j]);
        c->mt_heap[1] = k;
        downheap(c, 1);
        c->mt_left[k] = (u16)i; c->mt_right[k] = (u16)j;
    } while (c->mt_heapsize > 1);
    c->mt_sort = code;
    make_len(c, k);
    if (gen_codes) make_code(c, n, len, code);
}

/* 0x41bbd0 */
static void make_trees(lzx_ctx *c, int gen_codes)
{
    make_tree(c, 256 + 8 * (int)c->num_position_slots, c->main_freq, c->main_len, c->main_code, gen_codes);
    make_tree(c, NUM_SECONDARY, c->secondary_freq, c->secondary_len, c->secondary_code, gen_codes);
    make_tree(c, 8, c->aligned_freq, c->aligned_len, c->aligned_code, 1);
}

/* 0x41bcd0 prevent_far_matches: a length-2 match further than 128 KiB is never worth it */
static void prevent_far_matches(lzx_ctx *c)
{
    u32 s;
    for (s = c->slot_table[256] + 18u; s < c->num_position_slots; s++) c->main_len[256 + s * 8] = 100;
}

/* 0x41bc50 fix_tree_cost_estimates: unused symbols still need a price for the parser */
static void fix_tree_cost_estimates(lzx_ctx *c)
{
    u32 i, n = 256 + 8 * c->num_position_slots;
    for (i = 0; i < 256; i++) if (c->main_len[i] == 0) c->main_len[i] = 11;
    for (; i < n; i++) if (c->main_len[i] == 0) c->main_len[i] = 12;
    for (i = 0; i < NUM_SECONDARY; i++) if (c->secondary_len[i] == 0) c->secondary_len[i] = 8;
    prevent_far_matches(c);
}

/* ------------------------------------------------------------------------------------------ */
/* statistics                                                                                   */

/* 0x41c220 tally the tokens [lit_start, lit_end) into main_freq / secondary_freq; returns the
 * number of uncompressed bytes they cover */
static u32 tally_frequency(lzx_ctx *c, u32 lit_start, u32 dist_start, u32 lit_end)
{
    u32 i, d = dist_start, total = 0;
    for (i = lit_start; i < lit_end; i++) {
        if (!(c->ItemType[i >> 3] & (1 << (i & 7)))) {
            c->main_freq[c->LitData[i]]++;
            total++;
        } else {
            u32 len = c->LitData[i], slot = mp_slot(c, c->DistData[d++]);
            if (len < 7) c->main_freq[256 + slot * 8 + len]++;
            else { c->main_freq[256 + slot * 8 + 7]++; c->secondary_freq[len - 7]++; }
            total += len + 2;
        }
    }
    return total;
}

/* 0x41c1d0 get_block_stats: zero + tally */
static u32 get_block_stats(lzx_ctx *c, u32 lit_start, u32 dist_start, u32 lit_end)
{
    memset(c->main_freq, 0, (256 + 8 * c->num_position_slots) * 2);
    { u32 k; for (k = 0; k < NUM_SECONDARY; k++) c->secondary_freq[k] = 0; } /* the leaves only */
    return tally_frequency(c, lit_start, dist_start, lit_end);
}

/* 0x41c120 (+0x41c1a0) get_aligned_stats: returns the block type, 1 verbatim / 2 aligned offset */
static int get_aligned_stats(lzx_ctx *c, u32 dist_count)
{
    u32 i, sum = 0, max = 0;
    for (i = 0; i < 8; i++) c->aligned_freq[i] = 0;
    for (i = 0; i < dist_count; i++)
        if (c->DistData[i] >= 16) c->aligned_freq[c->DistData[i] & 7]++;
    for (i = 0; i < 8; i++) {
        if (c->aligned_freq[i] > max) max = c->aligned_freq[i];
        sum += c->aligned_freq[i];
    }
    if (sum / 5 < max && dist_count >= 100) return 2;
    return 1;
}

/* 0x41ca30 estimate_compressed_block_size (bytes) */
static u32 estimate_block_size(lzx_ctx *c)
{
    u32 est = 1200, i, s;
    for (i = 0; i < 256; i++) est += (u32)c->main_len[i] * c->main_freq[i];
    for (s = 0; s < c->num_position_slots; s++)
        for (i = 0; i < 8; i++)
            est += ((u32)c->main_len[256 + s * 8 + i] + extra_bits[s]) * c->main_freq[256 + s * 8 + i];
    for (i = 0; i < NUM_SECONDARY; i++) est += (u32)c->secondary_len[i] * c->secondary_freq[i];
    return (est + 7) >> 3;
}

/* 0x41c610: "distance" between the symbol statistics of two runs of n tokens */
static u32 tally_diff(lzx_ctx *c, u32 lit_a, u32 lit_b, u32 dist_a, u32 dist_b, u32 n)
{
    u16 fa[100 * 8], fb[100 * 8];
    u32 nsym = (c->num_position_slots + 32) * 8, k, sum = 0;
    if (c->num_position_slots + 32 >= 100) return 0;
    memset(fa, 0, nsym * 2); memset(fb, 0, nsym * 2);
    for (; n; n--) {
        u32 idx;
        if (!(c->ItemType[lit_a >> 3] & (1 << (lit_a & 7)))) idx = c->LitData[lit_a];
        else {
            u32 len = c->LitData[lit_a], slot = mp_slot(c, c->DistData[dist_a++]);
            idx = 256 + slot * 8 + (len < 7 ? len : 7);
        }
        fa[idx]++; lit_a++;
        if (!(c->ItemType[lit_b >> 3] & (1 << (lit_b & 7)))) idx = c->LitData[lit_b];
        else {
            u32 len = c->LitData[lit_b], slot = mp_slot(c, c->DistData[dist_b++]);
            idx = 256 + slot * 8 + (len < 7 ? len : 7);
        }
        fb[idx]++; lit_b++;
    }
    for (k = 0; k < nsym; k++) {
        u32 la = fa[k] >= 0x100 ? bitlen8(fa[k] >> 8) + 8u : bitlen8(fa[k]);
        u32 lb = fb[k] >= 0x100 ? bitlen8(fb[k] >> 8) + 8u : bitlen8(fb[k]);
        i32 d = (i32)square_table[la] - (i32)square_table[lb];
        sum += (u32)(d < 0 ? -d : d);
    }
    return sum;
}

/* 0x41c370 split_block: look for a point in the token buffer where the statistics change.
 * Returns 1 and the split point (a multiple of 64 tokens) or 0 (= take everything). */
static int split_block(lzx_ctx *c, u32 start, u32 end, u32 distances, u32 *plit, u32 *pdist)
{
    u16 matches_so_far[1024 + 8];
    u32 i, count = 0, nbytes = end >> 3;
    *plit = end;
    if (pdist) *pdist = distances;
    if (end - start < 0x1800) return 0;
    if (c->num_block_splits >= 4) return 0;
    memset(matches_so_far, 0, sizeof matches_so_far); /* entries past the end are never read */
    for (i = 0; i < nbytes; i++) {
        if (!(i & 7)) matches_so_far[i >> 3] = (u16)count;
        count += c->popcount[c->ItemType[i]];
    }
    start = (start + 63) & ~63u;
    for (i = start + 0x800; i < end - 0x1000; i += 0x400) {
        u32 j, best = 0, best_j = 0;
        if (tally_diff(c, i, i + 0x400, matches_so_far[i >> 6], matches_so_far[(i + 0x400) >> 6], 0x400) <= 1400) continue;
        if (tally_diff(c, i - 0x400, i + 0x800, matches_so_far[(i - 0x400) >> 6], matches_so_far[(i + 0x800) >> 6], 0x400) <= 1400) continue;
        if (tally_diff(c, i - 0x800, i + 0xc00, matches_so_far[(i - 0x800) >> 6], matches_so_far[(i + 0xc00) >> 6], 0x400) <= 1400) continue;
        for (j = i + 0x200; j < i + 0xa00; j += 0x40) {
            u32 r = tally_diff(c, j - 0x400, j, matches_so_far[(j - 0x400) >> 6], matches_so_far[j >> 6], 0x400);
            if (r > best) { best = r; best_j = j; }
        }
        if (best >= 1700 && best_j - start >= 0x1000) {
            c->num_block_splits++;
            *plit = best_j;
            if (pdist) *pdist = matches_so_far[best_j >> 6];
            return 1;
        }
    }
    return 0;
}

/* ------------------------------------------------------------------------------------------ */
/* block output                                                                                 */

/* 0x41bd60 encode_tree: write code lengths as pretree-coded deltas against the previous tree.
 * len[n] is used as a sentinel (saved / restored), so len must have one spare element. */
static void encode_tree(lzx_ctx *c, u8 *len, u8 *prev, int n)
{
    u16 freq[48], code[24];
    u8 plen[24];
    int i, run;
    u8 saved = len[n];
    memset(freq, 0, sizeof freq);
    len[n] = 0x7b;
    for (i = 0; i < n; i++) {
        u8 v = len[i];
        int j = i + 1;
        run = 0;                       /* number of FOLLOWING equal lengths (the run is run+1 long) */
        while (len[j] == v) { run++; j++; }
        if (run >= 4) {
            if (v == 0) {
                if (run > 51) run = 51;
                if (run <= 19) freq[17]++; else freq[18]++;
            } else {
                if (run > 5) run = 5;
                freq[(prev[i] - v + 17) % 17]++;
                freq[19]++;
            }
            i += run - 1;              /* only `run` elements are consumed: the last one starts the next round */
        } else
            freq[(prev[i] - v + 17) % 17]++;
    }
    make_tree(c, 20, freq, plen, code, 1);
    for (i = 0; i < 20; i++) output_bits(c, 4, plen[i]);
    for (i = 0; i < n; i++) {
        u8 v = len[i];
        int j = i + 1, sym;
        run = 0;
        while (len[j] == v) { run++; j++; }
        if (run >= 4) {
            if (v == 0) { if (run > 51) run = 51; sym = run > 19 ? 18 : 17; }
            else { if (run > 5) run = 5; sym = 19; }
        } else
            sym = (prev[i] - v + 17) % 17;
        output_bits(c, plen[sym], code[sym]);
        if (sym == 17) { output_bits(c, 4, (u32)(run - 4)); i += run - 1; }
        else if (sym == 18) { output_bits(c, 5, (u32)(run - 20)); i += run - 1; }
        else if (sym == 19) {
            int d = (prev[i] - v + 17) % 17;
            output_bits(c, 1, (u32)(run - 4));
            output_bits(c, plen[d], code[d]);
            i += run - 1;
        }
    }
    len[n] = saved;
    memcpy(prev, len, (size_t)n);
}

/* 0x41bd00 */
static void encode_trees(lzx_ctx *c)
{
    encode_tree(c, c->main_len, c->main_prev_len, 256);
    encode_tree(c, c->main_len + 256, c->main_prev_len + 256, (int)c->num_position_slots * 8);
    encode_tree(c, c->secondary_len, c->secondary_prev_len, NUM_SECONDARY);
}

/* 0x41bff0 */
static void encode_aligned_tree(lzx_ctx *c)
{
    int i;
    make_tree(c, 8, c->aligned_freq, c->aligned_len, c->aligned_code, 1);
    for (i = 0; i < 8; i++) output_bits(c, 3, c->aligned_len[i]);
}

/* 0x41cb00 encode_verbatim_block / 0x41cec0 encode_aligned_block */
static void encode_tokens(lzx_ctx *c, u32 lit_count, int aligned)
{
    u32 i, d = 0;
    for (i = 0; i < lit_count; i++) {
        if (!(c->ItemType[i >> 3] & (1 << (i & 7)))) {
            u32 ch = c->LitData[i];
            output_bits(c, c->main_len[ch], c->main_code[ch]);
            c->frame_bytes++;
        } else {
            u32 len = c->LitData[i], mpos = c->DistData[d++], slot = mp_slot(c, mpos), eb;
            if (len < 7) output_bits(c, c->main_len[256 + slot * 8 + len], c->main_code[256 + slot * 8 + len]);
            else {
                output_bits(c, c->main_len[256 + slot * 8 + 7], c->main_code[256 + slot * 8 + 7]);
                output_bits(c, c->secondary_len[len - 7], c->secondary_code[len - 7]);
            }
            eb = extra_bits[slot];
            if (aligned && eb >= 3) {
                if (eb > 3) output_bits(c, (int)eb - 3, (mpos >> 3) & ((1u << (eb - 3)) - 1));
                output_bits(c, c->aligned_len[mpos & 7], c->aligned_code[mpos & 7]);
            } else if (eb)
                output_bits(c, (int)eb, mpos & ((1u << eb) - 1));
            c->frame_bytes += len + 2;
        }
        if (c->frame_bytes == 0x8000) { flush_frame(c); c->num_block_splits = 0; }
    }
}

/* 0x41c970 encode_uncompressed_block */
static void encode_uncompressed_block(lzx_ctx *c, u32 pos, u32 bytes)
{
    const u8 *mw = MW(c);
    u32 i, n = bytes;
    int k;
    output_bits(c, c->bitcount - 16, 0);        /* 1..16 padding bits (16 when already aligned) */
    /* (the original writes these without output_bits' limit; content that leaves too little room would overrun the
       buffer: here it is refused as an error instead) */
#define PUTB(x) do { if (c->outptr >= c->outbuf + OUTBUF_SIZE) longjmp(c->stop, 1); *c->outptr++ = (x); } while (0)
    for (i = 0; i < 3; i++)
        for (k = 0; k < 4; k++) PUTB((u8)(c->S[i] >> (8 * k)));
    for (; n; n--) {
        PUTB(mw[pos++]);
        if (++c->frame_bytes == 0x8000) { flush_frame(c); c->num_block_splits = 0; }
    }
    if (bytes & 1) PUTB(0);
#undef PUTB
    c->bitcount = 32;
    c->bitbuf = 0;
}

/* 0x41c8e0 update the block-boundary repeated offsets by replaying the block's matches */
static void update_last_offsets(lzx_ctx *c, u32 dist_count)
{
    i32 i = (i32)dist_count - 1;
    u8 n = 0;
    for (; i >= 0; i--) {
        if (c->DistData[i] > 2) { if (++n >= 3) break; }
        else n = 0;
    }
    if (n < 3) i = 0;
    for (; i < (i32)dist_count; i++) {
        u32 m = c->DistData[i];
        if (m == 0) continue;
        if (m <= 2) { u32 t = c->S[m]; c->S[m] = c->S[0]; c->S[0] = t; }
        else { c->S[2] = c->S[1]; c->S[1] = c->S[0]; c->S[0] = m - 2; }
    }
}

/* 0x41abe0 output_block: the first lit_count tokens / dist_count matches of the token buffer */
static void output_block(lzx_ctx *c, u32 lit_count, u32 dist_count)
{
    u32 bytes = get_block_stats(c, 0, 0, lit_count);
    int type = get_aligned_stats(c, dist_count);
    make_trees(c, 1);
    if (estimate_block_size(c) >= bytes && c->pos_last_call <= c->pos_block_start) type = 3;
    output_bits(c, 3, (u32)type);
    output_bits(c, 8, (bytes >> 16) & 0xff);
    output_bits(c, 8, (bytes >> 8) & 0xff);
    output_bits(c, 8, bytes & 0xff);
    if (type == 1) {
        encode_trees(c);
        encode_tokens(c, lit_count, 0);
        update_last_offsets(c, dist_count);
    } else if (type == 2) {
        encode_aligned_tree(c);
        encode_trees(c);
        encode_tokens(c, lit_count, 1);
        update_last_offsets(c, dist_count);
    } else {
        update_last_offsets(c, dist_count);
        encode_uncompressed_block(c, c->pos_block_start, bytes);
    }
    c->pos_block_start += bytes;
}

/* 0x41aae0: split, output one block, keep the rest of the token buffer */
static void block_output(lzx_ctx *c)
{
    u32 lit_split, dist_split;
    split_block(c, 0, c->literals, c->distances, &lit_split, &dist_split);
    output_block(c, lit_split, dist_split);
    if (lit_split == c->literals) {
        memset(c->ItemType, 0, 0x2000);
        c->literals = c->distances = 0;
    } else {
        u32 nb = (c->literals >> 3) - (lit_split >> 3) + 1, rest = c->literals - lit_split;
        memmove(c->ItemType, c->ItemType + (lit_split >> 3), nb);
        memset(c->ItemType + (rest >> 3) + 1, 0, 0x1fff - (rest >> 3));
        memmove(c->LitData, c->LitData + lit_split, rest);
        memmove(c->DistData, c->DistData + dist_split, (c->distances - dist_split) * 4);
        c->literals -= lit_split;
        c->distances -= dist_split;
    }
    fix_tree_cost_estimates(c);
}

/* 0x41b7b0 */
static void output_block_and_continue(lzx_ctx *c, u32 BufPos)
{
    c->first_block = 0;
    c->need_full_stats = 1;
    block_output(c);
    c->next_tree_create = c->literals < 0x1000 ? 0x1000 : c->literals + 0x1000;
    c->block_start = BufPos;
}

/* 0x41b740 update_tree_estimates: re-price the symbols from the tokens produced so far */
static void update_tree_estimates(lzx_ctx *c)
{
    if (c->literals == 0) return;
    if (c->need_full_stats) {
        get_block_stats(c, 0, 0, c->literals);
        c->need_full_stats = 0;
    } else
        tally_frequency(c, c->last_literals, c->last_distances, c->literals);
    make_trees(c, 0);
    fix_tree_cost_estimates(c);
    c->last_literals = c->literals;
    c->last_distances = c->distances;
}

/* 0x41b800 redo_first_block: throw the first parse away and start over with real statistics.
 * Only possible while the block's data (and a window before it) is still in the buffer. */
static int redo_first_block(lzx_ctx *c, u32 *pBufPos)
{
    u32 start = c->block_start, ws = c->window_size, lit_split;
    u32 need = *pBufPos - start + (start - ws < ws ? start - ws : ws);
    c->first_block = 0;
    if ((i32)(*pBufPos - c->bias) < (i32)need) return 0;
    split_block(c, 0, c->literals, c->distances, &lit_split, NULL);
    get_block_stats(c, 0, 0, lit_split);
    make_trees(c, 0);
    fix_tree_cost_estimates(c);
    memset(c->root, 0, 65536 * 4);
    memset(c->ItemType, 0, 0x2000);
    c->R[0] = c->R[1] = c->R[2] = 1;
    c->S[0] = c->S[1] = c->S[2] = 1;
    c->need_full_stats = 1;
    c->frame_bytes = 0;
    c->literals = c->distances = 0;
    c->next_tree_create = lit_split;
    *pBufPos = start;
    return 1;
}

/* ------------------------------------------------------------------------------------------ */
/* match finder: binary trees keyed on the first two bytes.                                       */
/* left[] (ctx+0xc) holds the subtree of LARGER strings, right[] (ctx+0x10) the smaller ones.     */

/* 0x41d654 binary_search_findmatch: insert BufPos at the root of its tree, fill
 * matchpos_table[2..len] with the nearest position giving each length, then prefer the repeated
 * offsets.  Returns the longest length (0 = none), clipped so that a match never reaches the last
 * byte of a 32 KiB frame. */
static int findmatch(lzx_ctx *c, u32 BufPos)
{
    const u8 *w = MW(c);
    u32 *left = LEFT(c), *right = RIGHT(c);
    u32 h = w[BufPos] | ((u32)w[BufPos + 1] << 8);
    u32 ptr = c->root[h], end_pos = BufPos + 4 - c->window_size;
    u32 *A = &left[BufPos], *B = &right[BufPos], *tbl = c->matchpos_table;
    int same = 2, big = 2, small = 2, best = 2, len, i, len0, lim;

    STEP(c);
    c->root[h] = BufPos;
    if ((i32)ptr <= (i32)end_pos) { left[BufPos] = 0; right[BufPos] = 0; return 0; } /* 0x41d9b0 */
    tbl[2] = BufPos + 2 - ptr;
    for (;;) {
        STEP(c);
        len = same;
        while (len < MAX_MATCH && w[ptr + len] == w[BufPos + len]) len++;
        if (len >= MAX_MATCH) {                         /* 0x41d771 / 0x41d805 */
            for (i = best + 1; i <= MAX_MATCH; i++) tbl[i] = BufPos + 2 - ptr;
            best = MAX_MATCH;
            goto replace;
        }
        if (w[ptr + len] > w[BufPos + len]) {           /* 0x41d813: the tree string is larger */
            if (len > big) {
                if (len > best) {
                    for (i = best + 1; i <= len; i++) tbl[i] = BufPos + 2 - ptr;
                    best = len;
                    if (len >= BREAK_LENGTH) goto replace;
                }
                big = len;
                same = len < small ? len : small;
            }
            *A = ptr; A = &right[ptr]; ptr = *A;        /* 0x41d858 */
        } else {                                        /* 0x41d79c: the tree string is smaller */
            if (len > small) {
                if (len > best) {
                    for (i = best + 1; i <= len; i++) tbl[i] = BufPos + 2 - ptr;
                    best = len;
                    if (len >= BREAK_LENGTH) goto replace;
                }
                small = len;
                same = len < big ? len : big;
            }
            *B = ptr; B = &left[ptr]; ptr = *B;         /* 0x41d7d9 */
        }
        if (ptr <= end_pos) { *A = 0; *B = 0; break; }  /* 0x41d882 */
    }
    goto reps;
replace:                                                /* 0x41d77b: the new node takes the old one's place */
    *A = left[ptr];
    *B = right[ptr];
reps:
    /* 0x41d896: repeated offsets, compared only up to the tree's best length */
    for (len = 0; len < best && w[BufPos + len] == w[BufPos - c->R[0] + len]; len++) ;
    if (len == best) { for (i = len; i >= 2; i--) tbl[i] = 0; goto done; }
    len0 = len;
    if (len >= 2) {
        for (i = len; i >= 2; i--) tbl[i] = 0;
        if (len0 > BREAK_LENGTH) goto done;
    }
    for (len = 0; len < best && w[BufPos + len] == w[BufPos - c->R[1] + len]; len++) ;
    if (len == best) { for (i = len; i >= 2; i--) tbl[i] = 1; goto done; }
    if (len > len0) { for (i = len0 + 1; i <= len; i++) tbl[i] = 1; len0 = len; }
    for (len = 0; len < best && w[BufPos + len] == w[BufPos - c->R[2] + len]; len++) ;
    if (len == best) { for (i = len; i >= 2; i--) tbl[i] = 2; goto done; }
    if (len > len0) { for (i = len0 + 1; i <= len; i++) tbl[i] = 2; }
done:
    lim = 0x7fff - (int)(BufPos & 0x7fff);              /* 0x41d989 */
    if (best > lim) { best = lim; if (lim < 2) best = 0; }
    return best;
}

/* 0x41d410 quick_insert_bsearch_findmatch: insert without collecting matches (compares at most 50 bytes) */
static void quick_insert(lzx_ctx *c, u32 BufPos, u32 end_pos)
{
    const u8 *w = MW(c);
    u32 *left = LEFT(c), *right = RIGHT(c);
    u32 h = w[BufPos] | ((u32)w[BufPos + 1] << 8);
    u32 ptr = c->root[h];
    u32 *A = &left[BufPos], *B = &right[BufPos];
    int same = 2, big = 2, small = 2, len;

    STEP(c);
    c->root[h] = BufPos;
    if ((i32)ptr <= (i32)end_pos) { right[BufPos] = 0; left[BufPos] = 0; return; }
    for (;;) {
        int diff = 0;
        STEP(c);
        len = same;
        do {
            diff = (int)w[ptr + len] - (int)w[BufPos + len];
            if (diff) break;
            len++;
        } while (len < BREAK_LENGTH);
        if (diff < 0) {                                 /* tree string smaller */
            if (len > small) {
                if (len >= BREAK_LENGTH) break;
                small = len;
                same = len < big ? len : big;
            }
            *B = ptr; B = &left[ptr]; ptr = *B;
        } else {                                        /* larger, or equal for 50 bytes */
            if (len > big) {
                if (len >= BREAK_LENGTH) break;
                big = len;
                same = len < small ? len : small;
            }
            *A = ptr; A = &right[ptr]; ptr = *A;
        }
        if ((i32)ptr <= (i32)end_pos) { *A = 0; *B = 0; return; }
    }
    *A = left[ptr];                                     /* 0x41d555 / 0x41d579 */
    *B = right[ptr];
}

/* 0x41d5a0 binary_search_remove_node: only a node that is still the root of its tree is removed */
static void remove_node(lzx_ctx *c, u32 BufPos, u32 end_pos)
{
    const u8 *w = MW(c);
    u32 *left = LEFT(c), *right = RIGHT(c);
    u32 h = w[BufPos] | ((u32)w[BufPos + 1] << 8);
    u32 *link = &c->root[h], l, r;
    if (*link != BufPos) return;
    if (end_pos >= BufPos) { *link = 0; right[BufPos] = 0; left[BufPos] = 0; return; }
    l = left[BufPos];
    if (end_pos >= l) { left[BufPos] = 0; l = 0; }
    r = right[BufPos];
    if (end_pos >= r) { right[BufPos] = 0; r = 0; }
    for (;;) {
        STEP(c);
        if (r < l) {
            if (end_pos >= l) l = 0;
            *link = l;
            if (!l) return;
            link = &right[l];
            l = *link;
        } else {
            if (end_pos >= r) r = 0;
            *link = r;
            if (!r) return;
            link = &left[r];
            r = *link;
        }
    }
}

/* ------------------------------------------------------------------------------------------ */
/* the parser: 0x41ade0                                                                         */

static inline u32 match_cost(const lzx_ctx *c, u32 len, u32 mpos)
{
    u32 slot = mp_slot(c, mpos);
    if (len < 9) return (u32)c->main_len[256 + slot * 8 + len - 2] + extra_bits[slot];
    return (u32)c->main_len[256 + slot * 8 + 7] + c->secondary_len[len - 9] + extra_bits[slot];
}

static inline void add_literal(lzx_ctx *c, u8 ch) { c->LitData[c->literals++] = ch; }
static inline void add_match(lzx_ctx *c, u32 len, u32 mpos)
{
    c->ItemType[c->literals >> 3] |= (u8)(1 << (c->literals & 7));
    c->LitData[c->literals++] = (u8)(len - 2);
    if (c->distances >= MAX_DIST_ITEMS)
        /* original bug: after a statistical split that removed few matches, a whole optimal pass is appended
         * without a capacity check (0x41b40a..0x41b418) and runs past the 0x8000-entry buffer: from here the
         * original's output depends on its heap layout, so this is not reproducible — "not this encoder" */
        longjmp(c->stop, 2);
    memcpy((u8 *)c->DistData + (size_t)c->distances++ * 4, &mpos, 4);
}
static inline void update_reps(lzx_ctx *c, u32 mpos)
{
    if (mpos >= 3) { c->R[2] = c->R[1]; c->R[1] = c->R[0]; c->R[0] = mpos - 2; }
    else if (mpos != 0) { u32 t = c->R[0]; c->R[0] = c->R[mpos]; c->R[mpos] = t; }
}
/* the positions covered by a taken match enter the trees too; a long run of one byte only once */
static inline void insert_match_tail(lzx_ctx *c, u32 BufPos, u32 len, u32 mpos)
{
    u32 i;
    if (mpos == 3 && len > 16) quick_insert(c, BufPos + 1, BufPos - c->window_size + 5);
    else for (i = 1; i < len; i++) quick_insert(c, BufPos + i, BufPos + i - c->window_size + 4);
}

static void opt_encode(lzx_ctx *c, u32 bytes_read)
{
    u32 BufPos = c->BufPos, BufPosEnd = BufPos + bytes_read, i;
    const u8 *w;
    node_t *dd = c->dd;

    if (c->first_time) {
        c->first_time = 0;
        c->next_tree_create = 10000;
        if (c->file_size) {
            output_bits(c, 1, 1);
            output_bits(c, 16, c->file_size >> 16);
            output_bits(c, 16, c->file_size & 0xffff);
        } else
            output_bits(c, 1, 0);
    } else {
        /* the last 50 positions of the previous call were taken out of the trees (their strings
         * were not complete yet): put them back */
        for (i = BREAK_LENGTH; i > 0; i--) quick_insert(c, BufPos - i, BufPos - c->window_size + 4);
    }

    for (;;) {
        while (BufPos < BufPosEnd) {                    /* 0x41ae9e */
            u32 MatchLen;
            w = MW(c);
            MatchLen = (u32)findmatch(c, BufPos);
            if (MatchLen >= 2 && BufPos + MatchLen > BufPosEnd) MatchLen = BufPosEnd - BufPos;
            if (MatchLen < 2) {                         /* 0x41b5d7 */
                add_literal(c, w[BufPos]);
                BufPos++;
                if (c->literals >= 0xfff8) output_block_and_continue(c, BufPos);
                continue;
            }
            if (MatchLen >= BREAK_LENGTH) {             /* 0x41b503: long match, take it at once */
                u32 mpos = c->matchpos_table[MatchLen];
                insert_match_tail(c, BufPos, MatchLen, mpos);
                BufPos += MatchLen;
                add_match(c, MatchLen, mpos);
                update_reps(c, mpos);
                if (c->literals >= 0xfff8 || c->distances >= 0x7ff8) output_block_and_continue(c, BufPos);
                continue;
            }
            /* ---- optimal pass (0x41aeeb) ---- */
            {
                u32 start = BufPos, span_end = BufPos + MatchLen, limit = BufPos + LOOK, ntok, len;
#define N(p) dd[(p) - start]
                dd[1].numbits = c->main_len[w[BufPos]];
                dd[1].path = BufPos;
                for (len = 2; len <= MatchLen; len++) {
                    dd[len].numbits = match_cost(c, len, c->matchpos_table[len]);
                    dd[len].path = BufPos;
                    dd[len].link = c->matchpos_table[len];
                }
                dd[0].numbits = 0;
                dd[0].rep[0] = c->R[0]; dd[0].rep[1] = c->R[1]; dd[0].rep[2] = c->R[2];
                for (;;) {                              /* 0x41b065 */
                    node_t *n;
                    u32 cum, cost, ml;
                    BufPos++;
                    n = &N(BufPos);
                    if (n->path != BufPos - 1) {        /* arrived by a match: rebuild the repeated offsets */
                        const node_t *p = &N(n->path);
                        if (n->link >= 3) { c->R[0] = n->link - 2; c->R[1] = p->rep[0]; c->R[2] = p->rep[1]; }
                        else if (n->link == 0) { c->R[0] = p->rep[0]; c->R[1] = p->rep[1]; c->R[2] = p->rep[2]; }
                        else if (n->link == 1) { c->R[0] = p->rep[1]; c->R[1] = p->rep[0]; c->R[2] = p->rep[2]; }
                        else { c->R[0] = p->rep[2]; c->R[1] = p->rep[1]; c->R[2] = p->rep[0]; }
                    }
                    n->rep[0] = c->R[0]; n->rep[1] = c->R[1]; n->rep[2] = c->R[2];
                    if (BufPos == span_end) break;      /* every path meets here: 0x41b3c9 */
                    ml = (u32)findmatch(c, BufPos);
                    if (BufPos + ml > BufPosEnd) { ml = BufPosEnd - BufPos; if (ml < 2) ml = 0; }
                    if (ml > BREAK_LENGTH || BufPos + ml >= limit) {
                        /* 0x41b317: long match (or look-ahead exhausted): the pass ends with it */
                        u32 mpos = c->matchpos_table[ml];
                        N(BufPos + ml).link = mpos;
                        N(BufPos + ml).path = BufPos;
                        insert_match_tail(c, BufPos, ml, mpos);
                        BufPos += ml;
                        update_reps(c, mpos);
                        break;
                    }
                    if ((ml > 2 || (ml == 2 && c->matchpos_table[2] < 0x800)) && BufPos + ml > span_end) {
                        u32 hi = BufPos - start + ml, lo = span_end - start + 1;
                        if (hi > 0xefc) hi = 0xefc;
                        for (; lo <= hi; lo++) dd[lo].numbits = 0xffffffff;
                        span_end = BufPos + ml;
                    }
                    cum = n->numbits;                   /* 0x41b1c5 */
                    cost = cum + c->main_len[w[BufPos]];
                    if (N(BufPos + 1).numbits > cost) { N(BufPos + 1).numbits = cost; N(BufPos + 1).path = BufPos; }
                    for (len = 2; len <= ml; len++) {
                        u32 mpos = c->matchpos_table[len];
                        node_t *t = &N(BufPos + len);
                        cost = cum + match_cost(c, len, mpos);
                        if (t->numbits > cost) { t->numbits = cost; t->path = BufPos; t->link = mpos; }
                    }
                }
                /* 0x41b3c9: reverse the path */
                {
                    u32 cur = BufPos, prev = N(BufPos).path, t;
                    ntok = 0;
                    for (;;) {
                        t = N(prev).path;
                        N(prev).path = cur;
                        ntok++;
                        cur = prev;
                        if (prev == start) break;
                        prev = t;
                    }
                    BufPos = start;
                }
                if (c->literals + ntok >= 0xfff8 || c->distances + ntok >= 0x7ff8)
                    output_block_and_continue(c, BufPos);
                for (; ntok; ntok--) {                  /* 0x41b418 */
                    u32 next = N(BufPos).path;
                    if (next > BufPos + 1) { add_match(c, next - BufPos, N(next).link); BufPos = next; }
                    else { add_literal(c, w[BufPos]); BufPos++; }
                }
#undef N
                if (c->literals >= c->next_tree_create) { update_tree_estimates(c); c->next_tree_create += 0x1000; }
                if (c->first_block && (c->literals >= 0xfe00 || c->distances >= 0x7e00)) {
                    if (!redo_first_block(c, &BufPos)) output_block_and_continue(c, BufPos);
                }
            }
        }
        /* 0x41b618 */
        c->pos_last_call = BufPos - c->window_size;
        if (bytes_read < 0x8000) {
            if (c->first_block && redo_first_block(c, &BufPos)) continue;
            break;
        }
        for (i = 1; i <= BREAK_LENGTH; i++) remove_node(c, BufPos - i, BufPos - c->window_size + 4 + BREAK_LENGTH);
        if (BufPos - c->bias < c->window_size + c->second_partition) break;
        if (c->first_block && redo_first_block(c, &BufPos)) continue;
        /* slide the window down by one partition (its copying is work too: counted against the bound, a step per 64
           bytes moved) */
        c->steps += ((uint64_t)c->window_size * 9) >> 6;
        if (c->steps > c->limit) longjmp(c->stop, 4);
        memmove(c->real_window, c->real_window + c->second_partition, c->window_size);
        memmove(c->real_left, c->real_left + c->second_partition, (size_t)c->window_size * 4);
        memmove(c->real_right, c->real_right + c->second_partition, (size_t)c->window_size * 4);
        c->pos_last_call = BufPos - c->window_size;
        c->bias += c->second_partition;
        break;
    }
    c->BufPos = BufPos;
}

/* ------------------------------------------------------------------------------------------ */
/* input + E8 translation                                                                        */

/* 0x41baf0 */
static void translate_e8(lzx_ctx *c, u8 *mem, i32 bytes)
{
    u8 temp[6], *p = mem;
    u32 end_instr_pos;
    if (bytes <= 6) { c->instr_pos += (u32)bytes; return; }
    memcpy(temp, mem + bytes - 6, 6);
    memset(mem + bytes - 6, 0xe8, 6);
    end_instr_pos = c->instr_pos + (u32)bytes - 6;
    for (;;) {
        u32 value, absolute;
        while (*p++ != 0xe8) c->instr_pos++;
        if (end_instr_pos <= c->instr_pos) break;
        value = (u32)p[0] | ((u32)p[1] << 8) | ((u32)p[2] << 16) | ((u32)p[3] << 24);
        absolute = c->instr_pos + value;
        if ((i32)absolute >= 0 && c->instr_pos + c->file_size > absolute) {
            u32 v = c->file_size <= absolute ? value - c->file_size : absolute;
            p[0] = (u8)v; p[1] = (u8)(v >> 8); p[2] = (u8)(v >> 16); p[3] = (u8)(v >> 24);
        }
        c->instr_pos += 5;
        p += 4;
    }
    memcpy(mem + bytes - 6, temp, 6);
    c->instr_pos = end_instr_pos + 6;
}

/* 0x41b9f0 (+0x41ba70) */
static i32 read_input(lzx_ctx *c, u32 offset, i32 want)
{
    i32 n = want <= c->in_size ? want : c->in_size;
    if (n <= 0) return 0;
    memcpy(c->real_window + offset, c->in, (size_t)n);
    c->in += n; c->in_size -= n;
    if (c->translate && c->file_size != 0 && c->num_calls < 0x8000) translate_e8(c, c->real_window + offset, n);
    c->num_calls++;
    return n;
}

/* ------------------------------------------------------------------------------------------ */
/* API                                                                                           */

/* 0x41a660 LZX_EncodeNewGroup (LCIResetCompression).  NOT reset: the frequency tables, the
 * left/right arrays, the window contents, last_literals / last_distances. */
static void lzx_reset(lzx_ctx *c)
{
    memset(c->root, 0, 65536 * 4);
    c->bias = c->window_size;       /* window pointer = real - window_size, trees likewise */
    c->BufPos = c->window_size;
    c->R[0] = c->R[1] = c->R[2] = 1;
    c->S[0] = c->S[1] = c->S[2] = 1;
    c->first_block = 1;
    c->need_full_stats = 1;
    c->block_start = c->window_size;
    c->bitcount = 32; c->bitbuf = 0; c->output_overflow = 0;
    memset(c->main_prev_len, 0, 256 + 8 * c->num_position_slots);
    memset(c->secondary_prev_len, 0, NUM_SECONDARY);
    memset(c->main_len, 8, 256);
    memset(c->main_len + 256, 9, 8 * c->num_position_slots);
    memset(c->secondary_len, 6, NUM_SECONDARY);
    memset(c->aligned_len, 3, 8);
    prevent_far_matches(c);
    c->pos_block_start = c->BufPos;
    c->pos_last_call = c->BufPos;
    c->first_time = 1;
    c->frame_bytes = 0;
    memset(c->ItemType, 0, 0x2000);
    c->literals = c->distances = 0;
    c->num_block_splits = 0;
    c->instr_pos = 0;               /* 0x41b9e0 */
    c->num_calls = 0;
}

/* 0x418c20 + 0x41a7c0 LZX_EncodeInit */
static void lzx_free(lzx_ctx *c);
static lzx_ctx *lzx_init(u32 window_size, u32 second_partition)
{
    lzx_ctx *c = calloc(1, sizeof *c);
    u32 pos = 4, i, n, s;
    if (!c) return NULL;
    if (second_partition & 0x7fff) second_partition &= 0xffff8000u;
    if (second_partition < 0x8000) second_partition = 0x8000;
    if (window_size < 0x8000) { free(c); return NULL; }
    c->window_size = window_size;
    c->second_partition = second_partition;
    c->num_position_slots = 4;
    do {
        c->num_position_slots++;
        pos += 1u << extra_bits[c->num_position_slots - 1];
    } while (pos < window_size);
    c->root = calloc(65536, 4);
    c->real_left = calloc((size_t)(window_size + second_partition) * 4 + 0x4404, 1);
    c->real_right = calloc((size_t)(window_size + second_partition) * 4 + 0x4404, 1);
    c->real_window = calloc((size_t)window_size + second_partition + 0x1101, 1);
    c->LitData = calloc(0x10000, 1);
    /* The match buffer CAN OVERFLOW in the original (see add_match / NOTES.md "DistData overflow").  In the
     * oracle's process (Wine heap) the output buffer starts 8 bytes after the end of the match buffer, so the
     * overflowing entries land in the pending frame's first bytes.  One arena reproduces that aliasing. */
    c->DistData = calloc(0x20000 + 8 + OUTBUF_SIZE + 64, 1);
    c->ItemType = calloc(0x2000, 1);
    c->dd = calloc(NUM_NODES, sizeof(node_t));
    c->outbuf = c->outptr = c->DistData ? (u8 *)c->DistData + 0x20000 + 8 : NULL;
    if (!c->root || !c->real_left || !c->real_right || !c->real_window || !c->LitData || !c->DistData || !c->ItemType || !c->dd || !c->outbuf)
        { lzx_free(c); return NULL; }
    /* 0x41c040 slot table */
    c->slot_table[0] = 0; c->slot_table[1] = 1; c->slot_table[2] = 2; c->slot_table[3] = 3;
    for (pos = 4, n = 2, s = 4; pos < 1024; n *= 2) {
        memset(c->slot_table + pos, (int)s++, n); pos += n;
        memset(c->slot_table + pos, (int)s++, n); pos += n;
    }
    /* 0x41c0f0 popcount table */
    for (i = 0; i < 256; i++) { u32 v = i, b = 0; for (; v; v >>= 1) b += v & 1; c->popcount[i] = (u8)b; }
    lzx_reset(c);
    return c;
}

/* 0x418cd0 LZX_Encode (LCICompress): one call per <= 32768 input bytes */
static void lzx_compress(lzx_ctx *c, const u8 *in, i32 n, u32 file_size)
{
    i32 got;
    c->in = in; c->in_size = n; c->file_size = file_size;
    got = read_input(c, c->BufPos - c->bias, 0x8000);   /* 0x41ada0 */
    if (got > 0) opt_encode(c, (u32)got);
    /* 0x41ad40: the size estimate handed back to FCI re-prices the symbols as a side effect */
    make_trees(c, 0);
    (void)estimate_block_size(c);
    fix_tree_cost_estimates(c);
}

/* 0x41ad70 LZX_EncodeFlush (LCIFlushCompressorOutput) */
static void lzx_flush(lzx_ctx *c)
{
    while (c->literals > 0) block_output(c);
    flush_frame(c);
}


/* ------------------------------------------------------------------------------------------ */
/* the engine's API (lzxmakecab.h)                                                              */

struct LzxMakecab { lzx_ctx *c; int dead; };

static void lzx_free(lzx_ctx *c)
{
    if (!c) return;
    free(c->root); free(c->real_left); free(c->real_right); free(c->real_window); free(c->LitData); free(c->DistData);
    free(c->ItemType); free(c->dd); free(c);
}

LzxMakecab *LzxMakecabNew(uint32_t window_bits, uint32_t second_partition)
{
    LzxMakecab *m;
    if (window_bits < 15 || window_bits > 21 || second_partition > (1u << 20)) return NULL;
    m = calloc(1, sizeof *m);
    if (!m) return NULL;
    m->c = lzx_init(1u << window_bits, second_partition);
    if (!m->c) { free(m); return NULL; }
    m->c->limit = UINT64_MAX;
    return m;
}

void LzxMakecabFree(LzxMakecab *m) { if (m) { lzx_free(m->c); free(m); } }
int LzxMakecabNextFolderWindow(LzxMakecab *m, uint32_t window_bits, uint32_t second_partition)
{
    lzx_ctx *c;
    if (!m || m->dead || window_bits < 15 || window_bits > 21 || second_partition > (1u << 20)) return LZXMK_ERROR;
    c = lzx_init(1u << window_bits, second_partition);
    if (!c) return LZXMK_ERROR;
    /* MAKECAB makes its compressor anew for another CompressionMemory; the frequency tables, which no reset clears, carry
       over (they price the new folder's first chunk: probed, a 21-then-16 cabinet) */
    memcpy(c->main_freq, m->c->main_freq, sizeof c->main_freq);
    memcpy(c->secondary_freq, m->c->secondary_freq, sizeof c->secondary_freq);
    memcpy(c->aligned_freq, m->c->aligned_freq, sizeof c->aligned_freq);
    c->steps = m->c->steps; c->limit = m->c->limit;
    lzx_free(m->c); m->c = c;
    return LZXMK_OK;
}

void LzxMakecabLimit(LzxMakecab *m, uint64_t steps) { if (m) m->c->limit = steps; }
uint64_t LzxMakecabSteps(const LzxMakecab *m) { return m ? m->c->steps : 0; }

int LzxMakecabNextFolder(LzxMakecab *m)
{
    if (!m || m->dead) return LZXMK_ERROR;
    if (setjmp(m->c->stop)) { m->dead = 1; return LZXMK_ERROR; }
    lzx_reset(m->c);
    return LZXMK_OK;
}

int LzxMakecabCompress(LzxMakecab *m, const uint8_t *in, uint32_t n, uint32_t e8_size, int translate, LzxFrameSink sink, void *arg)
{
    int r;
    if (!m || m->dead || n == 0 || n > 0x8000) return LZXMK_ERROR;
    m->c->translate = translate; m->c->sink = sink; m->c->sink_arg = arg;
    if ((r = setjmp(m->c->stop)) != 0) { m->dead = 1; return r == 2 ? LZXMK_NOT_THIS : r == 3 ? LZXMK_STOPPED : r == 4 ? LZXMK_OVER : LZXMK_ERROR; }
    lzx_compress(m->c, in, (i32)n, e8_size);
    return LZXMK_OK;
}

int LzxMakecabFlush(LzxMakecab *m, LzxFrameSink sink, void *arg)
{
    int r;
    if (!m || m->dead) return LZXMK_ERROR;
    m->c->sink = sink; m->c->sink_arg = arg;
    if ((r = setjmp(m->c->stop)) != 0) { m->dead = 1; return r == 2 ? LZXMK_NOT_THIS : r == 3 ? LZXMK_STOPPED : r == 4 ? LZXMK_OVER : LZXMK_ERROR; }
    lzx_flush(m->c);
    if (m->c->output_overflow) { m->dead = 1; return LZXMK_ERROR; }
    return LZXMK_OK;
}
