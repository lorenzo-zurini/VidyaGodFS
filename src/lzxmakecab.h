#ifndef VIDYAGODFS_LZXMAKECAB_H
#define VIDYAGODFS_LZXMAKECAB_H
/* The LZX compressor of Microsoft Cabinet Maker 1.00 (1997), reimplemented (lzxmakecab.c): the coding algebra's LZX
 * encoder family. One context compresses a cabinet's folders in order (some state survives between folders, as in
 * MAKECAB); each folder is fed in calls of at most 32 KiB, then flushed; every CFDATA payload is handed to the sink as it
 * is made (payload, cbUncomp). A sink returning nonzero stops the run. */
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
enum { LZXMK_OK = 0, LZXMK_ERROR = 1, LZXMK_NOT_THIS = 2, LZXMK_STOPPED = 3, LZXMK_OVER = 4 };
/* NOT_THIS: the input drives the original past its match buffer (its own output depended on its heap layout there):
 * no reproduction exists. Any result but OK leaves the context unusable. */
typedef int (*LzxFrameSink)(void *arg, const uint8_t *payload, uint32_t n, uint32_t uncompressed);
typedef struct LzxMakecab LzxMakecab;
LzxMakecab *LzxMakecabNew(uint32_t window_bits /* 15..21 */, uint32_t second_partition /* MAKECAB: 0x10000 */);
void LzxMakecabFree(LzxMakecab *m);
/* The match finder's work: steps so far (cumulative over the context's life), and the total it may reach (default: no
 * bound). Past it the call stops with LZXMK_OVER: its binary trees have no depth limit, so crafted input could be slow. */
void LzxMakecabLimit(LzxMakecab *m, uint64_t steps);
uint64_t LzxMakecabSteps(const LzxMakecab *m);
int LzxMakecabNextFolder(LzxMakecab *m);   /* between folders (not before the first) */
/* between folders, the next one of another window or second partition (MAKECAB: a new CompressionMemory) */
int LzxMakecabNextFolderWindow(LzxMakecab *m, uint32_t window_bits, uint32_t second_partition);
int LzxMakecabCompress(LzxMakecab *m, const uint8_t *in, uint32_t n /* 1..32768 */, uint32_t e8_size, int translate,
                       LzxFrameSink sink, void *arg);
int LzxMakecabFlush(LzxMakecab *m, LzxFrameSink sink, void *arg);
#ifdef __cplusplus
}
#endif
#endif
