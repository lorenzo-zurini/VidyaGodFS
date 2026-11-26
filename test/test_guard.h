#ifndef VIDYAGODFS_TEST_GUARD_H
#define VIDYAGODFS_TEST_GUARD_H

// A test binary must never take the machine down with it. A mutant that removes a bound (a hostile record's count
// obeyed, say) makes a test allocate without end; on 2026-11-26 one grew to 16 GB of RAM plus all of swap and froze the
// PC, because it inherited the OOM protection of the session that started it, so the OOM killer took everything else
// first. So every test binary, first thing:
//   - asks to be the OOM killer's FIRST choice (raising one's own oom_score_adj needs no privilege), and
//   - caps its address space (VGFS_TEST_MEM_GB, default 8), so an endless allocation fails at once as bad_alloc, which
//     the run reports as a failure instead of a frozen desktop. Sanitizer builds reserve terabytes of shadow address
//     space, so they keep only the first guard.
#if defined(__linux__)
#include <cstdio>
#include <cstdlib>
#include <sys/resource.h>

#if defined(__SANITIZE_ADDRESS__) || defined(__SANITIZE_THREAD__)
#define VGFS_TEST_SANITIZED 1
#elif defined(__has_feature)
#if __has_feature(address_sanitizer) || __has_feature(thread_sanitizer) || __has_feature(memory_sanitizer)
#define VGFS_TEST_SANITIZED 1
#endif
#endif

inline void GuardTestProcess()
{
    if (FILE *f = std::fopen("/proc/self/oom_score_adj", "w")) { std::fputs("1000", f); std::fclose(f); }
#ifndef VGFS_TEST_SANITIZED
    unsigned long gb = 8;
    if (const char *e = std::getenv("VGFS_TEST_MEM_GB")) gb = std::strtoul(e, nullptr, 10);
    if (gb) {
        rlimit r{};
        r.rlim_cur = r.rlim_max = (rlim_t)gb << 30;
        setrlimit(RLIMIT_AS, &r);
    }
#endif
}
#else
inline void GuardTestProcess() {}
#endif

#endif // VIDYAGODFS_TEST_GUARD_H
