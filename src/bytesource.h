#ifndef VIDYAGODFS_BYTESOURCE_H
#define VIDYAGODFS_BYTESOURCE_H

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <cerrno>
#include <vector>
#include <memory>
#include <sys/types.h>
#include "hostio.h"    // host fd I/O behind the backend-neutral shim (Pread/Close)

// ---------------------------------------------------------------------------
// ByteSource — a random-access, read-only, thread-safe byte stream. This is the ONE abstraction the zip
// layer reads through, so a zip archive's bytes can come from a plain file (FdByteSource), an in-memory
// buffer (MemByteSource), or — the point of all this — a binary delta over ANOTHER ByteSource
// (DeltaByteSource, in vgdelta.h). Nothing is ever materialized: pread computes where to read from.
// pread has no shared cursor, so concurrent reads on one source are safe.
// ---------------------------------------------------------------------------
struct ByteSource {
    virtual ~ByteSource() = default;

    // Reads up to n bytes at absolute offset off into buf. Returns bytes read (>=0, short only at/near EOF)
    // or -errno. Implementations must be safe to call concurrently.
    virtual ssize_t pread(void *buf, size_t n, uint64_t off) = 0;
    virtual uint64_t size() const = 0;

    // Reads EXACTLY n bytes across any short reads; false on EOF/error. Convenience for header/CD parsers.
    bool preadAll(void *buf, size_t n, uint64_t off) {
        uint8_t *p = static_cast<uint8_t *>(buf);
        size_t done = 0;
        while (done < n) {
            ssize_t r = pread(p + done, n - done, off + done);
            if (r <= 0) return false;
            done += static_cast<size_t>(r);
        }
        return true;
    }
};

// Wraps an O_RDONLY fd (borrowed by default, owned when own=true). ::pread has no shared offset → thread-safe.
struct FdByteSource : ByteSource {
    int      fd  = -1;
    bool     own = false;
    uint64_t sz  = 0;
    FdByteSource(int f, uint64_t s, bool owns = false) : fd(f), own(owns), sz(s) {}
    ~FdByteSource() override { if (own && fd >= 0) HostIO::Close(fd); }
    ssize_t pread(void *buf, size_t n, uint64_t off) override {
        return HostIO::Pread(fd, buf, n, off);   // returns bytes read (>=0) or -errno
    }
    uint64_t size() const override { return sz; }
};

// Wraps an owned in-memory buffer (authoring byte-verification + tests).
struct MemByteSource : ByteSource {
    std::vector<uint8_t> data;
    explicit MemByteSource(std::vector<uint8_t> d) : data(std::move(d)) {}
    ssize_t pread(void *buf, size_t n, uint64_t off) override {
        if (off >= data.size()) return 0;
        size_t avail = data.size() - static_cast<size_t>(off);
        size_t want  = n < avail ? n : avail;
        std::memcpy(buf, data.data() + off, want);
        return static_cast<ssize_t>(want);
    }
    uint64_t size() const override { return data.size(); }
};

// ---------------------------------------------------------------------------
// ConcatByteSource — stitches N ByteSources into ONE contiguous address space, back to back in a fixed order.
// This is what makes a MULTI-BASE delta possible with NO format change: a .vgdelta's COPY offsets index into
// this concatenation, so one delta can pull identical runs from wine ‖ dxvk ‖ prev-prefix ‖ … The parts are
// themselves ByteSources (often DeltaByteSources reconstructing their own chains) — nothing is materialized;
// pread dispatches to the part covering an offset and splits reads that straddle a boundary. Order + each
// part's bytes must match what generation concatenated (deterministic reconstruction guarantees this).
// ---------------------------------------------------------------------------
struct ConcatByteSource : ByteSource {
    struct Part { std::shared_ptr<ByteSource> src; uint64_t start; uint64_t len; };
    std::vector<Part> parts;
    uint64_t total = 0;
    explicit ConcatByteSource(const std::vector<std::shared_ptr<ByteSource>> &sources) {
        for (const auto &s : sources) {
            const uint64_t len = s ? s->size() : 0;
            parts.push_back({s, total, len});
            total += len;
        }
    }
    ssize_t pread(void *buf, size_t n, uint64_t off) override {
        if (off >= total) return 0;
        uint8_t *p = static_cast<uint8_t *>(buf);
        size_t done = 0;
        while (done < n && off + done < total) {
            const uint64_t pos = off + done;
            // locate the part covering `pos` (binary search over start offsets; parts are ordered + contiguous)
            size_t lo = 0, hi = parts.size();
            while (lo + 1 < hi) { size_t mid = (lo + hi) / 2; if (parts[mid].start <= pos) lo = mid; else hi = mid; }
            const Part &pt = parts[lo];
            if (pt.len == 0 || pos >= pt.start + pt.len) break;   // gap/empty part → stop (short read)
            const uint64_t local = pos - pt.start;
            size_t want = n - done;
            const uint64_t avail = pt.len - local;
            if (want > avail) want = static_cast<size_t>(avail);
            const ssize_t r = pt.src->pread(p + done, want, local);
            if (r <= 0) return done > 0 ? static_cast<ssize_t>(done) : r;
            done += static_cast<size_t>(r);
        }
        return static_cast<ssize_t>(done);
    }
    uint64_t size() const override { return total; }
};

#endif // VIDYAGODFS_BYTESOURCE_H
