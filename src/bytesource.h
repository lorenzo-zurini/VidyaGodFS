#ifndef VIDYAGODFS_BYTESOURCE_H
#define VIDYAGODFS_BYTESOURCE_H

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <cerrno>
#include <vector>
#include <sys/types.h>
#include <unistd.h>

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
    ~FdByteSource() override { if (own && fd >= 0) ::close(fd); }
    ssize_t pread(void *buf, size_t n, uint64_t off) override {
        ssize_t r = ::pread(fd, buf, n, static_cast<off_t>(off));
        return r < 0 ? -errno : r;
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

#endif // VIDYAGODFS_BYTESOURCE_H
