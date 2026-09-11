# VidyaGodFS

`vidyagodfs` is the runtime filesystem for [VidyaGod](https://github.com/lorenzo-zurini/VidyaGod): a **single FUSE
mount** that assembles a game's entire runtime from a stack of layers — read-only `zip`/`dir`/`file`/`delta`
under-layers rooted at their targets, a writable copy-on-write top layer, and RW passthroughs for persisted state. It
replaces the former unionfs-fuse + fuse-zip + bindfs stack with one in-process filesystem.

It also builds and composes **`.vgdelta`** binary deltas (`vgdelta.*`), which is how a long version history ships as one
chain instead of N archives.

## Build

```bash
# Linux (FUSE3)
sudo pacman -S --needed base-devel cmake ninja libzip fuse3            # Arch
sudo apt install -y build-essential cmake ninja-build libzip-dev libfuse3-dev   # Debian/Ubuntu (libzip >= 1.10)
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release && cmake --build build   # -> ./build/vidyagodfs

# Windows (MSYS2 MINGW64 shell + WinFsp, "Developer" feature ticked)
pacman -S --needed mingw-w64-x86_64-{toolchain,cmake,ninja,pkgconf,libzip,zstd,nlohmann-json}
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release -DWINFSP_ROOT="C:/Program Files (x86)/WinFsp"
cmake --build build
```

No macOS build. Normally built as part of VidyaGod via `add_subdirectory`; the above is the standalone path.

---

## Zero-copy zip mounts

STORE (uncompressed) zip entries are served **zero-copy**: their bytes are contiguous in the archive, so a read is a
direct `pread` at the entry's offset — no decompression, no scratch copy, no RAM ceiling, any size. A multi-gigabyte
game "installs" simply by mounting its zip. (DEFLATE entries are materialized on open; STORE is the production form and
the one VidyaGod's validator/publisher enforce.)

## Delta layers

A `delta` layer is a random-access binary diff over a **base** — by default the composed view already mounted at the
same `target`, i.e. everything below it. Entries are reconstructed on demand, and a chain of deltas **flattens**, so
reads stay `O(log n)` however deep the history goes: 900 versions of one game mount as a single chain rather than 900
archives.

- **`baseTarget`** names a *different* base, for a delta that is not over the thing it mounts onto.
- **`baseTargets`** (array) makes the base the **concatenation** of several composed views, in order — so one delta can
  dedup against a wine build ‖ a DXVK build ‖ the previous prefix at once.
- A delta must reconstruct a **complete** tree. Authoring one from an *overlay* zip (only the changed files) produces a
  delta that masks its base instead of replacing it.

`GenerateDelta` and `VerifyDelta` both take a `ProgressFn(stage, done, total)` returning `false` to abort. Multi-GB
archives are the normal case here, and both passes stream the whole thing — so an uninstrumented verify meant a
finished-looking progress bar and a dead cancel button for the longest stretch of the operation.

## Usage

```
vidyagodfs <spec.json> <mountpoint> [--watch-pid <pid>] [fuse opts...]
```

- **`spec.json`** — the layer spec (below).
- **`--watch-pid <pid>`** — fork a watchdog that unmounts the filesystem if that process dies, so a crashed launcher
  never leaks a mount.
- Remaining args pass through to libfuse (e.g. `-o auto_cache`).

## Layer spec

```json
{
  "mountpoint": "/…/RUNTIME",
  "uid": 1000, "gid": 1000,
  "readonly": false,
  "writelayer": "/…/WRITELAYER",
  "layers": [
    { "type": "dir",   "source": "/…/DEFPREFIX",   "target": "",             "rw": false },
    { "type": "zip",   "source": "/…/game.zip",    "target": "drive_c/7804", "rw": false },
    { "type": "delta", "source": "/…/1.20.2.vgdelta", "target": "drive_c/7804" },
    { "type": "file",  "source": "/…/rom.sfc",     "target": "",             "rw": false }
  ]
}
```

- **`layers`** — array order is union priority, **lowest first**. Each layer is mounted under its `target` (relative to
  the mount root). `zip` serves the archive's entries; `dir` walks a directory tree; `file` places one file; `delta`
  reconstructs an archive from a diff over what is below it (see above).
- **`submounts`** — optional per-layer `source/path:dest/path` entries that relocate a subtree of a layer elsewhere in
  the runtime without repacking it.
- **`writelayer`** — the writable copy-on-write branch, highest priority. Writes land here; the lower layers are never
  modified. `readonly: true` omits it (a fully read-only mount).
- **`rw: true`** layers are durable passthroughs (persisted user state), unioned above the read-only content.

## Source layout

| File | Role |
|------|------|
| `main.cpp` | Entry point: arg parsing, the `--watch-pid` watchdog, `fuse_main`. |
| `layerspec.*` | Parse the JSON layer spec. |
| `overlay.*` / `fuseops.*` | The union overlay + copy-on-write writelayer; the FUSE operations. |
| `ziplayer.*` / `zipscan.*` | The zero-copy STORE zip reader (ZIP64-aware) and the central-directory scanner. |
| `vgdelta.*` | `.vgdelta` generation, verification and random-access composition (`DeltaByteSource`), with progress + cancellation. |
| `bytesource.h` | The byte-source abstraction deltas compose over: a file, a memory buffer, a concatenation, or another delta. |
| `vfsops.*` / `hostio_*.cpp` / `mountsession_*.cpp` | Backend-agnostic VFS ops, per-OS host I/O, and the FUSE / WinFsp session backends. |
