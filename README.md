# VidyaGodFS

`vidyagodfs` is the runtime filesystem for [VidyaGod](https://github.com/lorenzo-zurini/VidyaGod): a **single FUSE
mount** that assembles a game's entire runtime from a stack of layers — read-only `zip`/`dir`/`file` under-layers rooted
at their targets, a writable copy-on-write top layer, and RW passthroughs for persisted state. It replaces the former
unionfs-fuse + fuse-zip + bindfs stack with one in-process filesystem.

## Zero-copy zip mounts

STORE (uncompressed) zip entries are served **zero-copy**: their bytes are contiguous in the archive, so a read is a
direct `pread` at the entry's offset — no decompression, no scratch copy, no RAM ceiling, any size. A multi-gigabyte
game "installs" simply by mounting its zip. (DEFLATE entries are materialized on open; STORE is the production form and
the one VidyaGod's validator/publisher enforce.)

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
    { "type": "dir",  "source": "/…/DEFPREFIX", "target": "",             "rw": false },
    { "type": "zip",  "source": "/…/game.zip",   "target": "drive_c/7804", "rw": false },
    { "type": "file", "source": "/…/rom.sfc",    "target": "",             "rw": false }
  ]
}
```

- **`layers`** — array order is union priority, **lowest first**. Each layer is mounted under its `target` (relative to
  the mount root). `zip` serves the archive's entries; `dir` walks a directory tree; `file` places one file.
- **`writelayer`** — the writable copy-on-write branch, highest priority. Writes land here; the lower layers are never
  modified. `readonly: true` omits it (a fully read-only mount).
- **`rw: true`** layers are durable passthroughs (persisted user state), unioned above the read-only content.

## Building

Requires FUSE3 and a C++ compiler. Built as part of VidyaGod (via `add_subdirectory`), or standalone with CMake:

```bash
cmake -S . -B build && cmake --build build     # produces ./build/vidyagodfs
```

## Source layout

| File | Role |
|------|------|
| `main.cpp` | Entry point: arg parsing, the `--watch-pid` watchdog, `fuse_main`. |
| `layerspec.*` | Parse the JSON layer spec. |
| `overlay.*` / `fuseops.*` | The union overlay + copy-on-write writelayer; the FUSE operations. |
| `ziplayer.*` | The zero-copy STORE zip reader (ZIP64-aware). |
