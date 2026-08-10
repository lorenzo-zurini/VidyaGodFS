cmake_minimum_required(VERSION 3.16)
project(vidyagodfs LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# vidyagodfs links libzip + libzstd + a mount backend (FUSE on Linux, WinFsp on Windows); the merged-tree
# spec is parsed with nlohmann_json. libzstd backs the .vgdelta binary-delta layers (random-access,
# per-block-compressed reconstruction).
find_package(nlohmann_json REQUIRED)

# --- backend-neutral core: no FUSE / WinFsp / raw-POSIX; host I/O goes through the HostIO shim,
# the ops through VfsOps, and the mount lifecycle through MountSession. main.cpp only parses the
# spec, builds the state, and calls MountSession::Run — it knows nothing about the mount backend. ---
set(VGFS_CORE
    src/main.cpp
    src/layerspec.cpp
    src/ziplayer.cpp
    src/overlay.cpp
    src/vfsops.cpp
    src/vgdelta.cpp
)

# --- platform-selected mount backend: op adapter + mount lifecycle + host-I/O shim ---
if(WIN32)
    # Windows: native WinFsp adapter + WinFsp mount lifecycle + Win32 host I/O (added later).
    set(VGFS_BACKEND src/winfsp_backend.cpp src/mountsession_win.cpp src/hostio_win.cpp)
else()
    # Linux: the FUSE adapter (fuseops.cpp) + FUSE mount lifecycle + POSIX host I/O.
    set(VGFS_BACKEND src/fuseops.cpp src/mountsession_fuse.cpp src/hostio_posix.cpp)
endif()

add_executable(vidyagodfs ${VGFS_CORE} ${VGFS_BACKEND})

# No Qt — disable the Qt autogen steps in case this is built as a subdirectory of a Qt project
# (which inherits CMAKE_AUTOMOC=ON).
set_target_properties(vidyagodfs PROPERTIES AUTOMOC OFF AUTOUIC OFF AUTORCC OFF)

target_link_libraries(vidyagodfs PRIVATE nlohmann_json::nlohmann_json)

if(WIN32)
    # WinFsp's FUSE-compatibility layer (<fuse3/fuse.h>): header-only glue whose static inlines
    # load winfsp-x64.dll at runtime, so we only need its include dir — no import lib for the FUSE
    # API. WINFSP_ROOT is overridable; default to the standard 64-bit install path.
    set(WINFSP_ROOT "C:/Program Files (x86)/WinFsp" CACHE PATH "WinFsp SDK install root")
    if(NOT EXISTS "${WINFSP_ROOT}/inc/fuse3/fuse.h")
        message(FATAL_ERROR "WinFsp SDK not found at ${WINFSP_ROOT} (need inc/fuse3/fuse.h). Set -DWINFSP_ROOT=…")
    endif()
    target_include_directories(vidyagodfs PRIVATE "${WINFSP_ROOT}/inc")
    # The FUSE symbols (fsp_fuse3_*) are __declspec(dllimport) from winfsp-x64.dll. WinFsp's own
    # fuse3.pc links the DLL directly (MinGW ld generates the import stubs from it); do the same.
    # winfsp-x64.dll must then be reachable at runtime (WinFsp\bin on PATH, or beside the exe).
    target_link_libraries(vidyagodfs PRIVATE "${WINFSP_ROOT}/bin/winfsp-x64.dll")

    # libzip + libzstd come from MSYS2/MinGW via pkgconf (they ship .pc files) — same as Linux.
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(LIBZIP  REQUIRED IMPORTED_TARGET libzip)
    pkg_check_modules(LIBZSTD REQUIRED IMPORTED_TARGET libzstd)
    target_link_libraries(vidyagodfs PRIVATE PkgConfig::LIBZIP PkgConfig::LIBZSTD)
    # The two Windows backend TUs (winfsp_backend.cpp, mountsession_win.cpp) #define FUSE_USE_VERSION
    # themselves; hostio_win.cpp needs no FUSE. No _FILE_OFFSET_BITS on Windows.
else()
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(FUSE3 REQUIRED IMPORTED_TARGET fuse3)
    pkg_check_modules(LIBZIP REQUIRED IMPORTED_TARGET libzip)
    pkg_check_modules(LIBZSTD REQUIRED IMPORTED_TARGET libzstd)
    # FUSE_USE_VERSION=31 (FUSE 3.1 high-level API) — only the 3.0/3.1 ops are used, so this builds against
    # any libfuse 3.x. _FILE_OFFSET_BITS=64 for >4 GB archives (POSIX-only; irrelevant on Windows).
    target_compile_definitions(vidyagodfs PRIVATE FUSE_USE_VERSION=31 _FILE_OFFSET_BITS=64)
    target_link_libraries(vidyagodfs PRIVATE PkgConfig::FUSE3 PkgConfig::LIBZIP PkgConfig::LIBZSTD)
endif()
