cmake_minimum_required(VERSION 3.16)
project(vidyagodfs LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# vidyagodfs links libzip + libzstd + a mount backend (FUSE on Linux, WinFsp on Windows); the merged-tree
# spec is parsed with nlohmann_json. libzstd backs the .vgdelta binary-delta layers (random-access,
# per-block-compressed reconstruction).
find_package(nlohmann_json REQUIRED)

# --- backend-neutral core: no FUSE / WinFsp / raw-POSIX; host I/O goes through the HostIO shim ---
# (overlay/ziplayer/vgdelta/layerspec are shared by every mount backend). main.cpp still owns the mount
# lifecycle for now (to be split into a MountSession backend in a later step).
set(VGFS_CORE
    src/main.cpp
    src/layerspec.cpp
    src/ziplayer.cpp
    src/overlay.cpp
    src/vfsops.cpp
    src/vgdelta.cpp
)

# --- platform-selected mount backend + host-I/O shim ---
if(WIN32)
    # Windows: native WinFsp adapter + Win32 host I/O (added in the WinFsp-backend step).
    set(VGFS_BACKEND src/winfsp_backend.cpp src/hostio_win.cpp)
else()
    # Linux: the FUSE adapter (fuseops.cpp) + POSIX host I/O.
    set(VGFS_BACKEND src/fuseops.cpp src/hostio_posix.cpp)
endif()

add_executable(vidyagodfs ${VGFS_CORE} ${VGFS_BACKEND})

# No Qt — disable the Qt autogen steps in case this is built as a subdirectory of a Qt project
# (which inherits CMAKE_AUTOMOC=ON).
set_target_properties(vidyagodfs PROPERTIES AUTOMOC OFF AUTOUIC OFF AUTORCC OFF)

target_link_libraries(vidyagodfs PRIVATE nlohmann_json::nlohmann_json)

if(WIN32)
    # WinFsp + libzip/zstd (via vcpkg/find_package on MSYS2/MinGW). Wired in the WinFsp-backend step.
    find_package(LIBZIP CONFIG REQUIRED)
    find_package(zstd CONFIG REQUIRED)
    target_link_libraries(vidyagodfs PRIVATE libzip::zip $<IF:$<TARGET_EXISTS:zstd::libzstd_shared>,zstd::libzstd_shared,zstd::libzstd_static>)
    # winfsp include/lib wiring goes here.
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
