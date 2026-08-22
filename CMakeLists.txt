cmake_minimum_required(VERSION 3.16)
project(vidyagodfs LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ---- Build hardening ----
# Warnings mirror the parent's set; -Werror and sanitizers are opt-in and, when built as a subdirectory,
# are driven by the parent (which forwards VIDYAGOD_WERROR/VIDYAGOD_SANITIZE into VGFS_WERROR/VGFS_SANITIZE).
option(VGFS_WERROR      "Treat C++ warnings as errors" OFF)
option(VGFS_SANITIZE    "Build with AddressSanitizer + UndefinedBehaviorSanitizer" OFF)
option(VGFS_BUILD_TESTS "Build the vgfs_tests unit suite" ON)
# array-bounds/stringop-overflow are warnings, not errors — newer GCC false-positives via shared_ptr
# inplace control blocks in system headers (mirrors the parent's VG_WARNINGS rationale).
set(VGFS_WARNINGS -Wall -Wextra -Wshadow=local -Wnon-virtual-dtor
    -Wno-error=array-bounds -Wno-error=stringop-overflow)

# vidyagodfs links libzip + libzstd + a mount backend (FUSE on Linux, WinFsp on Windows); the merged-tree
# spec is parsed with nlohmann_json. libzstd backs the .vgdelta binary-delta layers (random-access,
# per-block-compressed reconstruction).
find_package(nlohmann_json REQUIRED)

# --- backend-neutral core (no FUSE / WinFsp): host I/O goes through the HostIO shim, the ops through
# VfsOps, the mount lifecycle through MountSession. Everything here is unit-testable WITHOUT mounting —
# a test builds a Spec + VfsState::Init and drives Resolve/CollectChildren/VfsOps directly. main.cpp
# (arg parse + backend handoff) is deliberately NOT part of the core so tests can link it. ---
set(VGFS_CORE_SRC
    src/layerspec.cpp
    src/ziplayer.cpp
    src/overlay.cpp
    src/vfsops.cpp
    src/vgdelta.cpp
    src/zipscan.cpp
)
if(WIN32)
    list(APPEND VGFS_CORE_SRC src/hostio_win.cpp)
else()
    list(APPEND VGFS_CORE_SRC src/hostio_posix.cpp)
endif()

add_library(vgfs_core STATIC ${VGFS_CORE_SRC})
set_target_properties(vgfs_core PROPERTIES AUTOMOC OFF AUTOUIC OFF AUTORCC OFF POSITION_INDEPENDENT_CODE ON)
target_include_directories(vgfs_core PUBLIC src)
target_link_libraries(vgfs_core PUBLIC nlohmann_json::nlohmann_json)
target_compile_options(vgfs_core PRIVATE ${VGFS_WARNINGS} $<$<BOOL:${VGFS_WERROR}>:-Werror>)
if(VGFS_SANITIZE)
    target_compile_options(vgfs_core PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(vgfs_core PUBLIC -fsanitize=address,undefined)
endif()
if(NOT WIN32)
    target_compile_definitions(vgfs_core PRIVATE _FILE_OFFSET_BITS=64)
endif()

# --- platform-selected mount backend: op adapter + mount lifecycle ---
if(WIN32)
    set(VGFS_BACKEND src/winfsp_backend.cpp src/mountsession_win.cpp)
else()
    set(VGFS_BACKEND src/fuseops.cpp src/mountsession_fuse.cpp)
endif()

add_executable(vidyagodfs src/main.cpp ${VGFS_BACKEND})
set_target_properties(vidyagodfs PROPERTIES AUTOMOC OFF AUTOUIC OFF AUTORCC OFF)
target_link_libraries(vidyagodfs PRIVATE vgfs_core)
target_compile_options(vidyagodfs PRIVATE ${VGFS_WARNINGS} $<$<BOOL:${VGFS_WERROR}>:-Werror>)

if(WIN32)
    # WinFsp's FUSE-compatibility layer (<fuse3/fuse.h>): header-only glue whose static inlines
    # load winfsp-x64.dll at runtime, so we only need its include dir — no import lib for the FUSE API.
    set(WINFSP_ROOT "C:/Program Files (x86)/WinFsp" CACHE PATH "WinFsp SDK install root")
    if(NOT EXISTS "${WINFSP_ROOT}/inc/fuse3/fuse.h")
        message(FATAL_ERROR "WinFsp SDK not found at ${WINFSP_ROOT} (need inc/fuse3/fuse.h). Set -DWINFSP_ROOT=…")
    endif()
    target_include_directories(vidyagodfs PRIVATE "${WINFSP_ROOT}/inc")
    target_link_libraries(vidyagodfs PRIVATE "${WINFSP_ROOT}/bin/winfsp-x64.dll")
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(LIBZIP  REQUIRED IMPORTED_TARGET libzip)
    pkg_check_modules(LIBZSTD REQUIRED IMPORTED_TARGET libzstd)
    target_link_libraries(vgfs_core  PUBLIC PkgConfig::LIBZIP PkgConfig::LIBZSTD)
else()
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(FUSE3  REQUIRED IMPORTED_TARGET fuse3)
    pkg_check_modules(LIBZIP REQUIRED IMPORTED_TARGET libzip)
    pkg_check_modules(LIBZSTD REQUIRED IMPORTED_TARGET libzstd)
    # FUSE_USE_VERSION=31: only the FUSE 3.0/3.1 ops are used, so this builds against any libfuse 3.x.
    target_compile_definitions(vidyagodfs PRIVATE FUSE_USE_VERSION=31 _FILE_OFFSET_BITS=64)
    target_link_libraries(vidyagodfs PRIVATE PkgConfig::FUSE3)
    target_link_libraries(vgfs_core  PUBLIC PkgConfig::LIBZIP PkgConfig::LIBZSTD)
endif()

# ---- unit tests (unmounted: real temp-dir fixtures + in-test zips, drive VfsState/Resolve/VfsOps) ----
if(VGFS_BUILD_TESTS AND NOT WIN32)
    enable_testing()
    add_executable(vgfs_tests test/vgfs_tests.cpp)
    set_target_properties(vgfs_tests PROPERTIES AUTOMOC OFF AUTOUIC OFF AUTORCC OFF)
    target_link_libraries(vgfs_tests PRIVATE vgfs_core PkgConfig::LIBZIP PkgConfig::LIBZSTD)
    target_compile_options(vgfs_tests PRIVATE ${VGFS_WARNINGS} $<$<BOOL:${VGFS_WERROR}>:-Werror>)
    if(VGFS_SANITIZE)
        target_compile_options(vgfs_tests PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
        target_link_options(vgfs_tests PRIVATE -fsanitize=address,undefined)
    endif()
    add_test(NAME vgfs_tests COMMAND vgfs_tests)
endif()
