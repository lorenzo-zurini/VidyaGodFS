cmake_minimum_required(VERSION 3.16)
project(vidyagodfs LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# vidyagodfs links libfuse3 + libzip; the merged-tree spec is parsed with nlohmann_json.
find_package(PkgConfig REQUIRED)
pkg_check_modules(FUSE3 REQUIRED IMPORTED_TARGET fuse3)
pkg_check_modules(LIBZIP REQUIRED IMPORTED_TARGET libzip)
find_package(nlohmann_json REQUIRED)

add_executable(vidyagodfs
    src/main.cpp
    src/layerspec.cpp
    src/ziplayer.cpp
    src/overlay.cpp
    src/fuseops.cpp
)

# No Qt — disable the Qt autogen steps in case this is built as a subdirectory of a Qt project
# (which inherits CMAKE_AUTOMOC=ON).
set_target_properties(vidyagodfs PROPERTIES AUTOMOC OFF AUTOUIC OFF AUTORCC OFF)

# FUSE_USE_VERSION=31 (FUSE 3.1 high-level API) — only the 3.0/3.1 ops are used, so this builds
# against any libfuse 3.x (e.g. 3.10 on Ubuntu 22.04). _FILE_OFFSET_BITS=64 for >4 GB archives.
target_compile_definitions(vidyagodfs PRIVATE FUSE_USE_VERSION=31 _FILE_OFFSET_BITS=64)
target_link_libraries(vidyagodfs PRIVATE PkgConfig::FUSE3 PkgConfig::LIBZIP nlohmann_json::nlohmann_json)
