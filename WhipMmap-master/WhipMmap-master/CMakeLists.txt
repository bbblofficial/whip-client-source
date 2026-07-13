cmake_minimum_required(VERSION 3.20)
project(WhipMmap)

set(CMAKE_CXX_STANDARD 20)

include_directories(include)

# Static library
add_library(WhipMmap STATIC
    src/ManualMapper/PeParser.cpp
    src/ManualMapper/ProcessUtils.cpp
    src/ManualMapper/LoaderStub.cpp
    src/ManualMapper/ManualMapper.cpp
)

target_include_directories(WhipMmap PUBLIC
    include
    ../WhipSysCall/include
)

target_link_libraries(WhipMmap PUBLIC
    $<$<CONFIG:Debug>:${CMAKE_CURRENT_SOURCE_DIR}/../WhipSysCall/cmake-build-debug/WhipSysCall.lib>
    $<$<CONFIG:Release>:${CMAKE_CURRENT_SOURCE_DIR}/../WhipSysCall/cmake-build-release/WhipSysCall.lib>
)

# Test executable
add_executable(WhipMmapTest main.cpp)
target_link_libraries(WhipMmapTest PRIVATE WhipMmap)
