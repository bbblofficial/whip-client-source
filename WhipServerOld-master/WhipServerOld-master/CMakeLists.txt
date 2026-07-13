cmake_minimum_required(VERSION 3.16)
project(AuthenticationServer VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_program(NINJA_EXECUTABLE ninja ninja-build)
if (NINJA_EXECUTABLE)
    set(CMAKE_GENERATOR "Ninja" CACHE STRING "CMake generator" FORCE)
    message(STATUS "Using Ninja build system: ${NINJA_EXECUTABLE}")
else ()
    set(CMAKE_GENERATOR "Unix Makefiles" CACHE STRING "CMake generator" FORCE)
    message(STATUS "Ninja not found, using Unix Makefiles")
endif ()

option(BUILD_STATIC "Build static executable" ON)
option(BUILD_PORTABLE "Build with maximum compatibility" ON)
option(BUILD_SECURE "Build with security hardening" ON)

if (NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif ()

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -pthread")

if (BUILD_STATIC)
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static-libgcc -static-libstdc++")
    set(CMAKE_FIND_LIBRARY_SUFFIXES ".a")
endif ()

if (BUILD_PORTABLE)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -static-libgcc -static-libstdc++")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -D_GLIBCXX_USE_CXX11_ABI=0")
endif ()

if (BUILD_SECURE)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -D_FORTIFY_SOURCE=2")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fstack-protector-strong")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wformat -Wformat-security")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fPIC")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,-z,relro -Wl,-z,now")
endif ()

set(CMAKE_CXX_FLAGS_RELEASE "-O2 -DNDEBUG")
set(CMAKE_CXX_FLAGS_DEBUG "-g -O0 -DDEBUG")

set(CONTROLLER_SOURCES
        Controller/impl/authController.cpp
        Controller/impl/ConfigController.cpp
        #Controller/impl/DestroySessionController.cpp
        ##Controller/impl/DllController.cpp
        ##Controller/impl/SessionManager.cpp
        Controller/impl/errorController.cpp
        ##Controller/impl/heartbeatController.cpp
        ##Controller/impl/shutdownController.cpp
)

set(UTILS_SOURCES
        utils/discord.cpp
        utils/Protocol/protocol.cpp
        utils/simplewebhook.cpp
        utils/Thread/ThreadSafeBuffer.cpp
        utils/xchacha20/xchacha20.cpp
        utils/native_crypto.cpp
        utils/native_http.cpp
)

set(MAIN_SOURCES
        main.cpp
        Tls_Server.cpp
)

set(ALL_SOURCES ${MAIN_SOURCES} ${CONTROLLER_SOURCES} ${UTILS_SOURCES})

add_executable(auth_server ${ALL_SOURCES})

target_compile_definitions(auth_server PRIVATE __linux__)
target_link_libraries(auth_server pthread)

if (BUILD_STATIC)
    target_link_libraries(auth_server -static)
endif ()

target_compile_definitions(auth_server PRIVATE
        $<$<CONFIG:Debug>:DEBUG>
        $<$<CONFIG:Release>:NDEBUG>
)

message(STATUS "=== AuthenticationServer Build Configuration ===")
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "Generator: ${CMAKE_GENERATOR}")
message(STATUS "C++ Standard: ${CMAKE_CXX_STANDARD}")
message(STATUS "Compiler: ${CMAKE_CXX_COMPILER}")
message(STATUS "Static build: ${BUILD_STATIC}")
message(STATUS "Portable build: ${BUILD_PORTABLE}")
message(STATUS "Secure build: ${BUILD_SECURE}")
message(STATUS "==============================================")

install(TARGETS auth_server
        RUNTIME DESTINATION bin
)

if (EXISTS "${CMAKE_SOURCE_DIR}/configs")
    install(DIRECTORY configs/
            DESTINATION share/auth_server/configs
    )
endif ()

# Tests
enable_testing()
add_test(NAME auth_server_version
        COMMAND auth_server --version
        WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
)

# Targets personnalisés
add_custom_target(clean-all
        COMMAND ${CMAKE_COMMAND} -E remove_directory ${CMAKE_BINARY_DIR}
        COMMENT "Cleaning all build files"
)

# Target pour build rapide
add_custom_target(quick
        COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR} --target auth_server --parallel
        COMMENT "Quick parallel build"
        DEPENDS auth_server
)

# Target pour build et test
add_custom_target(build-and-test
        COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR} --target auth_server --parallel
        COMMAND ${CMAKE_CTEST_COMMAND} --output-on-failure
        COMMENT "Build and run tests"
)