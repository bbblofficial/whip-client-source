cmake_minimum_required(VERSION 3.15)
project(WhipNexus VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Match WhipClient's /MT (static runtime) — sinon LNK1319 RuntimeLibrary mismatch
# au link de WhipClient.dll qui consomme WhipNexus.lib.
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

# VMProtect Configuration
set(VMPROTECT_SDK_PATH "C:/Users/Java/Desktop/VMP")
set(VMPROTECT_HEADER "${VMPROTECT_SDK_PATH}/VMProtectSDK.h")
set(VMPROTECT_LIB "${VMPROTECT_SDK_PATH}/VMProtectSDK64.lib")

if(EXISTS "${VMPROTECT_SDK_PATH}")
    message(STATUS "VMProtect SDK found at: ${VMPROTECT_SDK_PATH}")
    if(EXISTS "${VMPROTECT_HEADER}")
        message(STATUS "VMProtect header found: ${VMPROTECT_HEADER}")
    else()
        message(WARNING "VMProtect header not found: ${VMPROTECT_HEADER}")
    endif()
    if(EXISTS "${VMPROTECT_LIB}")
        message(STATUS "VMProtect library found: ${VMPROTECT_LIB}")
    else()
        message(WARNING "VMProtect library not found: ${VMPROTECT_LIB}")
    endif()
else()
    message(WARNING "VMProtect SDK not found at: ${VMPROTECT_SDK_PATH}")
endif()

# ---------------------------------------------------------------------------
# Configuration WhipSysCall (bibliothèque externe compilée automatiquement)
# ---------------------------------------------------------------------------
# WhipSysCall est compilé automatiquement via add_custom_command
# Le code est __forceinline dans les headers (anti-hook maximal)

set(WHIPSYSCALL_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../WhipSysCall" CACHE PATH "WhipSysCall directory")
set(WHIPSYSCALL_INCLUDE_DIR "${WHIPSYSCALL_DIR}/include")

# Déterminer le chemin de la lib selon la config
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(WHIPSYSCALL_BUILD_DIR "${WHIPSYSCALL_DIR}/cmake-build-debug")
    set(WHIPSYSCALL_LIB "${WHIPSYSCALL_BUILD_DIR}/WhipSysCall.lib")
    set(WHIPSYSCALL_CONFIG "Debug")
else()
    set(WHIPSYSCALL_BUILD_DIR "${WHIPSYSCALL_DIR}/cmake-build-release")
    set(WHIPSYSCALL_LIB "${WHIPSYSCALL_BUILD_DIR}/WhipSysCall.lib")
    set(WHIPSYSCALL_CONFIG "Release")
endif()

# Commande pour configurer WhipSysCall (CMake configure)
add_custom_command(
    OUTPUT ${WHIPSYSCALL_BUILD_DIR}/CMakeCache.txt
    COMMAND ${CMAKE_COMMAND} -B ${WHIPSYSCALL_BUILD_DIR} -G Ninja -DCMAKE_BUILD_TYPE=${WHIPSYSCALL_CONFIG}
    WORKING_DIRECTORY ${WHIPSYSCALL_DIR}
    COMMENT "Configuring WhipSysCall (${WHIPSYSCALL_CONFIG})..."
    VERBATIM
)

# Commande pour compiler WhipSysCall
add_custom_command(
    OUTPUT ${WHIPSYSCALL_LIB}
    COMMAND ${CMAKE_COMMAND} --build ${WHIPSYSCALL_BUILD_DIR}
    WORKING_DIRECTORY ${WHIPSYSCALL_DIR}
    DEPENDS ${WHIPSYSCALL_BUILD_DIR}/CMakeCache.txt
    COMMENT "Building WhipSysCall (${WHIPSYSCALL_CONFIG})..."
    VERBATIM
)

# Target custom pour déclencher la compilation de WhipSysCall
add_custom_target(BuildWhipSysCall
    DEPENDS ${WHIPSYSCALL_LIB}
)

# Créer une bibliothèque importée pour WhipSysCall
add_library(WhipSysCall STATIC IMPORTED GLOBAL)
set_target_properties(WhipSysCall PROPERTIES
    IMPORTED_LOCATION     "${WHIPSYSCALL_LIB}"
    INTERFACE_INCLUDE_DIRECTORIES "${WHIPSYSCALL_INCLUDE_DIR}"
)

# Faire dépendre WhipSysCall du build custom
add_dependencies(WhipSysCall BuildWhipSysCall)

# ---------------------------------------------------------------------------
# Répertoires de sortie
# ---------------------------------------------------------------------------
# Multi-config (Visual Studio) : suffixe _DEBUG / _RELEASE
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY_DEBUG    ${CMAKE_BINARY_DIR}/bin/Debug)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY_RELEASE  ${CMAKE_BINARY_DIR}/bin/Release)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_DEBUG    ${CMAKE_BINARY_DIR}/bin/Debug)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_RELEASE  ${CMAKE_BINARY_DIR}/bin/Release)
# Single-config (Ninja / CLion) : répertoire commun, le profil CLion sépare déjà
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

file(GLOB_RECURSE SOURCES "src/*.cpp")
file(GLOB_RECURSE HEADERS "include/whipnexus/*.h")

add_library(WhipNexus STATIC ${SOURCES} ${HEADERS}
        src/SyscallManager.cpp)

set(WHIPANTIDEBUG_DIR "C:/Users/Java/CLionProjects/WhipAntiDebugger" CACHE PATH "WhipAntiDebugger directory")

target_include_directories(WhipNexus
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        ${WHIPANTIDEBUG_DIR}
)

target_link_libraries(WhipNexus
    PUBLIC
        WhipSysCall # headers publics (TcpSocket.h) incluent whipsyscall/ → doit se propager
    PRIVATE
        bcrypt
        crypt32
)

# VMProtect Library Configuration
set(BUILD_WITH_VMPROTECT ON CACHE BOOL "Build with VMProtect" FORCE)
if(BUILD_WITH_VMPROTECT AND EXISTS "${VMPROTECT_HEADER}")
    message(STATUS "VMProtect SDK found - enabling protection for WhipNexus")
    target_include_directories(WhipNexus PRIVATE "${VMPROTECT_SDK_PATH}")
    target_link_libraries(WhipNexus PRIVATE "${VMPROTECT_LIB}")
    target_compile_definitions(WhipNexus PRIVATE BUILD_WITH_VMPROTECT)
    message(STATUS "VMProtect protection enabled for WhipNexus")
else()
    message(STATUS "VMProtect SDK not found or disabled for WhipNexus")
endif()

