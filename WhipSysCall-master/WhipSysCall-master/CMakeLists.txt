cmake_minimum_required(VERSION 3.15)
project(WhipSysCall VERSION 1.0.0 LANGUAGES CXX ASM_MASM)

# ==============================================================================
# Configuration Standard
# ==============================================================================
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

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

# Mode de build par défaut
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type (Debug or Release)" FORCE)
endif()

message(STATUS "========================================")
message(STATUS "WhipSysCall - Build Configuration")
message(STATUS "========================================")
message(STATUS "Build Type: ${CMAKE_BUILD_TYPE}")
message(STATUS "Compiler: ${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION}")
message(STATUS "Platform: ${CMAKE_SYSTEM_NAME} ${CMAKE_SYSTEM_PROCESSOR}")
message(STATUS "========================================")

# ==============================================================================
# Fichiers Source et Header
# ==============================================================================
# NOTE: Les implémentations sont INLINE dans les headers (__forceinline)
# Les .cpp sont gardés pour compatibilité et pour générer une .lib
# mais le code sera inline quand vous incluez les headers

set(SOURCES
    src/SyscallResolver.cpp
    src/SyscallInvoker.cpp
    src/SyscallWrappers.cpp
    src/SyscallStub.asm
)

set(HEADERS
    include/whipsyscall/Types.h
    include/whipsyscall/SyscallResolver.h
    include/whipsyscall/SyscallInvoker.h
    include/whipsyscall/SyscallWrappers.h
    include/whipsyscall/WhipSysCall.h
        include/whipsyscall/AfdSocket.h
)

# ==============================================================================
# Bibliothèque WhipSysCall - STATIC avec code INLINE
# ==============================================================================
# Approche HYBRIDE:
# - Génère une .lib pour compatibilité
# - Mais le code est __forceinline dans les headers
# - Quand vous incluez les headers, le code est inline (anti-hook)
add_library(WhipSysCall STATIC ${SOURCES} ${HEADERS})

target_include_directories(WhipSysCall
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

# VMProtect Library Configuration
set(BUILD_WITH_VMPROTECT ON CACHE BOOL "Build with VMProtect" FORCE)
if(BUILD_WITH_VMPROTECT AND EXISTS "${VMPROTECT_HEADER}")
    message(STATUS "VMProtect SDK found - enabling protection for WhipSysCall")
    target_include_directories(WhipSysCall PRIVATE "${VMPROTECT_SDK_PATH}")
    target_link_libraries(WhipSysCall PRIVATE "${VMPROTECT_LIB}")
    target_compile_definitions(WhipSysCall PRIVATE BUILD_WITH_VMPROTECT)
    message(STATUS "VMProtect protection enabled for WhipSysCall")
else()
    message(STATUS "VMProtect SDK not found or disabled for WhipSysCall")
endif()

# ==============================================================================
# Flags de Compilation - Debug
# ==============================================================================
if(MSVC)
    target_compile_options(WhipSysCall PRIVATE
        $<$<CONFIG:Debug>:
            /Od           # Désactiver optimisations
            /Zi           # Informations de debug complètes
            /RTC1         # Vérifications runtime
            /MDd          # Runtime library debug
            /W4           # Niveau warning 4
        >
    )

    target_link_options(WhipSysCall PRIVATE
        $<$<CONFIG:Debug>:
            /DEBUG:FULL
            /INCREMENTAL
        >
    )
endif()

# ==============================================================================
# Flags de Compilation - Release (FORCE INLINE)
# ==============================================================================
if(MSVC)
    target_compile_options(WhipSysCall PRIVATE
        $<$<CONFIG:Release>:
            /O2           # Optimisation maximale
            /Oi           # Intrinsics
            /Ob2          # Inline expansion maximale (__forceinline respected)
            /Ot           # Favoriser vitesse
            /GL           # Link-time code generation
            /MD           # Runtime library release
            /DNDEBUG      # Désactiver asserts
            /GS-          # Désactiver security checks
            /Gy           # Enable function-level linking
        >
    )

    target_link_options(WhipSysCall PRIVATE
        $<$<CONFIG:Release>:
            /LTCG         # Link-time code generation
            /OPT:REF      # Éliminer code non utilisé
            /OPT:ICF      # Fusionner fonctions identiques
        >
    )
endif()

# ==============================================================================
# Flags MASM pour x64
# ==============================================================================
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set_source_files_properties(src/SyscallStub.asm PROPERTIES
        COMPILE_FLAGS "/D_WIN64"
    )
endif()

# ==============================================================================
# Exemples (uniquement si WhipSysCall est le projet principal)
# ==============================================================================
# Si WhipSysCall est utilisé comme sous-projet (via add_subdirectory),
# on ne compile pas les exemples pour éviter les conflits

if(CMAKE_CURRENT_SOURCE_DIR STREQUAL CMAKE_SOURCE_DIR)
    # WhipSysCall est le projet principal, compiler les exemples

    # Exemple simple
    add_executable(SimpleExample examples/simple.cpp)
    target_link_libraries(SimpleExample PRIVATE WhipSysCall)

    # Exemple complet
    add_executable(WhipSysCallExample examples/example.cpp)
    target_link_libraries(WhipSysCallExample PRIVATE WhipSysCall)

    # Appliquer les mêmes flags aux exemples
    if(MSVC)
        foreach(target SimpleExample WhipSysCallExample)
            target_compile_options(${target} PRIVATE
                $<$<CONFIG:Debug>:/Od /Zi /RTC1 /MDd /W4>
                $<$<CONFIG:Release>:/O2 /Oi /Ot /GL /MD /DNDEBUG>
            )

            target_link_options(${target} PRIVATE
                $<$<CONFIG:Debug>:/DEBUG:FULL /INCREMENTAL>
                $<$<CONFIG:Release>:/LTCG /OPT:REF /OPT:ICF>
            )
        endforeach()
    endif()

    message(STATUS "  - SimpleExample (exemple basique)")
    message(STATUS "  - WhipSysCallExample (exemple complet)")
else()
    message(STATUS "  - WhipSysCall utilisé comme sous-projet (exemples désactivés)")
endif()

# ==============================================================================
# Messages de Fin
# ==============================================================================
if(CMAKE_CURRENT_SOURCE_DIR STREQUAL CMAKE_SOURCE_DIR)
    message(STATUS "========================================")
    message(STATUS "WhipSysCall - Configuration terminée")
    message(STATUS "========================================")
    message(STATUS "Targets configurés:")
    message(STATUS "  - WhipSysCall (bibliothèque STATIC avec code inline)")
    message(STATUS "========================================")
    message(STATUS "ANTI-HOOK: Code __forceinline dans headers!")
    message(STATUS "========================================")
    message(STATUS "Build avec: cmake --build . --config ${CMAKE_BUILD_TYPE}")
    message(STATUS "========================================")
endif()