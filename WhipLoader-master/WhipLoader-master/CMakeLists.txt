cmake_minimum_required(VERSION 3.20)
project(WhipLoader VERSION 1.0.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Match WhipClient + WhipNexus runtime: /MT (static CRT). Mixed /MD/MT linkage
# triggers LNK1319 'RuntimeLibrary mismatch'. Static CRT also removes the
# vcruntime/msvcp DLL dependency from the loader → fewer external imports for
# a reverser to trace, simpler standalone exe.
#
# /MT (Release CRT) is forced even for Debug builds. /MTd brings _RTC1,
# _ITERATOR_DEBUG_LEVEL=2 and the debug heap. Those assertion paths can
# unwind back to ad::spoof_my_ra()'s corrupted return slot → AV at startup
# at an "unknown module" address. Release CRT in a Debug-typed build keeps
# PDB symbols + no-optim, but skips the debug-only runtime checks.
cmake_policy(SET CMP0091 NEW)
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded")

# Strip /RTC1 from Debug flags. It requires the Debug CRT (/MTd) and can
# raise runtime checks that unwind into ad::spoof_my_ra's corrupted return
# slot → AV at startup. Keep /Zi (PDB) and /Od (no optim) for debuggability.
#
# Also flip /Ob0 → /Ob2: ad::spoof_my_ra() is __forceinline AND MUST be
# inlined into WinMain so _AddressOfReturnAddress resolves to WinMain's RA
# slot. At /Ob0 (Debug default) MSVC ignores __forceinline → spoof corrupts
# its OWN frame's RA → AV jumping to junk on return.
if(MSVC)
    string(REGEX REPLACE "/RTC[1csu]+" "" CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG}")
    string(REGEX REPLACE "/RTC[1csu]+" "" CMAKE_C_FLAGS_DEBUG   "${CMAKE_C_FLAGS_DEBUG}")
    string(REGEX REPLACE "/Ob0"        "/Ob2" CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG}")
    string(REGEX REPLACE "/Ob0"        "/Ob2" CMAKE_C_FLAGS_DEBUG   "${CMAKE_C_FLAGS_DEBUG}")
endif()

# VMProtect Configuration
set(VMPROTECT_SDK_PATH "C:/Users/Java/Desktop/VMP")
set(VMPROTECT_HEADER "${VMPROTECT_SDK_PATH}/VMProtectSDK.h")
set(VMPROTECT_LIB "${VMPROTECT_SDK_PATH}/VMProtectSDK64.lib")

# VMP est optionnel : les libs sœurs (WhipNexus, WhipSysCall, WhipAntiDebugger)
# ont été refactor pour guard leurs appels VMProtect sous #ifdef VMP, donc le
# loader peut builder sans le SDK. Si le SDK est présent on active VMP, sinon
# warn et continue sans (les markers VMProtect deviennent des no-ops).
if(EXISTS "${VMPROTECT_SDK_PATH}")
    set(VMPROTECT_AVAILABLE TRUE)
    message(STATUS "VMProtect SDK found at: ${VMPROTECT_SDK_PATH}")
else()
    set(VMPROTECT_AVAILABLE FALSE)
    message(WARNING "VMProtect SDK not found at: ${VMPROTECT_SDK_PATH} — VMP markers will be no-ops")
endif()

# WhipNexus Configuration
set(WHIPNEXUS_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../WhipNexus" CACHE PATH "WhipNexus directory")
set(WHIPNEXUS_INCLUDE_DIR "${WHIPNEXUS_DIR}/include")
set(WHIPSYSCALL_DIR "C:/Users/Java/Desktop/whip/WhipSysCall" CACHE PATH "WhipSysCall directory")
set(WHIPSYSCALL_INCLUDE_DIR "${WHIPSYSCALL_DIR}/include")
set(WHIPMMAP_DIR "C:/Users/Java/Desktop/whip/WhipMmap" CACHE PATH "WhipMmap directory")
set(WHIPMMAP_INCLUDE_DIR "${WHIPMMAP_DIR}/include")

# All deps are now consumed in their /MT Release-CRT variant regardless of
# WhipLoader build_type — see the CMAKE_MSVC_RUNTIME_LIBRARY note above.
set(WHIPNEXUS_LIB "${WHIPNEXUS_DIR}/cmake-build-release/bin/Release/WhipNexus.lib")
set(WHIPNEXUS_PDB "${WHIPNEXUS_DIR}/cmake-build-release/bin/Release/WhipNexus.pdb")
set(WHIPSYSCALL_LIB "${WHIPSYSCALL_DIR}/cmake-build-release/WhipSysCall.lib")
set(WHIPMMAP_LIB "${WHIPMMAP_DIR}/cmake-build-release/WhipMmap.lib")

add_library(WhipNexus STATIC IMPORTED)
set_target_properties(WhipNexus PROPERTIES
        IMPORTED_LOCATION "${WHIPNEXUS_LIB}"
        INTERFACE_INCLUDE_DIRECTORIES "${WHIPNEXUS_INCLUDE_DIR}"
        IMPORTED_LINK_DEPENDENT_LIBRARIES "${WHIPNEXUS_PDB}"
)

add_library(WhipSysCall STATIC IMPORTED)
set_target_properties(WhipSysCall PROPERTIES
        IMPORTED_LOCATION "${WHIPSYSCALL_LIB}"
        INTERFACE_INCLUDE_DIRECTORIES "${WHIPSYSCALL_INCLUDE_DIR}"
)

add_library(WhipMmap STATIC IMPORTED)
set_target_properties(WhipMmap PROPERTIES
        IMPORTED_LOCATION "${WHIPMMAP_LIB}"
        INTERFACE_INCLUDE_DIRECTORIES "${WHIPMMAP_INCLUDE_DIR}"
)


set(WHIPANTIDEBUG_DIR "C:/Users/Java/CLionProjects/WhipAntiDebugger" CACHE PATH "WhipAntiDebugger directory")
set(WHIPANTIDEBUG_LIB "${WHIPANTIDEBUG_DIR}/cmake-build-release/WhipAntiDebugger.lib")
add_library(WhipAntiDebug STATIC IMPORTED)
set_target_properties(WhipAntiDebug PROPERTIES
    IMPORTED_LOCATION "${WHIPANTIDEBUG_LIB}"
    INTERFACE_INCLUDE_DIRECTORIES "${WHIPANTIDEBUG_DIR}"
)

option(WHIP_BUILD_TESTS "Build tests" OFF)
option(WHIP_ENABLE_CONSOLE "Enable console window in debug" ON)
option(WHIP_UI_IMGUI "Use ImGui-based UI instead of Console UI" OFF)

# ─── Bypass mode ─────────────────────────────────────────────────────────────
# When ON, neuters the anti-debug checks that produce false positives in the
# bypass scenario (loader manual-mapped into a host process, hooks installed,
# host runs inside a Job object / Hyper-V VBS / etc.).
#
# Checks disabled in BYPASS:
#   vad_ldr_diff  — host's PEB.Ldr never registered us (always FP)
#   stack_unwind  — host's stack has frames our unwinder can't resolve
#   vm_full       — Hyper-V VBS on Win11 always triggers this
#   anti_emul     — same
#   frida_scan    — false positives on host's worker thread names
#   cross_timer   — host's scheduler noise breaks the triangulation
#   fake_hwbp     — host may legitimately use DRn registers
#   anti_attach   — host may have NoDebugInherit cleared
#   veh_decoy     — host owns the VEH chain
#   job_check     — host (Lunar Electron) routinely runs inside a Job object
#   pressure      — observed constant +4 FP without an actual debugger
#
# The hard signal checks (PEB.BeingDebugged, NtGlobalFlag, HW breakpoints,
# RDTSC timing, syscall timing, NtClose trap, ntdll-hooked, etc.) STAY ON
# so an actual debugger / RPM still trips the score.
option(WHIP_BYPASS_MODE "Disable anti-debug checks that FP in bypass scenarios" OFF)

set(WHIPCLIENT_IMGUI_DIR "C:/Users/Java/Desktop/whip/WhipClient/src/Thirdpary/Dear_ImGui"
    CACHE PATH "Dear ImGui source directory (from WhipClient)")

# ─── Whip Build Mode ──────────────────────────────────────────────────────────
# Options: LOCAL (hardcoded DLL + dev port), DEV (download DLL + dev port), PROD (download DLL + prod port)
set(WHIP_BUILD_MODE "LOCAL" CACHE STRING "Whip build configuration")
set_property(CACHE WHIP_BUILD_MODE PROPERTY STRINGS
    "LOCAL"
    "DEV"
    "PROD"
)

set(WHIP_SOURCES
    # Main
    src/main.cpp

    # Util
    src/util/Types.cpp
    src/util/Inflate.cpp
    src/util/Logger.cpp

    # Application
    src/application/Application.cpp

    # Security
    src/security/EmbeddedData.cpp
    src/security/SecureMemory.cpp
    src/security/HWIDCollector.cpp
    src/security/Sentinel.cpp
    src/security/Sentinel_bridge.c
    src/security/AntiRpmGuard.cpp
    src/security/ReverseDetector.cpp

    # Auth
    src/auth/WhipAuthService.cpp

    # Network
    src/network/WhipNexusClient.cpp

    # DLL
    src/dll/FileDownloader.cpp

    # Injection
    src/injection/ProcessFinder.cpp
    src/injection/ManualMapInjector.cpp

    # IPC
    src/ipc/LoaderIpcServer.cpp

    # UI
    src/ui/ConsoleUIImpl.cpp
    src/ui/ImGuiUIImpl.cpp

    # Loader (state machine + per-step files)
    src/loader/Loader.cpp
    src/loader/steps/ConnectStep.cpp
    src/loader/steps/AuthenticateStep.cpp
    src/loader/steps/FetchLicensesStep.cpp
    src/loader/steps/SelectProductStep.cpp
    src/loader/steps/ValidateLicenseStep.cpp
    src/loader/steps/DownloadStep.cpp
    src/loader/steps/WaitProcessStep.cpp
    src/loader/steps/InjectStep.cpp
)

if(WHIP_UI_IMGUI)
    set(WHIP_IMGUI_SOURCES
        ${WHIPCLIENT_IMGUI_DIR}/imgui.cpp
        ${WHIPCLIENT_IMGUI_DIR}/imgui_draw.cpp
        ${WHIPCLIENT_IMGUI_DIR}/imgui_tables.cpp
        ${WHIPCLIENT_IMGUI_DIR}/imgui_widgets.cpp
        ${WHIPCLIENT_IMGUI_DIR}/backends/imgui_impl_win32.cpp
        ${WHIPCLIENT_IMGUI_DIR}/backends/imgui_impl_opengl3.cpp
    )
    list(APPEND WHIP_SOURCES ${WHIP_IMGUI_SOURCES})
endif()

set(WHIP_HEADERS
    # Util
    includes/util/Types.h
    includes/util/Result.h
    includes/util/ConsoleUtils.h
    includes/util/Inflate.h

    # Application
    includes/application/Application.h

    # Config
    includes/config/Config.h
    includes/config/BuildConfig.h

    # Security
    includes/security/SecureMemory.h
    includes/security/HWIDCollector.h
    includes/security/EmbeddedData.h
    includes/security/StringObfuscation.h
    includes/security/xor.h
    includes/security/ReverseDetector.h

    # Auth
    includes/auth/Credentials.h
    includes/auth/Session.h
    includes/auth/WhipAuthService.h

    # Network
    includes/network/WhipNexusClient.h

    # Injection
    includes/injection/InjectionResult.h
    includes/injection/ProcessFinder.h
    includes/injection/ManualMapInjector.h

    # IPC
    includes/ipc/LoaderIpcServer.h

    # DLL
    includes/dll/FileDownloader.h

    # UI
    includes/ui/IConsoleUI.h
    includes/ui/ConsoleUIImpl.h
    includes/ui/ImGuiUIImpl.h

    # Loader
    includes/loader/Loader.h
    src/loader/LoaderInternal.h
)

# In bypass mode the loader is manual-mapped into Lunar's process, so it
# must be a DLL (DllMain dispatched by WhipMmap as DLL_PROCESS_ATTACH).
# In normal mode it stays a standalone WIN32 EXE with WinMain entry.
if(WHIP_BYPASS_MODE)
    add_library(WhipLoader SHARED ${WHIP_SOURCES} ${WHIP_HEADERS})
    set_target_properties(WhipLoader PROPERTIES
            OUTPUT_NAME "whiploader"
            PREFIX "")
else()
    add_executable(WhipLoader WIN32 ${WHIP_SOURCES} ${WHIP_HEADERS})
endif()

target_include_directories(WhipLoader PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/includes
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)
if(VMPROTECT_AVAILABLE)
    target_include_directories(WhipLoader PRIVATE ${VMPROTECT_SDK_PATH})
endif()

if(WHIP_UI_IMGUI)
    target_include_directories(WhipLoader PRIVATE
        ${WHIPCLIENT_IMGUI_DIR}
        ${WHIPCLIENT_IMGUI_DIR}/backends
        ${WHIPCLIENT_IMGUI_DIR}/../../../includes
    )
    target_compile_definitions(WhipLoader PRIVATE WHIP_UI_IMGUI)
    target_link_libraries(WhipLoader PRIVATE opengl32)
    message(STATUS "WhipLoader UI: ImGui (Win32 + OpenGL3) from ${WHIPCLIENT_IMGUI_DIR}")
else()
    message(STATUS "WhipLoader UI: Console")
endif()

target_link_libraries(WhipLoader PRIVATE
    WhipNexus
    WhipSysCall
    WhipMmap
    WhipAntiDebug
    bcrypt
    crypt32
    ncrypt
    kernel32
    user32
    shell32
    comctl32
    wbemuuid
    ole32
    oleaut32
    psapi
    iphlpapi
    shlwapi
    winmm
    imagehlp
)
if(VMPROTECT_AVAILABLE)
    target_link_libraries(WhipLoader PRIVATE ${VMPROTECT_LIB})
endif()

target_compile_definitions(WhipLoader PRIVATE
    WIN32_LEAN_AND_MEAN
    NOMINMAX
    UNICODE
    _UNICODE
    # WHIP_DEBUG is our own flag (logging gate). _DEBUG would auto-enable
    # _ITERATOR_DEBUG_LEVEL=2 in STL headers, which mismatches our /MT
    # Release-CRT libs (IDL=0) and triggers LNK2038. Keep WHIP_DEBUG only.
    $<$<CONFIG:Debug>:WHIP_DEBUG>
    _ITERATOR_DEBUG_LEVEL=0
)
if(VMPROTECT_AVAILABLE)
    target_compile_definitions(WhipLoader PRIVATE VMP)
endif()

if(WHIP_BYPASS_MODE)
    message(STATUS "WhipLoader Bypass Mode: ON (surgical FP suppression for Electron/manual-map)")
    # Only WHIP_BYPASS_MODE is passed as a compiler flag — the actual per-check
    # AD_ENABLE_* suppression is handled in Sentinel_bridge.c via #ifdef WHIP_BYPASS_MODE,
    # which disables only the three confirmed false positives in the Electron/manual-map
    # context (exception_rip_anchor, working_set_probe, tls_check). All other checks
    # stay active and detect real debugger/RE-tool presence.
    target_compile_definitions(WhipLoader PRIVATE
        WHIP_BYPASS_MODE
    )
    # Swap the WhipNexus.lib path to its bypass variant. WhipNexus_bypass is
    # compiled with WHIP_BYPASS_MODE=1 → its stopEventLoop / Server::stop use
    # cooperative signal+wait instead of TerminateThread, mandatory when the
    # loader is manual-mapped into a host process (Lunar Client.exe).
    set(WHIPNEXUS_BYPASS_LIB "${WHIPNEXUS_DIR}/cmake-build-release/bin/Release/WhipNexus_bypass.lib")
    if(EXISTS "${WHIPNEXUS_BYPASS_LIB}")
        set_target_properties(WhipNexus PROPERTIES IMPORTED_LOCATION "${WHIPNEXUS_BYPASS_LIB}")
        message(STATUS "WhipLoader linking WhipNexus_bypass.lib (safe shutdown)")
    else()
        message(WARNING "WhipNexus_bypass.lib not found at ${WHIPNEXUS_BYPASS_LIB}; falling back to WhipNexus.lib (build WhipNexus first)")
    endif()
endif()

# Apply build mode specific definitions
if(WHIP_BUILD_MODE STREQUAL "LOCAL")
    message(STATUS "WhipLoader Build Mode: LOCAL (hardcoded DLL + dev port 7778)")
    target_compile_definitions(WhipLoader PRIVATE
        WHIP_LOCAL_MODE
        WHIP_DEV_PORT
    )

    # Copie WhipClient.dll à côté de WhipLoader.exe après le build.
    # On prend la build "dev-with-loader" : c'est elle qui définit LOADER_IPC
    # et inclut LoaderIpcClient.cpp pour parler à LoaderIpcServer.
    set(WHIPCLIENT_DLL "C:/Users/Java/Desktop/whip/WhipClient/build/dev-with-loader/bin/WhipClient.dll"
        CACHE FILEPATH "Path to WhipClient.dll for LOCAL mode" FORCE)
    add_custom_command(TARGET WhipLoader POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${WHIPCLIENT_DLL}"
            "$<TARGET_FILE_DIR:WhipLoader>/WhipClient.dll"
        COMMENT "Copying WhipClient.dll for LOCAL mode"
    )
elseif(WHIP_BUILD_MODE STREQUAL "DEV")
    message(STATUS "WhipLoader Build Mode: DEV (download DLL + dev port 7778)")
    target_compile_definitions(WhipLoader PRIVATE
        WHIP_DEV_MODE
        WHIP_DEV_PORT
    )
elseif(WHIP_BUILD_MODE STREQUAL "PROD")
    message(STATUS "WhipLoader Build Mode: PROD (download DLL + prod port 7777)")
    target_compile_definitions(WhipLoader PRIVATE WHIP_PRODUCTION)
else()
    message(WARNING "Unknown WHIP_BUILD_MODE: ${WHIP_BUILD_MODE}, defaulting to LOCAL")
    target_compile_definitions(WhipLoader PRIVATE
        WHIP_LOCAL_MODE
        WHIP_DEV_PORT
    )
endif()

if(MSVC)
    target_compile_options(WhipLoader PRIVATE
        /W4
        /WX-
        /permissive-
        /Zc:__cplusplus
        /utf-8
        $<$<CONFIG:Release>:/O2>
        $<$<CONFIG:Release>:/GL>
        $<$<CONFIG:Debug>:/Od>
        $<$<CONFIG:Debug>:/Zi>
    )

    target_link_options(WhipLoader PRIVATE
        $<$<CONFIG:Release>:/LTCG>
        /STACK:4194304
    )

    # Sentinel_bridge.c includes the WhipAntiDebugger header-only framework,
    # whose AD_STRENC_* string-encoding macros write 1 byte past the encoded
    # buffer (intentional — the macro pads to a fixed alignment). RTC is
    # already disabled via `#pragma runtime_checks("scu", off)` in the file,
    # but /GS cannot be disabled by pragma — `#pragma strict_gs_check(off)`
    # only relaxes the strict-mode promotion, /GS itself stays on. In Debug
    # the stack cookie picks up the 1-byte over-write and __fastfail's →
    # STATUS_STACK_BUFFER_OVERRUN (0xC0000409) at the very first
    # ad_run_hardened call, before WinMain returns. Disable /GS for this
    # TU only.
    set_source_files_properties(
        src/security/Sentinel_bridge.c
        PROPERTIES COMPILE_OPTIONS "/GS-"
    )

endif()

set(WHIP_GROUP_SOURCES ${WHIP_SOURCES})
if(WHIP_UI_IMGUI)
    list(REMOVE_ITEM WHIP_GROUP_SOURCES ${WHIP_IMGUI_SOURCES})
endif()
source_group(TREE ${CMAKE_CURRENT_SOURCE_DIR} FILES ${WHIP_GROUP_SOURCES} ${WHIP_HEADERS})

if(WHIP_BYPASS_MODE)
    set_target_properties(WhipLoader PROPERTIES
        OUTPUT_NAME "whiploader"
        PREFIX ""
        VS_DEBUGGER_WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
    )
else()
    set_target_properties(WhipLoader PROPERTIES
        OUTPUT_NAME "WhipLoader"
        VS_DEBUGGER_WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
    )
endif()

# Copy WhipNexus PDB to output directory in Debug mode
if(CMAKE_BUILD_TYPE STREQUAL "Debug" AND EXISTS "${WHIPNEXUS_PDB}")
    add_custom_command(TARGET WhipLoader POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${WHIPNEXUS_PDB}"
            "$<TARGET_FILE_DIR:WhipLoader>/WhipNexus.pdb"
        COMMENT "Copying WhipNexus PDB for debugging"
    )
endif()

# ─── WhipADTest — anti-debug diagnostic DLL ───────────────────────────────────
# Load via WHIP_LOCAL_DLL_PATH (same mechanism as whiploader.dll).
# Runs every 5s, logs each check individually to whip_adtest.log.
# Attach/detach x64dbg while running to identify false positives vs real detections.
if(WHIP_BYPASS_MODE)
    add_library(WhipADTest SHARED
        src/test/WhipADTest.cpp
        src/security/Sentinel.cpp
        src/security/Sentinel_bridge.c
        src/util/Types.cpp
    )
    target_include_directories(WhipADTest PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/includes
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        ${WHIPANTIDEBUG_DIR}
    )
    target_compile_definitions(WhipADTest PRIVATE
        WIN32_LEAN_AND_MEAN NOMINMAX UNICODE _UNICODE
        WHIP_BYPASS_MODE WHIP_DEBUG WhipLoader_EXPORTS
        _ITERATOR_DEBUG_LEVEL=0
        # WHIP_BYPASS_MODE déclenche dans Sentinel_bridge.c les #ifdef qui
        # désactivent uniquement les 3 FP confirmés (exception_rip_anchor,
        # working_set_probe, tls_check). Tous les autres checks restent actifs
        # pour valider qu'ils ne produisent pas de FP dans Lunar Client.
    )
    target_link_libraries(WhipADTest PRIVATE
        WhipAntiDebug WhipSysCall bcrypt
        kernel32 user32 advapi32 psapi ole32 windowscodecs
    )
    if(VMPROTECT_AVAILABLE)
        target_link_libraries(WhipADTest PRIVATE ${VMPROTECT_LIB})
    endif()
    set_target_properties(WhipADTest PROPERTIES
        OUTPUT_NAME "whipadtest"
        PREFIX ""
        MSVC_RUNTIME_LIBRARY "MultiThreaded"
    )
    target_compile_options(WhipADTest PRIVATE /Zi /Od /Ob2 /W3 /WX-)
    message(STATUS "WhipADTest: diagnostic DLL enabled")
endif()