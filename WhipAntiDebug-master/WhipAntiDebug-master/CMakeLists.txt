cmake_minimum_required(VERSION 3.20)

# Mixed C + C++ project (C for the framework, C++ for the WhipSysCall bridge)
project(WhipAntiDebugger LANGUAGES C CXX ASM_MASM)

# Static CRT — match WhipNexus/Mmap/SysCall/Client/Loader. Mixed CRT
# (/MD vs /MT) triggers LNK1319 'RuntimeLibrary mismatch' at consumer link.
cmake_policy(SET CMP0091 NEW)
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

# Enable ctest. Test executables register themselves below via add_test().
enable_testing()

# ── Language standards ────────────────────────────────────────────────────────
set(CMAKE_C_STANDARD   17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ── WhipSysCall paths ─────────────────────────────────────────────────────────
set(WHIPSYSCALL_ROOT "C:/Users/Java/Desktop/whip/WhipSysCall")
set(WHIPSYSCALL_INCLUDE "${WHIPSYSCALL_ROOT}/include")

# Prefer release build of the lib; fall back to debug build
find_library(WHIPSYSCALL_LIB
    NAMES WhipSysCall
    PATHS
        "${WHIPSYSCALL_ROOT}/cmake-build-release"
        "${WHIPSYSCALL_ROOT}/cmake-build-debug"
        "${WHIPSYSCALL_ROOT}/build/Release"
        "${WHIPSYSCALL_ROOT}/build/Debug"
    NO_DEFAULT_PATH
)

if(NOT WHIPSYSCALL_LIB)
    message(FATAL_ERROR
        "WhipSysCall.lib not found under ${WHIPSYSCALL_ROOT}.\n"
        "Build WhipSysCall first (cmake --build cmake-build-release).")
endif()
message(STATUS "WhipSysCall lib: ${WHIPSYSCALL_LIB}")

# ── Anti-debug library ────────────────────────────────────────────────────────
# Sources: C++ bridge + ASM moonwalk trampoline
add_library(WhipAntiDebugger STATIC
    antidebug/syscall_bridge.cpp
    antidebug/stack/moonwalk_stub.asm
    antidebug/stack/cloaked_call.asm
    antidebug/tls_callback.c
    antidebug/early_warning.c
)

target_include_directories(WhipAntiDebugger
    PUBLIC
        ${CMAKE_SOURCE_DIR}           # so callers can #include "antidebug/..."
        "${VMP_ROOT}"                 # VMProtect SDK headers
    PRIVATE
        ${WHIPSYSCALL_INCLUDE}        # WhipSysCall headers (C++ only, bridge uses these)
)

target_link_libraries(WhipAntiDebugger
    PUBLIC
        ${WHIPSYSCALL_LIB}
)

# ── VMProtect SDK (required because WhipSysCall.lib was linked with /GL + VMP) ─
set(VMP_ROOT "C:/Users/Java/Desktop/VMP")

# ── MSVC-specific flags ───────────────────────────────────────────────────────
if(MSVC)
    # Apply C/C++ flags ONLY — exclude ASM_MASM targets which don't accept them
    target_compile_options(WhipAntiDebugger PRIVATE
        $<$<COMPILE_LANGUAGE:C,CXX>:/W3>
        $<$<COMPILE_LANGUAGE:C,CXX>:/GS->
        $<$<COMPILE_LANGUAGE:C,CXX>:/Oi>
        # Let CMake's BUILD_TYPE flags drive optimisation: /Od for Debug,
        # /O2 for Release. Forcing /O1 here was tripping D9025 in Release.
        $<$<AND:$<COMPILE_LANGUAGE:C,CXX>,$<CONFIG:Debug>>:/O1>
    )

    # WhipSysCall is now built without /GL — no /LTCG required.
    # (Re-enable if WhipSysCall is rebuilt with /GL.)

    # VMProtectSDK64.lib: WhipSysCall release build depends on it.
    target_link_directories(WhipAntiDebugger PUBLIC "${VMP_ROOT}")
    target_link_libraries(WhipAntiDebugger PUBLIC VMProtectSDK64.lib)
endif()

# ── Example executable ────────────────────────────────────────────────────────
add_executable(WhipAntiDebugger_Example
    main_example.c
    antidebug/static_analysis_orchestrator.c
)

# ── Attach detector test harness ──────────────────────────────────────────────
add_executable(TestAttachDetector
    tests/test_attach_detector.c
)
target_link_libraries(TestAttachDetector PRIVATE WhipAntiDebugger)
target_include_directories(TestAttachDetector PRIVATE ${CMAKE_SOURCE_DIR})
if(MSVC)
    target_compile_options(TestAttachDetector PRIVATE /W3 /Oi /GS-)
    set_source_files_properties(tests/test_attach_detector.c PROPERTIES LANGUAGE C)
endif()

# ── Moonwalk test executable ──────────────────────────────────────────────────
add_executable(MoonwalkTest
    tests/test_moonwalk.c
)

target_link_libraries(WhipAntiDebugger_Example
    PRIVATE
        WhipAntiDebugger
)

target_include_directories(WhipAntiDebugger_Example
    PRIVATE
        ${CMAKE_SOURCE_DIR}
        "${VMP_ROOT}"
)

if(MSVC)
    # AD_DEBUG_BREAKDOWN is for the TestMode diagnostic build only. Leaving
    # it on the production Example pulls in 100+ extra check invocations
    # after `[*] Checks hit:`, several of which mutate ad_state and don't
    # tolerate the post-scoring state — causing intermittent access faults
    # on clean exit. The Example only needs the score and the flag.
    target_compile_options(WhipAntiDebugger_Example PRIVATE
        /W3 /Oi /GS- /Oy-
        # /O1 only in Debug — let Release inherit /O2 from CMAKE_C_FLAGS_RELEASE
        $<$<CONFIG:Debug>:/O1>
    )
    set_source_files_properties(main_example.c PROPERTIES LANGUAGE C)
endif()

target_link_libraries(MoonwalkTest PRIVATE WhipAntiDebugger)
target_include_directories(MoonwalkTest PRIVATE ${CMAKE_SOURCE_DIR})

if(MSVC)
    target_compile_options(MoonwalkTest PRIVATE
        /W3
        /Oi
        /Oy-    # frame pointers obligatoires pour le stack walk dans le test
    )
    set_source_files_properties(tests/test_moonwalk.c PROPERTIES LANGUAGE C)
endif()

# ── New checks test executable ────────────────────────────────────────────────
add_executable(TestNewChecks
    tests/test_new_checks.c
)

target_link_libraries(TestNewChecks PRIVATE WhipAntiDebugger)
target_include_directories(TestNewChecks PRIVATE ${CMAKE_SOURCE_DIR})

if(MSVC)
    target_compile_options(TestNewChecks PRIVATE
        /W3
        /Oi
        /Oy-    # frame pointers pour ad_sh_dr_exception_clear (SEH)
        /GS-
    )
    set_source_files_properties(tests/test_new_checks.c PROPERTIES LANGUAGE C)
endif()

# ── Black-box bypass test ─────────────────────────────────────────────────────
add_executable(TestBlackbox
    tests/test_blackbox.c
)
target_link_libraries(TestBlackbox PRIVATE WhipAntiDebugger)
target_include_directories(TestBlackbox PRIVATE ${CMAKE_SOURCE_DIR})
if(MSVC)
    target_compile_options(TestBlackbox PRIVATE /W3 /Oi /Oy- /GS-)
    set_source_files_properties(tests/test_blackbox.c PROPERTIES LANGUAGE C)
endif()

# ── Red-team reverse test ─────────────────────────────────────────────────────
add_executable(TestReverse
    tests/test_reverse.c
)
target_link_libraries(TestReverse PRIVATE WhipAntiDebugger)
target_include_directories(TestReverse PRIVATE ${CMAKE_SOURCE_DIR})
if(MSVC)
    target_compile_options(TestReverse PRIVATE /W3 /Oi /Oy- /GS-)
    set_source_files_properties(tests/test_reverse.c PROPERTIES LANGUAGE C)
endif()

# ── Whip Hostile harness ──────────────────────────────────────────────────────
add_executable(TestWh
    tests/test_wh.c
)
target_link_libraries(TestWh PRIVATE WhipAntiDebugger)
target_include_directories(TestWh PRIVATE ${CMAKE_SOURCE_DIR})
if(MSVC)
    target_compile_options(TestWh PRIVATE /W3 /Oi /Oy- /GS-)
    set_source_files_properties(tests/test_wh.c PROPERTIES LANGUAGE C)
endif()

# ── Whip Meta harness ─────────────────────────────────────────────────────────
add_executable(TestWm
    tests/test_wm.c
)
target_link_libraries(TestWm PRIVATE WhipAntiDebugger)
target_include_directories(TestWm PRIVATE ${CMAKE_SOURCE_DIR})
if(MSVC)
    target_compile_options(TestWm PRIVATE /W3 /Oi /Oy- /GS-)
    set_source_files_properties(tests/test_wm.c PROPERTIES LANGUAGE C)
endif()

# ── Guardian Meta harness ─────────────────────────────────────────────────────
add_executable(TestGmeta
    tests/test_gmeta.c
)
target_link_libraries(TestGmeta PRIVATE WhipAntiDebugger)
target_include_directories(TestGmeta PRIVATE ${CMAKE_SOURCE_DIR})
if(MSVC)
    target_compile_options(TestGmeta PRIVATE /W3 /Oi /Oy- /GS-)
    set_source_files_properties(tests/test_gmeta.c PROPERTIES LANGUAGE C)
endif()

# ── Guardian Watchdog harness ─────────────────────────────────────────────────
add_executable(TestGw
    tests/test_gw.c
)
target_link_libraries(TestGw PRIVATE WhipAntiDebugger)
target_include_directories(TestGw PRIVATE ${CMAKE_SOURCE_DIR})
if(MSVC)
    target_compile_options(TestGw PRIVATE /W3 /Oi /Oy- /GS-)
    set_source_files_properties(tests/test_gw.c PROPERTIES LANGUAGE C)
endif()

# ── Guardian Matrix V2 harness ────────────────────────────────────────────────
add_executable(TestGm
    tests/test_gm.c
)
target_link_libraries(TestGm PRIVATE WhipAntiDebugger)
target_include_directories(TestGm PRIVATE ${CMAKE_SOURCE_DIR})
if(MSVC)
    target_compile_options(TestGm PRIVATE /W3 /Oi /Oy- /GS-)
    set_source_files_properties(tests/test_gm.c PROPERTIES LANGUAGE C)
endif()

# ── Guardian Ring harness ─────────────────────────────────────────────────────
add_executable(TestGr
    tests/test_gr.c
)
target_link_libraries(TestGr PRIVATE WhipAntiDebugger)
target_include_directories(TestGr PRIVATE ${CMAKE_SOURCE_DIR})
if(MSVC)
    target_compile_options(TestGr PRIVATE /W3 /Oi /Oy- /GS-)
    set_source_files_properties(tests/test_gr.c PROPERTIES LANGUAGE C)
endif()

# ── Universal export hook scanner harness ─────────────────────────────────────
add_executable(TestUhs
    tests/test_uhs.c
)
target_link_libraries(TestUhs PRIVATE WhipAntiDebugger)
target_include_directories(TestUhs PRIVATE ${CMAKE_SOURCE_DIR})
if(MSVC)
    target_compile_options(TestUhs PRIVATE /W3 /Oi /Oy- /GS-)
    set_source_files_properties(tests/test_uhs.c PROPERTIES LANGUAGE C)
endif()

# ── Section protection drift harness ──────────────────────────────────────────
add_executable(TestSp
    tests/test_sp.c
)
target_link_libraries(TestSp PRIVATE WhipAntiDebugger)
target_include_directories(TestSp PRIVATE ${CMAKE_SOURCE_DIR})
if(MSVC)
    target_compile_options(TestSp PRIVATE /W3 /Oi /Oy- /GS-)
    set_source_files_properties(tests/test_sp.c PROPERTIES LANGUAGE C)
endif()

# ── IAT target validation harness ─────────────────────────────────────────────
add_executable(TestIat
    tests/test_iat.c
)
target_link_libraries(TestIat PRIVATE WhipAntiDebugger)
target_include_directories(TestIat PRIVATE ${CMAKE_SOURCE_DIR})
if(MSVC)
    target_compile_options(TestIat PRIVATE /W3 /Oi /Oy- /GS-)
    set_source_files_properties(tests/test_iat.c PROPERTIES LANGUAGE C)
endif()

# ── Self disk-vs-memory harness ───────────────────────────────────────────────
add_executable(TestSdm
    tests/test_sdm.c
)
target_link_libraries(TestSdm PRIVATE WhipAntiDebugger)
target_include_directories(TestSdm PRIVATE ${CMAKE_SOURCE_DIR})
if(MSVC)
    target_compile_options(TestSdm PRIVATE /W3 /Oi /Oy- /GS-)
    set_source_files_properties(tests/test_sdm.c PROPERTIES LANGUAGE C)
endif()

# ── Orphan thread detection harness ───────────────────────────────────────────
add_executable(TestOt
    tests/test_ot.c
)
target_link_libraries(TestOt PRIVATE WhipAntiDebugger)
target_include_directories(TestOt PRIVATE ${CMAKE_SOURCE_DIR})
if(MSVC)
    target_compile_options(TestOt PRIVATE /W3 /Oi /Oy- /GS-)
    set_source_files_properties(tests/test_ot.c PROPERTIES LANGUAGE C)
endif()

# ── ntdll full-text integrity harness ─────────────────────────────────────────
add_executable(TestNft
    tests/test_nft.c
)
target_link_libraries(TestNft PRIVATE WhipAntiDebugger)
target_include_directories(TestNft PRIVATE ${CMAKE_SOURCE_DIR})
if(MSVC)
    target_compile_options(TestNft PRIVATE /W3 /Oi /Oy- /GS-)
    set_source_files_properties(tests/test_nft.c PROPERTIES LANGUAGE C)
endif()

# ── ntdll multi-point integrity harness ───────────────────────────────────────
add_executable(TestNdt
    tests/test_ndt.c
)
target_link_libraries(TestNdt PRIVATE WhipAntiDebugger)
target_include_directories(TestNdt PRIVATE ${CMAKE_SOURCE_DIR})
if(MSVC)
    target_compile_options(TestNdt PRIVATE /W3 /Oi /Oy- /GS-)
    set_source_files_properties(tests/test_ndt.c PROPERTIES LANGUAGE C)
endif()

# ── KiUserExceptionDispatcher integrity harness ───────────────────────────────
add_executable(TestXdp
    tests/test_xdp.c
)
target_link_libraries(TestXdp PRIVATE WhipAntiDebugger)
target_include_directories(TestXdp PRIVATE ${CMAKE_SOURCE_DIR})
if(MSVC)
    target_compile_options(TestXdp PRIVATE /W3 /Oi /Oy- /GS-)
    set_source_files_properties(tests/test_xdp.c PROPERTIES LANGUAGE C)
endif()

# ── Wireshark detection harness ───────────────────────────────────────────────
add_executable(TestWireshark
    tests/test_wireshark.c
)
target_link_libraries(TestWireshark PRIVATE WhipAntiDebugger)
target_include_directories(TestWireshark PRIVATE ${CMAKE_SOURCE_DIR})
if(MSVC)
    target_compile_options(TestWireshark PRIVATE /W3 /Oi /Oy- /GS-)
    set_source_files_properties(tests/test_wireshark.c PROPERTIES LANGUAGE C)
endif()

# ── HW BP via exception harness ───────────────────────────────────────────────
add_executable(TestHwViaExc
    tests/test_hw_via_exc.c
)
target_link_libraries(TestHwViaExc PRIVATE WhipAntiDebugger)
target_include_directories(TestHwViaExc PRIVATE ${CMAKE_SOURCE_DIR})
if(MSVC)
    target_compile_options(TestHwViaExc PRIVATE /W3 /Oi /Oy- /GS-)
    set_source_files_properties(tests/test_hw_via_exc.c PROPERTIES LANGUAGE C)
endif()

# ── TSC/QPC drift harness ─────────────────────────────────────────────────────
add_executable(TestTscQpcDrift
    tests/test_tsc_qpc_drift.c
)
target_link_libraries(TestTscQpcDrift PRIVATE WhipAntiDebugger)
target_include_directories(TestTscQpcDrift PRIVATE ${CMAKE_SOURCE_DIR})
if(MSVC)
    target_compile_options(TestTscQpcDrift PRIVATE /W3 /Oi /Oy- /GS-)
    set_source_files_properties(tests/test_tsc_qpc_drift.c PROPERTIES LANGUAGE C)
endif()

# ── BTB triangulation harness ─────────────────────────────────────────────────
add_executable(TestBtbTriangulate
    tests/test_btb_triangulate.c
)
target_link_libraries(TestBtbTriangulate PRIVATE WhipAntiDebugger)
target_include_directories(TestBtbTriangulate PRIVATE ${CMAKE_SOURCE_DIR})
if(MSVC)
    target_compile_options(TestBtbTriangulate PRIVATE /W3 /Oi /Oy- /GS-)
    set_source_files_properties(tests/test_btb_triangulate.c PROPERTIES LANGUAGE C)
endif()

# ── Boss test (isolates the four feat/* layers) ───────────────────────────────
add_executable(BossTest
    tests/boss_test.c
)

target_link_libraries(BossTest PRIVATE WhipAntiDebugger)
target_include_directories(BossTest PRIVATE ${CMAKE_SOURCE_DIR})

if(MSVC)
    target_compile_options(BossTest PRIVATE
        /W3
        /Oi
        /Oy-
        /GS-
    )
    set_source_files_properties(tests/boss_test.c PROPERTIES LANGUAGE C)
endif()

# ── Thread noise test ────────────────────────────────────────────────────
add_executable(ThreadNoiseTest tests/test_thread_noise.c)
target_link_libraries(ThreadNoiseTest PRIVATE WhipAntiDebugger)
target_include_directories(ThreadNoiseTest PRIVATE ${CMAKE_SOURCE_DIR} "${VMP_ROOT}")
if(MSVC)
    target_compile_options(ThreadNoiseTest PRIVATE /W3 /Oi /GS-)
    set_source_files_properties(tests/test_thread_noise.c PROPERTIES LANGUAGE C)
endif()

# ── kd_deep + al-khaser classics unit harness ───────────────────────────────
add_executable(TestKdClassics tests/test_kd_classics.c)
target_link_libraries(TestKdClassics PRIVATE WhipAntiDebugger)
target_include_directories(TestKdClassics PRIVATE ${CMAKE_SOURCE_DIR} "${VMP_ROOT}")
if(MSVC)
    target_compile_options(TestKdClassics PRIVATE /W3 /Oi /GS- /Oy-)
    set_source_files_properties(tests/test_kd_classics.c PROPERTIES LANGUAGE C)
endif()
# Register with ctest. The harness should print no DETECTED line on a
# clean run — passes the test by default. Under a debugger it will fail
# (which is the desired behaviour for CI: the build server itself
# isn't expected to be running cdb / x64dbg in the loop).
add_test(NAME kd_classics_clean
         COMMAND $<TARGET_FILE:TestKdClassics>)
set_tests_properties(kd_classics_clean PROPERTIES
    FAIL_REGULAR_EXPRESSION "DETECTED")

# ── VM checks false-positive test ────────────────────────────────────────────
add_executable(TestVmChecks tests/test_vm_checks.c)
target_link_libraries(TestVmChecks PRIVATE WhipAntiDebugger)
target_include_directories(TestVmChecks PRIVATE ${CMAKE_SOURCE_DIR} "${VMP_ROOT}")
if(MSVC)
    target_compile_options(TestVmChecks PRIVATE /W3 /Oi /GS- /Oy-)
    set_source_files_properties(tests/test_vm_checks.c PROPERTIES LANGUAGE C)
endif()

# ── Injected DLL target ─────────────────────────────────────────────────────
add_library(WhipAntiDebugger_DLL SHARED
    dll_example.c
)

target_link_libraries(WhipAntiDebugger_DLL
    PRIVATE
        WhipAntiDebugger
)

target_include_directories(WhipAntiDebugger_DLL
    PRIVATE
        ${CMAKE_SOURCE_DIR}
        "${VMP_ROOT}"
)

if(MSVC)
    target_compile_options(WhipAntiDebugger_DLL PRIVATE
        /W3 /Oi /GS-
        $<$<CONFIG:Debug>:/O1>
    )
    set_source_files_properties(dll_example.c PROPERTIES LANGUAGE C)
    # Custom DllMain entry — link msvcrt + vcruntime + ucrt for memcpy/memset/SEH.
    target_link_options(WhipAntiDebugger_DLL PRIVATE /ENTRY:DllMain)
    target_link_libraries(WhipAntiDebugger_DLL PRIVATE msvcrt.lib vcruntime.lib ucrt.lib)
endif()

# ── Test-mode binary (AD_TESTING_MODE=1) — latent arming + liveness disabled ──
# Use this binary in x64dbg to test VM meta-protections (Meta-A through Meta-E)
# without the latent sentinels killing the process before reaching the flag path.
add_executable(WhipAntiDebugger_TestMode
    main_example.c
    antidebug/honeypot/ai_symbols.c
    antidebug/static_analysis_orchestrator.c
)
target_link_libraries(WhipAntiDebugger_TestMode PRIVATE WhipAntiDebugger)
target_include_directories(WhipAntiDebugger_TestMode
    PRIVATE
        ${CMAKE_SOURCE_DIR}
        "${VMP_ROOT}"
)
if(MSVC)
    target_compile_definitions(WhipAntiDebugger_TestMode PRIVATE
        AD_TESTING_MODE=1
        AD_DEBUG_BREAKDOWN
    )
    target_compile_options(WhipAntiDebugger_TestMode PRIVATE
        /W3 /Oi /GS- /Oy-
        $<$<CONFIG:Debug>:/O1>
    )
    set_source_files_properties(main_example.c PROPERTIES LANGUAGE C)
endif()
