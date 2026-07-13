cmake_minimum_required(VERSION 3.20)
project(WhipLoader VERSION 1.0.0 LANGUAGES CXX C ASM_MASM)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Configuration pour le runtime C++ statique
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

set(THEMIDA_SDK_PATH "C:/Users/Java/Desktop/Themida/Themida_3.2.5.0_nU9EplZTHAR/ThemidaSDK/Include/C/Via ASM module")
set(THEMIDA_ASM_FILE "${THEMIDA_SDK_PATH}/SecureEngineMacros.asm")

add_executable(${PROJECT_NAME}
        src/main.cpp
        src/auth/Auth.cpp
        src/auth/protocol/protocol.cpp
        src/auth/Thread/ThreadSafeBuffer.cpp
        src/antidebug/SecurityHelper.cpp
        include/antidebug/SecurityHelper.h
        include/antidebug/nt.h
        src/antidebug/MonitoringThread.cpp
        include/antidebug/MonitoringThread.h
        include/utils/chacha20poly1305/chacha20poly1305.c
        include/utils/chacha20poly1305/chacha20poly1305.h
        include/utils/chacha20poly1305/chacha_merged.c
        include/utils/chacha20poly1305/ecrypt-config.h
        include/utils/chacha20poly1305/ecrypt-machine.h
        include/utils/chacha20poly1305/ecrypt-portable.h
        include/utils/chacha20poly1305/ecrypt-sync.h
        include/utils/chacha20poly1305/poly1305-donna.c
        include/utils/chacha20poly1305/poly1305-donna.h
        include/utils/chacha20poly1305/poly1305-donna-16.h
        include/utils/chacha20poly1305/rfc7539.c
        include/utils/chacha20poly1305/rfc7539.h
        include/utils/chacha20poly1305/poly1305-donna-64.h
        include/utils/chacha20poly1305/poly1305-donna-32.h
        src/utils/NativeCrypto/NativeCrypto.cpp
        include/utils/NativeCrypto/NativeCrypto.h
        src/utils/NativeCrypto/Crypto/XorCrypto.cpp
        include/utils/NativeCrypto/Crypto/XorCrypto.h
        include/utils/NativeCrypto/Crypto/Base64Crypto.h
        src/utils/NativeCrypto/Crypto/Base64Crypto.cpp
        include/utils/NativeCrypto/Crypto/AESCrypto.h
        src/utils/NativeCrypto/Crypto/AESCrypto.cpp
        include/utils/NativeCrypto/Crypto/ChaCha20Crypto.h
        src/utils/NativeCrypto/Crypto/ChaCha20Crypto.cpp
        include/utils/NativeCrypto/Crypto/SHA256Crypto.h
        src/utils/NativeCrypto/Crypto/SHA256Crypto.cpp
        include/utils/NativeCrypto/Crypto/HKDFCrypto.h
        src/utils/NativeCrypto/Crypto/HKDFCrypto.cpp
        include/utils/NativeCrypto/Crypto/P256Crypto.h
        src/utils/NativeCrypto/Crypto/P256Crypto.cpp
        src/mmap/utils/utility.cpp
        src/mmap/utils/import_resolver.cpp
        src/mmap/system/syscall_manager.cpp
        src/mmap/parsing/pe_parser.cpp
        src/mmap/memory/memory_manager.cpp
        src/mmap/memory/process_interface.cpp
        src/mmap/injection/manual_mapper.cpp
        src/mmap/injection/injector_controller.cpp
        src/mmap/execution/tls_manager.cpp
        src/mmap/execution/execution_engine.cpp
        src/mmap/core/mmap.cpp
        src/mmap/core/common.cpp
        include/mmap/execution/tls_manager.h
        include/mmap/core/common.h
        include/mmap/injection/manual_mapping.h
        include/mmap/memory/process_memory.h
        include/mmap/system/syscall_manager.h
        include/mmap/utils/utility.h
        include/utils/sha256/sha256.h
        src/utils/sha256/sha256.c
        include/utils/curveP256m/p256-m.h
        src/utils/curveP256m/p256-m.c
        src/utils/hkdf/hkdf.c
        include/utils/hkdf/hkdf.h
        src/utils/aes128gcm/aes128gcm.c
        include/utils/aes128gcm/aes128gcm.h
        src/utils/aes128gcm/aes128e.c
        include/utils/aes128gcm/aes128e.h
        include/antidebug/common.h
        src/antidebug/common.cpp
        include/antidebug/AntiAnalysis/process.h
        include/antidebug/TimingAttacks/pch.h
        include/antidebug/TimingAttacks/timing.h
        src/antidebug/AntiAnalysis/process.cpp
        src/antidebug/AntiDebug/BeingDebugged.cpp
        src/antidebug/AntiDebug/CheckRemoteDebuggerPresent.cpp
        src/antidebug/AntiDebug/CloseHandle_InvalidHandle.cpp
        src/antidebug/AntiDebug/HardwareBreakpoints.cpp
        src/antidebug/AntiDebug/Interrupt_0x2d.cpp
        src/antidebug/AntiDebug/Interrupt_3.cpp
        src/antidebug/AntiDebug/IsDebuggerPresent.cpp
        src/antidebug/AntiDebug/LowFragmentationHeap.cpp
        src/antidebug/AntiDebug/MemoryBreakpoints_PageGuard.cpp
        src/antidebug/AntiDebug/ModuleBoundsHookCheck.cpp
        src/antidebug/AntiDebug/NtGlobalFlag.cpp
        src/antidebug/AntiDebug/NtQueryInformationProcess_ProcessDebugFlags.cpp
        src/antidebug/AntiDebug/NtQueryInformationProcess_ProcessDebugObject.cpp
        src/antidebug/AntiDebug/NtQueryInformationProcess_ProcessDebugPort.cpp
        src/antidebug/AntiDebug/NtQueryObject_AllTypesInformation.cpp
        src/antidebug/AntiDebug/NtQueryObject_ObjectTypeInformation.cpp
        src/antidebug/AntiDebug/NtQuerySystemInformation_SystemKernelDebuggerInformation.cpp
        src/antidebug/AntiDebug/NtSetInformationThread_ThreadHideFromDebugger.cpp
        src/antidebug/AntiDebug/NtSystemDebugControl.cpp
        src/antidebug/AntiDebug/NtYieldExecution.cpp
        src/antidebug/AntiDebug/OutputDebugStringAPI.cpp
        src/antidebug/AntiDebug/PageExceptionBreakpointCheck.cpp
        src/antidebug/AntiDebug/ParentProcess.cpp
        src/antidebug/AntiDebug/ProcessHeap_Flags.cpp
        src/antidebug/AntiDebug/ProcessHeap_ForceFlags.cpp
        src/antidebug/AntiDebug/ProcessJob.cpp
        src/antidebug/AntiDebug/ScanForModules.cpp
        src/antidebug/AntiDebug/SeDebugPrivilege.cpp
        src/antidebug/AntiDebug/SetHandleInformation_API.cpp
        src/antidebug/AntiDebug/SharedUserData_KernelDebugger.cpp
        src/antidebug/AntiDebug/SoftwareBreakpoints.cpp
        src/antidebug/AntiDebug/TLS_callbacks.cpp
        src/antidebug/AntiDebug/TrapFlag.cpp
        src/antidebug/AntiDebug/UnhandledExceptionFilter_Handler.cpp
        src/antidebug/AntiDebug/WriteWatch.cpp
        src/antidebug/AntiDebug/WUDF_IsDebuggerPresent.cpp
        src/antidebug/AntiDisassm/AntiDisassm.cpp
        src/antidebug/AntiDump/ErasePEHeaderFromMemory.cpp
        src/antidebug/AntiDump/SizeOfImage.cpp
        src/antidebug/AntiVM/Generic.cpp
        src/antidebug/AntiVM/HyperV.cpp
        src/antidebug/AntiVM/KVM.cpp
        src/antidebug/AntiVM/Parallels.cpp
        src/antidebug/AntiVM/Qemu.cpp
        src/antidebug/AntiVM/Services.cpp
        src/antidebug/AntiVM/VirtualBox.cpp
        src/antidebug/AntiVM/VirtualPC.cpp
        src/antidebug/AntiVM/VMWare.cpp
        src/antidebug/AntiVM/Wine.cpp
        src/antidebug/AntiVM/Xen.cpp
        src/antidebug/Shared/APIs.cpp
        src/antidebug/Shared/ApiTypeDefs.cpp
        src/antidebug/Shared/Common.cpp
        src/antidebug/Shared/Utils.cpp
        src/antidebug/TimingAttacks/timing.cpp
        src/antidebug/AntiDisassm/AntiDisassm_x64.asm
        src/antidebug/AntiDebug/int2d_x64.asm
        include/utils/cliUtils.h
        include/Communication/LoaderCommunication.h
        src/communication/LoaderCommunication.cpp
)

target_include_directories(${PROJECT_NAME} PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        ${CMAKE_CURRENT_SOURCE_DIR}/src/auth
)

# Configuration Themida
if (EXISTS "${THEMIDA_SDK_PATH}")
    message(STATUS "Themida SDK found at: ${THEMIDA_SDK_PATH}")
    target_include_directories(${PROJECT_NAME} PRIVATE "${THEMIDA_SDK_PATH}")

    if (EXISTS "${THEMIDA_ASM_FILE}")
        # Créer une bibliothèque statique pour le fichier ASM de Themida
        add_library(ThemidaASM STATIC "${THEMIDA_ASM_FILE}")
        set_target_properties(ThemidaASM PROPERTIES LINKER_LANGUAGE ASM_MASM)

        # Lier la bibliothèque Themida à l'exécutable
        target_link_libraries(${PROJECT_NAME} PRIVATE ThemidaASM)

        message(STATUS "Themida ASM file found and linked: ${THEMIDA_ASM_FILE}")
    else()
        message(FATAL_ERROR "Themida ASM file not found: ${THEMIDA_ASM_FILE}")
    endif()
else()
    message(FATAL_ERROR "Themida SDK not found at: ${THEMIDA_SDK_PATH}")
endif()

# Compile definitions
target_compile_definitions(${PROJECT_NAME} PRIVATE
        Themida
        WHIPAUTH_DEV_MODE  # Skip signature verification (dev/test only)
)

if (MSVC)
    # Options de compilation pour runtime statique
    target_compile_options(${PROJECT_NAME} PRIVATE
            /permissive-
            /MT$<$<CONFIG:Debug>:d>
    )

    # Options de link pour runtime statique
    #target_link_options(${PROJECT_NAME} PRIVATE
    #        /SUBSYSTEM:WINDOWS
    #   )
endif ()

# Link Windows libraries
target_link_libraries(${PROJECT_NAME} PRIVATE
        kernel32
        user32
        advapi32
        psapi
        ntdll
        winmm
        iphlpapi
        wbemuuid
        ws2_32
        crypt32
        bcrypt
        secur32
)

message(STATUS "=== WhipLoader Build Configuration ===")
message(STATUS "Project: ${PROJECT_NAME}")
message(STATUS "Version: ${PROJECT_VERSION}")
message(STATUS "C++ Standard: ${CMAKE_CXX_STANDARD}")
message(STATUS "C Standard: ${CMAKE_C_STANDARD}")
message(STATUS "Runtime Library: Static (/MT)")
message(STATUS "Compiler: ${CMAKE_CXX_COMPILER_ID}")
message(STATUS "Themida ASM: ${THEMIDA_ASM_FILE}")
message(STATUS "=======================================")