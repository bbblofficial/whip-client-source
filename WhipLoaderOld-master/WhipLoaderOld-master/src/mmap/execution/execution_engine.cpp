#include "mmap/injection/manual_mapping.h"
#include <fstream>

// ExecutionEngine implementation
ExecutionEngine::ExecutionEngine(ErrorHandler* errorHandler, NameRandomizer* nameRandomizer,
    ProcessInterface* processInterface, MemoryManager* memoryManager, StaticTlsResolver* staitcTlsResolve)
    : m_errorHandler(errorHandler),
    m_nameRandomizer(nameRandomizer),
    m_processInterface(processInterface),
    m_memoryManager(memoryManager),
    m_staticTlsResolver(staitcTlsResolve),
    m_shellcodeAddress(NULL),
    m_parameterAddress(NULL),
    m_threadHijacked(false) {

    m_manualMapper = new ManualMapper(errorHandler, nameRandomizer, processInterface, memoryManager, staitcTlsResolve);
    m_manualMapper->SetExecutionEngine(this);

    ZeroMemory(&m_originalThreadContext, sizeof(CONTEXT));
}

ExecutionEngine::~ExecutionEngine() {
    // RAII cleanup - only local resources, no remote process memory cleanup
    if (m_manualMapper) {
        delete m_manualMapper;
        m_manualMapper = nullptr;
    }

    // Reset member pointers for safety
    m_errorHandler = nullptr;
    m_nameRandomizer = nullptr;
    m_processInterface = nullptr;
    m_memoryManager = nullptr;
    m_staticTlsResolver = nullptr;

    // Reset state variables
    m_shellcodeAddress = NULL;
    m_parameterAddress = NULL;
    m_threadHijacked = false;

    // Clear context structure
    ZeroMemory(&m_originalThreadContext, sizeof(CONTEXT));
}

bool ExecutionEngine::ExecuteDllMain(MemoryAddress baseAddress, DWORD entryPointRVA) {
    if (!baseAddress || entryPointRVA == 0) {
        return false;
    }

    MemoryAddress dllMainAddress = static_cast<BYTE*>(baseAddress) + entryPointRVA;

    struct DllMainParams {
        ULONGLONG ImageBase;
        ULONGLONG Reason;
        ULONGLONG Reserved;
        ULONGLONG DllMainAddress;
    };

    unsigned char shellcode[] = {
        // Sauvegarder RSP original
        0x48, 0x89, 0xE0,                           // mov rax, rsp
        0x48, 0x50,                                 // push rax

        // Aligner la pile sur 16 bytes (requis par Windows x64 ABI)
        0x48, 0x83, 0xE4, 0xF0,                     // and rsp, -16

        // Shadow space standard
        0x48, 0x83, 0xEC, 0x20,                     // sub rsp, 32

        // Sauvegarder les paramètres
        0x48, 0x89, 0xCB,                           // mov rbx, rcx

        // Vérifications et appel DllMain (votre code existant)
        0x48, 0x85, 0xDB,                           // test rbx, rbx
        0x74, 0x1A,                                 // jz cleanup_exit

        0x48, 0x8B, 0x0B,                           // mov rcx, [rbx+0]
        0x48, 0x8B, 0x53, 0x08,                     // mov rdx, [rbx+8]
        0x4C, 0x8B, 0x43, 0x10,                     // mov r8, [rbx+16]
        0x48, 0x8B, 0x43, 0x18,                     // mov rax, [rbx+24]

        0x48, 0x85, 0xC0,                           // test rax, rax
        0x74, 0x08,                                 // jz cleanup_exit

        0xFF, 0xD0,                                 // call rax
        0xEB, 0x02,                                 // jmp restore_stack

        // cleanup_exit:
        0x31, 0xC0,                                 // xor eax, eax

        // restore_stack: Restaurer RSP original
        0x48, 0x83, 0xC4, 0x20,                     // add rsp, 32
        0x58,                                       // pop rax (récupérer RSP original)
        0x48, 0x89, 0xC4,                           // mov rsp, rax
        0xC3                                        // ret
    };

    MemoryAddress shellcodeAddr = m_memoryManager->AllocateMemory(sizeof(shellcode), PAGE_EXECUTE_READWRITE);
    if (!shellcodeAddr || !m_memoryManager->WriteMemory(shellcodeAddr, shellcode, sizeof(shellcode))) {
        if (shellcodeAddr) m_memoryManager->FreeMemory(shellcodeAddr);
        return false;
    }

    MemoryAddress paramAddr = m_memoryManager->AllocateMemory(sizeof(DllMainParams), PAGE_READWRITE);
    if (!paramAddr) {
        m_memoryManager->FreeMemory(shellcodeAddr);
        return false;
    }

    DllMainParams params = { 0 };
    params.ImageBase = reinterpret_cast<ULONGLONG>(baseAddress);
    params.Reason = DLL_PROCESS_ATTACH;
    params.Reserved = 0;
    params.DllMainAddress = reinterpret_cast<ULONGLONG>(dllMainAddress);

    if (!m_memoryManager->WriteMemory(paramAddr, &params, sizeof(params))) {
        m_memoryManager->FreeMemory(paramAddr);
        m_memoryManager->FreeMemory(shellcodeAddr);
        return false;
    }

    ThreadHandle threadHandle = nullptr;
    if (!m_memoryManager->CreateRemoteThread(shellcodeAddr, paramAddr, &threadHandle)) {
        m_memoryManager->FreeMemory(paramAddr);
        m_memoryManager->FreeMemory(shellcodeAddr);
        return false;
    }

    bool threadFinished = m_memoryManager->WaitForThread(threadHandle, INFINITE);

    bool success = false;
    if (threadFinished) {
        DWORD exitCode = 0;
        if (GetExitCodeThread(threadHandle, &exitCode) && exitCode != 0) {
            success = true;
        }
    }
    else {
        TerminateThread(threadHandle, 1);
    }

    CloseHandle(threadHandle);
    m_memoryManager->FreeMemory(paramAddr);
    m_memoryManager->FreeMemory(shellcodeAddr);

    return success;
}

bool ExecutionEngine::DetachDll(MemoryAddress baseAddress, DWORD entryPointRVA) {
    if (!baseAddress || entryPointRVA == 0) {
        return false;
    }

    MemoryAddress dllMainAddress = static_cast<BYTE*>(baseAddress) + entryPointRVA;



    struct DllMainParams {
        ULONGLONG ImageBase;
        ULONGLONG Reason;
        ULONGLONG Reserved;
        ULONGLONG DllMainAddress;
    };

    // Même shellcode que pour ExecuteDllMain
    unsigned char shellcode[] = {
        // Sauvegarder RSP original
        0x48, 0x89, 0xE0,                           // mov rax, rsp
        0x48, 0x50,                                 // push rax

        // Aligner la pile sur 16 bytes
        0x48, 0x83, 0xE4, 0xF0,                     // and rsp, -16

        // Shadow space
        0x48, 0x83, 0xEC, 0x20,                     // sub rsp, 32

        // Sauvegarder les paramètres
        0x48, 0x89, 0xCB,                           // mov rbx, rcx

        // Charger les paramètres et appeler DllMain
        0x48, 0x85, 0xDB,                           // test rbx, rbx
        0x74, 0x1A,                                 // jz cleanup_exit

        0x48, 0x8B, 0x0B,                           // mov rcx, [rbx+0]    (ImageBase)
        0x48, 0x8B, 0x53, 0x08,                     // mov rdx, [rbx+8]    (Reason)
        0x4C, 0x8B, 0x43, 0x10,                     // mov r8, [rbx+16]    (Reserved)
        0x48, 0x8B, 0x43, 0x18,                     // mov rax, [rbx+24]   (DllMain address)

        0x48, 0x85, 0xC0,                           // test rax, rax
        0x74, 0x08,                                 // jz cleanup_exit

        0xFF, 0xD0,                                 // call rax
        0xEB, 0x02,                                 // jmp restore_stack

        // cleanup_exit:
        0x31, 0xC0,                                 // xor eax, eax

        // restore_stack:
        0x48, 0x83, 0xC4, 0x20,                     // add rsp, 32
        0x58,                                       // pop rax
        0x48, 0x89, 0xC4,                           // mov rsp, rax
        0xC3                                        // ret
    };

    MemoryAddress shellcodeAddr = m_memoryManager->AllocateMemory(sizeof(shellcode), PAGE_EXECUTE_READWRITE);
    if (!shellcodeAddr || !m_memoryManager->WriteMemory(shellcodeAddr, shellcode, sizeof(shellcode))) {
        if (shellcodeAddr) m_memoryManager->FreeMemory(shellcodeAddr);
        return false;
    }

    MemoryAddress paramAddr = m_memoryManager->AllocateMemory(sizeof(DllMainParams), PAGE_READWRITE);
    if (!paramAddr) {
        m_memoryManager->FreeMemory(shellcodeAddr);
        return false;
    }

    DllMainParams params = { 0 };
    params.ImageBase = reinterpret_cast<ULONGLONG>(baseAddress);
    params.Reason = DLL_PROCESS_DETACH;
    params.Reserved = 0;
    params.DllMainAddress = reinterpret_cast<ULONGLONG>(dllMainAddress);

    if (!m_memoryManager->WriteMemory(paramAddr, &params, sizeof(params))) {
        m_memoryManager->FreeMemory(paramAddr);
        m_memoryManager->FreeMemory(shellcodeAddr);
        return false;
    }

    ThreadHandle threadHandle = nullptr;
    if (!m_memoryManager->CreateRemoteThread(shellcodeAddr, paramAddr, &threadHandle)) {
        m_memoryManager->FreeMemory(paramAddr);
        m_memoryManager->FreeMemory(shellcodeAddr);
        return false;
    }

    // Timeout de 5 secondes au lieu de INFINITE
    bool threadFinished = m_memoryManager->WaitForThread(threadHandle, 5000);

    bool success = false;
    if (threadFinished) {
        DWORD exitCode = 0;
        if (GetExitCodeThread(threadHandle, &exitCode) && exitCode != STILL_ACTIVE) {
            success = true;
        }
    }
    else {
        // Log l'erreur si vous avez un système de logging
        TerminateThread(threadHandle, 1);
    }

    CloseHandle(threadHandle);
    m_memoryManager->FreeMemory(paramAddr);
    m_memoryManager->FreeMemory(shellcodeAddr);

    return success;
}