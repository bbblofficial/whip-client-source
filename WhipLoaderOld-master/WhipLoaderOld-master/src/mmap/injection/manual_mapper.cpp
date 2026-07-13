#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include "mmap/injection/manual_mapping.h"
#include "mmap/execution/tls_manager.h"
#include "Communication/LoaderCommunication.h"
#include <TlHelp32.h>
#include <set>
#include <mutex>

ManualMapper::ManualMapper(ErrorHandler *errorHandler, NameRandomizer *nameRandomizer,
                           ProcessInterface *processInterface, MemoryManager *memoryManager,
                           StaticTlsResolver *staticTlsResolver)
    : m_errorHandler(errorHandler),
      m_nameRandomizer(nameRandomizer),
      m_processInterface(processInterface),
      m_memoryManager(memoryManager),
      m_staticTlsResolver(staticTlsResolver),
      m_importResolver(nullptr),
      m_executionEngine(nullptr),
      m_mappedBaseAddress(nullptr),
      m_mappedImageSize(0),
      m_entryPointRVA(0),
      m_cachedPEParser(nullptr),
      m_remoteFunctionTable(nullptr),
      m_remoteFunctionTableEntryCount(0) {
    m_importResolver = new ImportResolver(errorHandler, nameRandomizer, processInterface, memoryManager);
}

ManualMapper::~ManualMapper() {
    if (m_importResolver) {
        delete m_importResolver;
        m_importResolver = nullptr;
    }

    m_errorHandler = nullptr;
    m_nameRandomizer = nullptr;
    m_processInterface = nullptr;
    m_memoryManager = nullptr;
    m_staticTlsResolver = nullptr;
    m_executionEngine = nullptr;
}

MemoryAddress ManualMapper::MapDll(const PEParser *peParser) {

    if (!peParser) {
        m_errorHandler->SetError(ErrorCode::INVALID_PARAMETER,
                                 "Invalid PE parser for DLL mapping");
        return NULL;
    }

    m_nameRandomizer->ApplyRandomTiming(5, 20);

    DWORD imageSize = peParser->GetSizeOfImage();
    if (imageSize == 0) {
        m_errorHandler->SetError(ErrorCode::PE_PARSE_FAILED,
                                 "Invalid image size");
        return NULL;
    }


    MemoryAddress baseAddress = m_memoryManager->AllocateMemory(imageSize, PAGE_EXECUTE_READWRITE);
    if (!baseAddress) {
        return NULL;
    }


    bool success = false;
    do {
        PIMAGE_DOS_HEADER dosHeader = peParser->GetDosHeader();
        if (!dosHeader) {
            m_errorHandler->SetError(ErrorCode::PE_PARSE_FAILED, "Failed to get DOS header");
            break;
        }

        DWORD headerSize = dosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS64);

        if (!m_memoryManager->WriteMemory(baseAddress, peParser->GetDllData(), headerSize)) {
            break;
        }

        if (!MapSections(peParser, baseAddress)) {
            break;
        }

        ULONGLONG originalImageBase = peParser->GetImageBase();
        ULONGLONG newImageBase = reinterpret_cast<ULONGLONG>(baseAddress);

        if (originalImageBase != newImageBase) {
            ULONGLONG deltaBase = newImageBase - originalImageBase;

            if (!ProcessRelocations(peParser, baseAddress, deltaBase)) {
                break;
            }
        }

        if (!m_importResolver->ResolveImports(peParser, baseAddress, m_memoryManager)) {
            break;
        }

        ApplyRemoteExceptionHandlers(peParser, (DWORD64) baseAddress);

        m_staticTlsResolver->ExecuteTlsCallbacks(peParser, baseAddress, DLL_PROCESS_ATTACH, nullptr);

        InitializeSecurityCookie(peParser, baseAddress);

        PIMAGE_SECTION_HEADER sectionHeaders = peParser->GetSectionHeaders();
        WORD numberOfSections = peParser->GetNumberOfSections();

        for (WORD i = 0; i < numberOfSections; i++) {
            MemoryAddress sectionAddress = reinterpret_cast<BYTE *>(baseAddress) + sectionHeaders[i].VirtualAddress;
            DWORD sectionSize = sectionHeaders[i].Misc.VirtualSize;
            DWORD protection = GetSectionProtection(sectionHeaders[i].Characteristics);

            char sectionName[9] = {0};
            memcpy(sectionName, sectionHeaders[i].Name, 8);

            DWORD oldProtection;
            m_memoryManager->ProtectMemory(sectionAddress, sectionSize, protection, &oldProtection);
        }

        m_memoryManager->FlushInstructionCache(baseAddress, imageSize);
        success = true;
    } while (false);

    if (!success && baseAddress) {
        baseAddress = NULL;
    }

    if (success) {
        m_mappedBaseAddress = baseAddress;
        m_mappedImageSize = imageSize;
        m_entryPointRVA = peParser->GetEntryPointRVA();
        m_cachedPEParser = peParser;
        m_errorHandler->ClearError();
    } else {
    }

    return baseAddress;
}

bool ManualMapper::CallRemoteDllMain(HANDLE hProcess, DWORD reason) {
    if (!m_mappedBaseAddress || m_entryPointRVA == 0) {
        std::cout << "[UNLOAD] CallRemoteDllMain: No valid DLL or entry point" << std::endl;
        return false;
    }

    struct DllMainParams {
        DWORD64 imageBase;        // 0x00
        DWORD64 reason;           // 0x08
        DWORD64 reserved;         // 0x10
        DWORD64 entryPoint;       // 0x18
        DWORD64 result;           // 0x20
    };

    // Shellcode x64 pour appeler DllMain(hModule, reason, reserved)
    BYTE shellcode[] = {
        // Prologue - sauvegarder et aligner stack
        0x48, 0x89, 0xE0,                   // mov rax, rsp
        0x48, 0x83, 0xE4, 0xF0,             // and rsp, -16 (align 16)
        0x50,                               // push rax (save original rsp)

        0x48, 0x83, 0xEC, 0x28,             // sub rsp, 0x28 (shadow space)
        0x48, 0x89, 0xCB,                   // mov rbx, rcx (save param pointer)

        // Charger les arguments pour DllMain
        0x48, 0x8B, 0x0B,                   // mov rcx, [rbx+0x00] (hModule)
        0x48, 0x8B, 0x53, 0x08,             // mov rdx, [rbx+0x08] (reason)
        0x4C, 0x8B, 0x43, 0x10,             // mov r8, [rbx+0x10]  (reserved)

        // Appeler DllMain
        0x48, 0x8B, 0x43, 0x18,             // mov rax, [rbx+0x18] (entryPoint)
        0xFF, 0xD0,                         // call rax

        // Stocker le résultat
        0x48, 0x89, 0x43, 0x20,             // mov [rbx+0x20], rax

        // Épilogue
        0x48, 0x83, 0xC4, 0x28,             // add rsp, 0x28
        0x58,                               // pop rax (original rsp)
        0x48, 0x89, 0xC4,                   // mov rsp, rax
        0xC3                                // ret
    };

    // Calculer l'adresse de DllMain
    DWORD64 dllMainAddr = (DWORD64)m_mappedBaseAddress + m_entryPointRVA;

    // Préparer les paramètres
    DllMainParams params = {0};
    params.imageBase = (DWORD64)m_mappedBaseAddress;
    params.reason = reason;
    params.reserved = 0;
    params.entryPoint = dllMainAddr;
    params.result = 0;

    // Allouer mémoire pour les paramètres
    LPVOID remoteParams = VirtualAllocEx(hProcess, nullptr, sizeof(DllMainParams),
                                         MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteParams) {
        std::cout << "[UNLOAD] Failed to allocate remote params" << std::endl;
        return false;
    }

    // Écrire les paramètres
    if (!WriteProcessMemory(hProcess, remoteParams, &params, sizeof(params), nullptr)) {
        VirtualFreeEx(hProcess, remoteParams, 0, MEM_RELEASE);
        std::cout << "[UNLOAD] Failed to write remote params" << std::endl;
        return false;
    }

    // Allouer mémoire pour le shellcode
    LPVOID remoteShellcode = VirtualAllocEx(hProcess, nullptr, sizeof(shellcode),
                                            MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteShellcode) {
        VirtualFreeEx(hProcess, remoteParams, 0, MEM_RELEASE);
        std::cout << "[UNLOAD] Failed to allocate remote shellcode" << std::endl;
        return false;
    }

    // Écrire le shellcode
    if (!WriteProcessMemory(hProcess, remoteShellcode, shellcode, sizeof(shellcode), nullptr)) {
        VirtualFreeEx(hProcess, remoteParams, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, remoteShellcode, 0, MEM_RELEASE);
        std::cout << "[UNLOAD] Failed to write remote shellcode" << std::endl;
        return false;
    }

    // Créer le thread distant
    HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0,
                                        (LPTHREAD_START_ROUTINE)remoteShellcode,
                                        remoteParams, 0, nullptr);
    if (!hThread) {
        VirtualFreeEx(hProcess, remoteParams, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, remoteShellcode, 0, MEM_RELEASE);
        std::cout << "[UNLOAD] Failed to create remote thread" << std::endl;
        return false;
    }

    // Attendre avec timeout
    DWORD waitResult = WaitForSingleObject(hThread, 10000);

    bool success = false;
    if (waitResult == WAIT_OBJECT_0) {
        // Lire le résultat
        DllMainParams result;
        if (ReadProcessMemory(hProcess, remoteParams, &result, sizeof(result), nullptr)) {
            success = (result.result != 0);
            std::cout << "[UNLOAD] DllMain returned: " << result.result << std::endl;
        }
    } else {
        std::cout << "[UNLOAD] DllMain call timed out or failed" << std::endl;
        TerminateThread(hThread, 0);
    }

    // Cleanup
    CloseHandle(hThread);
    VirtualFreeEx(hProcess, remoteParams, 0, MEM_RELEASE);
    VirtualFreeEx(hProcess, remoteShellcode, 0, MEM_RELEASE);

    return success;
}

bool ManualMapper::CallRemoteFreeLibrary(HANDLE hProcess, const std::string& moduleName) {
    // Trouver le module dans le processus distant
    HMODULE hRemoteModule = nullptr;

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
                                            m_processInterface->GetProcessId());
    if (hSnap == INVALID_HANDLE_VALUE) {
        return false;
    }

    MODULEENTRY32 me32;
    me32.dwSize = sizeof(MODULEENTRY32);

    if (Module32First(hSnap, &me32)) {
        do {
            if (_stricmp(me32.szModule, moduleName.c_str()) == 0) {
                hRemoteModule = me32.hModule;
                break;
            }
        } while (Module32Next(hSnap, &me32));
    }
    CloseHandle(hSnap);

    if (!hRemoteModule) {
        std::cout << "[UNLOAD] Module not found for FreeLibrary: " << moduleName << std::endl;
        return true;  // Pas une erreur si le module n'est plus là
    }

    // Obtenir l'adresse de FreeLibrary
    HMODULE kernel32Local = GetModuleHandleA("kernel32.dll");
    FARPROC freeLibraryLocal = GetProcAddress(kernel32Local, "FreeLibrary");

    // Calculer l'adresse dans le processus distant
    MemoryAddress kernel32Remote = nullptr;

    hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, m_processInterface->GetProcessId());
    if (hSnap != INVALID_HANDLE_VALUE) {
        me32.dwSize = sizeof(MODULEENTRY32);
        if (Module32First(hSnap, &me32)) {
            do {
                if (_stricmp(me32.szModule, "kernel32.dll") == 0) {
                    kernel32Remote = me32.modBaseAddr;
                    break;
                }
            } while (Module32Next(hSnap, &me32));
        }
        CloseHandle(hSnap);
    }

    if (!kernel32Remote) {
        return false;
    }

    ULONGLONG offset = (ULONGLONG)freeLibraryLocal - (ULONGLONG)kernel32Local;
    LPVOID freeLibraryRemote = (BYTE*)kernel32Remote + offset;

    // Créer un thread pour appeler FreeLibrary
    HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0,
                                        (LPTHREAD_START_ROUTINE)freeLibraryRemote,
                                        hRemoteModule, 0, nullptr);
    if (!hThread) {
        std::cout << "[UNLOAD] Failed to create FreeLibrary thread for: " << moduleName << std::endl;
        return false;
    }

    DWORD waitResult = WaitForSingleObject(hThread, 5000);

    bool success = (waitResult == WAIT_OBJECT_0);
    if (!success) {
        TerminateThread(hThread, 0);
    }

    CloseHandle(hThread);

    std::cout << "[UNLOAD] FreeLibrary for " << moduleName << ": "
              << (success ? "OK" : "FAILED") << std::endl;

    return success;
}

bool ManualMapper::UnloadImportedModules(HANDLE hProcess) {
    if (!m_importResolver) {
        return true;
    }

    const std::vector<std::string>& loadedModules = m_importResolver->GetLoadedModules();

    if (loadedModules.empty()) {
        std::cout << "[UNLOAD] No imported modules to unload" << std::endl;
        return true;
    }

    std::cout << "[UNLOAD] Unloading " << loadedModules.size() << " imported modules..." << std::endl;

    // Unload en ordre inverse (LIFO)
    bool allSuccess = true;
    for (auto it = loadedModules.rbegin(); it != loadedModules.rend(); ++it) {
        if (!CallRemoteFreeLibrary(hProcess, *it)) {
            allSuccess = false;
        }
        Sleep(50);  // Petit délai entre chaque FreeLibrary
    }

    return allSuccess;
}

std::vector<DWORD> ManualMapper::SuspendAllThreadsExceptCurrent(DWORD processId) {
    std::vector<DWORD> threadIds;
    DWORD currentThreadId = GetCurrentThreadId();

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return threadIds;
    }

    THREADENTRY32 te32;
    te32.dwSize = sizeof(THREADENTRY32);

    if (Thread32First(hSnapshot, &te32)) {
        do {
            if (te32.th32OwnerProcessID == processId &&
                te32.th32ThreadID != currentThreadId) {

                HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te32.th32ThreadID);
                if (hThread) {
                    SuspendThread(hThread);
                    threadIds.push_back(te32.th32ThreadID);
                    CloseHandle(hThread);
                }
            }
        } while (Thread32Next(hSnapshot, &te32));
    }

    CloseHandle(hSnapshot);
    return threadIds;
}

void ManualMapper::ResumeAllThreads(const std::vector<DWORD>& threadIds) {
    for (DWORD tid : threadIds) {
        HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, tid);
        if (hThread) {
            ResumeThread(hThread);
            CloseHandle(hThread);
        }
    }
}

bool ManualMapper::HijackThreadWithExitShellcode(HANDLE hProcess, DWORD threadId) {
    HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, threadId);
    if (!hThread) return false;

    SuspendThread(hThread);

    CONTEXT ctx = {0};
    ctx.ContextFlags = CONTEXT_FULL;
    if (!GetThreadContext(hThread, &ctx)) {
        ResumeThread(hThread);
        CloseHandle(hThread);
        return false;
    }

    BYTE shellcode[] = {
        0x48, 0x83, 0xEC, 0x28,
        0x48, 0x31, 0xC9,
        0xFF, 0x15, 0x02, 0x00, 0x00, 0x00,
        0xEB, 0x08,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    FARPROC exitThreadAddr = GetProcAddress(GetModuleHandleA("kernel32.dll"), "ExitThread");
    memcpy(&shellcode[15], &exitThreadAddr, sizeof(FARPROC));

    LPVOID remoteShellcode = VirtualAllocEx(hProcess, nullptr, sizeof(shellcode),
                                            MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteShellcode) {
        ResumeThread(hThread);
        CloseHandle(hThread);
        return false;
    }

    WriteProcessMemory(hProcess, remoteShellcode, shellcode, sizeof(shellcode), nullptr);
    FlushInstructionCache(hProcess, remoteShellcode, sizeof(shellcode));

    ctx.Rip = (DWORD64)remoteShellcode;
    SetThreadContext(hThread, &ctx);

    ResumeThread(hThread);
    WaitForSingleObject(hThread, 5000);

    VirtualFreeEx(hProcess, remoteShellcode, 0, MEM_RELEASE);
    CloseHandle(hThread);

    return true;
}

std::vector<DWORD> ManualMapper::FindThreadsInDll(HANDLE hProcess, DWORD processId, DWORD64 dllStart, DWORD64 dllEnd) {
    std::vector<DWORD> dllThreads;

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return dllThreads;

    THREADENTRY32 te32;
    te32.dwSize = sizeof(THREADENTRY32);

    if (Thread32First(hSnapshot, &te32)) {
        do {
            if (te32.th32OwnerProcessID == processId) {
                HANDLE hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME, FALSE, te32.th32ThreadID);
                if (hThread) {
                    SuspendThread(hThread);

                    CONTEXT ctx = {0};
                    ctx.ContextFlags = CONTEXT_CONTROL;
                    if (GetThreadContext(hThread, &ctx)) {
                        if (ctx.Rip >= dllStart && ctx.Rip < dllEnd) {
                            dllThreads.push_back(te32.th32ThreadID);
                        }
                    }

                    ResumeThread(hThread);
                    CloseHandle(hThread);
                }
            }
        } while (Thread32Next(hSnapshot, &te32));
    }

    CloseHandle(hSnapshot);
    return dllThreads;
}

bool ManualMapper::UnloadInjectedDll() {
    if (!m_mappedBaseAddress) {
        return false;
    }

    std::cout << "UnloadInjectedDll "<< m_mappedBaseAddress << std::endl;

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE,
                                   m_processInterface->GetProcessId());
    if (!hProcess) return false;

    auto* comm = LoaderCommunicator::getInstance();
    if (comm) {
        comm->stopHeartbeat();
        Sleep(500);
    }

    if (m_cachedPEParser && m_staticTlsResolver) {
        m_staticTlsResolver->ExecuteTlsCallbacks(
            m_cachedPEParser, m_mappedBaseAddress, DLL_PROCESS_DETACH, nullptr);
    }

    CallRemoteDllMain(hProcess, DLL_PROCESS_DETACH);

    ApplyRemoveExceptionHandlers(hProcess);

    if (comm) {
        comm->terminateClientThread();
    }

    m_memoryManager->FreeMemory(m_mappedBaseAddress);

    m_mappedBaseAddress = nullptr;
    m_mappedImageSize = 0;
    m_entryPointRVA = 0;
    m_cachedPEParser = nullptr;
    m_remoteFunctionTable = nullptr;

    CloseHandle(hProcess);
    return true;
}


bool ManualMapper::CallRemoteRtlAddFunctionTable(HANDLE hProcess, PRUNTIME_FUNCTION functionTable, DWORD entryCount,
                                                 DWORD64 baseAddress) {
    struct RtlAddFunctionTableParams {
        PRUNTIME_FUNCTION functionTable;
        DWORD entryCount;
        DWORD64 baseAddress;
        FARPROC rtlAddFunctionTableAddr;
        BOOL result;
    };

    BYTE shellcode[] = {
        0x48, 0x83, 0xec, 0x28,
        0x48, 0x89, 0xcb,

        0x48, 0x8b, 0x0b,

        0x8b, 0x53, 0x08,

        0x4c, 0x8b, 0x43, 0x10,

        0x48, 0x8b, 0x43, 0x18,
        0xff, 0xd0,

        0x89, 0x43, 0x20,

        0x48, 0x83, 0xc4, 0x28,
        0xc3
    };

    FARPROC rtlAddFunctionTableAddr = m_processInterface->GetRemoteProcAddress(
        hProcess, "ntdll.dll", "RtlAddFunctionTable");
    if (!rtlAddFunctionTableAddr) {
        return false;
    }

    RtlAddFunctionTableParams params = {
        functionTable,
        entryCount,
        baseAddress,
        rtlAddFunctionTableAddr,
        FALSE
    };

    LPVOID remoteParams = VirtualAllocEx(hProcess, nullptr, sizeof(RtlAddFunctionTableParams),
                                         MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteParams) {
        return false;
    }

    if (!WriteProcessMemory(hProcess, remoteParams, &params, sizeof(params), nullptr)) {
        VirtualFreeEx(hProcess, remoteParams, 0, MEM_RELEASE);
        return false;
    }

    LPVOID remoteShellcode = VirtualAllocEx(hProcess, nullptr, sizeof(shellcode),
                                            MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteShellcode) {
        VirtualFreeEx(hProcess, remoteParams, 0, MEM_RELEASE);
        return false;
    }

    if (!WriteProcessMemory(hProcess, remoteShellcode, shellcode, sizeof(shellcode), nullptr)) {
        VirtualFreeEx(hProcess, remoteParams, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, remoteShellcode, 0, MEM_RELEASE);
        return false;
    }

    HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0,
                                        (LPTHREAD_START_ROUTINE) remoteShellcode,
                                        remoteParams, 0, nullptr);
    if (!hThread) {
        VirtualFreeEx(hProcess, remoteParams, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, remoteShellcode, 0, MEM_RELEASE);
        return false;
    }

    WaitForSingleObject(hThread, INFINITE);

    RtlAddFunctionTableParams result;
    bool success = ReadProcessMemory(hProcess, remoteParams, &result, sizeof(result), nullptr) &&
                   result.result;

    CloseHandle(hThread);
    VirtualFreeEx(hProcess, remoteParams, 0, MEM_RELEASE);
    VirtualFreeEx(hProcess, remoteShellcode, 0, MEM_RELEASE);

    return success;
}

bool ManualMapper::CallRemoteRtlDeleteFunctionTable(HANDLE hProcess, PRUNTIME_FUNCTION functionTable) {
    struct RtlDeleteFunctionTableParams {
        PRUNTIME_FUNCTION functionTable;
        FARPROC rtlDeleteFunctionTableAddr;
        BOOL result;
        BYTE padding[4];  // Alignement
    };

    // Shellcode x64 pour appeler RtlDeleteFunctionTable(functionTable)
    BYTE shellcode[] = {
        0x48, 0x83, 0xec, 0x28,              // sub rsp, 0x28 (shadow space)
        0x48, 0x89, 0xcb,                    // mov rbx, rcx (sauvegarder param struct)

        0x48, 0x8b, 0x0b,                    // mov rcx, [rbx] (arg1: functionTable)

        0x48, 0x8b, 0x43, 0x08,              // mov rax, [rbx+8] (adresse RtlDeleteFunctionTable)
        0xff, 0xd0,                          // call rax

        0x89, 0x43, 0x10,                    // mov [rbx+0x10], eax (stocker résultat)

        0x48, 0x83, 0xc4, 0x28,              // add rsp, 0x28
        0xc3                                 // ret
    };

    FARPROC rtlDeleteFunctionTableAddr = m_processInterface->GetRemoteProcAddress(
        hProcess, "ntdll.dll", "RtlDeleteFunctionTable");

    if (!rtlDeleteFunctionTableAddr) {
        m_errorHandler->SetError(ErrorCode::UNKNOWN_ERROR,
            "Failed to get RtlDeleteFunctionTable address");
        return false;
    }

    RtlDeleteFunctionTableParams params = {
        functionTable,
        rtlDeleteFunctionTableAddr,
        FALSE,
        {0}
    };

    LPVOID remoteParams = VirtualAllocEx(hProcess, nullptr, sizeof(RtlDeleteFunctionTableParams),
                                         MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteParams) {
        m_errorHandler->SetError(ErrorCode::MEMORY_ALLOCATION_FAILED,
            "Failed to allocate remote parameters");
        return false;
    }

    if (!WriteProcessMemory(hProcess, remoteParams, &params, sizeof(params), nullptr)) {
        VirtualFreeEx(hProcess, remoteParams, 0, MEM_RELEASE);
        m_errorHandler->SetError(ErrorCode::MEMORY_WRITE_FAILED,
            "Failed to write remote parameters");
        return false;
    }

    LPVOID remoteShellcode = VirtualAllocEx(hProcess, nullptr, sizeof(shellcode),
                                            MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteShellcode) {
        VirtualFreeEx(hProcess, remoteParams, 0, MEM_RELEASE);
        m_errorHandler->SetError(ErrorCode::MEMORY_ALLOCATION_FAILED,
            "Failed to allocate remote shellcode");
        return false;
    }

    if (!WriteProcessMemory(hProcess, remoteShellcode, shellcode, sizeof(shellcode), nullptr)) {
        VirtualFreeEx(hProcess, remoteParams, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, remoteShellcode, 0, MEM_RELEASE);
        m_errorHandler->SetError(ErrorCode::MEMORY_WRITE_FAILED,
            "Failed to write remote shellcode");
        return false;
    }

    HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0,
                                        (LPTHREAD_START_ROUTINE)remoteShellcode,
                                        remoteParams, 0, nullptr);
    if (!hThread) {
        VirtualFreeEx(hProcess, remoteParams, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, remoteShellcode, 0, MEM_RELEASE);
        m_errorHandler->SetError(ErrorCode::UNKNOWN_ERROR,
            "Failed to create remote thread");
        return false;
    }

    WaitForSingleObject(hThread, INFINITE);

    RtlDeleteFunctionTableParams result;
    bool success = ReadProcessMemory(hProcess, remoteParams, &result, sizeof(result), nullptr) &&
                   result.result == TRUE;

    CloseHandle(hThread);
    VirtualFreeEx(hProcess, remoteParams, 0, MEM_RELEASE);
    VirtualFreeEx(hProcess, remoteShellcode, 0, MEM_RELEASE);

    if (!success) {
        m_errorHandler->SetError(ErrorCode::UNKNOWN_ERROR,
            "RtlDeleteFunctionTable failed in remote process");
    }

    return success;
}

bool ManualMapper::ApplyRemoteExceptionHandlers(const PEParser *peParser, DWORD64 remoteBaseAddress) {
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, m_processInterface->GetProcessId());
    if (!hProcess) {
        return false;
    }

    bool result = false;
    do {
        PIMAGE_DATA_DIRECTORY exceptionDir = peParser->GetDataDirectory(IMAGE_DIRECTORY_ENTRY_EXCEPTION);
        if (!exceptionDir || exceptionDir->VirtualAddress == 0) {
            result = true;
            break;
        }

        PRUNTIME_FUNCTION remoteFunctionTable = (PRUNTIME_FUNCTION) (remoteBaseAddress + exceptionDir->VirtualAddress);
        DWORD entryCount = exceptionDir->Size / sizeof(RUNTIME_FUNCTION);

        result = CallRemoteRtlAddFunctionTable(hProcess, remoteFunctionTable, entryCount, remoteBaseAddress);

        if (result) {
            m_remoteFunctionTable = remoteFunctionTable;
            m_remoteFunctionTableEntryCount = entryCount;
        }
    } while (false);

    CloseHandle(hProcess);
    return result;
}

bool ManualMapper::ApplyRemoveExceptionHandlers(HANDLE hProcess) {
    if (!m_remoteFunctionTable) {
        return true;
    }

    bool deleteSuccess = CallRemoteRtlDeleteFunctionTable(hProcess, m_remoteFunctionTable);

    if (!deleteSuccess) {
        m_errorHandler->SetError(ErrorCode::UNKNOWN_ERROR,
            "Failed to remove exception handler table");
    }

    m_remoteFunctionTable = nullptr;
    m_remoteFunctionTableEntryCount = 0;

    return deleteSuccess;
}

bool ManualMapper::ProcessRelocations(const PEParser *peParser, MemoryAddress baseAddress, ULONGLONG deltaBase) {
    if (!peParser || !baseAddress) {
        return true;
    }

    ULONGLONG originalImageBase = peParser->GetImageBase();
    ULONGLONG newImageBase = reinterpret_cast<ULONGLONG>(baseAddress);
    deltaBase = newImageBase - originalImageBase;

    if (deltaBase == 0) {
        return true;
    }

    PIMAGE_DATA_DIRECTORY relocationDir = peParser->GetDataDirectory(IMAGE_DIRECTORY_ENTRY_BASERELOC);
    if (!relocationDir || relocationDir->VirtualAddress == 0 || relocationDir->Size == 0) {
        return true;
    }

    PIMAGE_BASE_RELOCATION relocation = static_cast<PIMAGE_BASE_RELOCATION>(
        peParser->GetRvaPointer(relocationDir->VirtualAddress));
    if (!relocation) {
        m_errorHandler->SetError(ErrorCode::RELOCATION_FAILED,
                                 "Failed to get relocation table");
        return false;
    }

    DWORD relocationSize = relocationDir->Size;
    DWORD totalBlocks = 0;
    DWORD totalRelocations = 0;
    while (relocationSize > 0 && relocation->SizeOfBlock > 0) {
        if (!ApplyRelocations(relocation, baseAddress, deltaBase, relocation->SizeOfBlock, peParser)) {
            return false;
        }
        DWORD numberOfRelocations = (relocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        totalRelocations += numberOfRelocations;
        totalBlocks++;
        relocationSize -= relocation->SizeOfBlock;
        relocation = reinterpret_cast<PIMAGE_BASE_RELOCATION>(
            reinterpret_cast<BYTE *>(relocation) + relocation->SizeOfBlock);
    }
    m_errorHandler->ClearError();
    return true;
}

bool ManualMapper::InitializeSecurityCookie(const PEParser *peParser, MemoryAddress baseAddress) {
    if (!peParser || !baseAddress) {
        m_errorHandler->SetError(ErrorCode::INVALID_PARAMETER,
                                 "Invalid parameters for security cookie initialization");
        return false;
    }

    m_nameRandomizer->ApplyRandomTiming(1, 5);

    PIMAGE_DATA_DIRECTORY loadConfigDir = peParser->GetDataDirectory(IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG);
    if (!loadConfigDir || loadConfigDir->VirtualAddress == 0 || loadConfigDir->Size == 0) {
        return true;
    }

    ULONGLONG cookie = 0;
    if (peParser->Is64Bit()) {
        DWORD high = Utils::GetRandomNumber(0, 0xFFFFFFFF);
        DWORD low = Utils::GetRandomNumber(0, 0xFFFFFFFF);
        cookie = (static_cast<ULONGLONG>(high) << 32) | low;
    } else {
        cookie = Utils::GetRandomNumber(0, 0xFFFFFFFF);
    }

    if (cookie == 0 || cookie == 0xBB40E64E || cookie == 0xBB40E64EFDCDFFFF) {
        cookie = 0xABCDEF0123456789;
    }

    HANDLE hProcess = m_processInterface->GetProcessHandle();
    if (!hProcess) {
        m_errorHandler->SetError(ErrorCode::UNKNOWN_ERROR,
                                 "Failed to get process handle");
        return false;
    }

    if (peParser->Is64Bit()) {
        BYTE *loadConfigData = static_cast<BYTE *>(peParser->GetRvaPointer(loadConfigDir->VirtualAddress));
        if (!loadConfigData) {
            m_errorHandler->SetError(ErrorCode::PE_PARSE_FAILED,
                                     "Failed to get load config directory");
            return false;
        }

        ULONGLONG *securityCookieAddr = reinterpret_cast<ULONGLONG *>(loadConfigData + 0x40);
        if (*securityCookieAddr != 0) {
            ULONGLONG cookieRva = *securityCookieAddr - peParser->GetImageBase();

            if (cookieRva >= peParser->GetSizeOfImage()) {
                m_errorHandler->ClearError();
                return true;
            }

            LPVOID remoteCookieAddr = reinterpret_cast<BYTE *>(baseAddress) + cookieRva;

            SIZE_T bytesWritten;
            if (!WriteProcessMemory(hProcess, remoteCookieAddr, &cookie,
                                   sizeof(ULONGLONG), &bytesWritten) ||
                bytesWritten != sizeof(ULONGLONG)) {
                m_errorHandler->SetError(ErrorCode::MEMORY_WRITE_FAILED,
                                       "Failed to write security cookie");
                return false;
            }
        }
    } else {
        // 32-bit
        BYTE *loadConfigData = static_cast<BYTE *>(peParser->GetRvaPointer(loadConfigDir->VirtualAddress));
        if (!loadConfigData) {
            m_errorHandler->SetError(ErrorCode::PE_PARSE_FAILED,
                                     "Failed to get load config directory");
            return false;
        }

        DWORD *securityCookieAddr = reinterpret_cast<DWORD *>(loadConfigData + 0x1C);
        if (*securityCookieAddr != 0) {
            DWORD cookieRva = *securityCookieAddr - static_cast<DWORD>(peParser->GetImageBase());

            if (cookieRva >= peParser->GetSizeOfImage()) {
                m_errorHandler->ClearError();
                return true;
            }

            LPVOID remoteCookieAddr = reinterpret_cast<BYTE *>(baseAddress) + cookieRva;

            DWORD cookie32 = static_cast<DWORD>(cookie);
            SIZE_T bytesWritten;
            if (!WriteProcessMemory(hProcess, remoteCookieAddr, &cookie32,
                                   sizeof(DWORD), &bytesWritten) ||
                bytesWritten != sizeof(DWORD)) {
                m_errorHandler->SetError(ErrorCode::MEMORY_WRITE_FAILED,
                                       "Failed towrite security cookie");
                return false;
            }
        }
    }

    m_errorHandler->ClearError();
    return true;
}

bool ManualMapper::CleanupHeaders(MemoryAddress baseAddress) {
    if (!baseAddress) {
        m_errorHandler->SetError(ErrorCode::INVALID_PARAMETER,
                                 "Invalid base address for header cleanup");
        return false;
    }

    HANDLE targetProcess = m_processInterface->GetProcessHandle();
    if (!targetProcess) {
        return false;
    }

    m_nameRandomizer->ApplyRandomTiming(1, 5);

    IMAGE_DOS_HEADER dosHeader = {0};
    SIZE_T bytesRead = 0;

    if (!ReadProcessMemory(targetProcess, baseAddress, &dosHeader, sizeof(IMAGE_DOS_HEADER), &bytesRead) ||
        bytesRead != sizeof(IMAGE_DOS_HEADER)) {
        return false;
    }

    if (dosHeader.e_magic != 0x5A4D) {
        return false;
    }

    DWORD ntSignature = 0;
    LPVOID ntSignatureAddr = reinterpret_cast<BYTE *>(baseAddress) + dosHeader.e_lfanew;

    if (!ReadProcessMemory(targetProcess, ntSignatureAddr, &ntSignature, sizeof(DWORD), &bytesRead) ||
        bytesRead != sizeof(DWORD)) {
        return false;
    }

    if (ntSignature != 0x00004550) {
        m_errorHandler->SetError(ErrorCode::PE_PARSE_FAILED,
                                 "Invalid NT signature");
        return false;
    }

    IMAGE_FILE_HEADER fileHeader = {0};
    LPVOID fileHeaderAddr = reinterpret_cast<BYTE *>(baseAddress) + dosHeader.e_lfanew + sizeof(DWORD);

    if (!ReadProcessMemory(targetProcess, fileHeaderAddr, &fileHeader, sizeof(IMAGE_FILE_HEADER), &bytesRead) ||
        bytesRead != sizeof(IMAGE_FILE_HEADER)) {
        return false;
    }

    DWORD headerSize = 0;

    if (fileHeader.Machine == 0x8664) {
        IMAGE_OPTIONAL_HEADER64 optHeader = {0};
        LPVOID optHeaderAddr = reinterpret_cast<BYTE *>(baseAddress) + dosHeader.e_lfanew + sizeof(DWORD) + sizeof(
                                   IMAGE_FILE_HEADER);

        if (!ReadProcessMemory(targetProcess, optHeaderAddr, &optHeader, sizeof(IMAGE_OPTIONAL_HEADER64), &bytesRead) ||
            bytesRead != sizeof(IMAGE_OPTIONAL_HEADER64)) {
            return false;
        }

        headerSize = optHeader.SizeOfHeaders;
    } else {
        IMAGE_OPTIONAL_HEADER32 optHeader = {0};
        LPVOID optHeaderAddr = reinterpret_cast<BYTE *>(baseAddress) + dosHeader.e_lfanew + sizeof(DWORD) + sizeof(
                                   IMAGE_FILE_HEADER);

        if (!ReadProcessMemory(targetProcess, optHeaderAddr, &optHeader, sizeof(IMAGE_OPTIONAL_HEADER32), &bytesRead) ||
            bytesRead != sizeof(IMAGE_OPTIONAL_HEADER32)) {
            return false;
        }

        headerSize = optHeader.SizeOfHeaders;
    }

    if (headerSize == 0 || headerSize > 0x10000) {
        return false;
    }

    std::vector<BYTE> zeroBuffer(headerSize, 0);
    SIZE_T bytesWritten = 0;

    if (!WriteProcessMemory(targetProcess, baseAddress, zeroBuffer.data(), headerSize, &bytesWritten) ||
        bytesWritten != headerSize) {
        return false;
    }

    m_errorHandler->ClearError();
    return true;
}

DWORD ManualMapper::GetSectionProtection(DWORD characteristics) const {
    DWORD protection = PAGE_NOACCESS;

    if (characteristics & IMAGE_SCN_MEM_WRITE) {
        protection = PAGE_WRITECOPY;
    }

    if (characteristics & IMAGE_SCN_MEM_READ) {
        protection = (protection == PAGE_WRITECOPY) ? PAGE_READWRITE : PAGE_READONLY;
    }

    if (characteristics & IMAGE_SCN_MEM_EXECUTE) {
        if (protection == PAGE_READWRITE) {
            protection = PAGE_EXECUTE_READWRITE;
        } else if (protection == PAGE_READONLY) {
            protection = PAGE_EXECUTE_READ;
        } else if (protection == PAGE_WRITECOPY) {
            protection = PAGE_EXECUTE_WRITECOPY;
        } else {
            protection = PAGE_EXECUTE;
        }
    }

    return protection;
}

bool ManualMapper::MapSections(const PEParser *peParser, MemoryAddress baseAddress) {
    if (!peParser || !baseAddress) {
        m_errorHandler->SetError(ErrorCode::INVALID_PARAMETER,
                                 "Invalid parameters for section mapping");
        return false;
    }

    m_nameRandomizer->ApplyRandomTiming(1, 5);

    PIMAGE_SECTION_HEADER sectionHeaders = peParser->GetSectionHeaders();
    WORD numberOfSections = peParser->GetNumberOfSections();

    if (!sectionHeaders || numberOfSections == 0) {
        m_errorHandler->SetError(ErrorCode::PE_PARSE_FAILED,
                                 "Failed to get section headers");
        return false;
    }

    DWORD headerSize = 0;

    if (peParser->Is64Bit()) {
        PIMAGE_NT_HEADERS64 ntHeaders = static_cast<PIMAGE_NT_HEADERS64>(peParser->GetNtHeaders());
        headerSize = ntHeaders->OptionalHeader.SizeOfHeaders;
    } else {
        PIMAGE_NT_HEADERS32 ntHeaders = static_cast<PIMAGE_NT_HEADERS32>(peParser->GetNtHeaders());
        headerSize = ntHeaders->OptionalHeader.SizeOfHeaders;
    }

    if (!m_memoryManager->WriteMemory(baseAddress, peParser->GetDllData(), headerSize)) {
        return false;
    }

    for (WORD i = 0; i < numberOfSections; i++) {
        DWORD virtualAddress = sectionHeaders[i].VirtualAddress;
        DWORD virtualSize = sectionHeaders[i].Misc.VirtualSize;
        DWORD rawDataSize = sectionHeaders[i].SizeOfRawData;
        DWORD rawDataOffset = sectionHeaders[i].PointerToRawData;

        char sectionName[IMAGE_SIZEOF_SHORT_NAME + 1] = {0};
        memcpy(sectionName, sectionHeaders[i].Name, IMAGE_SIZEOF_SHORT_NAME);

        MemoryAddress sectionAddress = reinterpret_cast<MemoryAddress>(
            reinterpret_cast<BYTE *>(baseAddress) + virtualAddress);

        DWORD copySize = (rawDataSize > virtualSize) ? virtualSize : rawDataSize;

        if (copySize > 0) {
            const BYTE *sectionData = peParser->GetDllData() + rawDataOffset;
            if (!m_memoryManager->WriteMemory(sectionAddress, sectionData, copySize)) {
                return false;
            }
        }

        if (virtualSize > copySize) {
            DWORD zeroSize = virtualSize - copySize;
            MemoryAddress zeroAddress = reinterpret_cast<MemoryAddress>(
                reinterpret_cast<BYTE *>(sectionAddress) + copySize);

            std::vector<BYTE> zeroBuffer(zeroSize, 0);
            if (!m_memoryManager->WriteMemory(zeroAddress, zeroBuffer.data(), zeroSize)) {
                return false;
            }
        }

        if (Utils::GetRandomNumber(0, 10) > 8) {
            m_nameRandomizer->ApplyRandomTiming(1, 3);
        }
    }

    m_errorHandler->ClearError();
    return true;
}

bool ManualMapper::ApplyRelocations(PIMAGE_BASE_RELOCATION relocationBlock, MemoryAddress baseAddress,
                                    ULONGLONG deltaBase, DWORD blockSize, const PEParser *peParser) {
    if (!relocationBlock || !baseAddress || blockSize < sizeof(IMAGE_BASE_RELOCATION)) {
        return false;
    }

    HANDLE targetProcess = m_processInterface->GetProcessHandle();
    DWORD numberOfRelocations = (blockSize - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
    WORD *relocations = reinterpret_cast<WORD *>(relocationBlock + 1);

    ULONGLONG imageSize = peParser->GetSizeOfImage();

    for (DWORD i = 0; i < numberOfRelocations; i++) {
        WORD relocation = relocations[i];
        BYTE type = relocation >> 12;
        WORD offset = relocation & 0xFFF;

        if (type == IMAGE_REL_BASED_ABSOLUTE) {
            continue;
        }

        MemoryAddress patchAddress = reinterpret_cast<BYTE *>(baseAddress) +
                                     relocationBlock->VirtualAddress + offset;

        ULONGLONG rvaOffset = relocationBlock->VirtualAddress + offset;
        if (rvaOffset >= imageSize) {
            return false;
        }

        switch (type) {
            case IMAGE_REL_BASED_DIR64: {
                ULONGLONG currentValue = 0;
                SIZE_T bytesRead;

                if (!ReadProcessMemory(targetProcess, patchAddress,
                                       &currentValue, sizeof(ULONGLONG),
                                       &bytesRead) || bytesRead != sizeof(ULONGLONG)) {
                    return false;
                }

                ULONGLONG newValue = currentValue + deltaBase;

                SIZE_T bytesWritten;
                if (!WriteProcessMemory(targetProcess, patchAddress,
                                        &newValue, sizeof(ULONGLONG),
                                        &bytesWritten) || bytesWritten != sizeof(ULONGLONG)) {
                    return false;
                }

                break;
            }

            case IMAGE_REL_BASED_HIGHLOW: {
                DWORD currentValue = 0;
                SIZE_T bytesRead;

                if (!ReadProcessMemory(targetProcess, patchAddress,
                                       &currentValue, sizeof(DWORD), &bytesRead) || bytesRead != sizeof(DWORD)) {
                    return false;
                }

                DWORD newValue = currentValue + static_cast<DWORD>(deltaBase);

                SIZE_T bytesWritten;
                if (!WriteProcessMemory(targetProcess, patchAddress,
                                        &newValue, sizeof(DWORD), &bytesWritten) || bytesWritten != sizeof(DWORD)) {
                    return false;
                }

                break;
            }

            case IMAGE_REL_BASED_HIGH: {
                WORD currentValue = 0;
                SIZE_T bytesRead;

                if (!ReadProcessMemory(targetProcess, patchAddress,
                                       &currentValue, sizeof(WORD), &bytesRead) || bytesRead != sizeof(WORD)) {
                    return false;
                }

                WORD newValue = currentValue + static_cast<WORD>((deltaBase >> 16) & 0xFFFF);

                SIZE_T bytesWritten;
                if (!WriteProcessMemory(targetProcess, patchAddress,
                                        &newValue, sizeof(WORD), &bytesWritten) || bytesWritten != sizeof(WORD)) {
                    return false;
                }
                break;
            }

            case IMAGE_REL_BASED_LOW: {
                WORD currentValue = 0;
                SIZE_T bytesRead;

                if (!ReadProcessMemory(targetProcess, patchAddress,
                                       &currentValue, sizeof(WORD), &bytesRead) || bytesRead != sizeof(WORD)) {
                    return false;
                }

                WORD newValue = currentValue + static_cast<WORD>(deltaBase & 0xFFFF);

                SIZE_T bytesWritten;
                if (!WriteProcessMemory(targetProcess, patchAddress,
                                        &newValue, sizeof(WORD), &bytesWritten) || bytesWritten != sizeof(WORD)) {
                    return false;
                }

                break;
            }

            default:
                return false;
        }
    }

    return true;
}