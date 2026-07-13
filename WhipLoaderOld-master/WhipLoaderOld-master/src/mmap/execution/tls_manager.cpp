#include "mmap/execution/tls_manager.h"
#include <tlhelp32.h>

#include "mmap/injection/manual_mapping.h"

StaticTlsResolver::StaticTlsResolver(ErrorHandler* errorHandler, NameRandomizer* nameRandomizer,
                                     ProcessInterface* processInterface, MemoryManager* memoryManager)
    : m_errorHandler(errorHandler),
    m_nameRandomizer(nameRandomizer),
    m_processInterface(processInterface),
    m_memoryManager(memoryManager),
    m_tlsIndex(TLS_OUT_OF_INDEXES),
    m_tlsDataTemplate(nullptr),
    m_tlsDataSize(0),
    m_tlsCallbacksAddr(nullptr)
{
    memset(&m_tlsDirectory, 0, sizeof(m_tlsDirectory));
}

StaticTlsResolver::~StaticTlsResolver()
{
    Cleanup();

    m_errorHandler = nullptr;
    m_nameRandomizer = nullptr;
    m_processInterface = nullptr;
    m_memoryManager = nullptr;

    m_tlsIndex = TLS_OUT_OF_INDEXES;
    m_tlsDataSize = 0;
    m_tlsCallbacksAddr = nullptr;
    memset(&m_tlsDirectory, 0, sizeof(m_tlsDirectory));
}

bool StaticTlsResolver::ExecuteTlsCallbacks(const PEParser* peParser, MemoryAddress baseAddress,
    DWORD reason, PVOID context)
{
    MemoryAddress callbacksAddr = GetTlsCallbacksAddress(peParser, baseAddress);
    if (!callbacksAddr) {
        return true;
    }

    return ExecuteCallbacksViaShellcode(callbacksAddr, baseAddress, reason, context);
}

void StaticTlsResolver::Cleanup()
{
    if (m_tlsDataTemplate) {
        m_memoryManager->FreeMemory(m_tlsDataTemplate);
        m_tlsDataTemplate = nullptr;
    }

    if (m_tlsIndex != TLS_OUT_OF_INDEXES) {
        // Libérer le slot TLS proprement pour éviter les fuites
        TlsFree(m_tlsIndex);
        m_tlsIndex = TLS_OUT_OF_INDEXES;
    }

    m_tlsDataSize = 0;
    m_tlsCallbacksAddr = nullptr;
}

PIMAGE_TLS_DIRECTORY StaticTlsResolver::GetTlsDirectory(const PEParser* peParser, MemoryAddress baseAddress)
{
    if (!peParser || !baseAddress) return nullptr;

    PIMAGE_DATA_DIRECTORY tlsDataDir = peParser->GetDataDirectory(IMAGE_DIRECTORY_ENTRY_TLS);
    if (!tlsDataDir || tlsDataDir->Size == 0 || tlsDataDir->VirtualAddress == 0) {
        return nullptr;
    }

    MemoryAddress tlsDirAddr = static_cast<BYTE*>(baseAddress) + tlsDataDir->VirtualAddress;

    if (!m_memoryManager->ReadMemory(tlsDirAddr, &m_tlsDirectory, sizeof(m_tlsDirectory))) {
        return nullptr;
    }

    return reinterpret_cast<PIMAGE_TLS_DIRECTORY>(&m_tlsDirectory);
}

bool StaticTlsResolver::HasTlsData(PIMAGE_TLS_DIRECTORY tlsDirectory)
{
    return (tlsDirectory != nullptr &&
        tlsDirectory->AddressOfIndex != 0 &&
        tlsDirectory->StartAddressOfRawData != 0 &&
        tlsDirectory->EndAddressOfRawData != 0);
}

bool StaticTlsResolver::HasTlsCallbacks(PIMAGE_TLS_DIRECTORY tlsDirectory)
{
    if (tlsDirectory != nullptr && tlsDirectory->AddressOfCallBacks != 0) {
        ULONGLONG firstCallback = 0;
        if (m_memoryManager->ReadMemory(
            reinterpret_cast<MemoryAddress>(tlsDirectory->AddressOfCallBacks),
            &firstCallback, sizeof(firstCallback))) {
            return (firstCallback != 0);
        }
    }
    return false;
}

bool StaticTlsResolver::RelocateAddress(ULONGLONG* address, ULONGLONG originalImageBase, ULONGLONG newImageBase)
{
    if (!address) return false;

    if (*address >= originalImageBase && *address < originalImageBase + 0x10000000ULL) {
        DWORD rva = static_cast<DWORD>(*address - originalImageBase);
        *address = newImageBase + rva;
        return true;
    }

    return true;
}

MemoryAddress StaticTlsResolver::GetTlsCallbacksAddress(const PEParser* peParser, MemoryAddress baseAddress)
{
    PIMAGE_TLS_DIRECTORY tlsDirectory = GetTlsDirectory(peParser, baseAddress);
    if (!tlsDirectory || !HasTlsCallbacks(tlsDirectory)) {
        return nullptr;
    }

    ULONGLONG callbacksAddr = tlsDirectory->AddressOfCallBacks;
    ULONGLONG originalImageBase = peParser->GetImageBase();
    ULONGLONG newImageBase = reinterpret_cast<ULONGLONG>(baseAddress);

    if (!RelocateAddress(&callbacksAddr, originalImageBase, newImageBase)) {
        return nullptr;
    }

    m_tlsCallbacksAddr = reinterpret_cast<MemoryAddress>(callbacksAddr);
    return m_tlsCallbacksAddr;
}

bool StaticTlsResolver::ExecuteCallbacksViaShellcode(MemoryAddress callbacksAddress, MemoryAddress imageBase,
    DWORD reason, PVOID context)
{
    if (!callbacksAddress) return false;

    std::vector<ULONGLONG> callbacks;
    if (!ExtractCallbacksFromAddress(callbacksAddress, callbacks)) {
        return false;
    }

    if (callbacks.empty()) {
        return true;
    }

    struct ExtendedCallbackParams {
        ULONGLONG ImageBase;
        ULONGLONG Reason;
        ULONGLONG Reserved;
        ULONGLONG CallbackCount;
        ULONGLONG Callback1;
        ULONGLONG Callback2;
        ULONGLONG Callback3;
        ULONGLONG Callback4;
    };

    unsigned char callbackShellcode[] = {
        0x48, 0x83, 0xEC, 0x38,
        0x48, 0x89, 0x5C, 0x24, 0x30,
        0x48, 0x89, 0x74, 0x24, 0x28,
        0x48, 0x89, 0xCB,

        0x48, 0x8B, 0x73, 0x18,
        0x48, 0x85, 0xF6,
        0x0F, 0x84, 0x9A, 0x00, 0x00, 0x00,

        0x48, 0x83, 0xFE, 0x01,
        0x72, 0x1E,

        0x48, 0x8B, 0x43, 0x20,
        0x48, 0x85, 0xC0,
        0x74, 0x15,

        0x48, 0x8B, 0x0B,
        0x48, 0x8B, 0x53, 0x08,
        0x4C, 0x8B, 0x43, 0x10,
        0x48, 0x83, 0xEC, 0x20,
        0xFF, 0xD0,
        0x48, 0x83, 0xC4, 0x20,

        0x48, 0x83, 0xFE, 0x02,
        0x72, 0x1E,

        0x48, 0x8B, 0x43, 0x28,
        0x48, 0x85, 0xC0,
        0x74, 0x15,

        0x48, 0x8B, 0x0B,
        0x48, 0x8B, 0x53, 0x08,
        0x4C, 0x8B, 0x43, 0x10,
        0x48, 0x83, 0xEC, 0x20,
        0xFF, 0xD0,
        0x48, 0x83, 0xC4, 0x20,

        0x48, 0x83, 0xFE, 0x03,
        0x72, 0x1E,

        0x48, 0x8B, 0x43, 0x30,
        0x48, 0x85, 0xC0,
        0x74, 0x15,

        0x48, 0x8B, 0x0B,
        0x48, 0x8B, 0x53, 0x08,
        0x4C, 0x8B, 0x43, 0x10,
        0x48, 0x83, 0xEC, 0x20,
        0xFF, 0xD0,
        0x48, 0x83, 0xC4, 0x20,

        0x48, 0x83, 0xFE, 0x04,
        0x72, 0x1E,

        0x48, 0x8B, 0x43, 0x38,
        0x48, 0x85, 0xC0,
        0x74, 0x15,

        0x48, 0x8B, 0x0B,
        0x48, 0x8B, 0x53, 0x08,
        0x4C, 0x8B, 0x43, 0x10,
        0x48, 0x83, 0xEC, 0x20,
        0xFF, 0xD0,
        0x48, 0x83, 0xC4, 0x20,

        0x48, 0x8B, 0x5C, 0x24, 0x30,
        0x48, 0x8B, 0x74, 0x24, 0x28,
        0xB8, 0x01, 0x00, 0x00, 0x00,
        0x48, 0x83, 0xC4, 0x38,
        0xC3
    };

    MemoryAddress shellcodeAddr = m_memoryManager->AllocateMemory(sizeof(callbackShellcode), PAGE_EXECUTE_READWRITE);
    MemoryAddress paramAddr = m_memoryManager->AllocateMemory(sizeof(ExtendedCallbackParams), PAGE_READWRITE);

    if (!shellcodeAddr || !paramAddr) {
        if (shellcodeAddr) m_memoryManager->FreeMemory(shellcodeAddr);
        if (paramAddr) m_memoryManager->FreeMemory(paramAddr);
        return false;
    }

    bool success = false;
    ThreadHandle hThread = nullptr;

    do {
        if (!m_memoryManager->WriteMemory(shellcodeAddr, callbackShellcode, sizeof(callbackShellcode))) {
            break;
        }

        ExtendedCallbackParams params = { 0 };
        params.ImageBase = reinterpret_cast<ULONGLONG>(imageBase);
        params.Reason = reason;
        params.Reserved = reinterpret_cast<ULONGLONG>(context);
        params.CallbackCount = min(callbacks.size(), (size_t)4);

        if (callbacks.size() >= 1) {
            params.Callback1 = callbacks[0];
        }
        if (callbacks.size() >= 2) {
            params.Callback2 = callbacks[1];
        }
        if (callbacks.size() >= 3) {
            params.Callback3 = callbacks[2];
        }
        if (callbacks.size() >= 4) {
            params.Callback4 = callbacks[3];
        }

        if (!m_memoryManager->WriteMemory(paramAddr, &params, sizeof(params))) {
            break;
        }

        if (!m_memoryManager->CreateRemoteThread(shellcodeAddr, paramAddr, &hThread)) {
            break;
        }

        if (!m_memoryManager->WaitForThread(hThread, 15000)) {
            break;
        }

        DWORD exitCode = 0;
        if (GetExitCodeThread(hThread, &exitCode)) {
            success = (exitCode == 1);
        }

    } while (false);

    if (hThread) {
        CloseHandle(hThread);
    }

    if (shellcodeAddr) {
        m_memoryManager->FreeMemory(shellcodeAddr);
    }

    if (paramAddr) {
        m_memoryManager->FreeMemory(paramAddr);
    }

    return success;
}

bool StaticTlsResolver::ExtractCallbacksFromAddress(MemoryAddress callbacksAddress, std::vector<ULONGLONG>& callbacks)
{
    if (!callbacksAddress) return false;

    ULONGLONG callbackArray[16] = { 0 };
    if (!m_memoryManager->ReadMemory(callbacksAddress, callbackArray, sizeof(callbackArray))) {
        return false;
    }

    for (int i = 0; i < 16 && callbackArray[i] != 0; i++) {
        ULONGLONG callbackAddr = callbackArray[i];

        if (callbackAddr > 0x1000 && callbackAddr < 0x7FFFFFFFFFFF) {
            callbacks.push_back(callbackAddr);
        }
    }

    return !callbacks.empty();
}