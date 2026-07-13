#include "mmap/memory/process_memory.h"
#include "mmap/system/syscall_manager.h"
#include "mmap/utils/utility.h"

MemoryManager::MemoryManager(ErrorHandler *errorHandler, NameRandomizer *nameRandomizer,
                             ProcessInterface *processInterface, SyscallManager *syscallManager)
    : m_errorHandler(errorHandler),
      m_nameRandomizer(nameRandomizer),
      m_processInterface(processInterface),
      m_syscallManager(syscallManager) {
}

MemoryManager::~MemoryManager() {
    m_errorHandler = nullptr;
    m_nameRandomizer = nullptr;
    m_processInterface = nullptr;
    m_syscallManager = nullptr;

    m_cachedPebAddress = nullptr;
    m_cachedTebAddresses.clear();
}

bool MemoryManager::CreateRemoteThread(MemoryAddress startAddress, MemoryAddress parameter,
                                       ThreadHandle *threadHandle) {
    if (!startAddress || !threadHandle) {
        m_errorHandler->SetError(ErrorCode::INVALID_PARAMETER,
                                 "Invalid parameters for remote thread creation");
        return false;
    }

    m_nameRandomizer->ApplyRandomTiming(1, 5);

    if (!m_syscallManager->CreateRemoteThread(
        m_processInterface->GetProcessHandle(),
        startAddress,
        parameter,
        threadHandle)) {
        return false;
    }

    m_errorHandler->ClearError();
    return true;
}

bool MemoryManager::CreateSuspendedThread(MemoryAddress startAddress, MemoryAddress parameter,
                                          ThreadHandle *threadHandle) {
    if (!startAddress || !threadHandle) {
        m_errorHandler->SetError(ErrorCode::INVALID_PARAMETER,
                                 "Invalid parameters for suspended thread creation");
        return false;
    }

    m_nameRandomizer->ApplyRandomTiming(1, 5);

    if (!m_syscallManager->CreateSuspendedThread(
        m_processInterface->GetProcessHandle(),
        startAddress,
        parameter,
        threadHandle)) {
        return false;
    }

    m_errorHandler->ClearError();
    return true;
}

bool MemoryManager::QueueApcThread(ThreadHandle threadHandle, MemoryAddress apcRoutine,
                                   MemoryAddress arg1, MemoryAddress arg2, MemoryAddress arg3) {
    if (!threadHandle || !apcRoutine) {
        m_errorHandler->SetError(ErrorCode::INVALID_PARAMETER,
                                 "Invalid parameters for APC thread queue");
        return false;
    }

    m_nameRandomizer->ApplyRandomTiming(1, 5);

    if (!m_syscallManager->QueueApcThread(
        threadHandle,
        apcRoutine,
        arg1,
        arg2,
        arg3)) {
        return false;
    }

    m_errorHandler->ClearError();
    return true;
}

bool MemoryManager::ResumeThread(ThreadHandle threadHandle) {
    if (!threadHandle) {
        m_errorHandler->SetError(ErrorCode::INVALID_PARAMETER,
                                 "Invalid thread handle for resume operation");
        return false;
    }

    m_nameRandomizer->ApplyRandomTiming(1, 5);

    if (!m_syscallManager->ResumeThread(threadHandle)) {
        return false;
    }

    m_errorHandler->ClearError();
    return true;
}

bool MemoryManager::SuspendThread(ThreadHandle threadHandle) {
    if (!threadHandle) {
        m_errorHandler->SetError(ErrorCode::INVALID_PARAMETER,
                                 "Invalid thread handle for suspend operation");
        return false;
    }

    m_nameRandomizer->ApplyRandomTiming(1, 5);

    ULONG suspendCount = 0;
    NTSTATUS status = m_syscallManager->ExecuteNtSuspendThread(threadHandle, &suspendCount);

    if (!NT_SUCCESS(status)) {
        m_errorHandler->SetError(ErrorCode::EXECUTION_FAILED,
                                 "Failed to suspend thread", status);
        return false;
    }

    m_errorHandler->ClearError();
    return true;
}

bool MemoryManager::WaitForThread(ThreadHandle threadHandle, DWORD timeoutMs) {
    if (!threadHandle) {
        m_errorHandler->SetError(ErrorCode::INVALID_PARAMETER,
                                 "Invalid thread handle for wait operation");
        return false;
    }

    m_nameRandomizer->ApplyRandomTiming(1, 5);

    if (!m_syscallManager->WaitForSingleObject(threadHandle, timeoutMs)) {
        return false;
    }

    m_errorHandler->ClearError();
    return true;
}

bool MemoryManager::OpenProcess(DWORD processId, DWORD desiredAccess, ProcessHandle *processHandle) {
    if (!processHandle) {
        m_errorHandler->SetError(ErrorCode::INVALID_PARAMETER,
                                 "Invalid process handle pointer");
        return false;
    }

    m_nameRandomizer->ApplyRandomTiming(1, 5);

    if (!m_syscallManager->OpenProcess(processId, desiredAccess, processHandle)) {
        return false;
    }

    m_errorHandler->ClearError();
    return true;
}

MemoryAddress MemoryManager::AllocateMemory(MemorySize size, DWORD protection) {
    m_nameRandomizer->ApplyRandomTiming(1, 5);

    MemorySize paddedSize = m_nameRandomizer->GenerateRandomMemorySize(size, size + 2096);

    MemoryAddress baseAddress = (MemoryAddress) 0x190000000;

    if (!m_syscallManager->AllocateVirtualMemory(
        m_processInterface->GetProcessHandle(),
        &baseAddress,
        paddedSize,
        MEM_COMMIT | MEM_RESERVE,
        protection)) {
        uintptr_t fallbackBase = 0x190000000 + 0x10000000;

        while (fallbackBase > 0x10000000) {
            baseAddress = (MemoryAddress) fallbackBase;

            if (m_syscallManager->AllocateVirtualMemory(
                m_processInterface->GetProcessHandle(),
                &baseAddress,
                paddedSize,
                MEM_COMMIT | MEM_RESERVE,
                protection)) {
                break;
            }

            fallbackBase += 0x10000000;
            baseAddress = NULL;
        }
    }

    if (!baseAddress) {
        m_errorHandler->SetError(ErrorCode::MEMORY_ALLOCATION_FAILED,
                                 "Failed to allocate memory in target process");
        return NULL;
    }

    m_allocatedMemory.push_back(std::make_pair(baseAddress, paddedSize));

    m_nameRandomizer->ApplyRandomTiming(1, 5);

    m_errorHandler->ClearError();
    return baseAddress;
}

bool MemoryManager::WriteMemory(MemoryAddress targetAddress, const void *buffer, MemorySize size) {
    if (!targetAddress || !buffer || size == 0) {
        m_errorHandler->SetError(ErrorCode::INVALID_PARAMETER,
                                 "Invalid parameters for memory write");
        return false;
    }

    m_nameRandomizer->ApplyRandomTiming(1, 5);

    MemorySize bytesWritten = 0;
    if (!m_syscallManager->WriteVirtualMemory(
        m_processInterface->GetProcessHandle(),
        targetAddress,
        buffer,
        size,
        &bytesWritten)) {
        return false;
    }

    if (bytesWritten != size) {
        m_errorHandler->SetError(ErrorCode::MEMORY_WRITE_FAILED,
                                 "Incomplete memory write");
        return false;
    }

    m_errorHandler->ClearError();
    return true;
}

bool MemoryManager::ReadMemory(MemoryAddress address, void *buffer, MemorySize size) {
    if (!address || !buffer || size == 0) {
        m_errorHandler->SetError(ErrorCode::INVALID_PARAMETER,
                                 "Invalid parameters for memory read");
        return false;
    }

    m_nameRandomizer->ApplyRandomTiming(1, 5);

    MemorySize bytesRead = 0;
    if (!m_syscallManager->ReadVirtualMemory(
        m_processInterface->GetProcessHandle(),
        address,
        buffer,
        size,
        &bytesRead)) {
        return false;
    }

    if (bytesRead != size) {
        m_errorHandler->SetError(ErrorCode::MEMORY_WRITE_FAILED,
                                 "Incomplete memory read");
        return false;
    }

    m_errorHandler->ClearError();
    return true;
}

bool MemoryManager::ReadMemoryFast(MemoryAddress address, void *buffer, MemorySize size) {
    if (!address || !buffer || size == 0) {
        m_errorHandler->SetError(ErrorCode::INVALID_PARAMETER,
                                 "Invalid parameters for memory read");
        return false;
    }

    MemorySize bytesRead = 0;
    if (!m_syscallManager->ReadVirtualMemory(
        m_processInterface->GetProcessHandle(),
        address,
        buffer,
        size,
        &bytesRead)) {
        return false;
    }

    if (bytesRead != size) {
        m_errorHandler->SetError(ErrorCode::MEMORY_WRITE_FAILED,
                                 "Incomplete memory read");
        return false;
    }

    m_errorHandler->ClearError();
    return true;
}

bool MemoryManager::ProtectMemory(MemoryAddress address, MemorySize size, DWORD newProtection, PDWORD oldProtection) {
    if (!address || size == 0) {
        m_errorHandler->SetError(ErrorCode::INVALID_PARAMETER,
                                 "Invalid parameters for memory protection");
        return false;
    }

    m_nameRandomizer->ApplyRandomTiming(1, 5);

    PVOID baseAddress = address;
    SIZE_T regionSize = size;
    NTSTATUS status = m_syscallManager->ExecuteNtProtectVirtualMemory(
        m_processInterface->GetProcessHandle(),
        &baseAddress,
        &regionSize,
        newProtection,
        (PULONG) oldProtection
    );

    if (!NT_SUCCESS(status)) {
        m_errorHandler->SetError(ErrorCode::MEMORY_PROTECTION_FAILED,
                                 "Failed to change memory protection", status);
        return false;
    }

    m_errorHandler->ClearError();
    return true;
}

bool MemoryManager::FreeMemory(MemoryAddress address) {
    if (!address) {
        m_errorHandler->SetError(ErrorCode::INVALID_PARAMETER,
                                 "Invalid address for memory free");
        return false;
    }

    m_nameRandomizer->ApplyRandomTiming(1, 5);

    for (size_t i = 0; i < m_allocatedMemory.size(); ++i) {
        if (m_allocatedMemory[i].first == address) {
            PVOID baseAddress = address;
            SIZE_T regionSize = 0;

            NTSTATUS status = m_syscallManager->ExecuteNtFreeVirtualMemory(
                m_processInterface->GetProcessHandle(),
                &baseAddress,
                &regionSize,
                MEM_RELEASE
            );

            if (!NT_SUCCESS(status)) {
                m_errorHandler->SetError(ErrorCode::MEMORY_ALLOCATION_FAILED,
                                         "Failed to free memory via syscall", status);
                return false;
            }

            m_allocatedMemory.erase(m_allocatedMemory.begin() + i);

            m_errorHandler->ClearError();
            return true;
        }
    }

    m_errorHandler->SetError(ErrorCode::INVALID_PARAMETER,
                             "Address not found in allocated memory");
    return false;
}

MemoryAddress MemoryManager::QueryRemotePebAddress() {
    if (m_cachedPebAddress) {
        return m_cachedPebAddress;
    }

    PROCESS_BASIC_INFORMATION pbi = {0};
    NTSTATUS status = m_syscallManager->ExecuteNtQueryInformationProcess(
        m_processInterface->GetProcessHandle(),
        0,
        &pbi,
        sizeof(pbi),
        nullptr
    );

    if (!NT_SUCCESS(status)) {
        m_errorHandler->SetError(ErrorCode::PROCESS_ACCESS_DENIED,
                                 "Failed to query process PEB", status);
        return nullptr;
    }

    m_cachedPebAddress = pbi.PebBaseAddress;
    return m_cachedPebAddress;
}

MemoryAddress MemoryManager::QueryRemoteTebAddress(HANDLE hThread) {
    DWORD threadId = GetThreadId(hThread);

    auto it = m_cachedTebAddresses.find(threadId);
    if (it != m_cachedTebAddresses.end()) {
        return it->second;
    }

    typedef NTSTATUS (NTAPI*NtQueryInformationThread_t)(
        HANDLE ThreadHandle,
        ULONG ThreadInformationClass,
        PVOID ThreadInformation,
        ULONG ThreadInformationLength,
        PULONG ReturnLength
    );

    static NtQueryInformationThread_t NtQueryInformationThread = nullptr;
    if (!NtQueryInformationThread) {
        HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
        if (!hNtdll) return nullptr;

        NtQueryInformationThread = reinterpret_cast<NtQueryInformationThread_t>(
            GetProcAddress(hNtdll, "NtQueryInformationThread"));
        if (!NtQueryInformationThread) return nullptr;
    }

    struct THREAD_BASIC_INFORMATION {
        NTSTATUS ExitStatus;
        PVOID TebBaseAddress;
        ULONG_PTR UniqueProcessId;
        ULONG_PTR UniqueThreadId;
        ULONG_PTR AffinityMask;
        LONG Priority;
        LONG BasePriority;
    };

    THREAD_BASIC_INFORMATION tbi = {0};
    NTSTATUS status = NtQueryInformationThread(hThread, 0, &tbi, sizeof(tbi), nullptr);

    if (!NT_SUCCESS(status)) {
        m_errorHandler->SetError(ErrorCode::THREAD_CONTEXT_FAILED,
                                 "Failed to query thread TEB", status);
        return nullptr;
    }

    m_cachedTebAddresses[threadId] = tbi.TebBaseAddress;
    return tbi.TebBaseAddress;
}

bool MemoryManager::ReadTlsBitmap(ULONG *bitmap) {
    MemoryAddress pebAddress = QueryRemotePebAddress();
    if (!pebAddress) return false;

    MemoryAddress bitmapAddr = static_cast<BYTE *>(pebAddress) + 0x358;

    return ReadMemory(bitmapAddr, bitmap, sizeof(ULONG) * 2);
}

bool MemoryManager::WriteTlsBitmap(ULONG *bitmap) {
    MemoryAddress pebAddress = QueryRemotePebAddress();
    if (!pebAddress) return false;

    MemoryAddress bitmapAddr = static_cast<BYTE *>(pebAddress) + 0x358;

    return WriteMemory(bitmapAddr, bitmap, sizeof(ULONG) * 2);
}

bool MemoryManager::ReadTlsSlot(DWORD threadId, ULONG tlsIndex, MemoryAddress *tlsData) {
    HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, threadId);
    if (!hThread) return false;

    MemoryAddress tebAddress = QueryRemoteTebAddress(hThread);
    CloseHandle(hThread);

    if (!tebAddress) return false;

    SIZE_T tlsSlotsOffset = offsetof(TEB, TlsSlots);
    if (tlsSlotsOffset == 0) {
        tlsSlotsOffset = 0x1480;
    }

    MemoryAddress tlsSlotAddr = static_cast<BYTE *>(tebAddress) +
                                tlsSlotsOffset + (tlsIndex * sizeof(PVOID));

    return ReadMemory(tlsSlotAddr, tlsData, sizeof(MemoryAddress));
}

bool MemoryManager::FlushInstructionCache(MemoryAddress address, MemorySize size) {
    m_nameRandomizer->ApplyRandomTiming(1, 5);

    return m_syscallManager->FlushInstructionCache(m_processInterface->GetProcessHandle(), address, size);
}

std::string MemoryManager::GetLastErrorMessage() const {
    return m_errorHandler->GetLastErrorMessage();
}
