#include "mmap/system/syscall_manager.h"

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS                   ((NTSTATUS)0x00000000L)
#endif

#ifndef STATUS_TIMEOUT
#define STATUS_TIMEOUT                   ((NTSTATUS)0x00000102L)
#endif

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#ifndef STATUS_UNSUCCESSFUL
#define STATUS_UNSUCCESSFUL             ((NTSTATUS)0xC0000001L)
#endif

#ifndef STATUS_ACCESS_DENIED
#define STATUS_ACCESS_DENIED             ((NTSTATUS)0xC0000022L)
#endif

#ifndef STATUS_INVALID_PARAMETER
#define STATUS_INVALID_PARAMETER         ((NTSTATUS)0xC000000DL)
#endif

SyscallManager::SyscallManager(ErrorHandler *errorHandler)
    : m_errorHandler(errorHandler), m_ntdllHandle(NULL) {
    m_NtCreateThreadEx = NULL;
    m_NtAllocateVirtualMemory = NULL;
    m_NtProtectVirtualMemory = NULL;
    m_NtWriteVirtualMemory = NULL;
    m_NtReadVirtualMemory = NULL;
    m_NtCreateSection = NULL;
    m_NtMapViewOfSection = NULL;
    m_NtUnmapViewOfSection = NULL;
    m_NtFlushInstructionCache = NULL;
    m_NtFreeVirtualMemory = NULL;
    m_NtWaitForSingleObject = NULL;
}

SyscallManager::~SyscallManager() {
    m_NtCreateThreadEx = nullptr;
    m_NtAllocateVirtualMemory = nullptr;
    m_NtProtectVirtualMemory = nullptr;
    m_NtWriteVirtualMemory = nullptr;
    m_NtReadVirtualMemory = nullptr;
    m_NtCreateSection = nullptr;
    m_NtMapViewOfSection = nullptr;
    m_NtUnmapViewOfSection = nullptr;
    m_NtFlushInstructionCache = nullptr;
    m_NtFreeVirtualMemory = nullptr;
    m_NtWaitForSingleObject = nullptr;
    m_NtOpenProcess = nullptr;
    m_NtQueueApcThread = nullptr;
    m_NtResumeThread = nullptr;
    m_NtSuspendThread = nullptr;
    m_NtQueryInformationProcess = nullptr;

    m_ntdllHandle = nullptr;
}

bool SyscallManager::Initialize() {
    m_ntdllHandle = GetModuleHandleA("ntdll.dll");
    if (m_ntdllHandle == NULL) {
        m_errorHandler->SetLastWinError(ErrorCode::SYSCALL_FAILED, "Failed to get handle to ntdll.dll");
        return false;
    }

    m_NtCreateThreadEx = (NtCreateThreadExFunc) GetProcAddressSafe(m_ntdllHandle, "NtCreateThreadEx");
    m_NtAllocateVirtualMemory = (NtAllocateVirtualMemoryFunc) GetProcAddressSafe(
        m_ntdllHandle, "NtAllocateVirtualMemory");
    m_NtQueryInformationProcess = (NtQueryInformationProcessFunc) GetProcAddressSafe(
        m_ntdllHandle, "NtQueryInformationProcess");
    m_NtProtectVirtualMemory = (NtProtectVirtualMemoryFunc) GetProcAddressSafe(m_ntdllHandle, "NtProtectVirtualMemory");
    m_NtWriteVirtualMemory = (NtWriteVirtualMemoryFunc) GetProcAddressSafe(m_ntdllHandle, "NtWriteVirtualMemory");
    m_NtReadVirtualMemory = (NtReadVirtualMemoryFunc) GetProcAddressSafe(m_ntdllHandle, "NtReadVirtualMemory");
    m_NtCreateSection = (NtCreateSectionFunc) GetProcAddressSafe(m_ntdllHandle, "NtCreateSection");
    m_NtMapViewOfSection = (NtMapViewOfSectionFunc) GetProcAddressSafe(m_ntdllHandle, "NtMapViewOfSection");
    m_NtUnmapViewOfSection = (NtUnmapViewOfSectionFunc) GetProcAddressSafe(m_ntdllHandle, "NtUnmapViewOfSection");
    m_NtFlushInstructionCache = (NtFlushInstructionCacheFunc) GetProcAddressSafe(
        m_ntdllHandle, "NtFlushInstructionCache");
    m_NtFreeVirtualMemory = (NtFreeVirtualMemoryFunc) GetProcAddressSafe(m_ntdllHandle, "NtFreeVirtualMemory");
    m_NtWaitForSingleObject = (NtWaitForSingleObjectFunc) GetProcAddressSafe(m_ntdllHandle, "NtWaitForSingleObject");
    m_NtOpenProcess = (NtOpenProcessFunc) GetProcAddressSafe(m_ntdllHandle, "NtOpenProcess");
    m_NtQueueApcThread = (NtQueueApcThreadFunc) GetProcAddressSafe(m_ntdllHandle, "NtQueueApcThread");
    m_NtResumeThread = (NtResumeThreadFunc) GetProcAddressSafe(m_ntdllHandle, "NtResumeThread");
    m_NtSuspendThread = (NtSuspendThreadFunc) GetProcAddressSafe(m_ntdllHandle, "NtSuspendThread");

    if (!m_NtCreateThreadEx || !m_NtAllocateVirtualMemory || !m_NtProtectVirtualMemory ||
        !m_NtWriteVirtualMemory || !m_NtReadVirtualMemory || !m_NtCreateSection ||
        !m_NtMapViewOfSection || !m_NtUnmapViewOfSection || !m_NtFlushInstructionCache ||
        !m_NtFreeVirtualMemory || !m_NtWaitForSingleObject || !m_NtOpenProcess ||
        !m_NtQueueApcThread || !m_NtResumeThread || !m_NtSuspendThread || !m_NtQueryInformationProcess) {
        m_errorHandler->SetLastWinError(ErrorCode::SYSCALL_FAILED,
                                        "Failed to get address of one or more NT API functions");
        return false;
    }

    return true;
}

NTSTATUS SyscallManager::ExecuteNtWaitForSingleObject(
    HANDLE Handle,
    BOOLEAN Alertable,
    PLARGE_INTEGER Timeout) {
    return m_NtWaitForSingleObject(
        Handle,
        Alertable,
        Timeout
    );
}

NTSTATUS SyscallManager::ExecuteNtCreateSection(
    PHANDLE SectionHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PLARGE_INTEGER MaximumSize,
    ULONG SectionPageProtection,
    ULONG AllocationAttributes,
    HANDLE FileHandle) {
    return m_NtCreateSection(
        SectionHandle,
        DesiredAccess,
        ObjectAttributes,
        MaximumSize,
        SectionPageProtection,
        AllocationAttributes,
        FileHandle
    );
}

NTSTATUS SyscallManager::ExecuteNtMapViewOfSection(
    HANDLE SectionHandle,
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    ULONG_PTR ZeroBits,
    SIZE_T CommitSize,
    PLARGE_INTEGER SectionOffset,
    PSIZE_T ViewSize,
    DWORD InheritDisposition,
    ULONG AllocationType,
    ULONG Win32Protect) {
    return m_NtMapViewOfSection(
        SectionHandle,
        ProcessHandle,
        BaseAddress,
        ZeroBits,
        CommitSize,
        SectionOffset,
        ViewSize,
        InheritDisposition,
        AllocationType,
        Win32Protect
    );
}

NTSTATUS SyscallManager::ExecuteNtUnmapViewOfSection(
    HANDLE ProcessHandle,
    PVOID BaseAddress) {
    return m_NtUnmapViewOfSection(ProcessHandle, BaseAddress);
}

NTSTATUS SyscallManager::ExecuteNtProtectVirtualMemory(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,
    PULONG OldProtect) {
    return m_NtProtectVirtualMemory(
        ProcessHandle,
        BaseAddress,
        RegionSize,
        NewProtect,
        OldProtect
    );
}

NTSTATUS SyscallManager::ExecuteNtFreeVirtualMemory(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    PSIZE_T RegionSize,
    ULONG FreeType) {
    return m_NtFreeVirtualMemory(
        ProcessHandle,
        BaseAddress,
        RegionSize,
        FreeType
    );
}

NTSTATUS SyscallManager::ExecuteNtOpenProcess(
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    CLIENT_ID *ClientId) {
    return m_NtOpenProcess(
        ProcessHandle,
        DesiredAccess,
        ObjectAttributes,
        ClientId
    );
}

NTSTATUS SyscallManager::ExecuteNtQueueApcThread(
    HANDLE ThreadHandle,
    PVOID ApcRoutine,
    PVOID ApcArgument1,
    PVOID ApcArgument2,
    PVOID ApcArgument3) {
    return m_NtQueueApcThread(
        ThreadHandle,
        ApcRoutine,
        ApcArgument1,
        ApcArgument2,
        ApcArgument3
    );
}

NTSTATUS SyscallManager::ExecuteNtResumeThread(
    HANDLE ThreadHandle,
    PULONG PreviousSuspendCount) {
    return m_NtResumeThread(ThreadHandle, PreviousSuspendCount);
}

NTSTATUS SyscallManager::ExecuteNtSuspendThread(
    HANDLE ThreadHandle,
    PULONG PreviousSuspendCount) {
    return m_NtSuspendThread(ThreadHandle, PreviousSuspendCount);
}

bool SyscallManager::CreateSuspendedThread(ProcessHandle processHandle, MemoryAddress startAddress,
                                           MemoryAddress parameter, ThreadHandle *threadHandle) {
    NTSTATUS status = m_NtCreateThreadEx(
        threadHandle,
        THREAD_ALL_ACCESS,
        NULL,
        processHandle,
        startAddress,
        parameter,
        THREAD_CREATE_FLAGS_CREATE_SUSPENDED,
        0,
        0,
        0,
        NULL
    );

    if (!NT_SUCCESS(status)) {
        m_errorHandler->SetError(ErrorCode::THREAD_HIJACK_FAILED, "Failed to create suspended remote thread");
        return false;
    }

    return true;
}

bool SyscallManager::QueueApcThread(ThreadHandle threadHandle, MemoryAddress apcRoutine,
                                    MemoryAddress arg1, MemoryAddress arg2, MemoryAddress arg3) {
    NTSTATUS status = ExecuteNtQueueApcThread(
        threadHandle,
        apcRoutine,
        arg1,
        arg2,
        arg3
    );

    if (!NT_SUCCESS(status)) {
        m_errorHandler->SetError(ErrorCode::EXECUTION_FAILED, "Failed to queue APC to thread");
        return false;
    }

    return true;
}

bool SyscallManager::ResumeThread(ThreadHandle threadHandle) {
    ULONG suspendCount = 0;

    NTSTATUS status = ExecuteNtResumeThread(threadHandle, &suspendCount);

    if (!NT_SUCCESS(status)) {
        m_errorHandler->SetError(ErrorCode::EXECUTION_FAILED, "Failed to resume thread");
        return false;
    }

    return true;
}

bool SyscallManager::OpenProcess(DWORD processId, DWORD desiredAccess, ProcessHandle *processHandle) {
    if (!processHandle) {
        m_errorHandler->SetError(ErrorCode::INVALID_PARAMETER, "Invalid process handle pointer");
        return false;
    }

    CLIENT_ID clientId;
    clientId.UniqueProcess = (HANDLE) (ULONG_PTR) processId;
    clientId.UniqueThread = NULL;

    OBJECT_ATTRIBUTES objAttribs;
    InitializeObjectAttributes(&objAttribs, NULL, 0, NULL, NULL);

    NTSTATUS status = ExecuteNtOpenProcess(
        processHandle,
        desiredAccess,
        &objAttribs,
        &clientId
    );

    if (!NT_SUCCESS(status)) {
        m_errorHandler->SetError(ErrorCode::OPERATION_ABORTED, "Failed to open process");
        return false;
    }

    return true;
}

bool SyscallManager::WaitForSingleObject(HANDLE handle, DWORD timeoutMs) {
    if (!handle) {
        m_errorHandler->SetError(ErrorCode::INVALID_PARAMETER, "Invalid handle for wait operation");
        return false;
    }

    LARGE_INTEGER timeout;
    if (timeoutMs == INFINITE) {
        timeout.QuadPart = 0;
    } else {
        timeout.QuadPart = -(LONGLONG) timeoutMs * 10000LL;
    }

    NTSTATUS status = ExecuteNtWaitForSingleObject(
        handle,
        FALSE,
        timeoutMs == INFINITE ? NULL : &timeout
    );

    if (status == STATUS_SUCCESS) {
        return true;
    } else if (status == STATUS_TIMEOUT) {
        m_errorHandler->SetError(ErrorCode::EXECUTION_FAILED, "Wait operation timed out");
        return false;
    } else {
        m_errorHandler->SetError(ErrorCode::EXECUTION_FAILED, "Wait operation failed");
        return false;
    }
}

bool SyscallManager::CreateRemoteThread(ProcessHandle processHandle, MemoryAddress startAddress,
                                        MemoryAddress parameter, ThreadHandle *threadHandle) {
    NTSTATUS status = m_NtCreateThreadEx(
        threadHandle,
        THREAD_ALL_ACCESS,
        NULL,
        processHandle,
        startAddress,
        parameter,
        0,
        0,
        0,
        0,
        NULL
    );

    if (!NT_SUCCESS(status)) {
        m_errorHandler->SetError(ErrorCode::THREAD_HIJACK_FAILED, "Failed to create remote thread");
        return false;
    }

    return true;
}

bool SyscallManager::AllocateVirtualMemory(ProcessHandle processHandle, MemoryAddress *baseAddress,
                                           MemorySize size, DWORD allocationType, DWORD protection) {
    NTSTATUS status = m_NtAllocateVirtualMemory(
        processHandle,
        baseAddress,
        0,
        &size,
        allocationType,
        protection
    );

    if (!NT_SUCCESS(status)) {
        m_errorHandler->SetError(ErrorCode::MEMORY_ALLOCATION_FAILED, "Failed to allocate virtual memory");
        return false;
    }

    return true;
}

bool SyscallManager::ProtectVirtualMemory(ProcessHandle processHandle, MemoryAddress *baseAddress,
                                          MemorySize *size, DWORD newProtection, DWORD *oldProtection) {
    NTSTATUS status = m_NtProtectVirtualMemory(
        processHandle,
        baseAddress,
        size,
        newProtection,
        oldProtection
    );

    if (!NT_SUCCESS(status)) {
        m_errorHandler->SetError(ErrorCode::MEMORY_PROTECTION_FAILED, "Failed to change memory protection");
        return false;
    }

    return true;
}

bool SyscallManager::WriteVirtualMemory(ProcessHandle processHandle, MemoryAddress baseAddress,
                                        const void *buffer, MemorySize size, MemorySize *bytesWritten) {
    NTSTATUS status = m_NtWriteVirtualMemory(
        processHandle,
        baseAddress,
        (PVOID) buffer,
        size,
        bytesWritten
    );

    if (!NT_SUCCESS(status)) {
        m_errorHandler->SetError(ErrorCode::MEMORY_WRITE_FAILED, "Failed to write virtual memory");
        return false;
    }

    return true;
}

bool SyscallManager::ReadVirtualMemory(ProcessHandle processHandle, MemoryAddress baseAddress,
                                       void *buffer, MemorySize size, MemorySize *bytesRead) {
    NTSTATUS status = m_NtReadVirtualMemory(
        processHandle,
        baseAddress,
        buffer,
        size,
        bytesRead
    );

    if (!NT_SUCCESS(status)) {
        m_errorHandler->SetError(ErrorCode::MEMORY_WRITE_FAILED, "Failed to read virtual memory");
        return false;
    }

    return true;
}

bool SyscallManager::FreeVirtualMemory(ProcessHandle processHandle, MemoryAddress *baseAddress,
                                       MemorySize *regionSize, DWORD freeType) {
    NTSTATUS status = m_NtFreeVirtualMemory(
        processHandle,
        baseAddress,
        regionSize,
        freeType
    );

    if (!NT_SUCCESS(status)) {
        m_errorHandler->SetError(ErrorCode::MEMORY_ALLOCATION_FAILED, "Failed to free virtual memory");
        return false;
    }

    return true;
}

bool SyscallManager::CreateSection(SectionHandle *sectionHandle, DWORD desiredAccess,
                                   MemorySize maximumSize, DWORD pageProtection, DWORD allocationAttributes) {
    LARGE_INTEGER sectionSize;
    sectionSize.QuadPart = maximumSize;

    NTSTATUS status = m_NtCreateSection(
        sectionHandle,
        desiredAccess,
        NULL,
        &sectionSize,
        pageProtection,
        allocationAttributes,
        NULL
    );

    if (!NT_SUCCESS(status)) {
        m_errorHandler->SetError(ErrorCode::SECTION_CREATION_FAILED, "Failed to create section");
        return false;
    }

    return true;
}

bool SyscallManager::MapViewOfSection(SectionHandle sectionHandle, ProcessHandle processHandle,
                                      MemoryAddress *baseAddress, MemorySize commitSize,
                                      MemorySize *viewSize, DWORD allocationType, DWORD protection) {
    LARGE_INTEGER sectionOffset;
    sectionOffset.QuadPart = 0;

    NTSTATUS status = m_NtMapViewOfSection(
        sectionHandle,
        processHandle,
        baseAddress,
        0,
        commitSize,
        &sectionOffset,
        viewSize,
        ViewUnmap,
        allocationType,
        protection
    );

    if (!NT_SUCCESS(status)) {
        m_errorHandler->SetError(ErrorCode::MEMORY_ALLOCATION_FAILED, "Failed to map view of section");
        return false;
    }

    return true;
}

bool SyscallManager::UnmapViewOfSection(ProcessHandle processHandle, MemoryAddress baseAddress) {
    NTSTATUS status = m_NtUnmapViewOfSection(
        processHandle,
        baseAddress
    );

    if (!NT_SUCCESS(status)) {
        m_errorHandler->SetError(ErrorCode::MEMORY_ALLOCATION_FAILED, "Failed to unmap view of section");
        return false;
    }

    return true;
}

bool SyscallManager::FlushInstructionCache(ProcessHandle processHandle, MemoryAddress baseAddress, MemorySize size) {
    NTSTATUS status = m_NtFlushInstructionCache(
        processHandle,
        baseAddress,
        size
    );

    if (!NT_SUCCESS(status)) {
        m_errorHandler->SetError(ErrorCode::EXECUTION_FAILED, "Failed to flush instruction cache");
        return false;
    }

    return true;
}

std::string SyscallManager::GetLastErrorMessage() const {
    return m_errorHandler->GetLastErrorMessage();
}

void *SyscallManager::GetProcAddressSafe(HMODULE module, const char *procName) {
    return (void *) GetProcAddress(module, procName);
}
