#pragma once

#include "mmap/core/common.h"
#include "mmap/utils/utility.h"

typedef NTSTATUS(NTAPI* NtCreateThreadExFunc)(
    OUT PHANDLE ThreadHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    IN HANDLE ProcessHandle,
    IN PVOID StartRoutine,
    IN PVOID Argument OPTIONAL,
    IN ULONG CreateFlags,
    IN SIZE_T ZeroBits OPTIONAL,
    IN SIZE_T StackSize OPTIONAL,
    IN SIZE_T MaximumStackSize OPTIONAL,
    OUT PVOID AttributeList OPTIONAL
    );

typedef NTSTATUS(NTAPI* NtAllocateVirtualMemoryFunc)(
    IN HANDLE ProcessHandle,
    IN OUT PVOID* BaseAddress,
    IN ULONG_PTR ZeroBits,
    IN OUT PSIZE_T RegionSize,
    IN ULONG AllocationType,
    IN ULONG Protect
    );

typedef NTSTATUS(NTAPI* NtProtectVirtualMemoryFunc)(
    IN HANDLE ProcessHandle,
    IN OUT PVOID* BaseAddress,
    IN OUT PSIZE_T RegionSize,
    IN ULONG NewProtect,
    OUT PULONG OldProtect
    );

typedef NTSTATUS(NTAPI* NtWriteVirtualMemoryFunc)(
    IN HANDLE ProcessHandle,
    IN PVOID BaseAddress,
    IN PVOID Buffer,
    IN SIZE_T NumberOfBytesToWrite,
    OUT PSIZE_T NumberOfBytesWritten OPTIONAL
    );

typedef NTSTATUS(NTAPI* NtReadVirtualMemoryFunc)(
    IN HANDLE ProcessHandle,
    IN PVOID BaseAddress,
    OUT PVOID Buffer,
    IN SIZE_T NumberOfBytesToRead,
    OUT PSIZE_T NumberOfBytesRead OPTIONAL
    );

typedef NTSTATUS(NTAPI* NtCreateSectionFunc)(
    OUT PHANDLE SectionHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    IN PLARGE_INTEGER MaximumSize OPTIONAL,
    IN ULONG SectionPageProtection,
    IN ULONG AllocationAttributes,
    IN HANDLE FileHandle OPTIONAL
    );

typedef NTSTATUS(NTAPI* NtMapViewOfSectionFunc)(
    IN HANDLE SectionHandle,
    IN HANDLE ProcessHandle,
    IN OUT PVOID* BaseAddress,
    IN ULONG_PTR ZeroBits,
    IN SIZE_T CommitSize,
    IN OUT PLARGE_INTEGER SectionOffset OPTIONAL,
    IN OUT PSIZE_T ViewSize,
    IN DWORD InheritDisposition,
    IN ULONG AllocationType,
    IN ULONG Win32Protect
    );

typedef NTSTATUS(NTAPI* NtUnmapViewOfSectionFunc)(
    IN HANDLE ProcessHandle,
    IN PVOID BaseAddress
    );

typedef NTSTATUS(NTAPI* NtFlushInstructionCacheFunc)(
    IN HANDLE ProcessHandle,
    IN PVOID BaseAddress OPTIONAL,
    IN SIZE_T Length
    );

typedef NTSTATUS(NTAPI* NtFreeVirtualMemoryFunc)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG FreeType
    );

typedef NTSTATUS(NTAPI* NtWaitForSingleObjectFunc)(
    HANDLE Handle,
    BOOLEAN Alertable,
    PLARGE_INTEGER Timeout
    );

typedef NTSTATUS(NTAPI* NtOpenProcessFunc)(
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    CLIENT_ID* ClientId
    );

typedef NTSTATUS(NTAPI* NtQueueApcThreadFunc)(
    IN HANDLE ThreadHandle,
    IN PVOID ApcRoutine,
    IN PVOID ApcArgument1 OPTIONAL,
    IN PVOID ApcArgument2 OPTIONAL,
    IN PVOID ApcArgument3 OPTIONAL
    );

typedef NTSTATUS(NTAPI* NtResumeThreadFunc)(
    IN HANDLE ThreadHandle,
    OUT PULONG PreviousSuspendCount OPTIONAL
    );

typedef NTSTATUS(NTAPI* NtSuspendThreadFunc)(
    IN HANDLE ThreadHandle,
    OUT PULONG PreviousSuspendCount OPTIONAL
    );

typedef NTSTATUS(NTAPI* NtQueryInformationProcessFunc)(
    HANDLE ProcessHandle,
    ULONG ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
    );

// Syscall Manager class for direct syscalls
class SyscallManager {
public:
    SyscallManager(ErrorHandler* errorHandler);
    ~SyscallManager();

    // Initialize the syscall manager
    bool Initialize();

    // Execute syscalls
    NTSTATUS ExecuteNtCreateSection(
        PHANDLE SectionHandle,
        ACCESS_MASK DesiredAccess,
        POBJECT_ATTRIBUTES ObjectAttributes,
        PLARGE_INTEGER MaximumSize,
        ULONG SectionPageProtection,
        ULONG AllocationAttributes,
        HANDLE FileHandle
    );

    NTSTATUS ExecuteNtMapViewOfSection(
        HANDLE SectionHandle,
        HANDLE ProcessHandle,
        PVOID* BaseAddress,
        ULONG_PTR ZeroBits,
        SIZE_T CommitSize,
        PLARGE_INTEGER SectionOffset,
        PSIZE_T ViewSize,
        DWORD InheritDisposition,
        ULONG AllocationType,
        ULONG Win32Protect
    );

    NTSTATUS ExecuteNtUnmapViewOfSection(
        HANDLE ProcessHandle,
        PVOID BaseAddress
    );

    NTSTATUS ExecuteNtProtectVirtualMemory(
        HANDLE ProcessHandle,
        PVOID* BaseAddress,
        PSIZE_T RegionSize,
        ULONG NewProtect,
        PULONG OldProtect
    );

    NTSTATUS ExecuteNtFreeVirtualMemory(
        HANDLE ProcessHandle,
        PVOID* BaseAddress,
        PSIZE_T RegionSize,
        ULONG FreeType
    );

    NTSTATUS ExecuteNtWaitForSingleObject(
        HANDLE Handle,
        BOOLEAN Alertable,
        PLARGE_INTEGER Timeout
    );

    NTSTATUS ExecuteNtOpenProcess(
        PHANDLE ProcessHandle,
        ACCESS_MASK DesiredAccess,
        POBJECT_ATTRIBUTES ObjectAttributes,
        CLIENT_ID* ClientId
    );

    NTSTATUS ExecuteNtQueueApcThread(
        HANDLE ThreadHandle,
        PVOID ApcRoutine,
        PVOID ApcArgument1,
        PVOID ApcArgument2,
        PVOID ApcArgument3
    );

    NTSTATUS ExecuteNtResumeThread(
        HANDLE ThreadHandle,
        PULONG PreviousSuspendCount
    );

    NTSTATUS ExecuteNtSuspendThread(
        HANDLE ThreadHandle,
        PULONG PreviousSuspendCount
    );

    NTSTATUS ExecuteNtQueryInformationProcess(
        HANDLE ProcessHandle,
        ULONG ProcessInformationClass,
        PVOID ProcessInformation,
        ULONG ProcessInformationLength,
        PULONG ReturnLength) {

        return m_NtQueryInformationProcess(
            ProcessHandle,
            ProcessInformationClass,
            ProcessInformation,
            ProcessInformationLength,
            ReturnLength
        );
    }

    bool CreateSuspendedThread(ProcessHandle processHandle, MemoryAddress startAddress,
        MemoryAddress parameter, ThreadHandle* threadHandle);

    bool QueueApcThread(ThreadHandle threadHandle, MemoryAddress apcRoutine,
        MemoryAddress arg1, MemoryAddress arg2, MemoryAddress arg3);

    bool ResumeThread(ThreadHandle threadHandle);

    bool OpenProcess(DWORD processId, DWORD desiredAccess, ProcessHandle* processHandle);

    bool WaitForSingleObject(HANDLE handle, DWORD timeoutMs);

    bool CreateRemoteThread(ProcessHandle processHandle, MemoryAddress startAddress,
        MemoryAddress parameter, ThreadHandle* threadHandle);

    bool AllocateVirtualMemory(ProcessHandle processHandle, MemoryAddress* baseAddress,
        MemorySize size, DWORD allocationType, DWORD protection);

    bool ProtectVirtualMemory(ProcessHandle processHandle, MemoryAddress* baseAddress,
        MemorySize* size, DWORD newProtection, DWORD* oldProtection);

    bool WriteVirtualMemory(ProcessHandle processHandle, MemoryAddress baseAddress,
        const void* buffer, MemorySize size, MemorySize* bytesWritten);

    bool ReadVirtualMemory(ProcessHandle processHandle, MemoryAddress baseAddress,
        void* buffer, MemorySize size, MemorySize* bytesRead);

    bool FreeVirtualMemory(ProcessHandle processHandle, MemoryAddress* baseAddress,
        MemorySize* regionSize, DWORD freeType);

    bool CreateSection(SectionHandle* sectionHandle, DWORD desiredAccess,
        MemorySize maximumSize, DWORD pageProtection, DWORD allocationAttributes);

    bool MapViewOfSection(SectionHandle sectionHandle, ProcessHandle processHandle,
        MemoryAddress* baseAddress, MemorySize commitSize,
        MemorySize* viewSize, DWORD allocationType, DWORD protection);

    bool UnmapViewOfSection(ProcessHandle processHandle, MemoryAddress baseAddress);

    bool FlushInstructionCache(ProcessHandle processHandle, MemoryAddress baseAddress, MemorySize size);

    std::string GetLastErrorMessage() const;

private:
    ErrorHandler* m_errorHandler;

    HMODULE m_ntdllHandle;

    NtCreateThreadExFunc m_NtCreateThreadEx;
    NtAllocateVirtualMemoryFunc m_NtAllocateVirtualMemory;
    NtProtectVirtualMemoryFunc m_NtProtectVirtualMemory;
    NtWriteVirtualMemoryFunc m_NtWriteVirtualMemory;
    NtReadVirtualMemoryFunc m_NtReadVirtualMemory;
    NtCreateSectionFunc m_NtCreateSection;
    NtMapViewOfSectionFunc m_NtMapViewOfSection;
    NtUnmapViewOfSectionFunc m_NtUnmapViewOfSection;
    NtFlushInstructionCacheFunc m_NtFlushInstructionCache;
    NtFreeVirtualMemoryFunc m_NtFreeVirtualMemory;
    NtWaitForSingleObjectFunc m_NtWaitForSingleObject;
    NtOpenProcessFunc m_NtOpenProcess;
    NtQueueApcThreadFunc m_NtQueueApcThread;
    NtResumeThreadFunc m_NtResumeThread;
    NtSuspendThreadFunc m_NtSuspendThread;
    NtQueryInformationProcessFunc m_NtQueryInformationProcess;

    void* GetProcAddressSafe(HMODULE module, const char* procName);
};