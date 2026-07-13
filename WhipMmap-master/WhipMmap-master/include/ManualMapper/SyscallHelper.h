#pragma once

#include <whipsyscall/WhipSysCall.h>
#include "Types.h"

namespace ManualMapper
{
    class Syscalls
    {
    public:
        static bool Initialize() {
            return GetResolver().Init();
        }

        // --- Raw Nt* syscalls ---

        static NTSTATUS NtAllocateVirtualMemory(
            HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits,
            PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect)
        {
            WORD ssn; PVOID addr;
            if (!GetResolver().ResolveByName("NtAllocateVirtualMemory", ssn, addr))
                return 0xC0000001;
            return SyscallInvoker::Invoke(ssn, ProcessHandle, BaseAddress,
                (PVOID)(ULONG_PTR)ZeroBits, RegionSize,
                (PVOID)(ULONG_PTR)AllocationType, (PVOID)(ULONG_PTR)Protect);
        }

        static NTSTATUS NtFreeVirtualMemory(
            HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG FreeType)
        {
            WORD ssn; PVOID addr;
            if (!GetResolver().ResolveByName("NtFreeVirtualMemory", ssn, addr))
                return 0xC0000001;
            return SyscallInvoker::Invoke(ssn, ProcessHandle, BaseAddress,
                RegionSize, (PVOID)(ULONG_PTR)FreeType);
        }

        static NTSTATUS NtWriteVirtualMemory(
            HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer,
            SIZE_T NumberOfBytesToWrite, PSIZE_T NumberOfBytesWritten)
        {
            WORD ssn; PVOID addr;
            if (!GetResolver().ResolveByName("NtWriteVirtualMemory", ssn, addr))
                return 0xC0000001;
            return SyscallInvoker::Invoke(ssn, ProcessHandle, BaseAddress, Buffer,
                (PVOID)(ULONG_PTR)NumberOfBytesToWrite, NumberOfBytesWritten);
        }

        static NTSTATUS NtReadVirtualMemory(
            HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer,
            SIZE_T NumberOfBytesToRead, PSIZE_T NumberOfBytesRead)
        {
            WORD ssn; PVOID addr;
            if (!GetResolver().ResolveByName("NtReadVirtualMemory", ssn, addr))
                return 0xC0000001;
            return SyscallInvoker::Invoke(ssn, ProcessHandle, BaseAddress, Buffer,
                (PVOID)(ULONG_PTR)NumberOfBytesToRead, NumberOfBytesRead);
        }

        static NTSTATUS NtProtectVirtualMemory(
            HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize,
            ULONG NewProtect, PULONG OldProtect)
        {
            WORD ssn; PVOID addr;
            if (!GetResolver().ResolveByName("NtProtectVirtualMemory", ssn, addr))
                return 0xC0000001;
            return SyscallInvoker::Invoke(ssn, ProcessHandle, BaseAddress,
                RegionSize, (PVOID)(ULONG_PTR)NewProtect, OldProtect);
        }

        static NTSTATUS NtCreateThreadEx(
            PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, PVOID ObjectAttributes,
            HANDLE ProcessHandle, PVOID StartRoutine, PVOID Argument,
            ULONG CreateFlags, SIZE_T ZeroBits, SIZE_T StackSize,
            SIZE_T MaximumStackSize, PVOID AttributeList)
        {
            WORD ssn; PVOID addr;
            if (!GetResolver().ResolveByName("NtCreateThreadEx", ssn, addr))
                return 0xC0000001;
            return SyscallInvoker::Invoke(ssn, ThreadHandle,
                (PVOID)(ULONG_PTR)DesiredAccess, ObjectAttributes, ProcessHandle,
                StartRoutine, Argument, (PVOID)(ULONG_PTR)CreateFlags,
                (PVOID)(ULONG_PTR)ZeroBits, (PVOID)(ULONG_PTR)StackSize,
                (PVOID)(ULONG_PTR)MaximumStackSize, AttributeList);
        }

        static NTSTATUS NtOpenProcess(
            PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess,
            PVOID ObjectAttributes, PVOID ClientId)
        {
            WORD ssn; PVOID addr;
            if (!GetResolver().ResolveByName("NtOpenProcess", ssn, addr))
                return 0xC0000001;
            return SyscallInvoker::Invoke(ssn, ProcessHandle,
                (PVOID)(ULONG_PTR)DesiredAccess, ObjectAttributes, ClientId);
        }

        static NTSTATUS NtWaitForSingleObject(HANDLE Handle, BOOLEAN Alertable, PLARGE_INTEGER Timeout)
        {
            WORD ssn; PVOID addr;
            if (!GetResolver().ResolveByName("NtWaitForSingleObject", ssn, addr))
                return 0xC0000001;
            return SyscallInvoker::Invoke(ssn, Handle,
                (PVOID)(ULONG_PTR)Alertable, Timeout);
        }

        static NTSTATUS NtQueryInformationThread(
            HANDLE ThreadHandle, ULONG ThreadInformationClass,
            PVOID ThreadInformation, ULONG ThreadInformationLength, PULONG ReturnLength)
        {
            WORD ssn; PVOID addr;
            if (!GetResolver().ResolveByName("NtQueryInformationThread", ssn, addr))
                return 0xC0000001;
            return SyscallInvoker::Invoke(ssn, ThreadHandle,
                (PVOID)(ULONG_PTR)ThreadInformationClass, ThreadInformation,
                (PVOID)(ULONG_PTR)ThreadInformationLength, ReturnLength);
        }

        static NTSTATUS NtClose(HANDLE Handle)
        {
            WORD ssn; PVOID addr;
            if (!GetResolver().ResolveByName("NtClose", ssn, addr))
                return 0xC0000001;
            return SyscallInvoker::Invoke(ssn, Handle);
        }

        static NTSTATUS NtUnmapViewOfSection(HANDLE ProcessHandle, PVOID BaseAddress)
        {
            WORD ssn; PVOID addr;
            if (!GetResolver().ResolveByName("NtUnmapViewOfSection", ssn, addr))
                return 0xC0000001;
            return SyscallInvoker::Invoke(ssn, ProcessHandle, BaseAddress);
        }

        static NTSTATUS NtCreateSection(
            PHANDLE SectionHandle, ACCESS_MASK DesiredAccess, PVOID ObjectAttributes,
            PLARGE_INTEGER MaximumSize, ULONG SectionPageProtection, ULONG AllocationAttributes,
            HANDLE FileHandle)
        {
            WORD ssn; PVOID addr;
            if (!GetResolver().ResolveByName("NtCreateSection", ssn, addr))
                return 0xC0000001;
            return SyscallInvoker::Invoke(ssn, SectionHandle,
                (PVOID)(ULONG_PTR)DesiredAccess, ObjectAttributes, MaximumSize,
                (PVOID)(ULONG_PTR)SectionPageProtection, (PVOID)(ULONG_PTR)AllocationAttributes,
                FileHandle);
        }

        static NTSTATUS NtMapViewOfSection(
            HANDLE SectionHandle, HANDLE ProcessHandle, PVOID* BaseAddress,
            ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset,
            PSIZE_T ViewSize, ULONG InheritDisposition, ULONG AllocationType, ULONG Win32Protect)
        {
            WORD ssn; PVOID addr;
            if (!GetResolver().ResolveByName("NtMapViewOfSection", ssn, addr))
                return 0xC0000001;
            return SyscallInvoker::Invoke(ssn, SectionHandle, ProcessHandle, BaseAddress,
                (PVOID)(ULONG_PTR)ZeroBits, (PVOID)(ULONG_PTR)CommitSize, SectionOffset,
                ViewSize, (PVOID)(ULONG_PTR)InheritDisposition, (PVOID)(ULONG_PTR)AllocationType,
                (PVOID)(ULONG_PTR)Win32Protect);
        }

        // --- High-level helpers ---

        static void* AllocateMemory(HANDLE processHandle, size_t size)
        {
            PVOID baseAddress = nullptr;
            SIZE_T regionSize = size;
            NTSTATUS status = NtAllocateVirtualMemory(processHandle, &baseAddress, 0,
                &regionSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            return (status >= 0) ? baseAddress : nullptr;
        }

        static bool WriteMemory(HANDLE processHandle, void* address, const void* data, size_t size)
        {
            SIZE_T bytesWritten = 0;
            NTSTATUS status = NtWriteVirtualMemory(processHandle, address,
                const_cast<PVOID>(data), size, &bytesWritten);
            return (status >= 0) && (bytesWritten == size);
        }

        static bool ReadMemory(HANDLE processHandle, void* address, void* buffer, size_t size)
        {
            SIZE_T bytesRead = 0;
            NTSTATUS status = NtReadVirtualMemory(processHandle, address,
                buffer, size, &bytesRead);
            return (status >= 0) && (bytesRead == size);
        }

        static bool ProtectMemory(HANDLE processHandle, void* address, size_t size,
            DWORD protection, DWORD* oldProtection = nullptr)
        {
            PVOID baseAddress = address;
            SIZE_T regionSize = size;
            ULONG oldProt = 0;
            NTSTATUS status = NtProtectVirtualMemory(processHandle, &baseAddress,
                &regionSize, protection, &oldProt);
            if (oldProtection)
                *oldProtection = oldProt;
            return status >= 0;
        }

        static bool FreeMemory(HANDLE processHandle, void* address)
        {
            PVOID baseAddress = address;
            SIZE_T regionSize = 0;
            NTSTATUS status = NtFreeVirtualMemory(processHandle, &baseAddress,
                &regionSize, MEM_RELEASE);
            return status >= 0;
        }

        static bool UnmapMemory(HANDLE processHandle, void* address)
        {
            NTSTATUS status = NtUnmapViewOfSection(processHandle, address);
            return status >= 0;
        }

        static NTSTATUS WaitForSingleObject(HANDLE handle, DWORD maxMs = INFINITE)
        {
            LARGE_INTEGER timeout;
            PLARGE_INTEGER pTimeout = nullptr;

            if (maxMs != INFINITE)
            {
                // Convert milliseconds to 100-nanosecond intervals (negative for relative)
                timeout.QuadPart = -static_cast<LONGLONG>(maxMs) * 10000LL;
                pTimeout = &timeout;
            }

            return NtWaitForSingleObject(handle, FALSE, pTimeout);
        }

        static bool GetExitCodeThread(HANDLE threadHandle, DWORD* exitCode)
        {
            struct {
                NTSTATUS ExitStatus;
                PVOID TebBaseAddress;
                struct { HANDLE UniqueProcess; HANDLE UniqueThread; } ClientId;
                ULONG_PTR AffinityMask;
                LONG Priority;
                LONG BasePriority;
            } info = { 0 };

            ULONG returnLength = 0;
            NTSTATUS status = NtQueryInformationThread(threadHandle, 0, &info,
                static_cast<ULONG>(sizeof(info)), &returnLength);

            if (status >= 0 && exitCode)
                *exitCode = static_cast<DWORD>(info.ExitStatus);
            return status >= 0;
        }

        static NTSTATUS CloseHandle(HANDLE handle)
        {
            return NtClose(handle);
        }

    private:
        static SyscallResolver& GetResolver() {
            static SyscallResolver s_resolver;
            static bool s_init = false;
            if (!s_init) {
                s_resolver.Init();
                s_init = true;
            }
            return s_resolver;
        }
    };
}
