#pragma optimize("", off)
#include "whipsyscall/SyscallWrappers.h"

#ifdef BUILD_WITH_VMPROTECT
#include "VMProtectSDK.h"
#endif

// ========== HELPERS ==========

namespace SyscallWrappersHelpers {
    HANDLE GetProcessHeap() {
        // VMProtectBeginUltra("SyscallWrappersHelpers_GetProcessHeap");

#ifdef _WIN64
        BYTE* peb = reinterpret_cast<BYTE*>(__readgsqword(0x60));
#else
        BYTE* peb = reinterpret_cast<BYTE*>(__readfsdword(0x30));
#endif
        // ProcessHeap est à offset 0x30 dans PEB
        HANDLE heap = *reinterpret_cast<HANDLE*>(peb + 0x30);

        return heap;
        // VMProtectEnd();
    }
}

// ========== SYSCALLWRAPPERS CONSTRUCTOR ==========

SyscallWrappers::SyscallWrappers(SyscallResolver* res) : resolver(res) {
    // VMProtectBeginUltra("SyscallWrappers_SyscallWrappers");
    // VMProtectEnd();
}

// ========== GESTION MEMOIRE ==========

PVOID SyscallWrappers::HeapAlloc(SIZE_T size) {
    // VMProtectBeginUltra("SyscallWrappers_HeapAlloc");

    // Utiliser NtAllocateVirtualMemory au lieu de RtlAllocateHeap
    WORD ssn;
    PVOID addr;

    if (!resolver->ResolveByName("NtAllocateVirtualMemory", ssn, addr)) {
        return nullptr;
        // VMProtectEnd();
    }

    PVOID baseAddress = nullptr;
    SIZE_T regionSize = size;

    NTSTATUS status = SyscallInvoker::Invoke(
        ssn,
        NtCurrentProcess(),                                     // arg1: ProcessHandle
        &baseAddress,                                            // arg2: BaseAddress
        reinterpret_cast<PVOID>(static_cast<ULONG_PTR>(0)),    // arg3: ZeroBits
        &regionSize,                                            // arg4: RegionSize
        reinterpret_cast<PVOID>(static_cast<ULONG_PTR>(MEM_COMMIT | MEM_RESERVE)), // arg5: AllocationType
        reinterpret_cast<PVOID>(static_cast<ULONG_PTR>(PAGE_READWRITE))            // arg6: Protect
    );

    return NT_SUCCESS(status) ? baseAddress : nullptr;
    // VMProtectEnd();
}

PVOID SyscallWrappers::HeapReAlloc(PVOID ptr, SIZE_T newSize) {
    // VMProtectBeginUltra("SyscallWrappers_HeapReAlloc");

    if (!ptr) return HeapAlloc(newSize);

    // Query old allocation size using NtQueryVirtualMemory
    WORD ssn;
    PVOID addr;

    if (!resolver->ResolveByName("NtQueryVirtualMemory", ssn, addr)) {
        return nullptr;
        // VMProtectEnd();
    }

    MEMORY_BASIC_INFORMATION mbi = {0};
    SIZE_T returnLength = 0;

    NTSTATUS status = SyscallInvoker::Invoke(
        ssn,
        NtCurrentProcess(),                                           // arg1: ProcessHandle
        ptr,                                                           // arg2: BaseAddress
        reinterpret_cast<PVOID>(static_cast<ULONG_PTR>(0)),          // arg3: MemoryInformationClass (MemoryBasicInformation = 0)
        &mbi,                                                          // arg4: MemoryInformation
        reinterpret_cast<PVOID>(static_cast<ULONG_PTR>(sizeof(mbi))), // arg5: MemoryInformationLength
        &returnLength                                                  // arg6: ReturnLength
    );

    if (!NT_SUCCESS(status)) {
        // Fallback: assume old size = newSize (unsafe but better than nothing)
        mbi.RegionSize = newSize;
    }

    // Allocate new memory
    PVOID newPtr = HeapAlloc(newSize);
    if (!newPtr) return nullptr;

    // Copy min(oldSize, newSize) bytes to preserve data integrity
    SIZE_T copySize = (mbi.RegionSize < newSize) ? mbi.RegionSize : newSize;
    BYTE* src = static_cast<BYTE*>(ptr);
    BYTE* dst = static_cast<BYTE*>(newPtr);
    for (SIZE_T i = 0; i < copySize; i++) {
        dst[i] = src[i];
    }

    // Free old memory
    HeapFree(ptr);

    return newPtr;
    // VMProtectEnd();
}

bool SyscallWrappers::HeapFree(PVOID ptr) {
    // VMProtectBeginUltra("SyscallWrappers_HeapFree");

    if (!ptr) return true;

    WORD ssn;
    PVOID addr;

    if (!resolver->ResolveByName("NtFreeVirtualMemory", ssn, addr)) {
        return false;
        // VMProtectEnd();
    }

    SIZE_T regionSize = 0;

    NTSTATUS status = SyscallInvoker::Invoke(
        ssn,
        NtCurrentProcess(),                                    // arg1: ProcessHandle
        &ptr,                                                   // arg2: BaseAddress
        &regionSize,                                           // arg3: RegionSize
        reinterpret_cast<PVOID>(static_cast<ULONG_PTR>(MEM_RELEASE))  // arg4: FreeType
    );

    return NT_SUCCESS(status);
    // VMProtectEnd();
}

PVOID SyscallWrappers::VirtualAlloc(SIZE_T size, DWORD protect) {
    // VMProtectBeginUltra("SyscallWrappers_VirtualAlloc");

    WORD ssn;
    PVOID addr;

    if (!resolver->ResolveByName("NtAllocateVirtualMemory", ssn, addr)) {
        return nullptr;
        // VMProtectEnd();
    }

    PVOID baseAddress = nullptr;
    SIZE_T regionSize = size;

    NTSTATUS status = SyscallInvoker::Invoke(
        ssn,
        NtCurrentProcess(),                                     // arg1: ProcessHandle
        &baseAddress,                                            // arg2: BaseAddress
        reinterpret_cast<PVOID>(static_cast<ULONG_PTR>(0)),    // arg3: ZeroBits
        &regionSize,                                            // arg4: RegionSize
        reinterpret_cast<PVOID>(static_cast<ULONG_PTR>(MEM_COMMIT | MEM_RESERVE)), // arg5: AllocationType
        reinterpret_cast<PVOID>(static_cast<ULONG_PTR>(protect))                   // arg6: Protect
    );

    return NT_SUCCESS(status) ? baseAddress : nullptr;
    // VMProtectEnd();
}

bool SyscallWrappers::VirtualFree(PVOID address, SIZE_T size) {
    // VMProtectBeginUltra("SyscallWrappers_VirtualFree");

    WORD ssn;
    PVOID addr;

    if (!resolver->ResolveByName("NtFreeVirtualMemory", ssn, addr)) {
        return false;
        // VMProtectEnd();
    }

    SIZE_T regionSize = size;

    NTSTATUS status = SyscallInvoker::Invoke(
        ssn,
        NtCurrentProcess(),                                    // arg1: ProcessHandle
        &address,                                               // arg2: BaseAddress
        &regionSize,                                           // arg3: RegionSize
        reinterpret_cast<PVOID>(static_cast<ULONG_PTR>(MEM_RELEASE))  // arg4: FreeType
    );

    return NT_SUCCESS(status);
    // VMProtectEnd();
}

// ========== FICHIERS ==========

HANDLE SyscallWrappers::CreateFile(const WORD* path, DWORD access, DWORD share, DWORD disposition) {
    // VMProtectBeginUltra("SyscallWrappers_CreateFile");

    WORD ssn;
    PVOID addr;

    if (!resolver->ResolveByName("NtCreateFile", ssn, addr)) {
        return nullptr;
        // VMProtectEnd();
    }

    // Calculer la longueur du path en WCHAR
    SIZE_T pathLen = 0;
    while (path[pathLen] != 0) pathLen++;

    // Préparer UNICODE_STRING
    UNICODE_STRING fileName;
    fileName.Length = static_cast<USHORT>(pathLen * sizeof(WCHAR));
    fileName.MaximumLength = fileName.Length + sizeof(WCHAR);
    fileName.Buffer = reinterpret_cast<PWSTR>(const_cast<WORD*>(path));

    // Préparer OBJECT_ATTRIBUTES
    OBJECT_ATTRIBUTES objAttr;
    objAttr.Length = sizeof(OBJECT_ATTRIBUTES);
    objAttr.RootDirectory = nullptr;
    objAttr.ObjectName = &fileName;
    objAttr.Attributes = 0x00000040;  // OBJ_CASE_INSENSITIVE
    objAttr.SecurityDescriptor = nullptr;
    objAttr.SecurityQualityOfService = nullptr;

    // IO_STATUS_BLOCK
    IO_STATUS_BLOCK ioStatus = {0};

    // Handle
    HANDLE hFile = nullptr;

    // Appeler NtCreateFile
    NTSTATUS status = SyscallInvoker::Invoke(
        ssn,
        &hFile,                                                     // arg1: FileHandle
        reinterpret_cast<PVOID>(static_cast<ULONG_PTR>(access)),  // arg2: DesiredAccess
        &objAttr,                                                   // arg3: ObjectAttributes
        &ioStatus,                                                  // arg4: IoStatusBlock
        nullptr,                                                    // arg5: AllocationSize
        reinterpret_cast<PVOID>(static_cast<ULONG_PTR>(0x80)),    // arg6: FileAttributes (FILE_ATTRIBUTE_NORMAL)
        reinterpret_cast<PVOID>(static_cast<ULONG_PTR>(share)),   // arg7: ShareAccess
        reinterpret_cast<PVOID>(static_cast<ULONG_PTR>(disposition)), // arg8: CreateDisposition
        reinterpret_cast<PVOID>(static_cast<ULONG_PTR>(0x00000060)), // arg9: CreateOptions
        nullptr                                                     // arg10: EaBuffer
    );

    return NT_SUCCESS(status) ? hFile : nullptr;
    // VMProtectEnd();
}

bool SyscallWrappers::CloseHandle(HANDLE handle) {
    // VMProtectBeginUltra("SyscallWrappers_CloseHandle");

    WORD ssn;
    PVOID addr;

    if (!resolver->ResolveByName("NtClose", ssn, addr)) {
        return false;
        // VMProtectEnd();
    }

    NTSTATUS status = SyscallInvoker::Invoke(
        ssn,
        handle  // arg1: Handle
    );

    return NT_SUCCESS(status);
    // VMProtectEnd();
}

bool SyscallWrappers::ReadFile(HANDLE handle, PVOID buffer, DWORD size, DWORD* bytesRead) {
    // VMProtectBeginUltra("SyscallWrappers_ReadFile");

    WORD ssn;
    PVOID addr;

    if (!resolver->ResolveByName("NtReadFile", ssn, addr)) {
        return false;
        // VMProtectEnd();
    }

    IO_STATUS_BLOCK ioStatus = {0};

    NTSTATUS status = SyscallInvoker::Invoke(
        ssn,
        handle,                                                     // arg1: FileHandle
        nullptr,                                                    // arg2: Event
        nullptr,                                                    // arg3: ApcRoutine
        nullptr,                                                    // arg4: ApcContext
        &ioStatus,                                                  // arg5: IoStatusBlock
        buffer,                                                     // arg6: Buffer
        reinterpret_cast<PVOID>(static_cast<ULONG_PTR>(size)),    // arg7: Length
        nullptr,                                                    // arg8: ByteOffset
        nullptr                                                     // arg9: Key
    );

    if (NT_SUCCESS(status)) {
        if (bytesRead) {
            *bytesRead = static_cast<DWORD>(ioStatus.Information);
        }
        return true;
        // VMProtectEnd();
    }

    return false;
    // VMProtectEnd();
}

bool SyscallWrappers::WriteFile(HANDLE handle, PVOID buffer, DWORD size, DWORD* bytesWritten) {
    // VMProtectBeginUltra("SyscallWrappers_WriteFile");

    WORD ssn;
    PVOID addr;

    if (!resolver->ResolveByName("NtWriteFile", ssn, addr)) {
        return false;
        // VMProtectEnd();
    }

    IO_STATUS_BLOCK ioStatus = {0};

    NTSTATUS status = SyscallInvoker::Invoke(
        ssn,
        handle,                                                     // arg1: FileHandle
        nullptr,                                                    // arg2: Event
        nullptr,                                                    // arg3: ApcRoutine
        nullptr,                                                    // arg4: ApcContext
        &ioStatus,                                                  // arg5: IoStatusBlock
        buffer,                                                     // arg6: Buffer
        reinterpret_cast<PVOID>(static_cast<ULONG_PTR>(size)),    // arg7: Length
        nullptr,                                                    // arg8: ByteOffset
        nullptr                                                     // arg9: Key
    );

    if (NT_SUCCESS(status)) {
        if (bytesWritten) {
            *bytesWritten = static_cast<DWORD>(ioStatus.Information);
        }
        return true;
        // VMProtectEnd();
    }

    return false;
    // VMProtectEnd();
}

// ========== PROCESSUS/THREADS ==========

HANDLE SyscallWrappers::GetCurrentProcess() {
    // VMProtectBeginUltra("SyscallWrappers_GetCurrentProcess");

    return NtCurrentProcess();
    // VMProtectEnd();
}

HANDLE SyscallWrappers::GetCurrentThread() {
    // VMProtectBeginUltra("SyscallWrappers_GetCurrentThread");

    return NtCurrentThread();
    // VMProtectEnd();
}

DWORD SyscallWrappers::GetCurrentProcessId() {
    // VMProtectBeginUltra("SyscallWrappers_GetCurrentProcessId");

    // NtCurrentTeb()->ClientId.UniqueProcess
#ifdef _WIN64
    BYTE* teb = reinterpret_cast<BYTE*>(__readgsqword(0x30));
#else
    BYTE* teb = reinterpret_cast<BYTE*>(__readfsdword(0x18));
#endif
    // ClientId est à offset 0x40 dans TEB, UniqueProcess est le premier HANDLE
    DWORD pid = static_cast<DWORD>(reinterpret_cast<SIZE_T>(*reinterpret_cast<HANDLE*>(teb + 0x40)));

    return pid;
    // VMProtectEnd();
}

DWORD SyscallWrappers::GetCurrentThreadId() {
    // VMProtectBeginUltra("SyscallWrappers_GetCurrentThreadId");

#ifdef _WIN64
    BYTE* teb = reinterpret_cast<BYTE*>(__readgsqword(0x30));
#else
    BYTE* teb = reinterpret_cast<BYTE*>(__readfsdword(0x18));
#endif
    // UniqueThread est à offset 0x48 dans TEB
    DWORD tid = static_cast<DWORD>(reinterpret_cast<SIZE_T>(*reinterpret_cast<HANDLE*>(teb + 0x48)));

    return tid;
    // VMProtectEnd();
}

QWORD SyscallWrappers::GetSystemTime() {
    // VMProtectBeginUltra("SyscallWrappers_GetSystemTime");

    // Windows optimise NtQuerySystemTime en lisant directement KUSER_SHARED_DATA
    // On fait pareil au lieu d'utiliser un syscall
    // KUSER_SHARED_DATA.SystemTime est à l'adresse fixe 0x7FFE0014 (x64)

    const QWORD* pSystemTime = reinterpret_cast<const QWORD*>(0x7FFE0014);
    QWORD fileTime = *pSystemTime;

    if (fileTime == 0) {
        // Fallback: essayer le syscall si KUSER_SHARED_DATA n'est pas disponible
        WORD ssn;
        PVOID addr;

        if (resolver->ResolveByName("NtQuerySystemTime", ssn, addr)) {
            LARGE_INTEGER systemTime = {0};
            NTSTATUS status = SyscallInvoker::Invoke(ssn, &systemTime);

            if (NT_SUCCESS(status)) {
                fileTime = systemTime.QuadPart;
            }
        }
    }

    if (fileTime > 0) {
        // Convertir FILETIME (100-nanosecond intervals since 1601) vers Unix timestamp
        // Unix epoch = 116444736000000000 (100-ns intervals between 1601 and 1970)
        const QWORD UNIX_EPOCH_FILETIME = 116444736000000000ULL;

        if (fileTime >= UNIX_EPOCH_FILETIME) {
            return (fileTime - UNIX_EPOCH_FILETIME) / 10000000ULL; // Convert to seconds
            // VMProtectEnd();
        }
    }

    return 0;
    // VMProtectEnd();
}

// ========== SECURE CRT REPLACEMENTS ==========

void* SyscallWrappers::SecureMemCpy(void* dst, const void* src, SIZE_T size) {
    // VMProtectBeginUltra("SyscallWrappers_SecureMemCpy");

    volatile BYTE* d = (volatile BYTE*)dst;
    volatile const BYTE* s = (volatile const BYTE*)src;
    while (size--) *d++ = *s++;

    return dst;
    // VMProtectEnd();
}

void* SyscallWrappers::SecureMemSet(void* dst, int value, SIZE_T size) {
    // VMProtectBeginUltra("SyscallWrappers_SecureMemSet");

    volatile BYTE* d = (volatile BYTE*)dst;
    BYTE val = (BYTE)value;
    while (size--) *d++ = val;

    return dst;
    // VMProtectEnd();
}

int SyscallWrappers::SecureMemCmp(const void* a, const void* b, SIZE_T size) {
    // VMProtectBeginUltra("SyscallWrappers_SecureMemCmp");

    volatile const BYTE* pa = (const BYTE*)a;
    volatile const BYTE* pb = (const BYTE*)b;
    int result = 0;
    // Constant-time comparison pour éviter timing attacks
    for (SIZE_T i = 0; i < size; i++) {
        result |= (pa[i] ^ pb[i]);
    }

    return result;
    // VMProtectEnd();
}

void* SyscallWrappers::SecureZero(void* dst, SIZE_T size) {
    // VMProtectBeginUltra("SyscallWrappers_SecureZero");

    volatile BYTE* d = (volatile BYTE*)dst;
    while (size--) *d++ = 0;

    return dst;
    // VMProtectEnd();
}

SIZE_T SyscallWrappers::SecureStrLen(const char* str) {
    // VMProtectBeginUltra("SyscallWrappers_SecureStrLen");

    if (!str) return 0;
    SIZE_T len = 0;
    while (str[len]) len++;

    return len;
    // VMProtectEnd();
}

int SyscallWrappers::SecureStrCmp(const char* s1, const char* s2) {
    // VMProtectBeginUltra("SyscallWrappers_SecureStrCmp");

    if (!s1 || !s2) return s1 ? 1 : (s2 ? -1 : 0);
    while (*s1 && (*s1 == *s2)) {
        s1++;
        s2++;
    }

    return (unsigned char)*s1 - (unsigned char)*s2;
    // VMProtectEnd();
}