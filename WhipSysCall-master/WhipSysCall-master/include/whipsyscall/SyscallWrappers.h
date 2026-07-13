#ifndef WHIPSYSCALL_SYSCALLWRAPPERS_H
#define WHIPSYSCALL_SYSCALLWRAPPERS_H

#include "Types.h"
#include "SyscallResolver.h"
#include "SyscallInvoker.h"
#include <intrin.h>

// Inclure les headers Windows pour les structures NT
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <winternl.h>

// ========== CONSTANTES NT ==========
#ifndef PAGE_READWRITE
#define PAGE_READWRITE 0x04
#endif
#ifndef PAGE_EXECUTE_READWRITE
#define PAGE_EXECUTE_READWRITE 0x40
#endif
#ifndef MEM_COMMIT
#define MEM_COMMIT 0x1000
#endif
#ifndef MEM_RESERVE
#define MEM_RESERVE 0x2000
#endif
#ifndef MEM_RELEASE
#define MEM_RELEASE 0x8000
#endif

// ========== MACROS ==========
#define NtCurrentProcess() ((HANDLE)(LONG_PTR)-1)
#define NtCurrentThread() ((HANDLE)(LONG_PTR)-2)

// ========== HELPERS ==========
namespace SyscallWrappersHelpers {
    // Obtenir le heap du processus depuis PEB
    HANDLE GetProcessHeap();
}

// Wrappers haut niveau pour syscalls courants
class SyscallWrappers {
private:
    SyscallResolver* resolver;

public:
    explicit SyscallWrappers(SyscallResolver* res);

    // ========== GESTION MEMOIRE ==========
    PVOID HeapAlloc(SIZE_T size);
    PVOID HeapReAlloc(PVOID ptr, SIZE_T newSize);
    bool HeapFree(PVOID ptr);
    PVOID VirtualAlloc(SIZE_T size, DWORD protect);
    bool VirtualFree(PVOID address, SIZE_T size);

    // ========== FICHIERS ==========
    HANDLE CreateFile(const WORD* path, DWORD access, DWORD share, DWORD disposition);
    bool CloseHandle(HANDLE handle);
    bool ReadFile(HANDLE handle, PVOID buffer, DWORD size, DWORD* bytesRead);
    bool WriteFile(HANDLE handle, PVOID buffer, DWORD size, DWORD* bytesWritten);

    // ========== PROCESSUS/THREADS ==========
    HANDLE GetCurrentProcess();
    HANDLE GetCurrentThread();
    DWORD GetCurrentProcessId();
    DWORD GetCurrentThreadId();
    QWORD GetSystemTime();

    // ========== SECURE CRT REPLACEMENTS (ANTI-HOOK) ==========
    static void* SecureMemCpy(void* dst, const void* src, SIZE_T size);
    static void* SecureMemSet(void* dst, int value, SIZE_T size);
    static int SecureMemCmp(const void* a, const void* b, SIZE_T size);
    static void* SecureZero(void* dst, SIZE_T size);
    static SIZE_T SecureStrLen(const char* str);
    static int SecureStrCmp(const char* s1, const char* s2);
};

#endif // WHIPSYSCALL_SYSCALLWRAPPERS_H