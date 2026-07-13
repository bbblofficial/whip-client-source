#ifndef WHIPNEXUS_SYSCALLMANAGER_H
#define WHIPNEXUS_SYSCALLMANAGER_H

#include "Types.h"
#include "whipsyscall/WhipSysCall.h"

// Singleton pour gérer le syscall resolver
class SyscallManager {
private:
    // Allocation sur la pile au lieu du heap
    static SyscallResolver resolver;
    static SyscallWrappers wrappers;
    static bool initialized;

    SyscallManager() = delete;

public:
    static bool Init();
    static void Cleanup();
    static SyscallWrappers*  GetWrappers();
    static SyscallResolver*  GetResolver();

    // ========== SECURE CRT REPLACEMENTS (ANTI-HOOK) ==========

    // Helpers pour strlen et strcmp (pas de syscall direct pour ces fonctions)
    static inline u32 StrLen(const char* str) {
        return static_cast<u32>(SyscallWrappers::SecureStrLen(str));
    }

    static inline int StrCmp(const char* s1, const char* s2) {
        return SyscallWrappers::SecureStrCmp(s1, s2);
    }

    // Secure memory operations (remplace memcpy/memset/memcmp)
    // Utilise des loops volatiles pour éviter les hooks IAT
    static inline void* SecureMemCpy(void* dst, const void* src, u32 size) {
        return SyscallWrappers::SecureMemCpy(dst, src, size);
    }

    static inline void* SecureMemSet(void* dst, int value, u32 size) {
        return SyscallWrappers::SecureMemSet(dst, value, size);
    }

    static inline int SecureMemCmp(const void* a, const void* b, u32 size) {
        return SyscallWrappers::SecureMemCmp(a, b, size);
    }

    // Secure zero memory (garantit pas d'optimization par le compilateur)
    static inline void* SecureZero(void* dst, u32 size) {
        return SyscallWrappers::SecureZero(dst, size);
    }

    // ========== THREAD MANAGEMENT WRAPPERS ==========

    // Créer un thread
    static void* CreateThread(void* startAddr, void* param, u32* threadId);

    // Attendre la fin d'un thread (timeout en ms)
    static u32 WaitForThread(void* handle, u32 timeout);

    // Force-terminer un thread (kill mid-instruction). Réservé au cleanup
    // d'unload — toute lock/heap-state détenue par le thread leak.
    static bool TerminateThread(void* handle);

    // Fermer un handle
    static bool CloseHandle(void* handle);

    // Créer une critical section (mutex)
    static void* CreateCriticalSection();

    // Détruire une critical section
    static void DeleteCriticalSection(void* cs);

    // Entrer dans une critical section (lock)
    static void EnterCriticalSection(void* cs);

    // Sortir d'une critical section (unlock)
    static void LeaveCriticalSection(void* cs);
};

#endif // WHIPNEXUS_SYSCALLMANAGER_H