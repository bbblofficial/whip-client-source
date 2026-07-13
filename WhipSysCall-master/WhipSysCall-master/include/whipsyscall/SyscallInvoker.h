#ifndef WHIPSYSCALL_SYSCALLINVOKER_H
#define WHIPSYSCALL_SYSCALLINVOKER_H

#include "Types.h"

// ========== SHELLCODE IMPLEMENTATION ==========

namespace SyscallInvokerImpl {
    // Shellcode template pour syscall x64
    // Pattern: mov r10, rcx; mov eax, [SSN]; syscall; ret
    struct alignas(16) SyscallShellcode {
        BYTE code[16] = {
            0x4C, 0x8B, 0xD1,              // mov r10, rcx
            0xB8, 0x00, 0x00, 0x00, 0x00,  // mov eax, SSN (placeholder)
            0x0F, 0x05,                     // syscall
            0xC3,                           // ret
            0x90, 0x90, 0x90, 0x90, 0x90   // nop padding
        };

        void SetSSN(WORD ssn);
    };

    // Type de fonction pour le shellcode
    using SyscallFunc = NTSTATUS(*)(PVOID, PVOID, PVOID, PVOID, PVOID, PVOID, PVOID, PVOID, PVOID, PVOID);
}

// ========== DÉCLARATION EXTERNE ASM ==========
// Utiliser le stub ASM compilé (dans zone exécutable, contourne DEP)
extern "C" NTSTATUS SyscallStub(
    WORD ssn,
    PVOID arg1,
    PVOID arg2,
    PVOID arg3,
    PVOID arg4,
    PVOID arg5,
    PVOID arg6,
    PVOID arg7,
    PVOID arg8,
    PVOID arg9,
    PVOID arg10,
    PVOID arg11
);

class SyscallInvoker {
public:
    // Invoke générique avec SSN connu - UTILISE LE STUB ASM
    // Le stub .asm est dans une zone .text exécutable (contourne DEP)
    // Même si c'est un appel externe, il reste très rapide et difficile à hooker
    static NTSTATUS Invoke(
        WORD ssn,
        PVOID arg1  = nullptr,
        PVOID arg2  = nullptr,
        PVOID arg3  = nullptr,
        PVOID arg4  = nullptr,
        PVOID arg5  = nullptr,
        PVOID arg6  = nullptr,
        PVOID arg7  = nullptr,
        PVOID arg8  = nullptr,
        PVOID arg9  = nullptr,
        PVOID arg10 = nullptr,
        PVOID arg11 = nullptr
    );

    // Version alternative avec buffer RWX pré-alloué (pour shellcode dynamique si besoin)
    static NTSTATUS InvokeWithRWX(
        WORD ssn,
        PVOID rwxBuffer,  // Buffer RWX pré-alloué par l'appelant
        PVOID arg1 = nullptr,
        PVOID arg2 = nullptr,
        PVOID arg3 = nullptr,
        PVOID arg4 = nullptr,
        PVOID arg5 = nullptr,
        PVOID arg6 = nullptr,
        PVOID arg7 = nullptr,
        PVOID arg8 = nullptr,
        PVOID arg9 = nullptr,
        PVOID arg10 = nullptr
    );
};

#endif // WHIPSYSCALL_SYSCALLINVOKER_H