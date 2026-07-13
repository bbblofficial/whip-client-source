#pragma optimize("", off)
#include "whipsyscall/SyscallInvoker.h"

#ifdef BUILD_WITH_VMPROTECT
#include "VMProtectSDK.h"
#endif

#include "whipsyscall/AfdSocket.h"

// ========== SHELLCODE HELPERS ==========

namespace SyscallInvokerImpl {
    void SyscallShellcode::SetSSN(WORD ssn) {
        VMProtectBeginMutation("SyscallInvokerImpl_SyscallShellcode_SetSSN");

        // Injecter le SSN aux bytes 4-5 (little endian)
        *reinterpret_cast<WORD*>(&code[4]) = ssn;

        VMProtectEnd();
    }
}

// ========== SYSCALL INVOKER METHODS ==========

NTSTATUS SyscallInvoker::Invoke(
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
) {
    // VMProtect removed - this is called hundreds of times during network I/O (hot path)
    NTSTATUS result = SyscallStub(ssn, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11);

    return result;
}

NTSTATUS SyscallInvoker::InvokeWithRWX(
    WORD ssn,
    PVOID rwxBuffer,
    PVOID arg1,
    PVOID arg2,
    PVOID arg3,
    PVOID arg4,
    PVOID arg5,
    PVOID arg6,
    PVOID arg7,
    PVOID arg8,
    PVOID arg9,
    PVOID arg10
) {
    // VMProtect removed - alternative hot path for network I/O
    // Copier le shellcode dans le buffer RWX
    SyscallInvokerImpl::SyscallShellcode shellcode;
    shellcode.SetSSN(ssn);

    // Copie volatile pour éviter optimizations
    volatile BYTE* dest = reinterpret_cast<volatile BYTE*>(rwxBuffer);
    for (int i = 0; i < sizeof(shellcode.code); i++) {
        dest[i] = shellcode.code[i];
    }

    // Exécuter depuis le buffer RWX
    auto func = reinterpret_cast<SyscallInvokerImpl::SyscallFunc>(rwxBuffer);

    NTSTATUS result = func(arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10);

    return result;
}