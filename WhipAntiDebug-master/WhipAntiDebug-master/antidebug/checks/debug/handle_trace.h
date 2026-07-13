// ===== file: antidebug/checks/debug/handle_trace.h =====
//
// NtClose-based anti-debug: CloseHandle trap.
//
// Technique:
//   When a debugger is attached, calling NtClose() with an invalid handle
//   raises a STATUS_INVALID_HANDLE exception (0xC0000008). Under normal
//   execution (no debugger), NtClose just returns an error status.
//
//   We use SEH to catch the exception. If it fires → debugger detected.
//
// This is a classic anti-debug trick used by many packers (Themida, VMProtect).
// The twist here: we use a direct syscall via WhipSysCall, so there's no
// ntdll!NtClose in the call stack — harder to hook/bypass.
//
#ifndef ANTIDEBUG_HANDLE_TRACE_H
#define ANTIDEBUG_HANDLE_TRACE_H

#include "../../core/types.h"
#include "../../core/macros.h"
#include "../../core/syscall_bridge.h"
#include "../../core/string_encrypt.h"

// ---------------------------------------------------------------------------
// Check: NtClose invalid handle trap
//
// Pass a known-invalid handle (0xDEADBEEF). Under a debugger, this raises
// EXCEPTION_INVALID_HANDLE. Without a debugger, NtClose returns quietly.
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE b32 ad_close_handle_trap(void) {
    static u16 s_ssn = AD_SSN_UNRESOLVED;
    AD_RESOLVE_SSN_ENC(s_ssn, NtClose, 8);
    if (s_ssn == AD_SSN_FAILED) return 0;

    b32 detected = 0;

#if defined(_MSC_VER)
    __try {
        // 0xDEADBEEF is not a valid handle — under debugger this throws
        AD_SYSCALL1(s_ssn, (u64)0xDEADBEEFULL);
    }
    __except (1) {  // EXCEPTION_EXECUTE_HANDLER
        detected = 1;
    }
#endif

    return detected;
}

#endif // ANTIDEBUG_HANDLE_TRACE_H
