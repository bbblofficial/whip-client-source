// ===== file: antidebug/checks/threads/hide_thread.h =====
//
// Thread-hiding via NtSetInformationThread(ThreadHideFromDebugger).
//
// This call makes the current thread invisible to user-mode debuggers:
//   - The debugger receives no debug events for this thread.
//   - If a user-mode debugger is attached at call time, the kernel
//     raises an exception that terminates the process immediately.
//
// This is both a DEFENSIVE measure and a DETECTION mechanism:
//   - Success  → thread is now hidden (protection active)
//   - Failure  → a debugger may have been present at call time
//
// Uses WhipSysCall → zero ntdll IAT footprint.
//
#ifndef ANTIDEBUG_HIDE_THREAD_H
#define ANTIDEBUG_HIDE_THREAD_H

#include "../../core/types.h"
#include "../../core/macros.h"
#include "../../core/syscall_bridge.h"
#include "../../core/string_encrypt.h"

// ---------------------------------------------------------------------------
// Action + Check: hide current thread from debugger
//
// Returns 1 on success (thread hidden), 0 on failure.
// Call this as early as possible in initialization — before any other check.
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE b32 ad_hide_thread(void) {
    static u16 s_ssn = AD_SSN_UNRESOLVED;
    AD_RESOLVE_SSN_ENC(s_ssn, NtSetInformationThread, 23);
    if (s_ssn == AD_SSN_FAILED) return 0;

    // NtSetInformationThread(
    //   ThreadHandle              = NtCurrentThread(),
    //   ThreadInformationClass    = ThreadHideFromDebugger (17),
    //   ThreadInformation         = NULL,
    //   ThreadInformationLength   = 0
    // )
    ad_ntstatus_t st = AD_SYSCALL4(
        s_ssn,
        AD_CURRENT_THREAD,
        (u64)AD_THREAD_HIDE_FROM_DEBUGGER,
        (u64)0,
        (u64)0
    );

    return (b32)AD_NT_SUCCESS(st);
}

// ---------------------------------------------------------------------------
// Action: hide an arbitrary thread handle
//
// For use on worker/monitor threads that should never be visible to a debugger.
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE b32 ad_hide_thread_by_handle(ad_handle_t thread_handle) {
    static u16 s_ssn = AD_SSN_UNRESOLVED;
    AD_RESOLVE_SSN_ENC(s_ssn, NtSetInformationThread, 23);
    if (s_ssn == AD_SSN_FAILED) return 0;

    ad_ntstatus_t st = AD_SYSCALL4(
        s_ssn,
        (u64)thread_handle,
        (u64)AD_THREAD_HIDE_FROM_DEBUGGER,
        (u64)0,
        (u64)0
    );

    return (b32)AD_NT_SUCCESS(st);
}

// ---------------------------------------------------------------------------
// Encrypted string: "NtQueryInformationThread" (24 chars)
// ---------------------------------------------------------------------------
#define AD_STRENC_NtQueryInformationThread(buf)                              \
    do {                                                                     \
        const u8 _k = AD_STR_KEY(0xFE);                                     \
        char buf##_e[25];                                                    \
        AD_ENC(buf##_e,  0, 'N', _k); AD_ENC(buf##_e,  1, 't', _k);       \
        AD_ENC(buf##_e,  2, 'Q', _k); AD_ENC(buf##_e,  3, 'u', _k);       \
        AD_ENC(buf##_e,  4, 'e', _k); AD_ENC(buf##_e,  5, 'r', _k);       \
        AD_ENC(buf##_e,  6, 'y', _k); AD_ENC(buf##_e,  7, 'I', _k);       \
        AD_ENC(buf##_e,  8, 'n', _k); AD_ENC(buf##_e,  9, 'f', _k);       \
        AD_ENC(buf##_e, 10, 'o', _k); AD_ENC(buf##_e, 11, 'r', _k);       \
        AD_ENC(buf##_e, 12, 'm', _k); AD_ENC(buf##_e, 13, 'a', _k);       \
        AD_ENC(buf##_e, 14, 't', _k); AD_ENC(buf##_e, 15, 'i', _k);       \
        AD_ENC(buf##_e, 16, 'o', _k); AD_ENC(buf##_e, 17, 'n', _k);       \
        AD_ENC(buf##_e, 18, 'T', _k); AD_ENC(buf##_e, 19, 'h', _k);       \
        AD_ENC(buf##_e, 20, 'r', _k); AD_ENC(buf##_e, 21, 'e', _k);       \
        AD_ENC(buf##_e, 22, 'a', _k); AD_ENC(buf##_e, 23, 'd', _k);       \
        AD_DECODE_BUF(buf##_e, 24, _k);                                     \
        for (unsigned _ci = 0; _ci < 25; _ci++) (buf)[_ci] = buf##_e[_ci];  \
    } while (0)

// ---------------------------------------------------------------------------
// Verify: is the current thread ACTUALLY hidden from debugger?
//
// After calling ad_hide_thread(), ScyllaHide/TitanHide may have hooked the
// syscall to return STATUS_SUCCESS without doing anything.
//
// We verify by querying ThreadHideFromDebugger (class 17) back.
// On Windows 10+, NtQueryInformationThread with class 17 returns a BOOLEAN:
//   TRUE  = thread IS hidden
//   FALSE = thread is NOT hidden (bypass detected!)
//
// If the Set succeeded but the Query says we're not hidden → BYPASS.
// ---------------------------------------------------------------------------
#define AD_THREAD_HIDE_FROM_DEBUGGER_QUERY 17

ANTIDEBUG_INLINE b32 ad_verify_thread_hidden(void) {
    static u16 s_ssn = AD_SSN_UNRESOLVED;
    AD_RESOLVE_SSN_ENC(s_ssn, NtQueryInformationThread, 25);
    if (s_ssn == AD_SSN_FAILED) return 0;

    u8  is_hidden = 0;
    u32 ret_len   = 0;

    ad_ntstatus_t st = AD_SYSCALL5(
        s_ssn,
        AD_CURRENT_THREAD,
        (u64)AD_THREAD_HIDE_FROM_DEBUGGER_QUERY,
        &is_hidden,
        (u64)sizeof(is_hidden),
        &ret_len
    );

    if (!AD_NT_SUCCESS(st)) {
        // Query not supported (older Windows) — can't verify, assume ok
        return 0;
    }

    // is_hidden should be TRUE (nonzero) if ad_hide_thread worked for real.
    // If it's FALSE, someone faked the Set call → debugger present.
    return (b32)(is_hidden == 0);
}

#endif // ANTIDEBUG_HIDE_THREAD_H
