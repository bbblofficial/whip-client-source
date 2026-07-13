// ===== file: antidebug/checks/runtime/drop_privs.h =====
//
// Drop SeDebugPrivilege from our own token.
//
// Most reverse engineering tools (x64dbg, IDA, Cheat Engine, ScyllaHide,
// Frida) require SeDebugPrivilege to OpenProcess(PROCESS_VM_READ |
// PROCESS_VM_WRITE) on a hardened target. By disabling SeDebugPrivilege
// on our OWN token, we can't OpenProcess into ourselves with elevated
// rights — but neither can attached components running under our token.
//
// More importantly: a tool that elevated to grab us must have the
// privilege ENABLED. We snapshot our own token state at startup and
// later check if SeDebugPrivilege has been re-enabled in our token by
// some attached helper. If yes → tampering.
//
#ifndef ANTIDEBUG_DROP_PRIVS_H
#define ANTIDEBUG_DROP_PRIVS_H

#include "../../core/types.h"
#include "../../core/macros.h"
#include "../../core/syscall_bridge.h"
#include "../../core/string_encrypt.h"
#include "../../core/strenc_extra.h"
// NtOpenProcessToken strenc lives in se_debug.h
#include "../debug/se_debug.h"

// LUID/PRIVILEGE structures and TOKEN_QUERY/SE_DEBUG_* come from se_debug.h
// (included above). We only need to add the local variant of TOKEN_PRIVILEGES
// (the existing AD_TOKEN_PRIVILEGES_HDR doesn't expose Privileges[0]).
typedef struct {
    u32                    PrivilegeCount;
    AD_LUID_AND_ATTRIBUTES Privileges[1];
} AD_TOKEN_PRIVILEGES_DROP;

#define AD_TOKEN_ADJUST_PRIVILEGES 0x20u

ANTIDEBUG_INLINE b32 ad_drop_se_debug(void) {
#ifdef _MSC_VER
    static u16 s_open_ssn   = AD_SSN_UNRESOLVED;
    static u16 s_adjust_ssn = AD_SSN_UNRESOLVED;
    static u16 s_close_ssn  = AD_SSN_UNRESOLVED;
    AD_RESOLVE_SSN_ENC(s_open_ssn,   NtOpenProcessToken,       19);
    AD_RESOLVE_SSN_ENC(s_adjust_ssn, NtAdjustPrivilegesToken,  24);
    AD_RESOLVE_SSN_ENC(s_close_ssn,  NtClose,                  8);
    (void)s_close_ssn;
    if (s_open_ssn == AD_SSN_FAILED || s_adjust_ssn == AD_SSN_FAILED) return 0;

    ad_handle_t tok = 0;
    ad_ntstatus_t st = (ad_ntstatus_t)(s64)AD_SYSCALL3(
        s_open_ssn,
        AD_CURRENT_PROCESS,
        (u64)(AD_TOKEN_QUERY | AD_TOKEN_ADJUST_PRIVILEGES),
        &tok
    );
    if (!AD_NT_SUCCESS(st) || !tok) return 0;

    AD_TOKEN_PRIVILEGES_DROP tp;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid.LowPart = AD_SE_DEBUG_LUID_LOW;
    tp.Privileges[0].Luid.HighPart = 0;
    tp.Privileges[0].Attributes = 0;  // Disabled

    st = (ad_ntstatus_t)(s64)AD_SYSCALL6(
        s_adjust_ssn,
        tok,
        (u64)0,                  // DisableAllPrivileges = FALSE
        &tp,
        (u64)sizeof(tp),
        (u64)0,                  // PreviousState
        (u64)0                   // ReturnLength
    );

    if (s_close_ssn != AD_SSN_FAILED) {
        AD_SYSCALL1(s_close_ssn, (u64)(uintptr_t)tok);
    }

    return AD_NT_SUCCESS(st);
#else
    return 0;
#endif
}

#endif // ANTIDEBUG_DROP_PRIVS_H