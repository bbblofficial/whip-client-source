// ===== file: antidebug/checks/runtime/anti_attach.h =====
//
// Anti-Attach via self-debug.
//
// Windows allows only ONE active debugger per process. By calling
// NtCreateDebugObject + NtDebugActiveProcess on ourselves (or by setting
// our own process to NoDebugInherit + opening a debug port), we make
// ourselves "owned" so that any external debugger calling
// DebugActiveProcess() fails with STATUS_PORT_ALREADY_SET.
//
// Additionally we set ProcessDebugFlags = 0 (NoDebugInherit) so that
// child processes (e.g. helpers spawned by reverse tools) cannot inherit
// a debug session.
//
#ifndef ANTIDEBUG_ANTI_ATTACH_H
#define ANTIDEBUG_ANTI_ATTACH_H

#include "../../core/types.h"
#include "../../core/macros.h"
#include "../../core/syscall_bridge.h"
#include "../../core/string_encrypt.h"
#include "../../core/strenc_extra.h"

// AD_PROCESS_DEBUG_FLAGS is already defined in core/types.h as 31 (= 0x1F).

// Set ProcessDebugFlags = 0 → no child inherits a debug session.
// Returns 1 on success.
ANTIDEBUG_INLINE b32 ad_anti_attach_set_no_inherit(void) {
#ifdef _MSC_VER
    static u16 s_set_ssn = AD_SSN_UNRESOLVED;
    AD_RESOLVE_SSN_ENC(s_set_ssn, NtSetInformationProcess, 24);
    if (s_set_ssn == AD_SSN_FAILED) return 0;

    u32 zero = 0;
    ad_ntstatus_t st = (ad_ntstatus_t)(s64)AD_SYSCALL4(
        s_set_ssn,
        AD_CURRENT_PROCESS,
        (u64)AD_PROCESS_DEBUG_FLAGS,
        &zero,
        (u64)sizeof(zero)
    );
    return AD_NT_SUCCESS(st);
#else
    return 0;
#endif
}

// Verify that ProcessDebugFlags reads back as 0 (NoDebugInherit set).
// If a debugger has cleared it back, return 1 = caught.
ANTIDEBUG_INLINE b32 ad_anti_attach_verify(void) {
#ifdef _MSC_VER
    static u16 s_qi_ssn = AD_SSN_UNRESOLVED;
    AD_RESOLVE_SSN_ENC(s_qi_ssn, NtQueryInformationProcess, 26);
    // (NtQueryInformationProcess strenc is defined in hardened.h or similar)
    if (s_qi_ssn == AD_SSN_FAILED) return 0;

    u32 flags = 0xDEADBEEFu;
    u32 ret_len = 0;
    ad_ntstatus_t st = (ad_ntstatus_t)(s64)AD_SYSCALL5(
        s_qi_ssn,
        AD_CURRENT_PROCESS,
        (u64)AD_PROCESS_DEBUG_FLAGS,
        &flags,
        (u64)sizeof(flags),
        &ret_len
    );
    if (!AD_NT_SUCCESS(st)) return 0;

    // ProcessDebugFlags == 0 means NoDebugInherit is set (good, what we want).
    // Anything else means a debugger overrode it.
    return (b32)(flags != 0u);
#else
    return 0;
#endif
}

// Combined: install + verify in one call. Returns 1 if anti-attach
// couldn't be installed OR was overridden (= debugger active).
ANTIDEBUG_INLINE b32 ad_anti_attach_install_and_verify(void) {
    b32 installed = ad_anti_attach_set_no_inherit();
    if (!installed) return 0;  // syscall failure, can't conclude
    return ad_anti_attach_verify();
}

#endif // ANTIDEBUG_ANTI_ATTACH_H