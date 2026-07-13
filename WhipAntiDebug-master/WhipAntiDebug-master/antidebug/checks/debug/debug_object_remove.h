// ===== file: antidebug/checks/debug/debug_object_remove.h =====
//
// Anti-attach: NtRemoveProcessDebug
//
// Technique:
//   If a debugger is attached, we can forcefully detach it by removing
//   the debug object from our own process. This is both:
//     - A detection mechanism (success = debugger was attached)
//     - An active defense (removes the debugger)
//
//   Steps:
//     1. NtQueryInformationProcess(ProcessDebugObjectHandle) → get debug object
//     2. NtRemoveProcessDebug(process, debug_object) → detach debugger
//
// This is aggressive — the debugger will crash/disconnect.
// Only use in production, not during development.
//
#ifndef ANTIDEBUG_DEBUG_OBJECT_REMOVE_H
#define ANTIDEBUG_DEBUG_OBJECT_REMOVE_H

#include "../../core/types.h"
#include "../../core/macros.h"
#include "../../core/syscall_bridge.h"
#include "../../core/string_encrypt.h"

// ---------------------------------------------------------------------------
// Encrypted string: "NtRemoveProcessDebug" (20 chars)
// ---------------------------------------------------------------------------
#define AD_STRENC_NtRemoveProcessDebug(buf)                                  \
    do {                                                                     \
        const u8 _k = AD_STR_KEY(0xF1);                                     \
        char buf##_e[21];                                                    \
        AD_ENC(buf##_e,  0, 'N', _k); AD_ENC(buf##_e,  1, 't', _k);       \
        AD_ENC(buf##_e,  2, 'R', _k); AD_ENC(buf##_e,  3, 'e', _k);       \
        AD_ENC(buf##_e,  4, 'm', _k); AD_ENC(buf##_e,  5, 'o', _k);       \
        AD_ENC(buf##_e,  6, 'v', _k); AD_ENC(buf##_e,  7, 'e', _k);       \
        AD_ENC(buf##_e,  8, 'P', _k); AD_ENC(buf##_e,  9, 'r', _k);       \
        AD_ENC(buf##_e, 10, 'o', _k); AD_ENC(buf##_e, 11, 'c', _k);       \
        AD_ENC(buf##_e, 12, 'e', _k); AD_ENC(buf##_e, 13, 's', _k);       \
        AD_ENC(buf##_e, 14, 's', _k); AD_ENC(buf##_e, 15, 'D', _k);       \
        AD_ENC(buf##_e, 16, 'e', _k); AD_ENC(buf##_e, 17, 'b', _k);       \
        AD_ENC(buf##_e, 18, 'u', _k); AD_ENC(buf##_e, 19, 'g', _k);       \
        AD_DECODE_BUF(buf##_e, 20, _k);                                     \
        for (unsigned _ci = 0; _ci < 21; _ci++) (buf)[_ci] = buf##_e[_ci];  \
    } while (0)

// ---------------------------------------------------------------------------
// Action + Check: detach debugger by removing the debug object
//
// Returns 1 if a debugger was detached (= was attached).
// Returns 0 if no debugger was present or removal failed.
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE b32 ad_remove_debug_object(void) {
    // Step 1: Get debug object handle
    static u16 s_ssn_query = AD_SSN_UNRESOLVED;
    AD_RESOLVE_SSN_ENC(s_ssn_query, NtQueryInformationProcess, 26);
    if (s_ssn_query == AD_SSN_FAILED) return 0;

    void* debug_obj = (void*)0;
    u32 ret_len = 0;

    ad_ntstatus_t st = AD_SYSCALL5(
        s_ssn_query,
        AD_CURRENT_PROCESS,
        (u64)AD_PROCESS_DEBUG_OBJECT_HANDLE,
        &debug_obj,
        (u64)sizeof(debug_obj),
        &ret_len
    );

    // STATUS_PORT_NOT_SET (0xC0000353) means no debug object → no debugger
    if (!AD_NT_SUCCESS(st) || debug_obj == (void*)0) return 0;

    // Step 2: Remove the debug object → forcefully detach debugger
    static u16 s_ssn_remove = AD_SSN_UNRESOLVED;
    AD_RESOLVE_SSN_ENC(s_ssn_remove, NtRemoveProcessDebug, 21);
    if (s_ssn_remove == AD_SSN_FAILED) return 1; // still detected even if can't remove

    ad_ntstatus_t st2 = AD_SYSCALL2(
        s_ssn_remove,
        AD_CURRENT_PROCESS,
        (u64)debug_obj
    );

    AD_UNUSED(st2);
    return 1; // debugger was present (and hopefully detached)
}

#endif // ANTIDEBUG_DEBUG_OBJECT_REMOVE_H
