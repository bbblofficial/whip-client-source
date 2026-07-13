// ===== file: antidebug/checks/runtime/raise_hard_error.h =====
//
// NtSystemDebugControl privileged-action probe.
//
// NtSystemDebugControl is the canonical kernel-debug interface. Almost
// every command requires SeDebugPrivilege; without it the kernel
// returns STATUS_DEBUGGER_INACTIVE (0xC0000354) on commands related
// to a kernel debugger, or STATUS_ACCESS_DENIED (0xC0000022).
//
// We invoke SysDbgGetTriageDump (29) with a NULL output buffer. On a
// clean unprivileged process the kernel response is deterministic
// across every Win10/11 build:
//   - Without SeDebugPrivilege: STATUS_ACCESS_DENIED, or
//   - STATUS_INVALID_INFO_CLASS / STATUS_NOT_IMPLEMENTED depending on
//     the build's command set
//
// Any of those is fine — what we test for is the OPPOSITE:
//   - STATUS_SUCCESS, STATUS_INFO_LENGTH_MISMATCH, STATUS_BUFFER_TOO_SMALL
// These all imply the call REACHED the buffer-validation logic, which
// only happens after the privilege check passes — meaning the process
// has SeDebugPrivilege (a debugger / pentest tool gave it to us) OR a
// hook intercepted the syscall and faked a buffer-related response.
//
// Returns 1 if the response indicates the call advanced past the
// privilege gate.
//
#ifndef ANTIDEBUG_RAISE_HARD_ERROR_H
#define ANTIDEBUG_RAISE_HARD_ERROR_H

#include "../../core/types.h"
#include "../../core/macros.h"
#include "../../core/syscall_bridge.h"
#include "../../core/string_encrypt.h"
#include "../../core/strenc_extra.h"

#ifndef AD_STATUS_SUCCESS
#define AD_STATUS_SUCCESS                ((ad_ntstatus_t)0x00000000L)
#endif
#ifndef AD_STATUS_INFO_LENGTH_MISMATCH
#define AD_STATUS_INFO_LENGTH_MISMATCH   ((ad_ntstatus_t)0xC0000004L)
#endif
#ifndef AD_STATUS_BUFFER_TOO_SMALL
#define AD_STATUS_BUFFER_TOO_SMALL       ((ad_ntstatus_t)0xC0000023L)
#endif

// "NtSystemDebugControl" (20 chars) string-encrypt
#ifndef AD_STRENC_NtSystemDebugControl
#define AD_STRENC_NtSystemDebugControl(buf)                                  \
    do {                                                                     \
        const u8 _k = AD_STR_KEY(0x59);                                     \
        char buf##_e[21];                                                    \
        AD_ENC(buf##_e,  0, 'N', _k); AD_ENC(buf##_e,  1, 't', _k);       \
        AD_ENC(buf##_e,  2, 'S', _k); AD_ENC(buf##_e,  3, 'y', _k);       \
        AD_ENC(buf##_e,  4, 's', _k); AD_ENC(buf##_e,  5, 't', _k);       \
        AD_ENC(buf##_e,  6, 'e', _k); AD_ENC(buf##_e,  7, 'm', _k);       \
        AD_ENC(buf##_e,  8, 'D', _k); AD_ENC(buf##_e,  9, 'e', _k);       \
        AD_ENC(buf##_e, 10, 'b', _k); AD_ENC(buf##_e, 11, 'u', _k);       \
        AD_ENC(buf##_e, 12, 'g', _k); AD_ENC(buf##_e, 13, 'C', _k);       \
        AD_ENC(buf##_e, 14, 'o', _k); AD_ENC(buf##_e, 15, 'n', _k);       \
        AD_ENC(buf##_e, 16, 't', _k); AD_ENC(buf##_e, 17, 'r', _k);       \
        AD_ENC(buf##_e, 18, 'o', _k); AD_ENC(buf##_e, 19, 'l', _k);       \
        AD_DECODE_BUF(buf##_e, 20, _k);                                     \
        for (unsigned _ci = 0; _ci < 21; _ci++) (buf)[_ci] = buf##_e[_ci];  \
    } while (0)
#endif

ANTIDEBUG_INLINE b32 ad_raise_hard_error_probe(void) {
#ifdef _MSC_VER
    static u16 s_ssn = AD_SSN_UNRESOLVED;
    AD_RESOLVE_SSN_ENC(s_ssn, NtSystemDebugControl, 21);
    if (s_ssn == AD_SSN_FAILED) return 0;

    // SysDbgQueryVersion = 0; we deliberately pass NULL buffers so a
    // privileged kernel response would be STATUS_INFO_LENGTH_MISMATCH,
    // not STATUS_SUCCESS. Unprivileged response is STATUS_ACCESS_DENIED
    // (0xC0000022) or STATUS_DEBUGGER_INACTIVE (0xC0000354).
    u32 ret_len = 0;
    ad_ntstatus_t st = (ad_ntstatus_t)(s64)AD_SYSCALL6(
        s_ssn,
        (u64)0,           // SysDbgQueryModuleInformation
        (void*)0,         // input buffer
        (u64)0,
        (void*)0,         // output buffer
        (u64)0,
        &ret_len
    );

    // The "advanced past the gate" responses we want to flag.
    if (st == AD_STATUS_SUCCESS)              return 1;
    if (st == AD_STATUS_INFO_LENGTH_MISMATCH) return 1;
    if (st == AD_STATUS_BUFFER_TOO_SMALL)     return 1;

    // Any other status (ACCESS_DENIED, DEBUGGER_INACTIVE, INVALID_INFO_CLASS,
    // NOT_IMPLEMENTED) is the expected unprivileged response.
    return 0;
#else
    return 0;
#endif
}

#endif // ANTIDEBUG_RAISE_HARD_ERROR_H
