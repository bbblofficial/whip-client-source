// ===== file: antidebug/checks/debug/debug_port.h =====
//
// NtQueryInformationProcess-based debug detection.
// Uses WhipSysCall via the bridge — zero ntdll.dll IAT footprint.
//
#ifndef ANTIDEBUG_DEBUG_PORT_H
#define ANTIDEBUG_DEBUG_PORT_H

#include "../../core/types.h"
#include "../../core/macros.h"
#include "../../core/syscall_bridge.h"
#include "../../core/string_encrypt.h"

// ---------------------------------------------------------------------------
// Check: ProcessDebugPort (class 7)
//
// NtQueryInformationProcess returns a non-zero debug port handle when a
// user-mode debugger is attached. The value is typically -1 (0xFFFFFFFFFFFFFFFF)
// or a valid handle. Zero means no debugger.
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE b32 ad_debug_port(void) {
    static u16 s_ssn = AD_SSN_UNRESOLVED;
    AD_RESOLVE_SSN_ENC(s_ssn, NtQueryInformationProcess, 26);
    if (s_ssn == AD_SSN_FAILED) return 0;

    u64 port    = 0;
    u32 ret_len = 0;

    ad_ntstatus_t st = AD_SYSCALL5(
        s_ssn,
        AD_CURRENT_PROCESS,
        (u64)AD_PROCESS_DEBUG_PORT,
        &port,
        (u64)sizeof(port),
        &ret_len
    );

    return (b32)(AD_NT_SUCCESS(st) && port != 0);
}

// ---------------------------------------------------------------------------
// Check: ProcessDebugFlags (class 31)
//
// Returns a DWORD with bit 0 = NoDebugInherit.
// If the value is 0, the process is inheriting debug state → debugger attached.
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE b32 ad_debug_flags(void) {
    static u16 s_ssn = AD_SSN_UNRESOLVED;
    AD_RESOLVE_SSN_ENC(s_ssn, NtQueryInformationProcess, 26);
    if (s_ssn == AD_SSN_FAILED) return 0;

    u32 flags   = 0;
    u32 ret_len = 0;

    ad_ntstatus_t st = AD_SYSCALL5(
        s_ssn,
        AD_CURRENT_PROCESS,
        (u64)AD_PROCESS_DEBUG_FLAGS,
        &flags,
        (u64)sizeof(flags),
        &ret_len
    );

    // flags == 0 when NoDebugInherit is clear, meaning a debugger is present
    return (b32)(AD_NT_SUCCESS(st) && flags == 0);
}

// ---------------------------------------------------------------------------
// Check: ProcessDebugObjectHandle (class 30)
//
// Queries the debug object handle. Returns a valid handle (non-null) when
// a debugger is attached and the debug object has not been closed.
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE b32 ad_debug_object_handle(void) {
    static u16 s_ssn = AD_SSN_UNRESOLVED;
    AD_RESOLVE_SSN_ENC(s_ssn, NtQueryInformationProcess, 26);
    if (s_ssn == AD_SSN_FAILED) return 0;

    void* obj_handle = (void*)0;
    u32   ret_len    = 0;

    // NtQueryInformationProcess returns STATUS_PORT_NOT_SET (0xC0000353)
    // when there is no debug object — we treat the success case as suspicious.
    ad_ntstatus_t st = AD_SYSCALL5(
        s_ssn,
        AD_CURRENT_PROCESS,
        (u64)AD_PROCESS_DEBUG_OBJECT_HANDLE,
        &obj_handle,
        (u64)sizeof(obj_handle),
        &ret_len
    );

    return (b32)(AD_NT_SUCCESS(st) && obj_handle != (void*)0);
}

#endif // ANTIDEBUG_DEBUG_PORT_H
