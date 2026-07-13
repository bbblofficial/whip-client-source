// ===== file: antidebug/checks/advanced/cross_process.h =====
//
// Cross-Process Validation — query our own process from the kernel's
// perspective to detect debugger presence that userland checks miss.
// Uses NtQueryInformationProcess with ProcessDebugPort (class 7) and
// ProcessDebugObjectHandle (class 30) to get the kernel's ground truth.
// Then compares against PEB to detect PEB patching.
//
#ifndef ANTIDEBUG_CROSS_PROCESS_H
#define ANTIDEBUG_CROSS_PROCESS_H

#include "../../core/types.h"
#include "../../core/macros.h"
#include "../../core/syscall_bridge.h"
#include "../../core/string_encrypt.h"

#ifdef _MSC_VER
#include <intrin.h>
#endif

typedef struct {
    b32 kernel_says_debugged;    // kernel reports debug port
    b32 peb_says_debugged;       // PEB says debugged
    b32 debug_object_exists;     // debug object handle present
    b32 validated;
} ad_cross_proc_ctx_t;

// ---------------------------------------------------------------------------
// Cross-process: compare kernel truth vs userland PEB
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE b32 ad_cross_process_validate(ad_cross_proc_ctx_t* ctx) {
#ifdef _MSC_VER
    AD_ZERO_BUF(ctx, sizeof(*ctx));

    static u16 s_query_ssn = AD_SSN_UNRESOLVED;
    AD_RESOLVE_SSN_ENC(s_query_ssn, NtQueryInformationProcess, 26);
    if (s_query_ssn == AD_SSN_FAILED) return 0;

    // Query ProcessDebugPort (class 7) — kernel truth
    u64 debug_port = 0;
    u32 ret_len = 0;
    ad_ntstatus_t st = (ad_ntstatus_t)(s64)SyscallStub(s_query_ssn,
        AD_CURRENT_PROCESS,
        (void*)(u64)7,          // ProcessDebugPort
        (void*)&debug_port,
        (void*)(u64)sizeof(debug_port),
        (void*)&ret_len,
        (void*)0, (void*)0, (void*)0, (void*)0, (void*)0, (void*)0
    );
    ctx->kernel_says_debugged = (AD_NT_SUCCESS(st) && debug_port != 0) ? 1 : 0;

    // Query ProcessDebugObjectHandle (class 30)
    u64 debug_obj = 0;
    st = (ad_ntstatus_t)(s64)SyscallStub(s_query_ssn,
        AD_CURRENT_PROCESS,
        (void*)(u64)30,         // ProcessDebugObjectHandle
        (void*)&debug_obj,
        (void*)(u64)sizeof(debug_obj),
        (void*)&ret_len,
        (void*)0, (void*)0, (void*)0, (void*)0, (void*)0, (void*)0
    );
    // STATUS_PORT_NOT_SET = 0xC0000353 means no debug object → clean
    ctx->debug_object_exists = (AD_NT_SUCCESS(st)) ? 1 : 0;

    // Query ProcessDebugFlags (class 31)
    u32 debug_flags = 1;
    st = (ad_ntstatus_t)(s64)SyscallStub(s_query_ssn,
        AD_CURRENT_PROCESS,
        (void*)(u64)31,         // ProcessDebugFlags
        (void*)&debug_flags,
        (void*)(u64)sizeof(debug_flags),
        (void*)&ret_len,
        (void*)0, (void*)0, (void*)0, (void*)0, (void*)0, (void*)0
    );
    // NOTE: ProcessDebugFlags == 0 used to be flagged as "debugger
    // present", but our own anti-attach hardening sets it to 0 by
    // design. We treat this as inconclusive now.
    b32 flags_say_debug = 0;
    (void)debug_flags;

    // Read PEB.BeingDebugged directly
    u8* peb = (u8*)__readgsqword(0x60);
    ctx->peb_says_debugged = (*(u8*)(peb + 2)) ? 1 : 0;

    ctx->validated = 1;

    // Detection: compare kernel vs userland
    u32 suspicious = 0;

    // Kernel says debug port but PEB says clean → PEB patched (ScyllaHide)
    if (ctx->kernel_says_debugged && !ctx->peb_says_debugged) suspicious += 3;

    // Debug object exists → debugger attached (hard to fake)
    if (ctx->debug_object_exists) suspicious += 2;

    // Debug flags say debugged
    if (flags_say_debug) suspicious += 2;

    // Kernel agrees with PEB — debugger present and not hidden
    if (ctx->kernel_says_debugged && ctx->peb_says_debugged) suspicious += 1;

    return (b32)(suspicious > 0u);
#else
    return 0;
#endif
}

#endif // ANTIDEBUG_CROSS_PROCESS_H
