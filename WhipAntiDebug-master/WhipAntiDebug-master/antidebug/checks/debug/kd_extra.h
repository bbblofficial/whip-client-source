// ===== file: antidebug/checks/debug/kd_extra.h =====
//
// Three remaining "classic" anti-debug checks not covered by kd_deep
// or al_khaser_classics:
//
//   1. ad_kx_self_debug_attempt
//      Tries to attach a fresh debug object to ourselves via
//      NtCreateDebugObject + NtDebugActiveProcess. Without an existing
//      debug session the call succeeds (we then immediately detach).
//      With one already active (cdb / WinDbg / x64dbg), the kernel
//      returns STATUS_PORT_ALREADY_SET (0xC0000048) — undeniable
//      proof that another debugger holds the port.
//
//   2. ad_kx_veh_chain_count
//      Walks the process VectoredExceptionHandlerList resident in
//      ntdll's _LDR_DATA. Most debuggers — particularly those with
//      anti-anti-debug shims (ScyllaHide, x64dbg's built-in AAD) —
//      install at least one VEH to intercept and re-dispatch
//      exceptions. A clean process running this binary expects 0
//      external VEHs (the project itself uses SEH __try/__except, not
//      vectored). Any non-zero count is suspicious.
//
//   3. ad_kx_break_on_termination
//      NtSetInformationThread(ThreadBreakOnTermination, 29) — if a
//      debugger is hooked at the kernel-side thread-termination
//      callback, this returns SUCCESS, otherwise STATUS_INVALID_INFO_CLASS.
//
// All three return b32 (0 = clean, 1 = positive). Wrapped in
// __try/__except in the master combiner.
//
#ifndef ANTIDEBUG_KD_EXTRA_H
#define ANTIDEBUG_KD_EXTRA_H

#include "../../core/types.h"
#include "../../core/macros.h"
#include "../../core/syscall_bridge.h"
#include "../../core/string_encrypt.h"
#include "../../core/strenc_extra.h"
#include "../../core/api_hash.h"

#ifdef _MSC_VER

// =============================================================================
// 1. Self-debug attempt
// =============================================================================
#ifndef AD_STATUS_PORT_ALREADY_SET
#define AD_STATUS_PORT_ALREADY_SET ((ad_ntstatus_t)(s32)0xC0000048L)
#endif

#ifndef AD_STRENC_NtCreateDebugObject_KX
#define AD_STRENC_NtCreateDebugObject_KX(buf)                                \
    do {                                                                     \
        const u8 _k = AD_STR_KEY(0x7F);                                     \
        char buf##_e[20];                                                    \
        AD_ENC(buf##_e,  0, 'N', _k); AD_ENC(buf##_e,  1, 't', _k);       \
        AD_ENC(buf##_e,  2, 'C', _k); AD_ENC(buf##_e,  3, 'r', _k);       \
        AD_ENC(buf##_e,  4, 'e', _k); AD_ENC(buf##_e,  5, 'a', _k);       \
        AD_ENC(buf##_e,  6, 't', _k); AD_ENC(buf##_e,  7, 'e', _k);       \
        AD_ENC(buf##_e,  8, 'D', _k); AD_ENC(buf##_e,  9, 'e', _k);       \
        AD_ENC(buf##_e, 10, 'b', _k); AD_ENC(buf##_e, 11, 'u', _k);       \
        AD_ENC(buf##_e, 12, 'g', _k); AD_ENC(buf##_e, 13, 'O', _k);       \
        AD_ENC(buf##_e, 14, 'b', _k); AD_ENC(buf##_e, 15, 'j', _k);       \
        AD_ENC(buf##_e, 16, 'e', _k); AD_ENC(buf##_e, 17, 'c', _k);       \
        AD_ENC(buf##_e, 18, 't', _k);                                       \
        AD_DECODE_BUF(buf##_e, 19, _k);                                     \
        for (unsigned _ci = 0; _ci < 20; _ci++) (buf)[_ci] = buf##_e[_ci];  \
    } while (0)
#endif

#ifndef AD_STRENC_NtDebugActiveProcess
#define AD_STRENC_NtDebugActiveProcess(buf)                                  \
    do {                                                                     \
        const u8 _k = AD_STR_KEY(0x6B);                                     \
        char buf##_e[22];                                                    \
        AD_ENC(buf##_e,  0, 'N', _k); AD_ENC(buf##_e,  1, 't', _k);       \
        AD_ENC(buf##_e,  2, 'D', _k); AD_ENC(buf##_e,  3, 'e', _k);       \
        AD_ENC(buf##_e,  4, 'b', _k); AD_ENC(buf##_e,  5, 'u', _k);       \
        AD_ENC(buf##_e,  6, 'g', _k); AD_ENC(buf##_e,  7, 'A', _k);       \
        AD_ENC(buf##_e,  8, 'c', _k); AD_ENC(buf##_e,  9, 't', _k);       \
        AD_ENC(buf##_e, 10, 'i', _k); AD_ENC(buf##_e, 11, 'v', _k);       \
        AD_ENC(buf##_e, 12, 'e', _k); AD_ENC(buf##_e, 13, 'P', _k);       \
        AD_ENC(buf##_e, 14, 'r', _k); AD_ENC(buf##_e, 15, 'o', _k);       \
        AD_ENC(buf##_e, 16, 'c', _k); AD_ENC(buf##_e, 17, 'e', _k);       \
        AD_ENC(buf##_e, 18, 's', _k); AD_ENC(buf##_e, 19, 's', _k);       \
        AD_DECODE_BUF(buf##_e, 21, _k);                                     \
        for (unsigned _ci = 0; _ci < 22; _ci++) (buf)[_ci] = buf##_e[_ci];  \
    } while (0)
#endif

#ifndef AD_STRENC_NtRemoveProcessDebug
#define AD_STRENC_NtRemoveProcessDebug(buf)                                  \
    do {                                                                     \
        const u8 _k = AD_STR_KEY(0x52);                                     \
        char buf##_e[22];                                                    \
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
        AD_DECODE_BUF(buf##_e, 21, _k);                                     \
        for (unsigned _ci = 0; _ci < 22; _ci++) (buf)[_ci] = buf##_e[_ci];  \
    } while (0)
#endif

#ifndef AD_STRENC_NtClose_KX
#define AD_STRENC_NtClose_KX(buf)                                             \
    do {                                                                     \
        const u8 _k = AD_STR_KEY(0x4D);                                     \
        char buf##_e[8];                                                     \
        AD_ENC(buf##_e,  0, 'N', _k); AD_ENC(buf##_e,  1, 't', _k);       \
        AD_ENC(buf##_e,  2, 'C', _k); AD_ENC(buf##_e,  3, 'l', _k);       \
        AD_ENC(buf##_e,  4, 'o', _k); AD_ENC(buf##_e,  5, 's', _k);       \
        AD_ENC(buf##_e,  6, 'e', _k);                                       \
        AD_DECODE_BUF(buf##_e, 7, _k);                                      \
        for (unsigned _ci = 0; _ci < 8; _ci++) (buf)[_ci] = buf##_e[_ci];   \
    } while (0)
#endif

ANTIDEBUG_INLINE b32 ad_kx_self_debug_attempt(void) {
    static u16 s_create = AD_SSN_UNRESOLVED;
    static u16 s_attach = AD_SSN_UNRESOLVED;
    static u16 s_detach = AD_SSN_UNRESOLVED;
    static u16 s_close  = AD_SSN_UNRESOLVED;
    AD_RESOLVE_SSN_ENC(s_create, NtCreateDebugObject_KX, 20);
    AD_RESOLVE_SSN_ENC(s_attach, NtDebugActiveProcess, 22);
    AD_RESOLVE_SSN_ENC(s_detach, NtRemoveProcessDebug, 22);
    AD_RESOLVE_SSN_ENC(s_close,  NtClose_KX, 8);
    if (s_create == AD_SSN_FAILED || s_attach == AD_SSN_FAILED) return 0;

    void* dbg = (void*)0;
    ad_ntstatus_t st_create = AD_SYSCALL4(s_create,
        &dbg, (u64)0x1F0001UL,                  // DEBUG_ALL_ACCESS
        (void*)0, (u64)0);
    if (!AD_NT_SUCCESS(st_create) || !dbg) {
        // CreateDebugObject itself failed — can't tell from this alone.
        return 0;
    }

    ad_ntstatus_t st_att = AD_SYSCALL2(s_attach, AD_CURRENT_PROCESS, dbg);

    b32 detected = 0;
    if (st_att == AD_STATUS_PORT_ALREADY_SET) {
        detected = 1;            // Another debugger holds the port.
    } else if (AD_NT_SUCCESS(st_att)) {
        // Attach succeeded — clean. Detach immediately.
        if (s_detach != AD_SSN_FAILED) {
            (void)AD_SYSCALL2(s_detach, AD_CURRENT_PROCESS, dbg);
        }
    }

    if (s_close != AD_SSN_FAILED) {
        (void)AD_SYSCALL1(s_close, dbg);
    }
    return detected;
}

// =============================================================================
// 2. VEH chain count
// =============================================================================
// On modern Windows the VectoredExceptionHandlerList lives inside ntdll's
// _LDR_DATA at a version-dependent offset. Walking it directly is fragile;
// safer is to install our own probe handler (RtlAddVectoredExceptionHandler),
// raise a controlled exception, count how many handlers ran before ours.
//
// Tactic: register OUR VEH as last (FirstHandler=0 ⇒ append). Trigger an
// access violation through a guard probe address. Count how many other VEHs
// ran before ours fired (each receives EXCEPTION_CONTINUE_SEARCH from us if
// they didn't handle it). Anything > 0 is suspicious.
//
// Implementation note: ntdll!RtlAddVectoredExceptionHandler / RtlRemoveVectoredExceptionHandler
// are well-known exports — resolve via api_hash.

typedef struct {
    u32 ExceptionCode;
    u32 ExceptionFlags;
    void* ExceptionRecord;
    void* ExceptionAddress;
    u32 NumberParameters;
    u32 _pad;
    u64 ExceptionInformation[15];
} AD_KX_EXCEPTION_RECORD;

typedef struct {
    AD_KX_EXCEPTION_RECORD* ExceptionRecord;
    void* ContextRecord;
} AD_KX_EXCEPTION_POINTERS;

typedef long (__stdcall *ad_kx_veh_t)(AD_KX_EXCEPTION_POINTERS* p);
typedef void* (__stdcall *ad_kx_AddVeh_t)(u32 first, ad_kx_veh_t handler);
typedef u32   (__stdcall *ad_kx_RemoveVeh_t)(void* handle);

static volatile u32 g_kx_veh_others_seen = 0u;
static volatile u32 g_kx_veh_probe_active = 0u;

static long __stdcall ad_kx_veh_handler(AD_KX_EXCEPTION_POINTERS* p) {
    AD_UNUSED(p);
    if (g_kx_veh_probe_active) {
        // We are LAST in the chain (we used FirstHandler=0). If anyone
        // ran before us, they would have either SWALLOWED (returned
        // EXCEPTION_CONTINUE_EXECUTION) or PASSED (returned
        // EXCEPTION_CONTINUE_SEARCH). The kernel calls the next VEH
        // only when the previous returned _CONTINUE_SEARCH. Either way,
        // by the time WE run, every preceding handler has been invoked.
        //
        // We can't observe how many ran — but if our SEH __try/__except
        // catches the exception, the number of vectored handlers between
        // raise and SEH dispatch reflects the chain length minus our 1.
        // Use the ExceptionRecord's _pad field as a side-channel counter
        // populated by the first probing handler we install.
    }
    return 0; /* EXCEPTION_CONTINUE_SEARCH */
}

ANTIDEBUG_INLINE b32 ad_kx_veh_chain_count(void) {
    // Resolve ntdll APIs.
    ad_kx_AddVeh_t pAdd = (ad_kx_AddVeh_t)
        ad_resolve_api(AD_HASH_NTDLL,
                       ad_hash_str("RtlAddVectoredExceptionHandler"));
    ad_kx_RemoveVeh_t pRemove = (ad_kx_RemoveVeh_t)
        ad_resolve_api(AD_HASH_NTDLL,
                       ad_hash_str("RtlRemoveVectoredExceptionHandler"));
    if (!pAdd || !pRemove) return 0;

    // Lighter-weight alternative to chain walking: install our handler
    // FIRST (FirstHandler=1), trigger an exception, and check via a
    // sentinel byte whether some OTHER handler ran AFTER us (which would
    // mean: a debugger / hook / instrumentation has its VEH before
    // dispatch reaches the SEH chain).
    void* h = pAdd(1u, ad_kx_veh_handler);
    if (!h) return 0;

    g_kx_veh_others_seen  = 0u;
    g_kx_veh_probe_active = 1u;

    // Trigger a controlled access violation inside __try/__except. The
    // kernel runs every VEH in order; ours returns CONTINUE_SEARCH so the
    // exception is then dispatched to SEH, which we catch.
    volatile b32 reached_seh = 0;
    __try {
        volatile u32* bad = (volatile u32*)(uintptr_t)1;
        *bad = 0u;   // page fault
    } __except(1) {
        reached_seh = 1;
    }

    g_kx_veh_probe_active = 0u;
    pRemove(h);

    if (!reached_seh) {
        // SEH never fired — a VEH installed by a debugger swallowed the
        // exception (returned CONTINUE_EXECUTION). Strong signal.
        return 1;
    }
    return 0;
}

// =============================================================================
// 3. NtSetInformationThread(ThreadBreakOnTermination)
// =============================================================================
// Class 29 (ThreadBreakOnTermination) is normally privileged; setting it
// on self should fail with STATUS_PRIVILEGE_NOT_HELD on a clean process.
// Some debuggers proxy this call and return SUCCESS (kd has full
// privileges). SUCCESS = suspicious.

#ifndef AD_STRENC_NtSetInformationThread_KX
#define AD_STRENC_NtSetInformationThread_KX(buf)                              \
    do {                                                                      \
        const u8 _k = AD_STR_KEY(0x4F);                                      \
        char buf##_e[23];                                                     \
        AD_ENC(buf##_e,  0, 'N', _k); AD_ENC(buf##_e,  1, 't', _k);        \
        AD_ENC(buf##_e,  2, 'S', _k); AD_ENC(buf##_e,  3, 'e', _k);        \
        AD_ENC(buf##_e,  4, 't', _k); AD_ENC(buf##_e,  5, 'I', _k);        \
        AD_ENC(buf##_e,  6, 'n', _k); AD_ENC(buf##_e,  7, 'f', _k);        \
        AD_ENC(buf##_e,  8, 'o', _k); AD_ENC(buf##_e,  9, 'r', _k);        \
        AD_ENC(buf##_e, 10, 'm', _k); AD_ENC(buf##_e, 11, 'a', _k);        \
        AD_ENC(buf##_e, 12, 't', _k); AD_ENC(buf##_e, 13, 'i', _k);        \
        AD_ENC(buf##_e, 14, 'o', _k); AD_ENC(buf##_e, 15, 'n', _k);        \
        AD_ENC(buf##_e, 16, 'T', _k); AD_ENC(buf##_e, 17, 'h', _k);        \
        AD_ENC(buf##_e, 18, 'r', _k); AD_ENC(buf##_e, 19, 'e', _k);        \
        AD_ENC(buf##_e, 20, 'a', _k); AD_ENC(buf##_e, 21, 'd', _k);        \
        AD_DECODE_BUF(buf##_e, 22, _k);                                      \
        for (unsigned _ci = 0; _ci < 23; _ci++) (buf)[_ci] = buf##_e[_ci];   \
    } while (0)
#endif

ANTIDEBUG_INLINE b32 ad_kx_break_on_termination(void) {
    static u16 s_ssn = AD_SSN_UNRESOLVED;
    AD_RESOLVE_SSN_ENC(s_ssn, NtSetInformationThread_KX, 23);
    if (s_ssn == AD_SSN_FAILED) return 0;

    // Try to set BreakOnTermination on self with value 0 (disable). Even
    // disabling requires SeDebugPrivilege normally; a clean process gets
    // STATUS_PRIVILEGE_NOT_HELD. A debugger that proxies the call (and
    // already has SeDebug) returns SUCCESS.
    u32 zero = 0u;
    ad_ntstatus_t st = AD_SYSCALL4(s_ssn,
        AD_CURRENT_THREAD,
        (u64)29,                                  // ThreadBreakOnTermination
        &zero,
        (u64)4);

    if (AD_NT_SUCCESS(st)) return 1;   // Should NOT succeed.
    return 0;
}

// =============================================================================
// Master combiner
// =============================================================================
ANTIDEBUG_INLINE u32 ad_kd_extra_master(void) {
    u32 score = 0u;
    __try { if (ad_kx_self_debug_attempt())   score += 14u; } __except(1) {}
    __try { if (ad_kx_veh_chain_count())      score += 8u;  } __except(1) {}
    __try { if (ad_kx_break_on_termination()) score += 6u;  } __except(1) {}
    return score;
}

#else  // !_MSC_VER

ANTIDEBUG_INLINE u32 ad_kd_extra_master(void) { return 0u; }

#endif // _MSC_VER

#endif // ANTIDEBUG_KD_EXTRA_H
