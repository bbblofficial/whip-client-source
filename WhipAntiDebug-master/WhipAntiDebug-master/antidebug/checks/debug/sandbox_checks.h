// ===== file: antidebug/checks/debug/sandbox_checks.h =====
//
// Sandbox & debug-environment detection checks.
//
//   1. ad_job_object_check()           — detect if process runs inside a Job Object
//   2. ad_unhandled_exception_filter_check() — detect SetUnhandledExceptionFilter hooks
//   3. ad_debug_filter_state_check()   — probe kernel debug filter via NtSetDebugFilterState
//   4. ad_sandbox_master()             — composite scorer (weighted sum)
//
// Job Objects are used by sandboxes (Cuckoo, ANY.RUN, Windows Sandbox),
// analysis tools, and some debuggers to contain processes. A normal
// user-launched process is typically NOT inside a job (pre-Win8) or is
// in a trivial compatibility job (Win8+). We check via IsProcessInJob.
//
// SetUnhandledExceptionFilter is commonly hooked by debuggers and
// anti-anti-debug plugins to suppress crash dialogs. We detect this by
// setting a known filter address and immediately reading it back.
//
// NtSetDebugFilterState manipulates kernel debug output filters. On a
// system with an active kernel debugger, the call succeeds (STATUS_SUCCESS).
// On a normal system, it returns STATUS_ACCESS_DENIED or similar.
//
#ifndef ANTIDEBUG_SANDBOX_CHECKS_H
#define ANTIDEBUG_SANDBOX_CHECKS_H

#include "../../core/types.h"
#include "../../core/macros.h"
#include "../../core/api_hash.h"
#include "../../core/syscall_bridge.h"
#include "../../core/string_encrypt.h"

#if defined(_MSC_VER)

// =========================================================================
// 1. JOB OBJECT CHECK — IsProcessInJob from kernel32.dll
// =========================================================================
//
// IsProcessInJob(HANDLE hProcess, HANDLE hJob, PBOOL Result)
// hProcess = -1 (NtCurrentProcess), hJob = NULL (any job), Result = &flag
// If Result is TRUE after the call, we are inside a job object.
//

ANTIDEBUG_INLINE b32 ad_job_object_check(void) {
    // Build "IsProcessInJob" char-by-char on stack (14 chars)
    char fn_name[15];
    fn_name[0]  = 'I'; fn_name[1]  = 's'; fn_name[2]  = 'P';
    fn_name[3]  = 'r'; fn_name[4]  = 'o'; fn_name[5]  = 'c';
    fn_name[6]  = 'e'; fn_name[7]  = 's'; fn_name[8]  = 's';
    fn_name[9]  = 'I'; fn_name[10] = 'n'; fn_name[11] = 'J';
    fn_name[12] = 'o'; fn_name[13] = 'b'; fn_name[14] = '\0';
    AD_BARRIER();

    // Resolve via PEB walk + export hash
    typedef int (__stdcall *fn_IsProcessInJob)(void*, void*, int*);
    fn_IsProcessInJob pIsProcessInJob = (fn_IsProcessInJob)
        ad_resolve_api(AD_HASH_KERNEL32, AD_HASH(fn_name));

    AD_WIPE_STR(fn_name, 15);
    if (!pIsProcessInJob) return 0;

    int in_job = 0;
    int ok = pIsProcessInJob(AD_CURRENT_PROCESS, (void*)0, &in_job);
    AD_BARRIER();

    if (!ok) return 0;

    return (b32)(in_job != 0);
}

// =========================================================================
// 2. UNHANDLED EXCEPTION FILTER HOOK CHECK
// =========================================================================
//
// SetUnhandledExceptionFilter sets the top-level exception filter. We set
// it to a known dummy address, then immediately read it back by calling
// SetUnhandledExceptionFilter(NULL) — which returns the previous filter.
//
// If the returned pointer does not match what we set, something intercepted
// the call (common debugger / anti-anti-debug technique to eat crash
// exceptions and prevent detection via unhandled exception tricks).
//

ANTIDEBUG_INLINE b32 ad_unhandled_exception_filter_check(void) {
    // Build "SetUnhandledExceptionFilter" char-by-char on stack (27 chars)
    char fn_name[28];
    fn_name[0]  = 'S'; fn_name[1]  = 'e'; fn_name[2]  = 't';
    fn_name[3]  = 'U'; fn_name[4]  = 'n'; fn_name[5]  = 'h';
    fn_name[6]  = 'a'; fn_name[7]  = 'n'; fn_name[8]  = 'd';
    fn_name[9]  = 'l'; fn_name[10] = 'e'; fn_name[11] = 'd';
    fn_name[12] = 'E'; fn_name[13] = 'x'; fn_name[14] = 'c';
    fn_name[15] = 'e'; fn_name[16] = 'p'; fn_name[17] = 't';
    fn_name[18] = 'i'; fn_name[19] = 'o'; fn_name[20] = 'n';
    fn_name[21] = 'F'; fn_name[22] = 'i'; fn_name[23] = 'l';
    fn_name[24] = 't'; fn_name[25] = 'e'; fn_name[26] = 'r';
    fn_name[27] = '\0';
    AD_BARRIER();

    // SetUnhandledExceptionFilter takes a pointer and returns the previous one
    typedef void* (__stdcall *fn_SetUEF)(void*);
    fn_SetUEF pSetUEF = (fn_SetUEF)
        ad_resolve_api(AD_HASH_KERNEL32, AD_HASH(fn_name));

    AD_WIPE_STR(fn_name, 28);
    if (!pSetUEF) return 0;

    // Set current filter to NULL, read back the OLD one.
    // Then set our own dummy, read back — should get NULL.
    // Finally restore. A debugger that intercepts SetUEF will
    // return the wrong previous pointer.
    void* original = pSetUEF((void*)0);  // clear + get original
    AD_BARRIER();

    // Now set original back and read — should return NULL (what we just set)
    void* readback = pSetUEF(original);
    AD_BARRIER();

    // Restore
    pSetUEF(original);

    // readback should be NULL (the filter we set in the first call).
    // If something intercepted SetUEF, readback will be non-NULL.
    return (b32)(readback != (void*)0);
}

// =========================================================================
// 3. DEBUG FILTER STATE CHECK — NtSetDebugFilterState + NtSystemDebugControl
// =========================================================================
//
// NtSetDebugFilterState(ComponentId, Level, State):
//   - On a system with an active kernel debugger, returns STATUS_SUCCESS (0)
//   - On a normal system, returns STATUS_ACCESS_DENIED or similar error
//
// NtSystemDebugControl(SysDbgQueryModuleInformation = 0, ...):
//   - As a secondary probe, attempt a debug control query
//   - STATUS_SUCCESS or STATUS_DEBUGGER_INACTIVE indicates kernel debug state
//

// Encrypted string: "NtSetDebugFilterState" (21 chars)
#ifndef AD_STRENC_NtSetDebugFilterState
#define AD_STRENC_NtSetDebugFilterState(buf)                                  \
    do {                                                                     \
        const u8 _k = AD_STR_KEY(0x4B);                                     \
        char buf##_e[22];                                                    \
        AD_ENC(buf##_e,  0, 'N', _k); AD_ENC(buf##_e,  1, 't', _k);       \
        AD_ENC(buf##_e,  2, 'S', _k); AD_ENC(buf##_e,  3, 'e', _k);       \
        AD_ENC(buf##_e,  4, 't', _k); AD_ENC(buf##_e,  5, 'D', _k);       \
        AD_ENC(buf##_e,  6, 'e', _k); AD_ENC(buf##_e,  7, 'b', _k);       \
        AD_ENC(buf##_e,  8, 'u', _k); AD_ENC(buf##_e,  9, 'g', _k);       \
        AD_ENC(buf##_e, 10, 'F', _k); AD_ENC(buf##_e, 11, 'i', _k);       \
        AD_ENC(buf##_e, 12, 'l', _k); AD_ENC(buf##_e, 13, 't', _k);       \
        AD_ENC(buf##_e, 14, 'e', _k); AD_ENC(buf##_e, 15, 'r', _k);       \
        AD_ENC(buf##_e, 16, 'S', _k); AD_ENC(buf##_e, 17, 't', _k);       \
        AD_ENC(buf##_e, 18, 'a', _k); AD_ENC(buf##_e, 19, 't', _k);       \
        AD_ENC(buf##_e, 20, 'e', _k);                                       \
        AD_DECODE_BUF(buf##_e, 21, _k);                                     \
        for (unsigned _ci = 0; _ci < 22; _ci++) (buf)[_ci] = buf##_e[_ci]; \
    } while (0)
#endif

// Re-use NtSystemDebugControl from raise_hard_error.h if already defined
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
        for (unsigned _ci = 0; _ci < 21; _ci++) (buf)[_ci] = buf##_e[_ci]; \
    } while (0)
#endif

#ifndef AD_STATUS_ACCESS_DENIED_DEF
#define AD_STATUS_ACCESS_DENIED_DEF
#define AD_STATUS_ACCESS_DENIED   ((ad_ntstatus_t)0xC0000022L)
#endif

#ifndef AD_STATUS_DEBUGGER_INACTIVE_DEF
#define AD_STATUS_DEBUGGER_INACTIVE_DEF
#define AD_STATUS_DEBUGGER_INACTIVE ((ad_ntstatus_t)0xC0000354L)
#endif

ANTIDEBUG_INLINE b32 ad_debug_filter_state_check(void) {
    b32 detected = 0;

    // ── Probe 1: NtSetDebugFilterState(0, 0, TRUE) ─────────────────────
    // ComponentId = 0, Level = 0, State = TRUE
    // STATUS_SUCCESS → kernel debugger interface is active
    {
        static u16 s_ssn_sdfs = AD_SSN_UNRESOLVED;
        AD_RESOLVE_SSN_ENC(s_ssn_sdfs, NtSetDebugFilterState, 22);

        if (s_ssn_sdfs != AD_SSN_FAILED) {
            ad_ntstatus_t st = AD_SYSCALL3(s_ssn_sdfs,
                (u64)0,    // ComponentId
                (u64)0,    // Level
                (u64)1);   // State = TRUE
            AD_BARRIER();

            // STATUS_SUCCESS means the kernel debugger accepted the command
            if (st == AD_STATUS_SUCCESS) {
                detected = 1;
            }
        }
    }

    // ── Probe 2: NtSystemDebugControl (SysDbgQueryModuleInformation = 0) ─
    // Secondary signal: if NtSystemDebugControl succeeds or returns
    // STATUS_DEBUGGER_INACTIVE, the kernel debug subsystem is present.
    // STATUS_ACCESS_DENIED is normal (no privilege). Any other success
    // or debugger-specific status is suspicious.
    if (!detected) {
        static u16 s_ssn_sdc = AD_SSN_UNRESOLVED;
        AD_RESOLVE_SSN_ENC(s_ssn_sdc, NtSystemDebugControl, 21);

        if (s_ssn_sdc != AD_SSN_FAILED) {
            // SysDbgQueryModuleInformation = 0
            // Pass NULL buffers with zero length — we only care about status
            ad_ntstatus_t st = AD_SYSCALL6(s_ssn_sdc,
                (u64)0,       // Command: SysDbgQueryModuleInformation
                (u64)0,       // InputBuffer
                (u64)0,       // InputBufferLength
                (u64)0,       // OutputBuffer
                (u64)0,       // OutputBufferLength
                (u64)0);      // ReturnLength
            AD_BARRIER();

            // STATUS_SUCCESS means the debug control interface is live
            // (kernel debugger attached or debug-enabled boot)
            if (st == AD_STATUS_SUCCESS) {
                detected = 1;
            }
            // STATUS_DEBUGGER_INACTIVE is the expected "no kd" response;
            // STATUS_ACCESS_DENIED is normal unprivileged — both are clean.
        }
    }

    return detected;
}

// =========================================================================
// 4. SANDBOX MASTER — composite scorer
// =========================================================================
//
// Weights:
//   job_object_check           : 5  (common in sandboxes, but Win8+ uses jobs normally)
//   uef_hook_check             : 6  (strong indicator of debugger interception)
//   debug_filter_state_check   : 7  (kernel debugger presence is high confidence)
//

ANTIDEBUG_INLINE u32 ad_sandbox_master(void) {
    u32 score = 0;

#if AD_ENABLE_JOB_CHECK
    score += ad_job_object_check()                    ?  5u : 0u;
#endif

#if AD_ENABLE_UEF_CHECK
    score += ad_unhandled_exception_filter_check()    ?  6u : 0u;
#endif

#if AD_ENABLE_DEBUG_FILTER
    score += ad_debug_filter_state_check()            ?  7u : 0u;
#endif

    return score;
}

#else  // Non-MSVC stubs

ANTIDEBUG_INLINE b32 ad_job_object_check(void) { return 0; }
ANTIDEBUG_INLINE b32 ad_unhandled_exception_filter_check(void) { return 0; }
ANTIDEBUG_INLINE b32 ad_debug_filter_state_check(void) { return 0; }
ANTIDEBUG_INLINE u32 ad_sandbox_master(void) { return 0; }

#endif // _MSC_VER

#endif // ANTIDEBUG_SANDBOX_CHECKS_H
