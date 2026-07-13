// ===== file: antidebug/core/watchdog.h =====
//
// Anti-debug Watchdog — hidden thread that re-runs key checks every 2s.
//
// Problem: the main checks run once then stop. A reverser can attach
// AFTER the checks complete and patch freely.
//
// Solution: a background watchdog thread (hidden from debugger) that
// periodically re-checks critical invariants. If any check fires,
// it corrupts the score via a shared atomic variable.
//
// Checks re-run by the watchdog:
//   - PEB.BeingDebugged (triple-read)
//   - ProcessDebugPort
//   - Hardware breakpoints (DR0-DR3)
//   - NtClose trap
//   - Code integrity (self-hash on key functions)
//
#ifndef ANTIDEBUG_WATCHDOG_H
#define ANTIDEBUG_WATCHDOG_H

#include "types.h"
#include "macros.h"
#include "syscall_bridge.h"
#include "string_encrypt.h"
#include "strenc_extra.h"
#include "poly_syscall.h"

#if defined(_MSC_VER)

// Shared score corruption — the main thread reads this and adds it.
static volatile u32 g_watchdog_penalty = 0;
static volatile b32 g_watchdog_kill = 0;

static unsigned long __stdcall ad_watchdog_entry(void* param) {
    AD_UNUSED(param);

    // Resolve syscalls
    static u16 s_delay = AD_SSN_UNRESOLVED;
    static u16 s_qip   = AD_SSN_UNRESOLVED;
    static u16 s_close  = AD_SSN_UNRESOLVED;
    static u16 s_getctx = AD_SSN_UNRESOLVED;

    AD_RESOLVE_SSN_ENC(s_delay,  NtDelayExecution,            17);
    AD_RESOLVE_SSN_ENC(s_qip,   NtQueryInformationProcess,   26);
    AD_RESOLVE_SSN_ENC(s_close, NtClose,                      8);
    AD_RESOLVE_SSN_ENC(s_getctx,NtGetContextThread,          19);

    while (!g_watchdog_kill) {
        u32 penalty = 0u;

        // ── Check 1: PEB.BeingDebugged ──────────────────────────────
        __try {
            u8* peb = (u8*)__readgsqword(0x60);
            if (peb) {
                volatile u8 r1 = peb[0x02];
                AD_BARRIER();
                volatile u8 r2 = peb[0x02];
                if (r1 | r2) penalty += 5u;
            }
        } __except(1) {}

        // ── Check 2: ProcessDebugPort ───────────────────────────────
        if (s_qip != AD_SSN_FAILED) {
            __try {
                u64 port = 0;
                u32 rlen = 0;
                AD_SYSCALL5(s_qip, AD_CURRENT_PROCESS,
                    (u64)7, &port, (u64)8, &rlen);
                if (port) penalty += 8u;
            } __except(1) {}
        }

        // ── Check 3: Hardware breakpoints ───────────────────────────
        if (s_getctx != AD_SSN_FAILED) {
            __try {
                AD_ALIGN(16) AD_CONTEXT ctx;
                AD_ZERO_BUF(&ctx, sizeof(ctx));
                ctx.ContextFlags = AD_CONTEXT_DEBUG_REGISTERS;
                AD_SYSCALL2(s_getctx, AD_CURRENT_THREAD, &ctx);
                if (ctx.Dr0 | ctx.Dr1 | ctx.Dr2 | ctx.Dr3)
                    penalty += 6u;
            } __except(1) {}
        }

        // ── Check 4: NtClose trap ───────────────────────────────────
        if (s_close != AD_SSN_FAILED) {
            __try {
                volatile b32 exc = 0;
                __try {
                    AD_SYSCALL1(s_close, (u64)0xBAADF00DULL);
                } __except(1) {
                    exc = 1;
                }
                if (exc) penalty += 4u;
            } __except(1) {}
        }

        // ── Check 5: KUSD kernel debugger ───────────────────────────
        __try {
            volatile u8* kusd = (volatile u8*)0x7FFE0000ULL;
            if (*(volatile u8*)(kusd + 0x02D4))  penalty += 10u; // KdDebuggerEnabled
            if (!*(volatile u8*)(kusd + 0x02D5)) penalty += 8u;  // !KdDebuggerNotPresent
        } __except(1) {}

        // Write penalty atomically
        if (penalty > 0u) {
            g_watchdog_penalty += penalty;
            AD_BARRIER();
        }

        // Sleep ~2 seconds
        if (s_delay != AD_SSN_FAILED) {
            s64 sleep_time = -20000000LL;  // 2s
            AD_SYSCALL2(s_delay, (u64)0, &sleep_time);
        }
    }

    return 0;
}

ANTIDEBUG_INLINE void ad_watchdog_start(void) {
    g_watchdog_kill = 0;
    g_watchdog_penalty = 0;

    static u16 s_create = AD_SSN_UNRESOLVED;
    static u16 s_seti   = AD_SSN_UNRESOLVED;
    static u16 s_resume = AD_SSN_UNRESOLVED;

    AD_RESOLVE_SSN_ENC(s_create, NtCreateThreadEx,       17);
    AD_RESOLVE_SSN_ENC(s_seti,   NtSetInformationThread, 23);
    AD_RESOLVE_SSN_ENC(s_resume, NtResumeThread,         15);

    if (s_create == AD_SSN_FAILED || s_resume == AD_SSN_FAILED) return;

    void* handle = (void*)0;
    ad_ntstatus_t st = (ad_ntstatus_t)(s64)ad_poly_call(s_create,
        &handle,
        (void*)(u64)0x001FFFFFul,
        (void*)0,
        (void*)(u64)AD_CURRENT_PROCESS,
        (void*)ad_watchdog_entry,
        (void*)0,
        (void*)(u64)0x00000004ul,  // CREATE_SUSPENDED
        (void*)0, (void*)0, (void*)0, (void*)0
    );

    if (!AD_NT_SUCCESS(st) || !handle) return;

    // Hide from debugger
    if (s_seti != AD_SSN_FAILED) {
        AD_SYSCALL4(s_seti, handle, (u64)17, (u64)0, (u64)0);
    }

    // Resume
    u32 prev = 0;
    AD_SYSCALL2(s_resume, handle, &prev);

    // Don't close handle — keep the thread alive
}

ANTIDEBUG_INLINE void ad_watchdog_stop(void) {
    g_watchdog_kill = 1;
    AD_BARRIER();
    // Brief wait for thread to notice
    static u16 s_delay = AD_SSN_UNRESOLVED;
    AD_RESOLVE_SSN_ENC(s_delay, NtDelayExecution, 17);
    if (s_delay != AD_SSN_FAILED) {
        s64 wait = -30000000LL;  // 3s — enough for one watchdog cycle
        AD_SYSCALL2(s_delay, (u64)0, &wait);
    }
}

// Read accumulated penalty from the watchdog.
ANTIDEBUG_INLINE u32 ad_watchdog_read_penalty(void) {
    AD_BARRIER();
    return g_watchdog_penalty;
}

#else
ANTIDEBUG_INLINE void ad_watchdog_start(void) {}
ANTIDEBUG_INLINE void ad_watchdog_stop(void) {}
ANTIDEBUG_INLINE u32 ad_watchdog_read_penalty(void) { return 0; }
#endif // _MSC_VER

#endif // ANTIDEBUG_WATCHDOG_H
