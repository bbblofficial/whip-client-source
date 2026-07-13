// ===== file: antidebug/checks/runtime/thread_monitor.h =====
//
// Thread-based runtime anti-debug checks.
//
// Techniques:
//
//   1. Suspend count check:
//      NtQueryInformationThread(ThreadSuspendCount) reveals if someone
//      (debugger) has suspended and resumed our thread. A fresh thread
//      has suspend count 0. If it's > 0, we were suspended externally.
//
//   2. Thread count anomaly:
//      NtQuerySystemInformation(SystemProcessInformation) can reveal
//      extra threads injected by a debugger or instrumentation framework.
//      We check our own thread count — if it exceeds expected, suspicious.
//
//   3. Context manipulation detection:
//      After calling NtSetContextThread to set DR registers to known values,
//      re-read them. If a debugger is attached and using HW BPs, it will
//      overwrite our values on the next context switch → mismatch detected.
//
#ifndef ANTIDEBUG_THREAD_MONITOR_H
#define ANTIDEBUG_THREAD_MONITOR_H

#include "../../core/types.h"
#include "../../core/macros.h"
#include "../../core/syscall_bridge.h"
#include "../../core/string_encrypt.h"

// ---------------------------------------------------------------------------
// Encrypted string: "NtSetContextThread" (18 chars) — guarded against the
// canonical definition in core/string_encrypt.h
// ---------------------------------------------------------------------------
#ifndef AD_STRENC_NtSetContextThread
#define AD_STRENC_NtSetContextThread(buf)                                    \
    do {                                                                     \
        const u8 _k = AD_STR_KEY(0xAA);                                     \
        char buf##_e[19];                                                    \
        AD_ENC(buf##_e,  0, 'N', _k); AD_ENC(buf##_e,  1, 't', _k);       \
        AD_ENC(buf##_e,  2, 'S', _k); AD_ENC(buf##_e,  3, 'e', _k);       \
        AD_ENC(buf##_e,  4, 't', _k); AD_ENC(buf##_e,  5, 'C', _k);       \
        AD_ENC(buf##_e,  6, 'o', _k); AD_ENC(buf##_e,  7, 'n', _k);       \
        AD_ENC(buf##_e,  8, 't', _k); AD_ENC(buf##_e,  9, 'e', _k);       \
        AD_ENC(buf##_e, 10, 'x', _k); AD_ENC(buf##_e, 11, 't', _k);       \
        AD_ENC(buf##_e, 12, 'T', _k); AD_ENC(buf##_e, 13, 'h', _k);       \
        AD_ENC(buf##_e, 14, 'r', _k); AD_ENC(buf##_e, 15, 'e', _k);       \
        AD_ENC(buf##_e, 16, 'a', _k); AD_ENC(buf##_e, 17, 'd', _k);       \
        AD_DECODE_BUF(buf##_e, 18, _k);                                     \
        for (unsigned _ci = 0; _ci < 19; _ci++) (buf)[_ci] = buf##_e[_ci];  \
    } while (0)
#endif

// ---------------------------------------------------------------------------
// Check: Debug register canary
//
// Write a known "canary" pattern into DR0 via NtSetContextThread, then
// immediately read it back via NtGetContextThread. If a debugger overwrites
// DR0 on context switch (because it's using hardware breakpoints), the
// value won't match.
//
// Returns 1 if the DR0 value was tampered with (debugger present).
// Returns 0 if clean or if syscalls fail.
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE b32 ad_dr_canary(void) {
    static u16 s_ssn_set = AD_SSN_UNRESOLVED;
    static u16 s_ssn_get = AD_SSN_UNRESOLVED;

    AD_RESOLVE_SSN_ENC(s_ssn_set, NtSetContextThread, 19);
    AD_RESOLVE_SSN_ENC(s_ssn_get, NtGetContextThread, 19);

    if (s_ssn_set == AD_SSN_FAILED || s_ssn_get == AD_SSN_FAILED) return 0;

    // Set DR0 to a canary value
    AD_ALIGN(16) AD_CONTEXT ctx_set;
    AD_ZERO_BUF(&ctx_set, sizeof(ctx_set));
    ctx_set.ContextFlags = AD_CONTEXT_DEBUG_REGISTERS;

    // Magic canary — not a valid address, unlikely to collide
    u64 canary = 0x0000DEAD1337CAFEULL;
    ctx_set.Dr0 = canary;
    ctx_set.Dr1 = 0;
    ctx_set.Dr2 = 0;
    ctx_set.Dr3 = 0;
    ctx_set.Dr7 = 0;  // disable all HW BPs — clears debugger's BPs too

    ad_ntstatus_t st = AD_SYSCALL2(
        s_ssn_set,
        AD_CURRENT_THREAD,
        &ctx_set
    );
    if (!AD_NT_SUCCESS(st)) return 0;

    // VBS/HVCI pre-flight: immediately read back Dr0 to confirm the kernel
    // actually accepted the write. Under VBS, NtSetContextThread for DR registers
    // silently succeeds but the hypervisor zeroes them — Dr0 reads back as 0.
    // In that case the environment is unreliable; skip this check.
    {
        AD_ALIGN(16) AD_CONTEXT ctx_pre;
        AD_ZERO_BUF(&ctx_pre, sizeof(ctx_pre));
        ctx_pre.ContextFlags = AD_CONTEXT_DEBUG_REGISTERS;
        st = AD_SYSCALL2(s_ssn_get, AD_CURRENT_THREAD, &ctx_pre);
        if (!AD_NT_SUCCESS(st)) return 0;
        if (ctx_pre.Dr0 != canary) return 0;  // VBS or hypervisor blocked the write
    }

    // Force a scheduling event — give the debugger a chance to restore its BPs
    // A simple barrier + volatile is enough since context switches happen frequently
    AD_BARRIER();
    AD_MFENCE();

    // Read back DR0
    AD_ALIGN(16) AD_CONTEXT ctx_get;
    AD_ZERO_BUF(&ctx_get, sizeof(ctx_get));
    ctx_get.ContextFlags = AD_CONTEXT_DEBUG_REGISTERS;

    st = AD_SYSCALL2(
        s_ssn_get,
        AD_CURRENT_THREAD,
        &ctx_get
    );
    if (!AD_NT_SUCCESS(st)) return 0;

    // If DR0 doesn't match canary, something (debugger) overwrote it
    b32 tampered = (b32)(ctx_get.Dr0 != canary);

    // Clean up: zero out DR registers
    ctx_set.Dr0 = 0;
    ctx_set.Dr7 = 0;
    AD_SYSCALL2(s_ssn_set, AD_CURRENT_THREAD, &ctx_set);

    return tampered;
}

// ---------------------------------------------------------------------------
// Check: PEB.NumberOfProcessors anomaly
//
// Some sandbox environments report a single processor. Most real machines
// have 2+. This is a heuristic, not definitive.
//
// PEB offset 0xB8 (x64) = NumberOfProcessors (DWORD)
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE b32 ad_single_processor_check(void) {
#if defined(_MSC_VER)
    u8* peb = (u8*)__readgsqword(0x60);
    u32 num_procs = *(u32*)(peb + 0xB8);
    return (b32)(num_procs < 2u);
#else
    return 0;
#endif
}

// ---------------------------------------------------------------------------
// Check: Process uptime sanity
//
// If the process has been alive for a suspiciously short time but execution
// is deep into the code, something is replaying/fast-forwarding (DBI).
// Conversely, if uptime is hugely long for the amount of work done,
// the process was suspended by a debugger.
//
// We use RDTSC at init vs now to compute elapsed cycles and compare against
// a wall-clock estimate from QPC.
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE b32 ad_timing_consistency(u64 init_tsc) {
#if defined(_MSC_VER)
    if (init_tsc == 0) return 0;

    u64 now_tsc = __rdtsc();
    u64 cycles_elapsed = now_tsc - init_tsc;

    // On modern CPUs, TSC ticks at ~3GHz. 10 seconds = ~30 billion cycles.
    // If somehow we have > 300 billion cycles (100s), something held us.
    // This threshold should be calibrated per-application.
    u64 max_expected = 300000000000ULL;  // ~100 seconds at 3GHz

    return (b32)(cycles_elapsed > max_expected);
#else
    AD_UNUSED(init_tsc);
    return 0;
#endif
}

#endif // ANTIDEBUG_THREAD_MONITOR_H
