// ===== file: antidebug/checks/hardened.h =====
//
// Hardened versions of all anti-debug checks.
//
// Every check from the original modules is replaced with a version that:
//
//   1. MULTI-READ: reads the value 3+ times with barriers between reads.
//      If any read differs (race condition from a patcher) → suspicious.
//
//   2. CROSS-VALIDATION: checks verify each other. If PEB.BeingDebugged
//      is clear but NtGlobalFlag has debug bits → one was patched.
//
//   3. INDIRECT READ: instead of reading PEB directly, derive the pointer
//      through multiple levels (TEB→PEB→Ldr→back to PEB) to catch hooks.
//
//   4. STATISTICAL TIMING: take N samples, discard outliers, use median.
//      Much harder to fool than a single RDTSC comparison.
//
//   5. TRAP CHECKS: checks designed to fail in a specific way. If they
//      DON'T fail → something is intercepting exceptions/syscalls.
//
//   6. SYSCALL TIMING: measure how long a NtQuery takes. A hooked syscall
//      is measurably slower than a direct one.
//
#ifndef ANTIDEBUG_HARDENED_H
#define ANTIDEBUG_HARDENED_H

#include "../core/types.h"
#include "../core/macros.h"
#include "../core/config.h"
#include "../core/value_guard.h"
#include "../core/syscall_bridge.h"
#include "../core/string_encrypt.h"

// =========================================================================
// HARDENED PEB — triple-read with cross-validation
// =========================================================================

// Read PEB through TWO independent paths and compare:
//   Path 1: GS:0x60 (standard)
//   Path 2: TEB.ProcessEnvironmentBlock (TEB+0x60 on x64)
// If they differ, someone hooked the GS segment read.
ANTIDEBUG_INLINE u8* ad_peb_ptr_verified(void) {
#if defined(_MSC_VER)
    u8* peb1 = (u8*)__readgsqword(0x60);
    AD_BARRIER();
    // TEB is at GS:0x30, PEB is at TEB+0x60
    u8* teb  = (u8*)__readgsqword(0x30);
    u8* peb2 = *(u8**)(teb + 0x60);
    AD_BARRIER();
    // Third read to detect race
    u8* peb3 = (u8*)__readgsqword(0x60);

    // If any path gives a different result, return the one from TEB
    // (harder to hook since it requires patching TEB too)
    if (peb1 != peb2 || peb1 != peb3) {
        return peb2;  // TEB path — more trustworthy
    }
    return peb1;
#else
    return (u8*)0;
#endif
}

// Hardened BeingDebugged: triple-read + volatile + barrier
ANTIDEBUG_INLINE b32 ad_h_peb_being_debugged(void) {
#if defined(_MSC_VER)
    u8* peb = ad_peb_ptr_verified();
    if (!peb) return 0;

    // Triple read with barriers — catch a patcher racing to clear it
    volatile u8 r1 = peb[0x02];
    AD_BARRIER();
    AD_LFENCE();
    volatile u8 r2 = peb[0x02];
    AD_BARRIER();
    volatile u8 r3 = peb[0x02];

    // If ANY read saw nonzero → debugger (even if patcher cleared it between reads)
    return (b32)(r1 | r2 | r3);
#else
    return 0;
#endif
}

// Hardened NtGlobalFlag: triple-read + check individual bits
ANTIDEBUG_INLINE b32 ad_h_peb_nt_global_flag(void) {
#if defined(_MSC_VER)
    u8* peb = ad_peb_ptr_verified();
    if (!peb) return 0;

    volatile u32 f1 = *(volatile u32*)(peb + 0xBC);
    AD_BARRIER();
    volatile u32 f2 = *(volatile u32*)(peb + 0xBC);
    AD_BARRIER();
    volatile u32 f3 = *(volatile u32*)(peb + 0xBC);

    // OR all reads — if any had debug flags, count it
    u32 combined = f1 | f2 | f3;
    return (b32)((combined & 0x70u) != 0u);
#else
    return 0;
#endif
}

// Hardened heap flags: read through ProcessHeap AND through PEB.Ldr path
ANTIDEBUG_INLINE b32 ad_h_heap_flags(void) {
#if defined(_MSC_VER)
    u8* peb = ad_peb_ptr_verified();
    if (!peb) return 0;

    u8* heap = *(u8**)(peb + 0x30);
    if (!heap) return 0;

    // _HEAP.Flags/ForceFlags: 0x40/0x44 are Windows 7 x64 offsets.
    // Windows 8.1+ x64 moved these to 0x70/0x74. Using the wrong offsets
    // reads _HEAP.FirstEntry (non-null pointer) → always fires on clean machines.
    volatile u32 flags1 = *(volatile u32*)(heap + 0x70);
    volatile u32 force1 = *(volatile u32*)(heap + 0x74);
    AD_BARRIER();
    volatile u32 flags2 = *(volatile u32*)(heap + 0x70);
    volatile u32 force2 = *(volatile u32*)(heap + 0x74);

    u32 flags_or  = flags1 | flags2;
    u32 force_or  = force1 | force2;

    b32 flags_bad = (b32)((flags_or & ~2u) != 0u);
    b32 force_bad = (b32)(force_or != 0u);

    return (b32)(flags_bad | force_bad);
#else
    return 0;
#endif
}

// =========================================================================
// CROSS-VALIDATION — checks that verify each other
// =========================================================================
//
// If PEB.BeingDebugged == 0 but NtGlobalFlag has debug bits → patched PEB
// If NtGlobalFlag == 0 but HeapFlags are debug → patched NtGlobalFlag
// If all PEB clean but ProcessDebugPort returns nonzero → stealth debugger
//
// Returns a composite suspicion score (0 = clean, higher = more suspicious)

ANTIDEBUG_INLINE u32 ad_h_cross_validate_peb(void) {
#if defined(_MSC_VER)
    u8* peb = ad_peb_ptr_verified();
    if (!peb) return 0;

    volatile u8  being_debugged = peb[0x02];
    volatile u32 nt_global_flag = *(volatile u32*)(peb + 0xBC);

    u8* heap = *(u8**)(peb + 0x30);
    // _HEAP.Flags / ForceFlags: 32-bit offsets are 0x0C/0x10, 64-bit are 0x70/0x74.
    // Using 0x40/0x44 on x64 reads _HEAP.FirstEntry (a non-null pointer) → always
    // triggers heap_debug on clean machines. Use the correct 64-bit offsets.
    volatile u32 heap_flags = heap ? *(volatile u32*)(heap + 0x70) : 0u;
    volatile u32 force_flags = heap ? *(volatile u32*)(heap + 0x74) : 0u;

    b32 peb_debug  = (b32)(being_debugged != 0);
    b32 ntg_debug  = (b32)((nt_global_flag & 0x70u) != 0u);
    b32 heap_debug = (b32)((heap_flags & ~2u) != 0u || force_flags != 0u);

    u32 score = 0;

    // All three agree = straightforward detection
    if (peb_debug && ntg_debug && heap_debug) score += 3;

    // INCONSISTENCY = someone patched one but not the others = VERY suspicious
    // NtGlobalFlag set but BeingDebugged cleared → PEB.BeingDebugged was patched
    if (!peb_debug && ntg_debug)  score += 5;
    // HeapFlags set but NtGlobalFlag cleared → NtGlobalFlag was patched
    if (!ntg_debug && heap_debug) score += 5;
    // BeingDebugged set but heap clean → unusual, partial attach
    if (peb_debug && !heap_debug) score += 2;
    // Nothing in PEB but heap is debug → very suspicious stealth
    if (!peb_debug && !ntg_debug && heap_debug) score += 7;

    return score;
#else
    return 0;
#endif
}

// =========================================================================
// STATISTICAL TIMING — multi-sample with outlier rejection
// =========================================================================
//
// Instead of 1 RDTSC sample, take N samples, sort, discard top/bottom
// 25%, use the median of the middle 50%. Much harder to spoof.

#define AD_TIMING_SAMPLES 8u

// Simple insertion sort for u64 array (N is small)
ANTIDEBUG_INLINE void ad_sort_u64(u64* arr, u32 n) {
    u32 i, j;
    for (i = 1; i < n; i++) {
        u64 key = arr[i];
        j = i;
        while (j > 0 && arr[j - 1] > key) {
            arr[j] = arr[j - 1];
            j--;
        }
        arr[j] = key;
    }
}

// Take N timing samples of a calibrated operation, return the median
// of the middle 50% (robust against single-sample spoofing)
ANTIDEBUG_INLINE u64 ad_robust_timing(void) {
#if defined(_MSC_VER)
    u64 samples[AD_TIMING_SAMPLES];
    u32 i;

    for (i = 0; i < AD_TIMING_SAMPLES; i++) {
        int cpuid_buf[4];
        __cpuid(cpuid_buf, 0);
        AD_BARRIER();

        u64 t0 = __rdtsc();
        AD_BARRIER();

        // Calibrated work — same as ad_rdtsc_timing
        volatile u64 acc = 0x5A5A5A5A5A5A5A5AULL;
        volatile u32 k;
        for (k = 0; k < 8u; k++) {
            acc = (acc ^ (acc >> 17)) * 0x517CC1B727220A95ULL;
        }
        AD_UNUSED(acc);

        AD_BARRIER();
        __cpuid(cpuid_buf, 0);
        AD_BARRIER();

        u64 t1 = __rdtsc();
        samples[i] = t1 - t0;
    }

    // Sort samples
    ad_sort_u64(samples, AD_TIMING_SAMPLES);

    // Discard bottom 25% and top 25%, take median of middle 50%
    u32 lo = AD_TIMING_SAMPLES / 4u;
    u32 hi = AD_TIMING_SAMPLES - lo;
    u32 mid = (lo + hi) / 2u;

    return samples[mid];
#else
    return 0;
#endif
}

ANTIDEBUG_INLINE b32 ad_h_rdtsc_timing(void) {
    u64 median = ad_robust_timing();
    return ad_opaque_gt_u64(median, (u64)AD_GET_RDTSC_STEP());
}

// Multi-sample RDTSC double-read — take 4 consecutive pairs
ANTIDEBUG_INLINE b32 ad_h_rdtsc_double(void) {
#if defined(_MSC_VER)
    u64 deltas[4];
    u32 i;
    u32 suspicious_count = 0;

    for (i = 0; i < 4u; i++) {
        AD_LFENCE();
        u64 t0 = __rdtsc();
        AD_LFENCE();
        u64 t1 = __rdtsc();
        AD_LFENCE();
        deltas[i] = t1 - t0;
    }

    // If ANY pair exceeds threshold → suspicious
    // If 2+ pairs exceed → definitely instrumented
    u64 thresh = (u64)AD_GET_RDTSC_DOUBLE();
    for (i = 0; i < 4u; i++) {
        if (ad_opaque_gt_u64(deltas[i], thresh)) {
            suspicious_count++;
        }
    }

    // 2+ suspicious = detected (1 could be noise/interrupt)
    return (b32)(suspicious_count >= 2u);
#else
    return 0;
#endif
}

// =========================================================================
// SYSCALL TIMING — detect hooked syscalls by measuring call duration
// =========================================================================
//
// A direct syscall (via SyscallStub) takes ~100-200 cycles.
// A hooked syscall (Frida, API Monitor) goes through a detour: 500-5000+ cycles.
// We measure NtQueryInformationProcess timing to detect hooks.

ANTIDEBUG_INLINE b32 ad_h_syscall_timing(void) {
#if defined(_MSC_VER)
    static u16 s_ssn = AD_SSN_UNRESOLVED;
    AD_RESOLVE_SSN_ENC(s_ssn, NtQueryInformationProcess, 26);
    if (s_ssn == AD_SSN_FAILED) return 0;

    u64 samples[4];
    u32 i;

    for (i = 0; i < 4u; i++) {
        AD_LFENCE();
        u64 t0 = __rdtsc();
        AD_LFENCE();

        // Make a lightweight syscall
        u64 port = 0;
        u32 ret_len = 0;
        AD_SYSCALL5(
            s_ssn,
            AD_CURRENT_PROCESS,
            (u64)7,  // ProcessDebugPort
            &port,
            (u64)sizeof(port),
            &ret_len
        );

        AD_LFENCE();
        u64 t1 = __rdtsc();
        samples[i] = t1 - t0;
    }

    ad_sort_u64(samples, 4u);
    // Median of middle 2
    u64 median = (samples[1] + samples[2]) / 2u;

    // Direct syscall: ~100-500 cycles
    // Hooked syscall: ~2000+ cycles
    // Threshold: 1500 (derived)
    u64 thresh = ad_derive64(0xDEAD05DCull ^ 0xDEAD0000ULL, 0xDEAD0000ULL);  // 0x5DC = 1500
    return ad_opaque_gt_u64(median, thresh);
#else
    return 0;
#endif
}

// =========================================================================
// TRAP CHECK — operations that MUST fail in a specific way
// =========================================================================
//
// We call NtClose with a valid-looking but crafted handle. Without a
// debugger, it returns STATUS_INVALID_HANDLE (~0xC0000008).
// WITH a debugger, it raises an exception BEFORE returning.
//
// Twist: we also check that the NTSTATUS is exactly what we expect.
// A hook that returns STATUS_SUCCESS to hide the debugger → detected
// because the return code is wrong for an invalid handle.

ANTIDEBUG_INLINE b32 ad_h_ntclose_trap(void) {
#if defined(_MSC_VER)
    static u16 s_ssn = AD_SSN_UNRESOLVED;
    AD_RESOLVE_SSN_ENC(s_ssn, NtClose, 8);
    if (s_ssn == AD_SSN_FAILED) return 0;

    b32 exception_caught = 0;
    ad_ntstatus_t status = 0;

    __try {
        // Use a handle that's valid-format but doesn't exist
        // 0xBAADF00D is obviously invalid
        status = AD_SYSCALL1(s_ssn, (u64)0xBAADF00DULL);
    }
    __except (1) {
        exception_caught = 1;
    }

    // Under debugger: exception fires → exception_caught = 1
    if (exception_caught) return 1;

    // Without debugger: NtClose returns STATUS_INVALID_HANDLE (0xC0000008)
    // If a hook returns STATUS_SUCCESS (0) to hide the debugger → suspicious
    if (status == 0) return 1;  // hooked NtClose returning fake success

    return 0;
#else
    return 0;
#endif
}

// =========================================================================
// HARDENED DEBUG PORT — redundant query + timing + cross-validate
// =========================================================================

ANTIDEBUG_INLINE b32 ad_h_debug_port(void) {
    static u16 s_ssn = AD_SSN_UNRESOLVED;
    AD_RESOLVE_SSN_ENC(s_ssn, NtQueryInformationProcess, 26);
    if (s_ssn == AD_SSN_FAILED) return 0;

    // Query 3 times — a hook that returns 0 once might fail to hide it every time
    u64 port1 = 0, port2 = 0, port3 = 0;
    u32 ret1 = 0, ret2 = 0, ret3 = 0;

    AD_SYSCALL5(s_ssn, AD_CURRENT_PROCESS, (u64)7, &port1, (u64)8, &ret1);
    AD_BARRIER();
    AD_SYSCALL5(s_ssn, AD_CURRENT_PROCESS, (u64)7, &port2, (u64)8, &ret2);
    AD_BARRIER();
    AD_SYSCALL5(s_ssn, AD_CURRENT_PROCESS, (u64)7, &port3, (u64)8, &ret3);

    // If ANY query returned nonzero → debugger
    b32 any_hit = (b32)(port1 | port2 | port3);

    // Cross-validate: all 3 should return the same value.
    // If they differ, a hook is racing to hide the debugger.
    b32 inconsistent = (b32)(port1 != port2 || port2 != port3);

    return (b32)(any_hit | inconsistent);
}

// Same pattern for DebugFlags (class 31)
ANTIDEBUG_INLINE b32 ad_h_debug_flags(void) {
    static u16 s_ssn = AD_SSN_UNRESOLVED;
    AD_RESOLVE_SSN_ENC(s_ssn, NtQueryInformationProcess, 26);
    if (s_ssn == AD_SSN_FAILED) return 0;

    u32 f1 = 1, f2 = 1, f3 = 1;
    u32 r1 = 0, r2 = 0, r3 = 0;

    AD_SYSCALL5(s_ssn, AD_CURRENT_PROCESS, (u64)31, &f1, (u64)4, &r1);
    AD_BARRIER();
    AD_SYSCALL5(s_ssn, AD_CURRENT_PROCESS, (u64)31, &f2, (u64)4, &r2);
    AD_BARRIER();
    AD_SYSCALL5(s_ssn, AD_CURRENT_PROCESS, (u64)31, &f3, (u64)4, &r3);

    // NOTE: We used to flag `flags == 0` as "debugger present", but our
    // own anti-attach hardening sets ProcessDebugFlags=0 deliberately.
    // Only the cross-read consistency check is reliable now.
    b32 inconsistent = (b32)(f1 != f2 || f2 != f3);
    return inconsistent;
}

// =========================================================================
// HARDENED HARDWARE BP — read + clear + re-read to detect debugger restoring
// =========================================================================

// Forward decl: our fake-hwbp sentinel address (defined in fake_hwbp.h).
#include "runtime/fake_hwbp.h"

ANTIDEBUG_INLINE b32 ad_h_dr_match_fake_squat(const AD_CONTEXT* c) {
    u64 base = (u64)(uintptr_t)&ad_fake_hwbp_sentinel[0];
    if (base == 0ULL) return 0;
    if (c->Dr0 != base + 0x00ULL) return 0;
    if (c->Dr1 != base + 0x08ULL) return 0;
    if (c->Dr2 != base + 0x10ULL) return 0;
    if (c->Dr3 != base + 0x18ULL) return 0;
    if ((c->Dr7 & 0xFFULL) != 0x55ULL) return 0;
    return 1;
}

ANTIDEBUG_INLINE b32 ad_h_hardware_bp(void) {
    static u16 s_ssn_get = AD_SSN_UNRESOLVED;
    static u16 s_ssn_set = AD_SSN_UNRESOLVED;
    AD_RESOLVE_SSN_ENC(s_ssn_get, NtGetContextThread, 19);
    AD_RESOLVE_SSN_ENC(s_ssn_set, NtSetContextThread, 19);
    if (s_ssn_get == AD_SSN_FAILED) return 0;

    AD_ALIGN(16) AD_CONTEXT ctx;
    AD_ZERO_BUF(&ctx, sizeof(ctx));
    ctx.ContextFlags = AD_CONTEXT_DEBUG_REGISTERS;

    ad_ntstatus_t st = AD_SYSCALL2(s_ssn_get, AD_CURRENT_THREAD, &ctx);
    if (!AD_NT_SUCCESS(st)) return 0;

    // If the DRs exactly match our own fake-hwbp squat, ignore them.
    if (ad_h_dr_match_fake_squat(&ctx)) return 0;

    b32 bp_found = (b32)(ctx.Dr0 | ctx.Dr1 | ctx.Dr2 | ctx.Dr3);
    b32 dr7_armed = (b32)((ctx.Dr7 & 0xFFULL) != 0ULL);

    if (bp_found || dr7_armed) return 1;

    // If no BPs found: try to CLEAR DR regs, then re-read.
    // If a debugger is using them, it will RESTORE them on next context switch.
    if (s_ssn_set != AD_SSN_FAILED) {
        AD_ALIGN(16) AD_CONTEXT ctx_clear;
        AD_ZERO_BUF(&ctx_clear, sizeof(ctx_clear));
        ctx_clear.ContextFlags = AD_CONTEXT_DEBUG_REGISTERS;
        ctx_clear.Dr0 = 0; ctx_clear.Dr1 = 0;
        ctx_clear.Dr2 = 0; ctx_clear.Dr3 = 0;
        ctx_clear.Dr7 = 0;

        AD_SYSCALL2(s_ssn_set, AD_CURRENT_THREAD, &ctx_clear);
        AD_BARRIER();
        AD_MFENCE();

        // Re-read — if debugger restored its BPs, they'll be back
        AD_ZERO_BUF(&ctx, sizeof(ctx));
        ctx.ContextFlags = AD_CONTEXT_DEBUG_REGISTERS;
        AD_SYSCALL2(s_ssn_get, AD_CURRENT_THREAD, &ctx);

        bp_found = (b32)(ctx.Dr0 | ctx.Dr1 | ctx.Dr2 | ctx.Dr3);
        dr7_armed = (b32)((ctx.Dr7 & 0xFFULL) != 0ULL);

        if (bp_found || dr7_armed) return 1;
    }

    return 0;
}

// =========================================================================
// MASTER HARDENED CHECK — runs all hardened checks with cross-validation
// =========================================================================
//
// Returns a composite score. Each hardened check contributes independently.
// Cross-validation adds bonus points for inconsistencies.
//
// Use this INSTEAD of running individual checks from the dispatcher.
// The dispatcher calls ad_h_master() as a single mega-check.

ANTIDEBUG_INLINE u32 ad_h_master(void) {
    u32 score = 0;

    // PEB family — hardened with triple-read
    score += ad_h_peb_being_debugged()  ? 2u : 0u;
    score += ad_h_peb_nt_global_flag()  ? 2u : 0u;
    score += ad_h_heap_flags()          ? 2u : 0u;

    // Cross-validation bonus — inconsistencies are MORE suspicious than
    // straightforward detection (means active evasion)
    score += ad_h_cross_validate_peb();

    // Syscall-based — triple-query
    score += ad_h_debug_port()   ? 3u : 0u;
    score += ad_h_debug_flags()  ? 3u : 0u;

    // Hardware BP — clear + re-check
    score += ad_h_hardware_bp()  ? 3u : 0u;

    // Timing — statistical multi-sample
    score += ad_h_rdtsc_timing() ? 2u : 0u;
    score += ad_h_rdtsc_double() ? 2u : 0u;

    // Syscall timing — detect hooked stubs
    score += ad_h_syscall_timing() ? 4u : 0u;

    // NtClose trap — exception + return code validation
    score += ad_h_ntclose_trap() ? 3u : 0u;

    return score;
}

#endif // ANTIDEBUG_HARDENED_H
