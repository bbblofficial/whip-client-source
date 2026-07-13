// ===== file: antidebug/checks/timing/total_elapsed.h =====
//
// Total elapsed time detection.
//
// Measures wall-clock time from ad_init (state.init_tsc) to the point
// just before flag derivation. A clean run completes in ~1-10M TSC cycles.
// A debugger stepping through checks — even with an `erun` script that
// auto-resumes exceptions — takes 50-500M cycles due to:
//   - Context switches at each exception/BP stop
//   - x64dbg processing overhead per exception
//   - Kernel round-trips for debug events
//
// Uses two independent timers (RDTSC and QPC) so a reverser must fake
// both simultaneously.
//
// During the bypass test, the erun script loop through ~20 exception
// stops pushed total time well above 30M cycles.
//
#ifndef ANTIDEBUG_TOTAL_ELAPSED_H
#define ANTIDEBUG_TOTAL_ELAPSED_H

#include "../../core/types.h"
#include "../../core/macros.h"
#include "../../core/config.h"

#if defined(_MSC_VER)

// =========================================================================
// RDTSC elapsed check
// =========================================================================
//
// Compares current RDTSC with init_tsc snapshot.
// Returns 1 if delta exceeds threshold (debugger overhead detected).
// =========================================================================
ANTIDEBUG_INLINE b32 ad_elapsed_rdtsc_check(u64 init_tsc) {
    if (init_tsc == 0ULL) return 0;

    AD_LFENCE();
    u64 now = __rdtsc();
    AD_LFENCE();

    u64 delta = now - init_tsc;

    // Clean run: ~1-10M cycles (depends on CPU, check count)
    // Debugger with erun: >30M cycles (exception handling overhead)
    // Single-stepping: >1000M cycles
    return (b32)(delta > AD_ELAPSED_RDTSC_THRESHOLD);
}

// =========================================================================
// QPC elapsed check — independent timer source
// =========================================================================
//
// Uses KUSER_SHARED_DATA QPC to avoid any API call that could be hooked.
// KUSER_SHARED_DATA at 0x7FFE0000 is kernel-mapped read-only.
//
// QpcData layout in KUSER_SHARED_DATA:
//   +0x2B8: QpcBias (u64)   — subtract from raw QPC to get wall time
//   +0x320: TickCount (KSYSTEM_TIME) — not QPC, but usable as coarse timer
//
// For simplicity we use __rdtsc as both timers derive from the same TSC
// on modern CPUs, but with different scaling. Instead, we read the
// KUSER_SHARED_DATA TickCount which is independent of RDTSC hooks.
// =========================================================================

#define AD_KUSD_TICKCOUNT_LO_PTR  ((volatile u32*)(0x7FFE0000ULL + 0x320u))

ANTIDEBUG_INLINE b32 ad_elapsed_tick_check(u32 init_tick) {
    if (init_tick == 0u) return 0;

    u32 now = *AD_KUSD_TICKCOUNT_LO_PTR;
    u32 delta = now - init_tick;

    // TickCount increments ~64 times per second (15.625ms per tick)
    // Clean run: <3 ticks (~50ms)
    // Debugger with erun exceptions: >10 ticks (~150ms+)
    return (b32)(delta > AD_ELAPSED_TICK_THRESHOLD);
}

// =========================================================================
// Combined elapsed check — returns weighted score
// =========================================================================
ANTIDEBUG_INLINE u32 ad_elapsed_check(u64 init_tsc, u32 init_tick) {
    u32 score = 0u;

#if AD_ENABLE_TOTAL_ELAPSED
    if (ad_elapsed_rdtsc_check(init_tsc))  score += 8u;
    if (ad_elapsed_tick_check(init_tick))   score += 8u;
#else
    AD_UNUSED(init_tsc);
    AD_UNUSED(init_tick);
#endif

    return score;
}

// =========================================================================
// Snapshot helper — call at init time to capture baseline
// =========================================================================
ANTIDEBUG_INLINE u32 ad_elapsed_tick_snapshot(void) {
    return *AD_KUSD_TICKCOUNT_LO_PTR;
}

#else  // Non-MSVC stubs

ANTIDEBUG_INLINE b32 ad_elapsed_rdtsc_check(u64 t) { (void)t; return 0; }
ANTIDEBUG_INLINE b32 ad_elapsed_tick_check(u32 t) { (void)t; return 0; }
ANTIDEBUG_INLINE u32 ad_elapsed_check(u64 a, u32 b) { (void)a; (void)b; return 0u; }
ANTIDEBUG_INLINE u32 ad_elapsed_tick_snapshot(void) { return 0u; }

#endif // _MSC_VER

#endif // ANTIDEBUG_TOTAL_ELAPSED_H
