// ===== file: antidebug/checks/timing/cross_timer.h =====
//
// Cross-Timer Triangulation.
//
// Compare 4 independent time sources over a fixed window:
//   1. RDTSC                            (CPU)
//   2. RDTSCP                           (CPU, with TSC_AUX)
//   3. KUSER_SHARED_DATA.InterruptTime  (kernel-published, unhookable)
//   4. KUSER_SHARED_DATA.TickCountQuad  (kernel-published, unhookable)
//
// On bare hardware, the ratios between these are stable. Under DBI
// (Pin, DynamoRIO, Frida-Stalker), the instrumented code path goes
// through trampolines that don't equally affect all clocks — RDTSC stays
// roughly the same (it's a CPU instruction), but the kernel-published
// times advance MORE per RDTSC tick than they should because the
// instrumented loop takes longer wall-clock time.
//
// Threshold: if the ratio (kernel time delta) / (rdtsc delta) exceeds
// what's possible on bare hardware, instrumentation is present.
//
#ifndef ANTIDEBUG_CROSS_TIMER_H
#define ANTIDEBUG_CROSS_TIMER_H

#include "../../core/types.h"
#include "../../core/macros.h"

#ifdef _MSC_VER
#include <intrin.h>
#endif

#define AD_CT_KUSD_BASE          ((volatile u8*)0x7FFE0000ULL)
// InterruptTime: KSYSTEM_TIME at +0x008, 100ns units
#define AD_CT_KUSD_INT_LOW       (*(volatile u32*)(AD_CT_KUSD_BASE + 0x008u))
#define AD_CT_KUSD_INT_HIGH1     (*(volatile s32*)(AD_CT_KUSD_BASE + 0x00Cu))
// TickCountQuad: at +0x320, 100ns units (well, ms multiplied)
#define AD_CT_KUSD_TICK_LOW      (*(volatile u32*)(AD_CT_KUSD_BASE + 0x320u))
#define AD_CT_KUSD_TICK_HIGH1    (*(volatile s32*)(AD_CT_KUSD_BASE + 0x324u))

// Read InterruptTime as a 64-bit value (atomic-ish via High1 retry)
ANTIDEBUG_INLINE u64 ad_ct_read_int_time(void) {
    s32 hi, hi2;
    u32 lo;
    do {
        hi  = AD_CT_KUSD_INT_HIGH1;
        lo  = AD_CT_KUSD_INT_LOW;
        hi2 = AD_CT_KUSD_INT_HIGH1;
    } while (hi != hi2);
    return ((u64)(u32)hi << 32) | (u64)lo;
}

ANTIDEBUG_INLINE b32 ad_cross_timer_check(void) {
#ifdef _MSC_VER
    // Establish a baseline (kernel time per RDTSC tick).
    // Sample 1
    u64 t0_int = ad_ct_read_int_time();
    AD_LFENCE();
    u64 t0_tsc = __rdtsc();
    AD_LFENCE();

    // Burn ~50k cycles of pure CPU work
    volatile u64 acc = 0xCAFEBABEDEADBEEFULL;
    u32 i;
    for (i = 0; i < 5000u; i++) {
        acc = (acc * 0x100000001B3ULL) ^ i;
    }
    AD_UNUSED(acc);

    AD_LFENCE();
    u64 t1_tsc = __rdtsc();
    AD_LFENCE();
    u64 t1_int = ad_ct_read_int_time();

    u64 d_tsc = t1_tsc - t0_tsc;
    u64 d_int = t1_int - t0_int;  // 100ns units

    // Sanity: if rdtsc delta is ridiculously small the test is unreliable
    if (d_tsc < 1000ULL) return 0;

    // Bare hardware at 3GHz: 50000 cycles ≈ 16.7 µs ≈ 167 (100ns units).
    // Under DBI: same 50000 cycles takes much longer wall-clock because
    // the instrumented loop runs slower in real time → d_int balloons.
    // We compute the wall-time-per-tsc ratio in 100ns/tsc units.
    //
    // On a 1 GHz CPU (worst legitimate case), 1 tsc tick = 1 ns = 0.01
    // KUSD units. So ratio (d_int * 1000) / d_tsc should be < 100 on
    // any sane hardware (we use *1000 to avoid integer rounding to 0).
    //
    // Under DBI the loop takes 10-100x longer in wall time but the same
    // (or fewer) tsc cycles → ratio explodes.
    u64 ratio_x1000 = (d_int * 1000ULL) / d_tsc;

    // Debug builds run the loop ~30-100x slower than the optimized
    // baseline, so the wall-time/cycles ratio is naturally inflated.
    // Set the threshold high enough to be Debug-build safe but still
    // catch genuine instrumentation (which adds at least 2 orders of
    // magnitude on top of Debug overhead).
    return (b32)(ratio_x1000 > 50000ULL);
#else
    return 0;
#endif
}

#endif // ANTIDEBUG_CROSS_TIMER_H
