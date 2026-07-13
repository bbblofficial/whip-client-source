// ===== file: antidebug/checks/timing/rdtsc.h =====
//
// RDTSC-based timing anti-debug checks.
// When a debugger is single-stepping or tracing, the CPU cycle count between
// two RDTSC reads grows by orders of magnitude relative to bare metal.
//
#ifndef ANTIDEBUG_RDTSC_H
#define ANTIDEBUG_RDTSC_H

#include "../../core/types.h"
#include "../../core/macros.h"
#include "../../core/config.h"
#include "../../core/value_guard.h"

// ---------------------------------------------------------------------------
// Check: RDTSC step-detection
//
// Measures the cycle cost of a tiny but non-trivial block.
// CPUID serializes the instruction stream so out-of-order execution doesn't
// artificially compress the reading.
//
// Expected cost (bare metal): < 200 cycles
// Under single-step / hardware tracing: > 10,000 cycles per step
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE b32 ad_rdtsc_timing(void) {
#if defined(_MSC_VER)
    // Run 3 times and keep the minimum.
    // Rationale: a single run can be inflated by an interrupt or scheduler
    // preemption (causing a false positive). Taking the minimum reliably
    // reflects the true hardware cost, because interrupts are rare events —
    // at least one of the 3 runs will be interrupt-free on bare metal.
    // Under a debugger (single-step / hardware trace), ALL runs are slow,
    // so the minimum is still far above the threshold.
    //
    // LFENCE is used instead of CPUID for serialization. CPUID causes a VM
    // exit under Hyper-V/VBS, adding thousands of cycles of overhead that
    // would cause false positives on VBS-enabled systems. LFENCE serializes
    // only load operations but is sufficient for RDTSC ordering (Intel SDM
    // recommends LFENCE; RDTSC; LFENCE for precise measurements).
    u64 min_delta = (u64)(-1);
    u32 k;
    for (k = 0; k < 3u; k++) {
        AD_LFENCE();
        u64 t0 = __rdtsc();
        AD_LFENCE();

        // Deterministic, non-trivial work the optimizer cannot eliminate
        volatile u64 acc = 0x5A5A5A5A5A5A5A5AULL;
        volatile u32 i;
        for (i = 0u; i < 8u; i++) {
            acc = (acc ^ (acc >> 17)) * 0x517CC1B727220A95ULL;
        }
        AD_UNUSED(acc);

        AD_LFENCE();
        u64 t1    = __rdtsc();
        u64 delta = t1 - t0;
        if (delta < min_delta) min_delta = delta;
    }

    return ad_opaque_gt_u64(min_delta, (u64)AD_GET_RDTSC_STEP());
#else
    return 0;
#endif
}

// ---------------------------------------------------------------------------
// Check: RDTSC double-read (consecutive)
//
// Two back-to-back RDTSC reads with a load-fence between them should cost
// almost nothing on real hardware (< 10 cycles).
// Some debuggers and hypervisors emulate/intercept RDTSC and introduce
// measurable latency, causing a large delta even with no code between reads.
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE b32 ad_rdtsc_double(void) {
#if defined(_MSC_VER)
    // Run 5 times and keep the minimum delta.
    // An interrupt between the two RDTSC reads inflates a single-run result
    // dramatically (IRQ handler takes 5–100 µs = thousands of ticks).
    // Taking the minimum across 5 runs gives the true back-to-back RDTSC cost,
    // because interrupts are rare — at least one run will be interrupt-free.
    // Under a hypervisor that intercepts RDTSC (heavy emulation), ALL 5 runs
    // have the same elevated cost, so the minimum still exceeds the threshold.
    u64 min_delta = (u64)(-1);
    u32 k;
    for (k = 0; k < 5u; k++) {
        AD_LFENCE();
        u64 t0 = __rdtsc();
        AD_LFENCE();
        u64 t1 = __rdtsc();
        AD_LFENCE();
        u64 d = t1 - t0;
        if (d < min_delta) min_delta = d;
    }
    return ad_opaque_gt_u64(min_delta, (u64)AD_GET_RDTSC_DOUBLE());
#else
    return 0;
#endif
}

#endif // ANTIDEBUG_RDTSC_H
