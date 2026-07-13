// ===== file: antidebug/checks/advanced/pipeline_desync.h =====
//
// CPU Pipeline Desynchronization Detection.
// Creates instruction sequences where single-stepping causes measurable
// logical divergence (not just timing).
//
// Technique 1: CPUID serialization gap — under single-step, the pipeline
//   flush between CPUID and the next instruction is invisible (debugger
//   steps over it), but the TSC delta changes non-linearly.
//
// Technique 2: REP prefix atomicity — under normal execution REP STOSB
//   is atomic (hardware-accelerated). Under single-step, some debuggers
//   decompose it, changing observable side effects.
//
#ifndef ANTIDEBUG_PIPELINE_DESYNC_H
#define ANTIDEBUG_PIPELINE_DESYNC_H

#include "../../core/types.h"
#include "../../core/macros.h"

#ifdef _MSC_VER
#include <intrin.h>
#endif

// ---------------------------------------------------------------------------
// CPUID serialization desync
// Measures TSC delta across a CPUID (serializing instruction).
// Single-stepping inserts its own serialization, flattening the delta
// distribution. We take multiple samples and check variance.
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE b32 ad_pipeline_desync_cpuid(void) {
#ifdef _MSC_VER
    u64 samples[8];
    int regs[4];
    u32 i;

    for (i = 0; i < 8u; i++) {
        AD_LFENCE();
        u64 t0 = __rdtsc();
        __cpuid(regs, 0);  // serializing
        u64 t1 = __rdtsc();
        AD_LFENCE();
        samples[i] = t1 - t0;
    }

    // Under normal execution: CPUID takes 50-200 cycles, variance is moderate.
    // Under single-step: each sample includes debugger overhead (thousands),
    // and variance is very low relative to magnitude (debugger adds ~constant).
    u64 min_v = samples[0], max_v = samples[0];
    u64 sum = 0;
    for (i = 0; i < 8u; i++) {
        if (samples[i] < min_v) min_v = samples[i];
        if (samples[i] > max_v) max_v = samples[i];
        sum += samples[i];
    }

    u64 avg = sum / 8u;
    u64 range = max_v - min_v;

    // Heuristic: if average is very high (>5000) AND range is very small
    // relative to average (<10%), it's likely single-stepped
    if (avg > 5000ULL && range < avg / 10ULL) return 1;

    // Also check: if ALL samples exceed 3000, something is instrumenting
    u32 all_high = 1;
    for (i = 0; i < 8u; i++) {
        if (samples[i] < 3000ULL) { all_high = 0; break; }
    }
    if (all_high) return 1;

    return 0;
#else
    return 0;
#endif
}

// ---------------------------------------------------------------------------
// REP STOSB atomicity check
// Fill a buffer with REP STOSB, then immediately check it.
// Under normal execution: the entire fill completes atomically.
// Under some debuggers: partial fill may be observable between iterations.
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE b32 ad_pipeline_desync_rep(void) {
#ifdef _MSC_VER
    volatile u8 buf[64];
    u32 i;

    // Fill with known pattern
    for (i = 0; i < 64u; i++) buf[i] = 0xAA;

    // Use REP STOSB via intrinsic
    AD_LFENCE();
    u64 t0 = __rdtsc();
    __stosb((unsigned char*)buf, 0x55, 64);
    u64 t1 = __rdtsc();
    AD_LFENCE();

    // Verify all bytes were written (should always pass)
    u32 mismatch = 0;
    for (i = 0; i < 64u; i++) {
        if (buf[i] != 0x55) mismatch++;
    }

    // REP STOSB of 64 bytes: ~20-50 cycles on real hardware.
    // Under debugger single-step: 1000+ cycles easily.
    u64 delta = t1 - t0;
    if (delta > 2000ULL) return 1;
    if (mismatch > 0u) return 1;  // shouldn't happen, but indicates interference

    return 0;
#else
    return 0;
#endif
}

// ---------------------------------------------------------------------------
// Master pipeline desync check
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE b32 ad_pipeline_desync_check(void) {
    b32 cpuid_hit = ad_pipeline_desync_cpuid();
    b32 rep_hit   = ad_pipeline_desync_rep();
    return cpuid_hit | rep_hit;
}

#endif // ANTIDEBUG_PIPELINE_DESYNC_H
