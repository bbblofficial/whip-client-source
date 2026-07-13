// ===== file: antidebug/checks/timing/loops.h =====
//
// Loop-timing anti-debug check.
// A calibrated loop with a known upper bound on bare-metal cost.
// Heavy instrumentation (DBI, full tracing) expands the cost dramatically.
//
#ifndef ANTIDEBUG_LOOPS_H
#define ANTIDEBUG_LOOPS_H

#include "../../core/types.h"
#include "../../core/macros.h"
#include "../../core/config.h"
#include "../../core/value_guard.h"

// ---------------------------------------------------------------------------
// Check: calibrated LCG loop timing
//
// A Linear Congruential Generator loop of AD_LOOP_ITER_COUNT iterations.
// On bare metal at 3 GHz+, ~800 LCG steps finish in <10,000 cycles.
// Under single-stepping or Pin/DynamoRIO tracing this blows up to millions.
//
// The volatile accumulator prevents dead-code elimination.
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE b32 ad_loop_timing(void) {
#if defined(_MSC_VER)
    u64 t0 = __rdtsc();

    // LCG: Knuth's multiplicative congruential generator
    volatile u64 acc = 1ULL;
    volatile u32 i;
    u32 loop_count = AD_GET_LOOP_ITER();
    for (i = 0u; i < loop_count; i++) {
        acc = acc * 6364136223846793005ULL + 1442695040888963407ULL;
    }
    AD_UNUSED(acc);

    u64 t1    = __rdtsc();
    u64 delta = t1 - t0;

    return ad_opaque_gt_u64(delta, (u64)AD_GET_LOOP_CYCLE());
#else
    return 0;
#endif
}

#endif // ANTIDEBUG_LOOPS_H
