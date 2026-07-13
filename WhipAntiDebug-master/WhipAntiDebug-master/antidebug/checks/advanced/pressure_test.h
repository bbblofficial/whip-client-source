// ===== file: antidebug/checks/advanced/pressure_test.h =====
//
// Debugger Pressure Test — overwhelm the debugger with rapid exceptions
// and measure the total time. In-process exception handling is fast (<1us
// per exception). A debugger intercepts each one, adding round-trip latency.
//
#ifndef ANTIDEBUG_PRESSURE_TEST_H
#define ANTIDEBUG_PRESSURE_TEST_H

#include "../../core/types.h"
#include "../../core/macros.h"

#ifdef _MSC_VER
#include <intrin.h>
#endif

#define AD_PRESSURE_FLOOD_COUNT 200u

// ---------------------------------------------------------------------------
// Exception flood: trigger N divide-by-zero exceptions rapidly
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE b32 ad_pressure_exception_flood(void) {
#ifdef _MSC_VER
    AD_LFENCE();
    u64 t0 = __rdtsc();

    u32 i;
    for (i = 0; i < AD_PRESSURE_FLOOD_COUNT; i++) {
        __try {
            volatile u32 z = 0;
            volatile u32 r = 1u / z;
            (void)r;
        }
        __except (1) {
            // Caught — this is fast in-process
        }
    }

    u64 t1 = __rdtsc();
    AD_LFENCE();

    u64 delta = t1 - t0;
    u64 per_exception = delta / AD_PRESSURE_FLOOD_COUNT;

    // Normal: ~500-2000 cycles per exception (SEH dispatch is fast)
    // Debugger: ~50000+ cycles per exception (debugger round-trip)
    return (b32)(per_exception > 15000ULL);
#else
    return 0;
#endif
}

// ---------------------------------------------------------------------------
// INT3 flood variant — less destructive, same principle
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE b32 ad_pressure_int3_flood(void) {
#ifdef _MSC_VER
    AD_LFENCE();
    u64 t0 = __rdtsc();

    u32 i;
    for (i = 0; i < 100u; i++) {
        __try {
            __debugbreak();
        }
        __except (1) {
            // Fast in-process
        }
    }

    u64 t1 = __rdtsc();
    AD_LFENCE();

    u64 per_bp = (t1 - t0) / 100u;
    // INT3 under debugger: debugger ALWAYS intercepts first-chance
    return (b32)(per_bp > 20000ULL);
#else
    return 0;
#endif
}

// ---------------------------------------------------------------------------
// Master pressure test
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE b32 ad_pressure_test_check(void) {
    // Run exception flood first (less likely to be filtered)
    b32 flood_hit = ad_pressure_exception_flood();
    // Only run INT3 flood if exception flood didn't trigger
    // (avoids wasting time if already detected)
    b32 int3_hit = flood_hit ? 0 : ad_pressure_int3_flood();
    return flood_hit | int3_hit;
}

#endif // ANTIDEBUG_PRESSURE_TEST_H
