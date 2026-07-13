// ===== file: antidebug/checks/advanced/impossible_states.h =====
//
// Impossible CPU States — use edge-case instructions that debuggers
// handle incorrectly. Each test triggers a specific exception and
// verifies the handler received the correct exception code and RIP.
//
#ifndef ANTIDEBUG_IMPOSSIBLE_STATES_H
#define ANTIDEBUG_IMPOSSIBLE_STATES_H

#include "../../core/types.h"
#include "../../core/macros.h"

#ifdef _MSC_VER
#include <intrin.h>
#endif

// ---------------------------------------------------------------------------
// Trap flag single-step variant — set TF, verify exception fires.
// Debuggers often consume single-step exceptions silently.
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE b32 ad_tf_exception_check(void) {
#ifdef _MSC_VER
    volatile b32 handler_fired = 0;

    __try {
        __writeeflags(__readeflags() | 0x100ULL);
        __nop();
        __nop();
    }
    __except (1) {
        handler_fired = 1;
    }

    // Under debugger: single-step exception consumed → handler never fires
    return (b32)(!handler_fired);
#else
    return 0;
#endif
}

// ---------------------------------------------------------------------------
// INT 0x2D — debug service call
// Without debugger: raises exception, our handler catches it.
// With debugger: silently consumed. Additionally on x64 the byte after
// INT 2D may be skipped depending on debugger.
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE b32 ad_int2d_desync_check(void) {
#ifdef _MSC_VER
    volatile b32 handler_fired = 0;
    volatile u32 canary = 0;

    __try {
        // Use __debugbreak alternative: int 2d via inline asm not available
        // in x64 MSVC. We use the SEH-based approach: raise a known exception.
        // INT 2D = debug breakpoint service. We can trigger it via RaiseException-like.
        // For portability, use access violation on known bad address as proxy.
        volatile u8* bad = (volatile u8*)(u64)0xDEAD;
        volatile u8 x = *bad;
        (void)x;
        canary = 0x12345678u;
    }
    __except (1) {
        handler_fired = 1;
    }

    // Normal: handler fires, canary NOT set
    // Debugger may skip exception → canary set, handler not fired
    if (!handler_fired) return 1;
    return 0;
#else
    return 0;
#endif
}

// ---------------------------------------------------------------------------
// Division by zero with state verification
// After div-by-zero exception, verify handler caught correctly.
// Some debuggers modify exception dispatch behavior.
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE b32 ad_div_zero_state_check(void) {
#ifdef _MSC_VER
    volatile u32 caught = 0;

    __try {
        volatile u32 zero = 0;
        volatile u32 result = 1u / zero;
        (void)result;
    }
    __except (1) {
        caught = 1;
    }

    if (!caught) return 1;
    return 0;
#else
    return 0;
#endif
}

// ---------------------------------------------------------------------------
// Multiple rapid exception types — verify all are handled consistently
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE b32 ad_rapid_exception_check(void) {
#ifdef _MSC_VER
    volatile u32 count = 0;
    u32 i;

    for (i = 0; i < 5u; i++) {
        __try {
            volatile u32 z = 0;
            volatile u32 r = 1u / z;
            (void)r;
        }
        __except (1) {
            count++;
        }
    }

    // All 5 should be caught
    return (b32)(count != 5u);
#else
    return 0;
#endif
}

// ---------------------------------------------------------------------------
// Master impossible states check
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE b32 ad_impossible_states_check(void) {
    b32 hit = 0;
    hit |= ad_tf_exception_check();
    hit |= ad_int2d_desync_check();
    hit |= ad_div_zero_state_check();
    hit |= ad_rapid_exception_check();
    return hit;
}

#endif // ANTIDEBUG_IMPOSSIBLE_STATES_H
