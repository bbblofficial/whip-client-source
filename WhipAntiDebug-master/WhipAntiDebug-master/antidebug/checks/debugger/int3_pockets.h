// ===== file: antidebug/checks/debugger/int3_pockets.h =====
//
// INT3 / UD2 pockets — traps in dead branches protected by opaque-false
// predicates.
//
// A static disassembler that follows both sides of `if (AD_OPAQUE_DEAD_
// BRANCH())` sees the trap instructions and has to reason about them.
// At runtime the branch is never taken (the predicate is provably
// false), so normal execution never hits a pocket.
//
// If a reverser:
//   * patches the opaque predicate to force the dead branch to execute
//   * misses a branch while stepping and lands in a pocket
//   * bulk-NOPs a region that happens to contain a pocket
// ...they either crash on `ud2` (#UD) or trip a breakpoint exception
// on `int3` (0xCC).  Our AD_VEH_CALL handler in veh_dispatch.h already
// claims any int3 with the MAGIC pending tag set.  An int3 fired from a
// pocket does NOT carry the tag, so the handler falls through — which
// usually means the debugger attached to the process catches it.
//
// Pocket placement suggestions
// ----------------------------
//   * Immediately after a score-related branch (`if (score == 0)`), put
//     `AD_INT3_POCKET()` in the `else` side.
//   * Inside loops that run exactly N times, put `AD_UD2_POCKET()` under
//     a loop-variable opaque predicate.
//   * Near flag decryption, seed several pockets so a naïve "set bp
//     around these bytes" strategy produces spurious hits.
//
#ifndef ANTIDEBUG_INT3_POCKETS_H
#define ANTIDEBUG_INT3_POCKETS_H

#include "../../core/types.h"
#include "../../core/macros.h"
#include "../../core/opaque.h"

#if defined(_MSC_VER)

// Single-byte int3 pocket.  Wrapped in a dead branch; never runs.
#define AD_INT3_POCKET()                                                 \
    do {                                                                 \
        if (AD_OPAQUE_DEAD_BRANCH()) {                                   \
            __debugbreak();                                              \
            __debugbreak();                                              \
            __debugbreak();                                              \
        }                                                                \
    } while (0)

// Undefined-instruction pocket.  `__ud2()` emits the UD2 opcode which
// raises #UD unconditionally.  Heavier trap than int3 because Windows
// cannot swallow it with a debugger-attached handler; the process dies
// immediately if the path is reached.
#define AD_UD2_POCKET()                                                  \
    do {                                                                 \
        if (AD_OPAQUE_DEAD_BRANCH()) {                                   \
            __ud2();                                                     \
        }                                                                \
    } while (0)

// Composite pocket: both int3 and ud2 in sequence.  If the reverser
// patches the first to continue, the second kills the process.
#define AD_COMBO_POCKET()                                                \
    do {                                                                 \
        if (AD_OPAQUE_DEAD_BRANCH()) {                                   \
            __debugbreak();                                              \
            __ud2();                                                     \
            __debugbreak();                                              \
        }                                                                \
    } while (0)

// Alive-guard pocket: always-taken branch containing a decoy int3 that
// is in fact never reached because of a second opaque-false gate.
// Produces a disassembly that LOOKS like it breakpoints but never does.
#define AD_DECOY_POCKET()                                                \
    do {                                                                 \
        if (AD_OPAQUE_ALIVE_BRANCH()) {                                  \
            if (AD_OPAQUE_DEAD_BRANCH()) {                               \
                __debugbreak();                                          \
            }                                                            \
        }                                                                \
    } while (0)

#else  // !_MSC_VER
#define AD_INT3_POCKET()   ((void)0)
#define AD_UD2_POCKET()    ((void)0)
#define AD_COMBO_POCKET()  ((void)0)
#define AD_DECOY_POCKET()  ((void)0)
#endif

#endif // ANTIDEBUG_INT3_POCKETS_H
