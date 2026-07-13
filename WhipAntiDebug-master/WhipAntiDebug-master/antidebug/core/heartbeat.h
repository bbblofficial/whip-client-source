// ===== file: antidebug/core/heartbeat.h =====
//
// Cross-thread heartbeat anti-suspend detection.
//
// Problem:
//   A debugger can SuspendThread() on the watchdog or sentinel thread,
//   neutralizing all background checks. The main thread keeps running
//   but never notices the watchdog is dead.
//
// Solution:
//   Two threads exchange heartbeats via a shared struct. Thread A
//   increments beat_a, thread B increments beat_b. Each thread checks
//   whether the other's counter has advanced since the last snapshot.
//   If the other thread's beat hasn't moved for 3+ cycles, we know
//   it was suspended (or killed) by a debugger.
//
//   Typical cadence:
//     - Watchdog calls pump_a() every ~2 seconds
//     - Main check loop calls pump_b() every ~3-7 seconds
//     - 3 consecutive stalls = detection
//
#ifndef ANTIDEBUG_HEARTBEAT_H
#define ANTIDEBUG_HEARTBEAT_H

#include "types.h"
#include "macros.h"

// ---------------------------------------------------------------------------
// Heartbeat state — shared between two cooperating threads
// ---------------------------------------------------------------------------
typedef struct {
    volatile u64 beat_a;        // Thread A increments this
    volatile u64 beat_b;        // Thread B increments this
    volatile u64 last_seen_a;   // Thread B's last snapshot of beat_a
    volatile u64 last_seen_b;   // Thread A's last snapshot of beat_b
    volatile u32 stall_count_a; // Consecutive stalls detected for A
    volatile u32 stall_count_b; // Consecutive stalls detected for B
} ad_heartbeat_t;

// ---------------------------------------------------------------------------
// ad_heartbeat_init — zero everything
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE void ad_heartbeat_init(ad_heartbeat_t* hb) {
    hb->beat_a        = 0;
    hb->beat_b        = 0;
    hb->last_seen_a   = 0;
    hb->last_seen_b   = 0;
    hb->stall_count_a = 0;
    hb->stall_count_b = 0;
    AD_BARRIER();
}

// ---------------------------------------------------------------------------
// ad_heartbeat_pump_a — called by thread A (e.g. watchdog, every ~2s)
//
// 1. Increment our own beat counter so thread B knows we're alive
// 2. Check if thread B's beat has advanced since our last snapshot
//    - If unchanged: B may be suspended, increment stall counter
//    - If changed: B is alive, reset stall counter and update snapshot
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE void ad_heartbeat_pump_a(ad_heartbeat_t* hb) {
    // Signal that we (thread A) are alive
    hb->beat_a++;
    AD_BARRIER();

    // Check thread B's liveness
    volatile u64 current_b = hb->beat_b;
    AD_BARRIER();

    if (current_b == hb->last_seen_b) {
        // Thread B hasn't moved — possibly suspended
        hb->stall_count_b++;
        AD_BARRIER();
    } else {
        // Thread B is alive — reset
        hb->stall_count_b = 0;
        AD_BARRIER();
        hb->last_seen_b = current_b;
        AD_BARRIER();
    }
}

// ---------------------------------------------------------------------------
// ad_heartbeat_pump_b — called by thread B (e.g. main loop, every ~3-7s)
//
// Mirror of pump_a: increments beat_b, checks beat_a.
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE void ad_heartbeat_pump_b(ad_heartbeat_t* hb) {
    // Signal that we (thread B) are alive
    hb->beat_b++;
    AD_BARRIER();

    // Check thread A's liveness
    volatile u64 current_a = hb->beat_a;
    AD_BARRIER();

    if (current_a == hb->last_seen_a) {
        // Thread A hasn't moved — possibly suspended
        hb->stall_count_a++;
        AD_BARRIER();
    } else {
        // Thread A is alive — reset
        hb->stall_count_a = 0;
        AD_BARRIER();
        hb->last_seen_a = current_a;
        AD_BARRIER();
    }
}

// ---------------------------------------------------------------------------
// ad_heartbeat_stalled_a — returns 1 if thread A was suspended for 3+ cycles
//
// Called by thread B to check if A (the watchdog) is still pumping.
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE b32 ad_heartbeat_stalled_a(ad_heartbeat_t* hb) {
    AD_BARRIER();
    return (hb->stall_count_a >= 3u) ? 1 : 0;
}

// ---------------------------------------------------------------------------
// ad_heartbeat_stalled_b — returns 1 if thread B was suspended for 3+ cycles
//
// Called by thread A to check if B (the main loop) is still pumping.
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE b32 ad_heartbeat_stalled_b(ad_heartbeat_t* hb) {
    AD_BARRIER();
    return (hb->stall_count_b >= 3u) ? 1 : 0;
}

// ---------------------------------------------------------------------------
// ad_heartbeat_should_respawn_a — returns 1 if thread A is DEAD (not just
// suspended). Dead = stall count >= 10 cycles (vs 3 for "stalled").
//
// The distinction matters: a suspended thread will resume eventually and
// catch up. A killed thread (TerminateThread, NtTerminateThread) will
// NEVER increment its counter again. 10 consecutive stalls at typical
// pump cadence = ~20-30 seconds of silence — definitely dead.
//
// Called by thread B: "should I respawn thread A?"
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE b32 ad_heartbeat_should_respawn_a(ad_heartbeat_t* hb) {
    AD_BARRIER();
    return (hb->stall_count_a >= 10u) ? 1 : 0;
}

// ---------------------------------------------------------------------------
// ad_heartbeat_should_respawn_b — returns 1 if thread B is DEAD.
//
// Called by thread A: "should I respawn thread B?"
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE b32 ad_heartbeat_should_respawn_b(ad_heartbeat_t* hb) {
    AD_BARRIER();
    return (hb->stall_count_b >= 10u) ? 1 : 0;
}

#endif // ANTIDEBUG_HEARTBEAT_H
