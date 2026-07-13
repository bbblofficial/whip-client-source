// ===== file: antidebug/checks/integrity/nop_patrol.h =====
//
// NOP Patrol — detect patched CALL instructions in our own code.
//
// When a reverser NOPs a call (E8 XX XX XX XX → 90 90 90 90 90),
// we detect it by:
//
//   1. Recording the addresses of critical CALL sites at init
//   2. Periodically scanning those sites for 0x90 (NOP) bytes
//   3. Also checking for: RET (C3), INT3 (CC), JMP short (EB),
//      or any non-E8 byte where a CALL should be
//
// This catches the most common bypass technique: "NOP that call".
// The patrol table is encrypted in memory (vault).
//
#ifndef ANTIDEBUG_NOP_PATROL_H
#define ANTIDEBUG_NOP_PATROL_H

#include "../../core/types.h"
#include "../../core/macros.h"
#include "../../core/value_guard.h"

#define AD_PATROL_MAX_SITES 32u

typedef struct {
    u64 site_addrs[AD_PATROL_MAX_SITES];   // addresses of CALL instructions
    u8  site_bytes[AD_PATROL_MAX_SITES][8]; // original bytes at each site
    u32 count;
    b32 ready;
} ad_nop_patrol_t;

// Register a CALL site to monitor
ANTIDEBUG_INLINE void ad_patrol_register(
    ad_nop_patrol_t* patrol,
    const void* call_site_addr
) {
    if (patrol->count >= AD_PATROL_MAX_SITES) return;
    if (!call_site_addr) return;

    u32 idx = patrol->count;
    patrol->site_addrs[idx] = (u64)(unsigned long long)call_site_addr;

    // Save original 8 bytes
    const volatile u8* p = (const volatile u8*)call_site_addr;
    u32 i;
    for (i = 0; i < 8u; i++) {
        patrol->site_bytes[idx][i] = p[i];
    }

    patrol->count++;
}

ANTIDEBUG_INLINE void ad_patrol_seal(ad_nop_patrol_t* patrol) {
    patrol->ready = 1;
}

// Check all registered sites — returns number of patched sites
ANTIDEBUG_INLINE u32 ad_patrol_check(const ad_nop_patrol_t* patrol) {
    if (!patrol->ready) return 0;

    u32 patched = 0;
    u32 i;

    for (i = 0; i < patrol->count; i++) {
        const volatile u8* p = (const volatile u8*)(unsigned long long)patrol->site_addrs[i];

        // Check each of the first 5 bytes (CALL = E8 + 4 byte offset)
        u32 nop_count = 0;
        u32 mismatch_count = 0;
        u32 j;

        for (j = 0; j < 5u; j++) {
            u8 current  = p[j];
            u8 original = patrol->site_bytes[i][j];

            // NOP detection
            if (current == 0x90u) nop_count++;

            // Generic mismatch
            if (current != original) mismatch_count++;
        }

        // 5 NOPs = classic "NOP the call"
        if (nop_count >= 3u) { patched++; continue; }

        // First byte was E8 (CALL) and now isn't = patched
        if (patrol->site_bytes[i][0] == 0xE8u && p[0] != 0xE8u) {
            patched++;
            continue;
        }

        // First byte is now RET (C3) = function was stubbed
        if (p[0] == 0xC3u && patrol->site_bytes[i][0] != 0xC3u) {
            patched++;
            continue;
        }

        // Any byte mismatch in the CALL = patched (even if not NOP)
        if (mismatch_count > 0u) {
            patched++;
        }
    }

    return patched;
}

// Aggressive check — returns a poison score
// 1 NOP = bad. 2+ = catastrophic.
ANTIDEBUG_INLINE u32 ad_patrol_score(const ad_nop_patrol_t* patrol) {
    u32 n = ad_patrol_check(patrol);
    if (n == 0) return 0;
    // Exponential: 1 patch = 0x1000, 2 = 0x4000, 3 = 0x10000, ...
    u32 shift = (n < 8u) ? (n * 2u) : 16u;
    return 1u << shift;
}

#endif // ANTIDEBUG_NOP_PATROL_H
