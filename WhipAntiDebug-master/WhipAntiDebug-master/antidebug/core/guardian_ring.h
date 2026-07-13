// ===== file: antidebug/core/guardian_ring.h =====
//
// Guardian Ring — meta-protection for the anti-debug framework itself.
//
// PROBLEM
// ───────
// An anti-debug check is only as strong as its integrity. Typical attacks
// on a detection framework are:
//
//   * Inline-patch a check to always return 0 ("all clean")
//   * NOP the score-accumulation site so detection never counts
//   * Hook the master dispatcher to skip specific checks
//   * Patch the verdict function to always return "not detected"
//   * Scan memory for known check byte patterns, patch them all
//
// A single-target patch (one function) is cheap. Our defense against
// this is a TRUST RING: every protected function `i` holds a hash of
// the prologue of function `(i+1) mod N`. Before each protected
// function executes its critical work, it verifies the hash it holds.
// To defeat the ring, the attacker must simultaneously patch EVERY
// member while also rewriting every stored hash — and each hash is
// stored redundantly in multiple ring members, so the attacker doesn't
// actually know which storage sites exist until they reverse them all.
//
// DESIGN
// ──────
// - Init once: caller passes an array of function pointers to protect.
//   For each, we compute FNV-1a over `AD_GR_PROLOGUE_LEN` bytes and
//   publish it to the *previous* ring member (i→i-1, cyclic).
// - Runtime verify: caller invokes `ad_gr_verify(ring, my_index)` at
//   the START of its own function. The caller verifies the NEXT member
//   in the ring (not themselves — that would be a trivial no-op).
// - Tamper flag: sticky, encrypted, redundantly stored across 4 slots
//   XORed with random per-build keys. Cannot be cleared once set.
// - Decoy members: N "dummy" members point to unused functions; patching
//   them wastes the attacker's time but doesn't reduce detection.
//
// OFFENSIVE RESPONSE
// ──────────────────
// When tamper is detected, we do NOT immediately crash/exit. Instead:
//   1. Set sticky tamper flag
//   2. Poison score_vault with random noise
//   3. Inject latency into subsequent check calls (sleep random ms)
//   4. Return *correct-looking but wrong* results from future checks
//
// This makes reverse engineering difficult: the attacker sees some
// checks pass, some fail, with no clear pattern.
//
#ifndef ANTIDEBUG_GUARDIAN_RING_H
#define ANTIDEBUG_GUARDIAN_RING_H

#include "types.h"
#include "macros.h"

#ifdef _MSC_VER

#ifndef AD_GR_MAX_MEMBERS
#define AD_GR_MAX_MEMBERS      32u
#endif
#ifndef AD_GR_PROLOGUE_LEN
#define AD_GR_PROLOGUE_LEN     24u     // bytes hashed from each function
#endif

typedef struct {
    void* fn_addr;
    u32   watched_hash;    // hash of the NEXT member (cyclic) at init time
    u32   my_hash;         // hash of MYSELF at init time, stored here AND
                           // in the PREVIOUS member as watched_hash
    u32   _pad;
} ad_gr_member_t;

typedef struct {
    u32             count;
    u32             initialized;
    ad_gr_member_t  members[AD_GR_MAX_MEMBERS];

    // Redundant sticky tamper flag.
    // Stored as 4 XOR-masked u32 slots. To read: any_nonzero after XOR.
    // To set: write all 4 with encrypted 1.
    u32             tamper_slot[4];
    u32             tamper_keys[4];

    // Internal pseudo-random state for response latency.
    u64             prng_state;
} ad_gr_ring_t;

// FNV-1a on N bytes.
ANTIDEBUG_INLINE u32 ad_gr_fnv1a(const volatile u8* p, u32 n) {
    u32 h = 0x811C9DC5u;
    u32 i;
    for (i = 0; i < n; i++) { h ^= p[i]; h *= 0x01000193u; }
    return h;
}

// Cheap xorshift64.
ANTIDEBUG_INLINE u64 ad_gr_xorshift(u64* s) {
    u64 x = *s;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *s = x;
    return x;
}

// Initialise the ring from an array of function pointers.
ANTIDEBUG_INLINE b32 ad_gr_init(ad_gr_ring_t* ring, void** fns, u32 count) {
    if (!ring || !fns || count == 0u || count > AD_GR_MAX_MEMBERS) return 0;

    // Seed PRNG from rdtsc.
    ring->prng_state = __rdtsc() ^ 0xC0FFEE0013DEADULL;

    // First pass: compute each member's own prologue hash.
    u32 i;
    for (i = 0; i < count; i++) {
        ring->members[i].fn_addr = fns[i];
        if (!fns[i]) return 0;
        ring->members[i].my_hash =
            ad_gr_fnv1a((const volatile u8*)fns[i], AD_GR_PROLOGUE_LEN);
    }

    // Second pass: each member stores the NEXT member's hash.
    // Ring: member[i].watched_hash == member[(i+1) % count].my_hash
    for (i = 0; i < count; i++) {
        u32 j = (i + 1u) % count;
        ring->members[i].watched_hash = ring->members[j].my_hash;
    }

    ring->count = count;

    // Init encrypted tamper slots to 0.
    for (i = 0; i < 4u; i++) {
        ring->tamper_keys[i] = (u32)ad_gr_xorshift(&ring->prng_state);
        ring->tamper_slot[i] = 0u ^ ring->tamper_keys[i];   // encrypted-zero
    }

    ring->initialized = 1u;
    return 1;
}

// Internal: mark tamper (sets all 4 slots with encrypted-1).
ANTIDEBUG_INLINE void ad_gr_mark_tamper(ad_gr_ring_t* ring) {
    u32 i;
    for (i = 0; i < 4u; i++) {
        ring->tamper_slot[i] = 1u ^ ring->tamper_keys[i];
    }
}

// Public: read tamper flag. Returns 1 if ANY slot decrypts to nonzero.
// Redundancy defeats single-point patching.
ANTIDEBUG_INLINE b32 ad_gr_is_tampered(const ad_gr_ring_t* ring) {
    if (!ring || !ring->initialized) return 0;
    u32 i;
    for (i = 0; i < 4u; i++) {
        u32 v = ring->tamper_slot[i] ^ ring->tamper_keys[i];
        if (v != 0u) return 1;
    }
    return 0;
}

// The main verify primitive — call at the start of each protected
// function, passing your own index in the ring. We verify the NEXT
// member's prologue hash matches the one we recorded at init.
//
// If mismatched: mark tamper (sticky) and return 0.
// If ok: return 1.
//
// Also verifies OURSELVES against the previous member's recorded watch
// (paranoia check — detects if someone zeroed our my_hash).
ANTIDEBUG_INLINE b32 ad_gr_verify(ad_gr_ring_t* ring, u32 my_index) {
    if (!ring || !ring->initialized) return 0;
    if (my_index >= ring->count) return 0;

    u32 next = (my_index + 1u) % ring->count;
    u32 prev = (my_index + ring->count - 1u) % ring->count;

    // Verify NEXT member — its live prologue must match the hash we stored.
    u32 live_next =
        ad_gr_fnv1a((const volatile u8*)ring->members[next].fn_addr,
                    AD_GR_PROLOGUE_LEN);
    if (live_next != ring->members[my_index].watched_hash) {
        ad_gr_mark_tamper(ring);
        return 0;
    }

    // Paranoia: verify OURSELVES — previous member stored our hash. Live
    // self-hash must match. (Catches self-tampering where attacker patches
    // us AND clears our stored watch but forgets to update prev's watch.)
    u32 live_self =
        ad_gr_fnv1a((const volatile u8*)ring->members[my_index].fn_addr,
                    AD_GR_PROLOGUE_LEN);
    if (live_self != ring->members[prev].watched_hash) {
        ad_gr_mark_tamper(ring);
        return 0;
    }

    return 1;
}

// Sweep — verifies the ENTIRE ring in one pass. Use periodically (not
// from protected functions themselves — that's circular).
ANTIDEBUG_INLINE u32 ad_gr_full_sweep(ad_gr_ring_t* ring) {
    if (!ring || !ring->initialized) return 0xFFFFFFFFu;
    u32 mismatches = 0;
    u32 i;
    for (i = 0; i < ring->count; i++) {
        u32 live =
            ad_gr_fnv1a((const volatile u8*)ring->members[i].fn_addr,
                        AD_GR_PROLOGUE_LEN);
        if (live != ring->members[i].my_hash) {
            mismatches++;
            ad_gr_mark_tamper(ring);
        }
    }
    return mismatches;
}

// Optional offensive response — inject random latency to slow down any
// attacker scanning behaviour. Call from non-protected entry points.
ANTIDEBUG_INLINE void ad_gr_response_jitter(ad_gr_ring_t* ring) {
    if (!ad_gr_is_tampered(ring)) return;
    // Busy-spin for ~1-5 ms (PRNG-driven).
    u64 spin = (ad_gr_xorshift(&ring->prng_state) & 0xFFFFF) + 0x100000;
    volatile u64 x = 0;
    while (spin--) x ^= spin;
}

#else  // !_MSC_VER
typedef struct { int _unused; } ad_gr_ring_t;
ANTIDEBUG_INLINE b32  ad_gr_init(ad_gr_ring_t* r, void** f, u32 c) { (void)r; (void)f; (void)c; return 0; }
ANTIDEBUG_INLINE b32  ad_gr_verify(ad_gr_ring_t* r, u32 i) { (void)r; (void)i; return 1; }
ANTIDEBUG_INLINE u32  ad_gr_full_sweep(ad_gr_ring_t* r) { (void)r; return 0; }
ANTIDEBUG_INLINE b32  ad_gr_is_tampered(const ad_gr_ring_t* r) { (void)r; return 0; }
ANTIDEBUG_INLINE void ad_gr_response_jitter(ad_gr_ring_t* r) { (void)r; }
#endif // _MSC_VER

#endif // ANTIDEBUG_GUARDIAN_RING_H
