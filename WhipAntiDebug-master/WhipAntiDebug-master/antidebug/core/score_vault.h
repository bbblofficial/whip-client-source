// ===== file: antidebug/core/score_vault.h =====
//
// Encrypted interim score accumulation.
//
// Problem:
//   During the dispatcher check loop, the score is accumulated in
//   plaintext. A reverser who breakpoints between checks can see the
//   score variable in the watch window and patch it to 0, defeating
//   all detection. Even a single "mov [score], 0" gadget is enough.
//
// Solution:
//   The score is stored as (cipher, key) where cipher = score ^ key.
//   After each ad_score_vault_add(), the key rotates via an LCG seeded
//   from RDTSC — so the (cipher, key) pair is different every time.
//
//   The score only exists decrypted for ~3 instructions between the
//   XOR-decrypt and XOR-reencrypt. A reverser who patches cipher to 0
//   gets garbage because the key has already rotated. They'd need to
//   patch BOTH cipher and key to a matching pair — but the "correct"
//   pair for score=0 changes every cycle.
//
//   Key rotation: new_key = old_key * 6364136223846793005 + (__rdtsc() | 1)
//   If key ever becomes 0 (astronomically unlikely), force it to a
//   sentinel value so cipher != plaintext.
//
#ifndef ANTIDEBUG_SCORE_VAULT_H
#define ANTIDEBUG_SCORE_VAULT_H

#include "types.h"
#include "macros.h"

#if defined(_MSC_VER)
#  include <intrin.h>
#endif

// ---------------------------------------------------------------------------
// Sentinel key — used if RDTSC-based rotation ever produces key == 0
// ---------------------------------------------------------------------------
#define AD_VAULT_DEAD_KEY   0xDEADFACECAFEBABEULL

// ---------------------------------------------------------------------------
// LCG multiplier (Knuth's constant for 64-bit LCG)
// ---------------------------------------------------------------------------
#define AD_VAULT_LCG_MULT   6364136223846793005ULL

// ---------------------------------------------------------------------------
// Score vault state
// ---------------------------------------------------------------------------
typedef struct {
    volatile u64 cipher;    // score XOR key
    volatile u64 key;       // rotating key
} ad_score_vault_t;

// ---------------------------------------------------------------------------
// ad_score_vault_init — seed key from RDTSC, set cipher = 0 ^ key
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE void ad_score_vault_init(ad_score_vault_t* sv) {
#if defined(_MSC_VER)
    u64 k = __rdtsc();
    if (k == 0) k = AD_VAULT_DEAD_KEY;
    AD_BARRIER();
    sv->key    = k;
    AD_BARRIER();
    sv->cipher = 0ULL ^ k;   // score=0 encrypted
    AD_BARRIER();
#else
    sv->key    = AD_VAULT_DEAD_KEY;
    sv->cipher = 0ULL ^ AD_VAULT_DEAD_KEY;
#endif
}

// ---------------------------------------------------------------------------
// ad_score_vault_add — decrypt, add points, rotate key, re-encrypt
//
// The plaintext score exists for exactly 3 operations:
//   1. XOR-decrypt:  score = cipher ^ key
//   2. ADD:          score += points
//   3. XOR-encrypt:  cipher = score ^ new_key
//
// Key rotation uses an LCG with RDTSC addend to ensure each cycle
// produces a unique key. Even replaying the same binary at the same
// instruction will get a different RDTSC value.
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE void ad_score_vault_add(ad_score_vault_t* sv, u32 points) {
#if defined(_MSC_VER)
    AD_BARRIER();
    // Decrypt
    volatile u64 score = sv->cipher ^ sv->key;
    AD_BARRIER();

    // Add points
    score += (u64)points;
    AD_BARRIER();

    // Rotate key: LCG with RDTSC entropy
    volatile u64 new_key = sv->key * AD_VAULT_LCG_MULT + (__rdtsc() | 1ULL);
    if (new_key == 0) new_key = AD_VAULT_DEAD_KEY;
    AD_BARRIER();

    // Re-encrypt with new key
    sv->cipher = score ^ new_key;
    AD_BARRIER();
    sv->key = new_key;
    AD_BARRIER();
#else
    AD_BARRIER();
    volatile u64 score = sv->cipher ^ sv->key;
    score += (u64)points;
    volatile u64 new_key = sv->key * AD_VAULT_LCG_MULT + 1ULL;
    if (new_key == 0) new_key = AD_VAULT_DEAD_KEY;
    sv->cipher = score ^ new_key;
    sv->key = new_key;
    AD_BARRIER();
#endif
}

// ---------------------------------------------------------------------------
// ad_score_vault_read — decrypt and return current score as u32
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE u32 ad_score_vault_read(ad_score_vault_t* sv) {
    AD_BARRIER();
    volatile u64 score = sv->cipher ^ sv->key;
    AD_BARRIER();
    return (u32)score;
}

// ---------------------------------------------------------------------------
// ad_score_vault_reset — re-init with a fresh key (score back to 0)
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE void ad_score_vault_reset(ad_score_vault_t* sv) {
    ad_score_vault_init(sv);
}

#endif // ANTIDEBUG_SCORE_VAULT_H
