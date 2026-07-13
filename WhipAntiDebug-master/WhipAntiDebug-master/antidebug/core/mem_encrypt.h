// ===== file: antidebug/core/mem_encrypt.h =====
//
// Runtime memory value encryption for anti-debug framework.
//
// Problem:
//   Sensitive values (suspicion scores, check results, PRNG state, thresholds)
//   live in plaintext in memory. A reverse engineer with a memory scanner
//   (Cheat Engine, x64dbg memory view) can locate and patch them.
//
// Solution:
//   - All sensitive values are stored XOR'd with a runtime key
//   - The key is derived from RDTSC at init time (unique per-run)
//   - Read/write go through encrypt/decrypt accessors
//   - The key itself is split across two variables (key_lo ^ key_hi)
//     so a single memory read doesn't reveal it
//
// Design:
//   ad_vault_t wraps a u64 value. To store: val ^ effective_key.
//   To read: stored ^ effective_key. The effective key is reconstructed
//   from two halves each time (never materialized as a single value in memory).
//
#ifndef ANTIDEBUG_MEM_ENCRYPT_H
#define ANTIDEBUG_MEM_ENCRYPT_H

#include "types.h"
#include "macros.h"
#include "config.h"

// ---------------------------------------------------------------------------
// Key context — one per ad_state_t, initialized once
//
// The effective key is (key_lo ^ key_hi). Both halves are stored separately
// so no single memory read reveals the full key.
// ---------------------------------------------------------------------------
typedef struct {
    volatile u64 key_lo;
    volatile u64 key_hi;
} ad_memkey_t;

// Initialize the memory encryption key from RDTSC entropy
ANTIDEBUG_INLINE void ad_memkey_init(ad_memkey_t* mk) {
#if defined(_MSC_VER)
    u64 tsc1 = __rdtsc();
    AD_LFENCE();
    u64 tsc2 = __rdtsc();
    // Mix both samples — tsc2-tsc1 adds noise from pipeline timing
    u64 full = tsc1 ^ (tsc2 << 32) ^ (tsc2 >> 32) ^ 0xBADC0FFEE0DDF00DULL;
#else
    u64 full = 0xDEADBEEFCAFEBABEULL;
#endif
    // Split into two halves with different bit rotations
    mk->key_lo = full ^ (full >> 17);
    mk->key_hi = full ^ (full << 23) ^ 0x1337CAFE42424242ULL;
}

// Reconstruct the effective key (never stored as a single value)
ANTIDEBUG_INLINE u64 ad_memkey_get(const ad_memkey_t* mk) {
    volatile u64 lo = mk->key_lo;
    AD_BARRIER();
    volatile u64 hi = mk->key_hi;
    return lo ^ hi;
}

// ---------------------------------------------------------------------------
// Encrypted value container — "vault"
//
// Stores a u64 value XOR'd with the memory key.
// All reads/writes go through ad_vault_store / ad_vault_load.
// ---------------------------------------------------------------------------
typedef struct {
    volatile u64 cipher;   // stored value: plaintext ^ key
} ad_vault_t;

// Store a value into the vault (encrypts)
ANTIDEBUG_INLINE void ad_vault_store(ad_vault_t* v, u64 val, const ad_memkey_t* mk) {
    u64 k = ad_memkey_get(mk);
    AD_BARRIER();
    v->cipher = val ^ k;
}

// Load a value from the vault (decrypts)
ANTIDEBUG_INLINE u64 ad_vault_load(const ad_vault_t* v, const ad_memkey_t* mk) {
    u64 k = ad_memkey_get(mk);
    AD_BARRIER();
    return v->cipher ^ k;
}

// Store a u32 value (zero-extends to u64 internally)
ANTIDEBUG_INLINE void ad_vault_store32(ad_vault_t* v, u32 val, const ad_memkey_t* mk) {
    ad_vault_store(v, (u64)val, mk);
}

// Load as u32 (truncates from u64)
ANTIDEBUG_INLINE u32 ad_vault_load32(const ad_vault_t* v, const ad_memkey_t* mk) {
    return (u32)ad_vault_load(v, mk);
}

// ---------------------------------------------------------------------------
// Encrypted result structure — replaces plaintext ad_result_t
//
// Each field is individually encrypted. A memory dump shows random-looking
// values that change every run (different RDTSC key).
// ---------------------------------------------------------------------------
typedef struct {
    ad_vault_t score;
    ad_vault_t checks_run;
    ad_vault_t checks_hit;
    ad_vault_t check_mask;
} ad_enc_result_t;

// Convert plaintext result → encrypted result
ANTIDEBUG_INLINE void ad_result_encrypt(
    ad_enc_result_t* enc,
    const ad_result_t* plain,
    const ad_memkey_t* mk
) {
    ad_vault_store32(&enc->score,      plain->score,      mk);
    ad_vault_store32(&enc->checks_run, plain->checks_run, mk);
    ad_vault_store32(&enc->checks_hit, plain->checks_hit, mk);
    ad_vault_store32(&enc->check_mask, plain->check_mask, mk);
}

// Convert encrypted result → plaintext result (on the stack, temporary)
ANTIDEBUG_INLINE ad_result_t ad_result_decrypt(
    const ad_enc_result_t* enc,
    const ad_memkey_t* mk
) {
    ad_result_t r;
    r.score      = ad_vault_load32(&enc->score,      mk);
    r.checks_run = ad_vault_load32(&enc->checks_run, mk);
    r.checks_hit = ad_vault_load32(&enc->checks_hit, mk);
    r.check_mask = ad_vault_load32(&enc->check_mask, mk);
    return r;
}

// ---------------------------------------------------------------------------
// Encrypted PRNG state
//
// The PRNG state is a high-value target: if an attacker reads it, they can
// predict skip patterns and score noise. We encrypt it in memory.
// ---------------------------------------------------------------------------
typedef struct {
    ad_vault_t state;
} ad_enc_prng_t;

ANTIDEBUG_INLINE u64 ad_enc_prng_next(ad_enc_prng_t* rng, const ad_memkey_t* mk) {
    u64 x = ad_vault_load(&rng->state, mk);
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    ad_vault_store(&rng->state, x, mk);
    return x;
}

ANTIDEBUG_INLINE void ad_enc_prng_init(ad_enc_prng_t* rng, const ad_memkey_t* mk) {
#if defined(_MSC_VER)
    u64 tsc = __rdtsc();
#else
    u64 tsc = 0;
#endif
    u64 seed = (u64)AD_PRNG_SEED ^ tsc;
    if (seed == 0ULL) seed = 0xDEADC0FFEE1337ABULL;
    // Warm up
    seed ^= seed << 13; seed ^= seed >> 7; seed ^= seed << 17;
    seed ^= seed << 13; seed ^= seed >> 7; seed ^= seed << 17;
    ad_vault_store(&rng->state, seed, mk);
}

ANTIDEBUG_INLINE b32 ad_enc_prng_should_skip(ad_enc_prng_t* rng, const ad_memkey_t* mk) {
    u64 r = ad_enc_prng_next(rng, mk);
    return (b32)((r & 0xFULL) < (u64)AD_SKIP_PROBABILITY);
}

// ---------------------------------------------------------------------------
// Pointer vault — encrypt pointers stored in memory
//
// Decoy table addresses, image base, etc. are stored XOR'd.
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE void ad_vault_store_ptr(ad_vault_t* v, void* ptr, const ad_memkey_t* mk) {
    ad_vault_store(v, (u64)(unsigned long long)ptr, mk);
}

ANTIDEBUG_INLINE void* ad_vault_load_ptr(const ad_vault_t* v, const ad_memkey_t* mk) {
    return (void*)(unsigned long long)ad_vault_load(v, mk);
}

// ---------------------------------------------------------------------------
// Encrypted decoy table — requires moonwalk.h to be included BEFORE this
// section is used. Guard with ANTIDEBUG_MOONWALK_H to avoid compile errors
// when mem_encrypt.h is included from dispatcher.h (which doesn't need it).
// ---------------------------------------------------------------------------
#ifdef ANTIDEBUG_MOONWALK_H

typedef struct {
    ad_vault_t addrs[8];    // AD_DECOY_TABLE_SIZE encrypted pointers
    ad_vault_t count;
    b32        ready;
} ad_enc_decoy_table_t;

ANTIDEBUG_INLINE void ad_enc_decoy_table_init(
    ad_enc_decoy_table_t* etbl,
    const ad_decoy_table_t* plain,
    const ad_memkey_t* mk
) {
    u32 i;
    for (i = 0; i < plain->count && i < 8u; i++) {
        ad_vault_store_ptr(&etbl->addrs[i], plain->addrs[i], mk);
    }
    ad_vault_store32(&etbl->count, plain->count, mk);
    etbl->ready = plain->ready;
}

ANTIDEBUG_INLINE void* ad_enc_pick_decoy(
    const ad_enc_decoy_table_t* etbl,
    u32 n,
    const ad_memkey_t* mk
) {
    if (!etbl->ready) return (void*)0;
    u32 cnt = ad_vault_load32(&etbl->count, mk);
    if (cnt == 0) return (void*)0;
    return ad_vault_load_ptr(&etbl->addrs[n % cnt], mk);
}

#endif // ANTIDEBUG_MOONWALK_H

#endif // ANTIDEBUG_MEM_ENCRYPT_H
