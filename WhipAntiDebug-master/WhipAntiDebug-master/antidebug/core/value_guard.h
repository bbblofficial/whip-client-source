// ===== file: antidebug/core/value_guard.h =====
//
// Runtime value protection for anti-debug framework.
//
// Problems solved:
//
//   1. CONSTANT LEAKAGE: Thresholds like 2000, 200000, 3000 appear as
//      immediate operands in disassembly (mov eax, 0x7D0; cmp ...).
//      A reverser patches the CMP to always pass.
//
//   2. MEMORY SCANNING: Tools like Cheat Engine search for known values
//      (e.g. scan for int 2000). If found → patch to 0xFFFFFFFF → bypass.
//
//   3. VALUE INTEGRITY: An attacker modifies score/counter values in memory
//      between checks to keep them below the detection threshold.
//
// Solutions:
//
//   AD_CONST_DERIVE: Derive a constant at runtime from two compile-time
//   halves. The real value never appears as a single immediate.
//     e.g. 2000 = (0x03F2 ^ 0x048A) + (0x03F2 & 0x048A)
//     The compiler can't fold this because volatile blocks optimization.
//
//   ad_guarded_u32 / ad_guarded_u64: Store values XOR'd with a rotating
//   key that changes on every write. A Cheat Engine scan for "2000" finds
//   nothing because the stored value is 2000 ^ random_key, and the key
//   changes each time the value is updated.
//
//   AD_OPAQUE_CMP: Compare values through arithmetic instead of direct CMP.
//   Harder to find and patch in disassembly.
//
#ifndef ANTIDEBUG_VALUE_GUARD_H
#define ANTIDEBUG_VALUE_GUARD_H

#include "types.h"
#include "macros.h"

// ---------------------------------------------------------------------------
// Compile-time constant splitting
//
// Given a constant C and a mask M, we store (C ^ M) and M separately.
// At runtime: value = (C ^ M) ^ M = C. But the immediate (C ^ M) in the
// binary is meaningless without knowing M.
//
// Usage:
//   u64 threshold = AD_CONST_DERIVE64(0x07D0, 0xDEAD);
//   // Binary contains 0xD97D and 0xDEAD, not 0x07D0 (2000)
// ---------------------------------------------------------------------------

// 64-bit derive: two halves XOR'd together at runtime via volatile to
// prevent constant folding by the optimizer.
#define AD_CONST_DERIVE64(encoded, mask)                    \
    ({                                                      \
        volatile u64 _e = (u64)(encoded);                   \
        volatile u64 _m = (u64)(mask);                      \
        (u64)(_e ^ _m);                                     \
    })

// MSVC C doesn't support GCC statement expressions ({...}).
// Use an inline function instead.
ANTIDEBUG_INLINE u64 ad_derive64(u64 encoded, u64 mask) {
    volatile u64 e = encoded;
    AD_BARRIER();
    volatile u64 m = mask;
    AD_BARRIER();
    return e ^ m;
}

ANTIDEBUG_INLINE u32 ad_derive32(u32 encoded, u32 mask) {
    volatile u32 e = encoded;
    AD_BARRIER();
    volatile u32 m = mask;
    AD_BARRIER();
    return e ^ m;
}

// ---------------------------------------------------------------------------
// Pre-computed encoded threshold constants
//
// For each threshold T, we pick a random mask M and store (T ^ M, M).
// The real value is NEVER an immediate in the binary.
//
// T=2000  (0x7D0):  M=0xA5B3C7E1 → encoded = 0x7D0 ^ 0xA5B3C7E1 = 0xA5B3C031
// T=20    (0x14):   M=0x3F91E7D2 → encoded = 0x14 ^ 0x3F91E7D2  = 0x3F91E7C6
// T=800   (0x320):  M=0x7C4B18F0 → encoded = 0x320 ^ 0x7C4B18F0 = 0x7C4B1BD0
// T=200000(0x30D40):M=0xF1E2D3C4 → encoded = 0x30D40^0xF1E2D3C4= 0xF1E3FE84
// T=3000  (0xBB8):  M=0x58A6C2F9 → encoded = 0xBB8^0x58A6C2F9  = 0x58A6C941
// T=5000  (0x1388): M=0x2D4E6F8A → encoded = 0x1388^0x2D4E6F8A= 0x2D4E7C02
// T=128   (0x80):   M=0x1B3D5F7E → encoded = 0x80^0x1B3D5F7E   = 0x1B3D5FFE
// T=0x2000:         M=0xC9A8B7D6 → encoded = 0x2000^0xC9A8B7D6 = 0xC9A897D6
// ---------------------------------------------------------------------------

// RDTSC step threshold (real value: 5000 = 0x1388; 0x1388^0xA5B3C7E1=0xA5B3D469)
#define AD_ENC_RDTSC_STEP       0xA5B3D469UL
#define AD_MASK_RDTSC_STEP      0xA5B3C7E1UL

// RDTSC double-read threshold (real value: 1000 = 0x3E8; 0x3E8^0x3F91E7D2=0x3F91E43A)
#define AD_ENC_RDTSC_DOUBLE     0x3F91E43AUL
#define AD_MASK_RDTSC_DOUBLE    0x3F91E7D2UL

// Loop iteration count (real value: 800)
#define AD_ENC_LOOP_ITER        0x7C4B1BD0UL
#define AD_MASK_LOOP_ITER       0x7C4B18F0UL

// Loop cycle threshold (real value: 200000)
#define AD_ENC_LOOP_CYCLE       0xF1E3FE84UL
#define AD_MASK_LOOP_CYCLE      0xF1E2D3C4UL

// VM RDTSC overhead threshold (real value: 3000)
#define AD_ENC_VM_RDTSC         0x58A6C941UL
#define AD_MASK_VM_RDTSC        0x58A6C2F9UL

// QPC threshold (real value: 5000)
#define AD_ENC_QPC              0x2D4E7C02UL
#define AD_MASK_QPC             0x2D4E6F8AUL

// INT3 scan range (real value: 128)
#define AD_ENC_INT3_RANGE       0x1B3D5FFEUL
#define AD_MASK_INT3_RANGE      0x1B3D5F7EUL

// Code hash region size (real value: 0x2000)
#define AD_ENC_CODE_HASH_SIZE   0xC9A897D6UL
#define AD_MASK_CODE_HASH_SIZE  0xC9A8B7D6UL

// Convenience macros to get the real value at runtime
#define AD_GET_RDTSC_STEP()     ad_derive32(AD_ENC_RDTSC_STEP,    AD_MASK_RDTSC_STEP)
#define AD_GET_RDTSC_DOUBLE()   ad_derive32(AD_ENC_RDTSC_DOUBLE,  AD_MASK_RDTSC_DOUBLE)
#define AD_GET_LOOP_ITER()      ad_derive32(AD_ENC_LOOP_ITER,     AD_MASK_LOOP_ITER)
#define AD_GET_LOOP_CYCLE()     ad_derive32(AD_ENC_LOOP_CYCLE,    AD_MASK_LOOP_CYCLE)
#define AD_GET_VM_RDTSC()       ad_derive32(AD_ENC_VM_RDTSC,      AD_MASK_VM_RDTSC)
#define AD_GET_QPC()            ad_derive32(AD_ENC_QPC,            AD_MASK_QPC)
#define AD_GET_INT3_RANGE()     ad_derive32(AD_ENC_INT3_RANGE,    AD_MASK_INT3_RANGE)
#define AD_GET_CODE_HASH_SIZE() ad_derive32(AD_ENC_CODE_HASH_SIZE,AD_MASK_CODE_HASH_SIZE)

// ---------------------------------------------------------------------------
// Guarded integer — anti-scan, anti-patch
//
// Stores a u32/u64 XOR'd with a key that ROTATES on every write.
// Cheat Engine scanning for a known value (e.g. "2") finds nothing
// because the memory contains 2 ^ key, and key changes each write.
//
// Integrity: a MAC tag (truncated FNV hash of value + key) detects
// if someone patches the stored cipher directly.
// ---------------------------------------------------------------------------
typedef struct {
    volatile u32 cipher;    // value ^ key
    volatile u32 key;       // current XOR key
    volatile u32 mac;       // integrity tag: fnv(value, key)
} ad_guarded_u32;

typedef struct {
    volatile u64 cipher;
    volatile u64 key;
    volatile u32 mac;
} ad_guarded_u64;

// Simple fast MAC: FNV-1a folded to 32 bits
ANTIDEBUG_INLINE u32 ad_value_mac32(u64 value, u64 key) {
    u64 h = 0xCBF29CE484222325ULL;
    h ^= value;       h *= 0x00000100000001B3ULL;
    h ^= key;         h *= 0x00000100000001B3ULL;
    h ^= (value >> 32); h *= 0x00000100000001B3ULL;
    return (u32)(h ^ (h >> 32));
}

// Rotate key using RDTSC entropy + LCG
ANTIDEBUG_INLINE u64 ad_rotate_key(u64 old_key) {
#if defined(_MSC_VER)
    u64 tsc = __rdtsc();
#else
    u64 tsc = 0x1234567890ABCDEFULL;
#endif
    // LCG step with TSC noise
    u64 k = old_key * 6364136223846793005ULL + (tsc | 1ULL);
    // Ensure key is never zero
    if (k == 0ULL) k = 0xDEADFACECAFEBABEULL;
    return k;
}

// ── ad_guarded_u32 operations ───────────────────────────────────────────

ANTIDEBUG_INLINE void ad_guard32_init(ad_guarded_u32* g) {
    u64 k64 = ad_rotate_key(0xA5A5A5A5A5A5A5A5ULL);
    g->key    = (u32)k64;
    g->cipher = 0u ^ g->key;
    g->mac    = ad_value_mac32(0, (u64)g->key);
}

ANTIDEBUG_INLINE void ad_guard32_store(ad_guarded_u32* g, u32 value) {
    // Rotate key for this write
    u64 new_key = ad_rotate_key((u64)g->key);
    g->key    = (u32)new_key;
    AD_BARRIER();
    g->cipher = value ^ g->key;
    g->mac    = ad_value_mac32((u64)value, (u64)g->key);
}

ANTIDEBUG_INLINE u32 ad_guard32_load(const ad_guarded_u32* g) {
    u32 k = g->key;
    AD_BARRIER();
    u32 c = g->cipher;
    u32 value = c ^ k;

    // Verify integrity — if someone patched cipher directly, MAC fails
    u32 expected_mac = ad_value_mac32((u64)value, (u64)k);
    if (expected_mac != g->mac) {
        // Tampered! Return a poisoned value that will trigger detection
        return 0xFFFFFFFFu;
    }
    return value;
}

// ── ad_guarded_u64 operations ───────────────────────────────────────────

ANTIDEBUG_INLINE void ad_guard64_init(ad_guarded_u64* g) {
    g->key    = ad_rotate_key(0xB6B6B6B6B6B6B6B6ULL);
    g->cipher = 0ULL ^ g->key;
    g->mac    = ad_value_mac32(0, g->key);
}

ANTIDEBUG_INLINE void ad_guard64_store(ad_guarded_u64* g, u64 value) {
    g->key    = ad_rotate_key(g->key);
    AD_BARRIER();
    g->cipher = value ^ g->key;
    g->mac    = ad_value_mac32(value, g->key);
}

ANTIDEBUG_INLINE u64 ad_guard64_load(const ad_guarded_u64* g) {
    u64 k = g->key;
    AD_BARRIER();
    u64 c = g->cipher;
    u64 value = c ^ k;

    u32 expected_mac = ad_value_mac32(value, k);
    if (expected_mac != g->mac) {
        return 0xFFFFFFFFFFFFFFFFULL;
    }
    return value;
}

// ---------------------------------------------------------------------------
// Opaque comparison — avoid obvious CMP instruction patterns
//
// Instead of: if (delta > threshold)
// We use:     if (ad_opaque_gt(delta, threshold))
//
// This compiles to arithmetic, not a simple CMP+JA that a reverser
// can find by searching for "cmp rax, 0x7D0".
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE b32 ad_opaque_gt_u64(u64 a, u64 b) {
    // (a - b - 1) won't underflow if a > b
    // We check the sign bit of the subtraction result
    volatile u64 va = a;
    volatile u64 vb = b;
    AD_BARRIER();
    u64 diff = va - vb;
    // If a > b, diff is in [1, 2^64-1], and (diff - 1) doesn't wrap
    // If a <= b, diff is 0 or wraps to a huge number
    // Use sign-bit check: if a <= b, diff-1 has bit 63 set (wrapped) or diff is 0
    u64 not_zero = (diff | (~diff + 1ULL)) >> 63;  // 1 if diff != 0
    u64 no_wrap  = ~(diff >> 63);                    // 1 if diff didn't wrap (a >= b)
    return (b32)(not_zero & no_wrap & 1ULL);
}

ANTIDEBUG_INLINE b32 ad_opaque_gt_u32(u32 a, u32 b) {
    volatile u32 va = a;
    volatile u32 vb = b;
    AD_BARRIER();
    u32 diff = va - vb;
    u32 not_zero = (diff | (~diff + 1u)) >> 31;
    u32 no_wrap  = ~(diff >> 31);
    return (b32)(not_zero & no_wrap & 1u);
}

#endif // ANTIDEBUG_VALUE_GUARD_H
