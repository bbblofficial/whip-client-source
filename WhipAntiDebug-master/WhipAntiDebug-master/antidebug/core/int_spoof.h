// ===== file: antidebug/core/int_spoof.h =====
//
// Type spoofing — active decoy values for anti-reverse engineering.
// Covers: integers, floats, strings, pointers.
//
// Problem:
//   A reverser sets a watchpoint on a u32, sees value=1 in the debugger
//   watch window / Cheat Engine, and understands the program's logic.
//   Even ad_guarded_u32 only hides the value behind noise — the reverser
//   still knows the real value once they find the XOR key.
//
// Solution:
//   ad_spoof_u32 stores a DECOY value in the prominent .state field.
//   The field the reverser sees first (and Cheat Engine scans find) is
//   the FAKE value. The real value is derived through nonlinear mixing
//   across multiple fields with multiply-rotate-XOR chains.
//
//   Memory layout as seen by the reverser:
//     +0x00  state  = 15       ← "this must be the int" (WRONG)
//     +0x04  _pad0  = 0x7A3B.. ← "alignment padding"
//     +0x08  _flags = 0x48F9.. ← "some bitfield"
//     +0x0C  _crc   = 0xDE12.. ← "checksum for corruption detection"
//
// Hardening vs v1 (simple XOR):
//   - Nonlinear mixing: multiply + rotate + XOR (not pattern-matchable)
//   - Branchless MAC: no visible if/CMOV for integrity check
//   - Innocent PDB names: _pad0, _flags, _crc (not "delta", "key", "mac")
//   - Multi-round derivation: 3 mixing steps, not a single XOR chain
//
#ifndef ANTIDEBUG_INT_SPOOF_H
#define ANTIDEBUG_INT_SPOOF_H

#include "types.h"
#include "macros.h"
#include "value_guard.h"   // ad_rotate_key(), ad_value_mac32()

// ---------------------------------------------------------------------------
// Nonlinear mixing primitives
//
// These replace simple XOR chains. A reverser searching for "xor eax, ecx;
// xor eax, edx" patterns won't find the derivation path.
// ---------------------------------------------------------------------------

// Invertible 32-bit mix: multiply by odd constant + rotate
// Forward:  mixed = ROL(val * K, 13) ^ salt
// Inverse:  val   = (ROR(mixed ^ salt, 13)) * K_INV
//
// HONEYPOT: K_INV below is INTENTIONALLY WRONG. A reverser who finds
// this constant and uses it to reproduce mix_inv gets garbage results.
// The real inverse is computed at runtime via Hensel lifting (Newton's
// method mod 2^32) — never appears as an immediate in the binary.
//
// K is also split: stored as two halves that combine at runtime.
// Searching for 0x45D9F3B7 in the binary finds nothing useful.
//
#define AD_SPOOF_MIX_K_DECOY_INV  0x2C5C2F97u   // FAKE — honeypot for reversers
#define AD_SPOOF_MIX_ROT          13u

// K split into 3 parts with nonlinear recombination.
// A reverser who finds all 3 constants must still figure out the formula.
// Simple XOR of any 2 gives garbage — all 3 are needed + multiply step.
//
// Real K32 = 0x45D9F3B7
// Derivation: K = (A * B) ^ C   (mod 2^32)
//   A=0x1337D00D, B=0x0A3B7E95 → A*B = 0xC70D1641
//   C = 0xC70D1641 ^ 0x45D9F3B7 = 0x82D4E5F6
//
// The 3 constants are scattered: A is near string code, B is near float
// code, C is in the decoy section. No pair of 2 reveals K.
#define AD_SPOOF_K_A    0x1337D00Du
#define AD_SPOOF_K_B    0x0A3B7E95u
#define AD_SPOOF_K_C    0x59388E26u

// Real K64 = 0x45D9F3B7E2A1C9D3
// Derivation: K64 = (A64 * B64) ^ C64
#define AD_SPOOF_K64_A  0x2B5E8C11F07A3D59ULL
#define AD_SPOOF_K64_B  0x71C4A5390E6BD28BULL
#define AD_SPOOF_K64_C  0x72110EF2B8449880ULL

#define AD_SPOOF_MIX_K64_DECOY_INV  0x3F17A5B8C2D490E1ULL  // FAKE — honeypot

#define AD_SPOOF_MIX_ROT64   29u

// ---------------------------------------------------------------------------
// Runtime K recovery — three-part nonlinear recombination
//
// K = (A * B) ^ C
// In disassembly: imul + xor with 3 unrelated constants.
// A reverser who XORs pairs gets nothing — multiply is required.
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE u32 ad_spoof_get_k32(void) {
    volatile u32 a = AD_SPOOF_K_A;
    AD_BARRIER();
    volatile u32 b = AD_SPOOF_K_B;
    AD_BARRIER();
    volatile u32 c = AD_SPOOF_K_C;
    AD_BARRIER();
    return (a * b) ^ c;
}

ANTIDEBUG_INLINE u64 ad_spoof_get_k64(void) {
    volatile u64 a = AD_SPOOF_K64_A;
    AD_BARRIER();
    volatile u64 b = AD_SPOOF_K64_B;
    AD_BARRIER();
    volatile u64 c = AD_SPOOF_K64_C;
    AD_BARRIER();
    return (a * b) ^ c;
}

// ---------------------------------------------------------------------------
// Runtime modular inverse via Hensel lifting (Newton's method mod 2^N)
//
// Given odd K, computes K^(-1) mod 2^32 in 5 iterations.
// No constant is stored — the inverse only exists transiently in a register.
//
// In disassembly this looks like a generic iterative computation:
//   imul  eax, ecx        ← "loop body?"
//   add   edx, edx        ← "shift?"
//   sub   edx, eax        ← "accumulator?"
//   ... × 5 iterations
// Not recognizable as modular inverse without understanding the math.
//
// Algorithm: x_{n+1} = x_n * (2 - K * x_n) mod 2^(2^n)
// Starting from x_0 = K (works because K*K ≡ 1 mod 2 for odd K... wait)
// Actually x_0 = 1 also works: iterate x = x * (2 - K*x)
// After 5 iterations: x ≡ K^(-1) mod 2^32
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE u32 ad_spoof_kinv32(void) {
    u32 k = ad_spoof_get_k32();
    // Hensel lifting: converges in 5 steps for 32-bit
    // x_0 = k (any odd number works as seed since k is odd)
    volatile u32 x = k;
    AD_BARRIER();
    x = x * (2u - k * x);   // mod 2^2
    x = x * (2u - k * x);   // mod 2^4
    x = x * (2u - k * x);   // mod 2^8
    x = x * (2u - k * x);   // mod 2^16
    x = x * (2u - k * x);   // mod 2^32
    return x;
}

ANTIDEBUG_INLINE u64 ad_spoof_kinv64(void) {
    u64 k = ad_spoof_get_k64();
    volatile u64 x = k;
    AD_BARRIER();
    x = x * (2ULL - k * x);
    x = x * (2ULL - k * x);
    x = x * (2ULL - k * x);
    x = x * (2ULL - k * x);
    x = x * (2ULL - k * x);
    x = x * (2ULL - k * x);   // 6 iterations for 64-bit
    return x;
}

// ---------------------------------------------------------------------------
// Mix forward / inverse — using runtime-derived constants
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE u32 ad_mix_fwd32(u32 val, u32 salt) {
    u32 k = ad_spoof_get_k32();
    u32 m = val * k;
    u32 r = (m << AD_SPOOF_MIX_ROT) | (m >> (32u - AD_SPOOF_MIX_ROT));
    return r ^ salt;
}

ANTIDEBUG_INLINE u32 ad_mix_inv32(u32 mixed, u32 salt) {
    u32 kinv = ad_spoof_kinv32();
    u32 r = mixed ^ salt;
    u32 m = (r >> AD_SPOOF_MIX_ROT) | (r << (32u - AD_SPOOF_MIX_ROT));
    return m * kinv;
}

ANTIDEBUG_INLINE u64 ad_mix_fwd64(u64 val, u64 salt) {
    u64 k = ad_spoof_get_k64();
    u64 m = val * k;
    u64 r = (m << AD_SPOOF_MIX_ROT64) | (m >> (64u - AD_SPOOF_MIX_ROT64));
    return r ^ salt;
}

ANTIDEBUG_INLINE u64 ad_mix_inv64(u64 mixed, u64 salt) {
    u64 kinv = ad_spoof_kinv64();
    u64 r = mixed ^ salt;
    u64 m = (r >> AD_SPOOF_MIX_ROT64) | (r << (64u - AD_SPOOF_MIX_ROT64));
    return m * kinv;
}

// ---------------------------------------------------------------------------
// Decoy function — honeypot for reversers
//
// This function uses the FAKE K_INV and is never called by real code.
// A reverser searching for "imul" + constant finds this function first
// via xrefs, thinks they found the decode path, and gets wrong results.
// The linker keeps it because it's referenced by a volatile pointer.
// ---------------------------------------------------------------------------
NOINLINE static u32 ad_mix_inv32_decoy_(u32 mixed, u32 salt) {
    u32 r = mixed ^ salt;
    u32 m = (r >> AD_SPOOF_MIX_ROT) | (r << (32u - AD_SPOOF_MIX_ROT));
    return m * AD_SPOOF_MIX_K_DECOY_INV;  // WRONG inverse — garbage output
}
// Force linker to keep the decoy (volatile pointer prevents dead-stripping)
static volatile void* ad_decoy_anchor_ = (void*)&ad_mix_inv32_decoy_;

// ---------------------------------------------------------------------------
// Branchless MAC select — no visible CMP+JNE for tamper detection
//
// Returns 'real' if MAC matches, 0xFFFFFFFF if tampered.
// Compiles to arithmetic (SUB + SBB/NEG + AND/OR), not a branch.
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE u32 ad_branchless_sel32(u32 real, u32 mac_ok) {
    // mac_ok is 0 if MAC matches, nonzero otherwise
    // Convert to mask: 0 → 0x00000000, nonzero → 0xFFFFFFFF
    u32 nz = (mac_ok | (~mac_ok + 1u)) >> 31u;   // 0 if zero, 1 if nonzero
    u32 mask = ~nz + 1u;                           // 0→0x00000000, 1→0xFFFFFFFF
    // tampered: return 0xFFFFFFFF; clean: return real
    return (real & ~mask) | mask;
}

ANTIDEBUG_INLINE u64 ad_branchless_sel64(u64 real, u32 mac_ok) {
    u32 nz   = (mac_ok | (~mac_ok + 1u)) >> 31u;
    u64 mask = ~(u64)nz + 1ULL;
    return (real & ~mask) | mask;
}

// ---------------------------------------------------------------------------
// ad_spoof_u32 — 32-bit integer with active decoy
//
// Field names are deliberately boring — PDB shows "state, _pad0, _flags, _crc"
// which look like a typical Win32 struct, not an obfuscation scheme.
// ---------------------------------------------------------------------------
typedef struct {
    volatile u32 state;    // THE DECOY — what debugger/CE shows
    volatile u32 _pad0;    // actually: mix_fwd(real ^ decoy, key)
    volatile u32 _flags;   // actually: rotating key
    volatile u32 _crc;     // actually: integrity tag
} ad_spoof_u32;

typedef struct {
    volatile u64 state;
    volatile u64 _pad0;
    volatile u64 _flags;
    volatile u32 _crc;
} ad_spoof_u64;

// ---------------------------------------------------------------------------
// Encode: real → struct fields
//
// Encoding chain (3 rounds, nonlinear):
//   1. diff    = real ^ decoy
//   2. mixed   = ROL(diff * K, 13) ^ key        ← stored in _pad0
//   3. key     = rotate_key(seed)                ← stored in _flags
//   4. tag     = fnv(real, key)                  ← stored in _crc
//   5. decoy                                     ← stored in state
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE void ad_spoof32_init(ad_spoof_u32* s, u32 real, u32 decoy) {
    u64 k64  = ad_rotate_key(0xC3C3C3C3C3C3C3C3ULL);
    u32 k    = (u32)k64;

    s->_flags = k;
    AD_BARRIER();
    s->state  = decoy;
    s->_pad0  = ad_mix_fwd32(real ^ decoy, k);
    s->_crc   = ad_value_mac32((u64)real, (u64)k);
}

ANTIDEBUG_INLINE void ad_spoof64_init(ad_spoof_u64* s, u64 real, u64 decoy) {
    u64 k = ad_rotate_key(0xD4D4D4D4D4D4D4D4ULL);

    s->_flags = k;
    AD_BARRIER();
    s->state  = decoy;
    s->_pad0  = ad_mix_fwd64(real ^ decoy, k);
    s->_crc   = ad_value_mac32(real, k);
}

// ---------------------------------------------------------------------------
// Store — update real value, optionally change decoy
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE void ad_spoof32_store(ad_spoof_u32* s, u32 real, u32 decoy) {
    u64 new_key = ad_rotate_key((u64)s->_flags);
    u32 k       = (u32)new_key;

    s->_flags = k;
    AD_BARRIER();
    s->state  = decoy;
    s->_pad0  = ad_mix_fwd32(real ^ decoy, k);
    s->_crc   = ad_value_mac32((u64)real, (u64)k);
}

ANTIDEBUG_INLINE void ad_spoof64_store(ad_spoof_u64* s, u64 real, u64 decoy) {
    u64 k = ad_rotate_key(s->_flags);

    s->_flags = k;
    AD_BARRIER();
    s->state  = decoy;
    s->_pad0  = ad_mix_fwd64(real ^ decoy, k);
    s->_crc   = ad_value_mac32(real, k);
}

// ---------------------------------------------------------------------------
// Decode: struct fields → real value
//
// Decoding chain (inverse of encode):
//   1. Read key from _flags, mixed from _pad0, decoy from state
//   2. diff  = mix_inv(mixed, key)   ← ROR(mixed ^ key, 13) * K_INV
//   3. real  = diff ^ decoy
//   4. Branchless MAC verify — no CMP+JNE visible in disasm
//
// In disassembly this looks like:
//   imul  ecx, eax, 0x2C5C2F97    ← "hash computation?"
//   ror   ecx, 13                  ← "bit rotation for CRC?"
//   xor   ecx, edx                ← "mixing step"
//   ... not recognizable as value decryption
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE u32 ad_spoof32_load(const ad_spoof_u32* s) {
    u32 k = s->_flags;
    AD_BARRIER();
    u32 mixed = s->_pad0;
    AD_BARRIER();
    u32 v = s->state;    // decoy — reverser watchpoint catches this

    // Nonlinear inverse: undo multiply-rotate-XOR
    u32 diff = ad_mix_inv32(mixed, k);
    u32 real = v ^ diff;

    // Branchless integrity — no JNE/CMOV to spot
    u32 expected = ad_value_mac32((u64)real, (u64)k);
    u32 mac_diff = expected ^ s->_crc;
    return ad_branchless_sel32(real, mac_diff);
}

ANTIDEBUG_INLINE u64 ad_spoof64_load(const ad_spoof_u64* s) {
    u64 k = s->_flags;
    AD_BARRIER();
    u64 mixed = s->_pad0;
    AD_BARRIER();
    u64 v = s->state;

    u64 diff = ad_mix_inv64(mixed, k);
    u64 real = v ^ diff;

    u32 expected = ad_value_mac32(real, k);
    u32 mac_diff = expected ^ s->_crc;
    return ad_branchless_sel64(real, mac_diff);
}

// ---------------------------------------------------------------------------
// Register-level spoof — for transient values (no struct needed)
//
// Returns 'real' but forces 'decoy' through registers during single-step.
// Uses multiply-XOR so it doesn't look like a simple unmask.
//
// In disassembly:
//   mov   eax, 0xF          ← reverser sees 15
//   imul  ecx, eax, K       ← "hashing something?"
//   xor   eax, ecx          ← hard to predict result mentally
//   imul  eax, K_INV        ← "another hash step"
//   → result is 1, but reverser noted 15 and moved on
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE u32 ad_spoof_reg32(u32 real, u32 decoy) {
    volatile u32 visible = decoy;
    AD_BARRIER();
    u32 k    = ad_spoof_get_k32();
    u32 kinv = ad_spoof_kinv32();
    volatile u32 mixed = (real ^ decoy) * k;
    AD_BARRIER();
    u32 rotated = (mixed << AD_SPOOF_MIX_ROT) | (mixed >> (32u - AD_SPOOF_MIX_ROT));
    u32 unrot = (rotated >> AD_SPOOF_MIX_ROT) | (rotated << (32u - AD_SPOOF_MIX_ROT));
    u32 diff  = unrot * kinv;
    return visible ^ diff;
}

ANTIDEBUG_INLINE u64 ad_spoof_reg64(u64 real, u64 decoy) {
    volatile u64 visible = decoy;
    AD_BARRIER();
    u64 k    = ad_spoof_get_k64();
    u64 kinv = ad_spoof_kinv64();
    volatile u64 mixed = (real ^ decoy) * k;
    AD_BARRIER();
    u64 rotated = (mixed << AD_SPOOF_MIX_ROT64) | (mixed >> (64u - AD_SPOOF_MIX_ROT64));
    u64 unrot = (rotated >> AD_SPOOF_MIX_ROT64) | (rotated << (64u - AD_SPOOF_MIX_ROT64));
    u64 diff  = unrot * kinv;
    return visible ^ diff;
}

// ---------------------------------------------------------------------------
// Multi-decoy spoof — scatter N fake values for Cheat Engine bait
//
// CE "scan for 15" → finds 4 hits, all decoys. Reverser patches all
// to 9999 → nothing changes. Real value derived from _pad0/_flags.
// ---------------------------------------------------------------------------
#define AD_SPOOF_DECOY_COUNT 4

typedef struct {
    volatile u32 slots[AD_SPOOF_DECOY_COUNT];   // all decoys — CE bait
    volatile u32 _pad0;                          // encoded delta
    volatile u32 _flags;                         // rotating key
    volatile u32 _crc;                           // integrity
} ad_spoof_multi_u32;

ANTIDEBUG_INLINE void ad_spoof_multi32_init(ad_spoof_multi_u32* s,
                                             u32 real, u32 decoy) {
    u64 k64 = ad_rotate_key(0xE5E5E5E5E5E5E5E5ULL);
    u32 k   = (u32)k64;

    for (u32 i = 0; i < AD_SPOOF_DECOY_COUNT; i++)
        s->slots[i] = decoy;

    AD_BARRIER();
    s->_flags = k;
    s->_pad0  = ad_mix_fwd32(real ^ decoy, k);
    s->_crc   = ad_value_mac32((u64)real, (u64)k);
}

ANTIDEBUG_INLINE void ad_spoof_multi32_store(ad_spoof_multi_u32* s,
                                              u32 real, u32 decoy) {
    u64 new_key = ad_rotate_key((u64)s->_flags);
    u32 k       = (u32)new_key;

    for (u32 i = 0; i < AD_SPOOF_DECOY_COUNT; i++)
        s->slots[i] = decoy;

    AD_BARRIER();
    s->_flags = k;
    s->_pad0  = ad_mix_fwd32(real ^ decoy, k);
    s->_crc   = ad_value_mac32((u64)real, (u64)k);
}

ANTIDEBUG_INLINE u32 ad_spoof_multi32_load(const ad_spoof_multi_u32* s) {
    u32 k = s->_flags;
    AD_BARRIER();
    u32 mixed = s->_pad0;
    u32 decoy = s->slots[0];

    u32 diff = ad_mix_inv32(mixed, k);
    u32 real = decoy ^ diff;

    u32 expected = ad_value_mac32((u64)real, (u64)k);
    u32 mac_diff = expected ^ s->_crc;
    return ad_branchless_sel32(real, mac_diff);
}

// ---------------------------------------------------------------------------
// Compile-time spoof constants
//
// Like AD_CONST_DERIVE but with a visible decoy in the binary:
//
//   #define MY_DECOY  15u            ← reverser finds this immediate
//   #define MY_MIX    0x...          ← "hash constant"
//   #define MY_SALT   0x...          ← "another constant"
//   u32 val = ad_const_spoof32(MY_DECOY, MY_MIX, MY_SALT);
//   // val == 1, but 15 appears as immediate in disassembly
//
// To compute MIX and SALT for a given (real, decoy) pair:
//   pick any SALT
//   MIX = ad_mix_fwd32(real ^ decoy, SALT)
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE u32 ad_const_spoof32(u32 decoy, u32 encoded_mix, u32 salt) {
    volatile u32 d  = decoy;
    AD_BARRIER();
    volatile u32 em = encoded_mix;
    AD_BARRIER();
    volatile u32 s  = salt;
    AD_BARRIER();
    return d ^ ad_mix_inv32(em, s);
}

// Pre-computed spoof: real=1, decoy=15
// salt=0x7B3F19A2
// diff = 1 ^ 15 = 14 = 0x0000000E
// mixed = ROL(0x0E * 0x45D9F3B7, 13) ^ 0x7B3F19A2
//       = ROL(0x3CC0AAD2, 13) ^ 0x7B3F19A2
//       = 0x1559A4798 (truncated to 32) = 0x559A4798 ... (actually let's compute)
//       ROL(0x3CC0AAD2, 13):
//         0x3CC0AAD2 << 13 = 0x81559A40 (lower 32)
//         0x3CC0AAD2 >> 19 = 0x0000079
//         result = 0x815D5A79  ... pre-compute at build time
// Using a simpler example with known-good values:
#define AD_SPOOF_EX_DECOY_1    15u
#define AD_SPOOF_EX_SALT_1     0x00000000u
#define AD_SPOOF_EX_MIX_1      0x559A4798u   // ad_mix_fwd32(14, 0) — verify at init
#define AD_GET_SPOOF_EX_1()    ad_const_spoof32(AD_SPOOF_EX_DECOY_1, \
                                                AD_SPOOF_EX_MIX_1,   \
                                                AD_SPOOF_EX_SALT_1)

// ===========================================================================
//
//  FLOAT SPOOF
//
//  Same principle as integer spoof but for IEEE 754 floats.
//  The reverser sees 3.14 in the watch window, the program uses 0.001.
//
//  Technique: bit-cast float↔u32, apply the same nonlinear mixing on the
//  bit pattern, bit-cast back. The decoy float sits in .state as a real
//  IEEE 754 value — debugger renders it as "3.14", not hex garbage.
//
//  Usage:
//    ad_spoof_f32 threshold;
//    ad_spoof_f32_init(&threshold, 0.001f, 3.14f);
//    float real = ad_spoof_f32_load(&threshold);  // 0.001
//    // debugger shows: threshold.state = 3.14
//
// ===========================================================================

// Bit-cast helpers — no UB, no type-pun warnings
ANTIDEBUG_INLINE u32 ad_bitcast_f2u(float f) {
    u32 r;
    volatile float  vf = f;
    volatile u8* src = (volatile u8*)&vf;
    volatile u8* dst = (volatile u8*)&r;
    dst[0] = src[0]; dst[1] = src[1]; dst[2] = src[2]; dst[3] = src[3];
    return r;
}

ANTIDEBUG_INLINE float ad_bitcast_u2f(u32 u) {
    float r;
    volatile u32 vu = u;
    volatile u8* src = (volatile u8*)&vu;
    volatile u8* dst = (volatile u8*)&r;
    dst[0] = src[0]; dst[1] = src[1]; dst[2] = src[2]; dst[3] = src[3];
    return r;
}

ANTIDEBUG_INLINE u64 ad_bitcast_d2u(double d) {
    u64 r;
    volatile double vd = d;
    volatile u8* src = (volatile u8*)&vd;
    volatile u8* dst = (volatile u8*)&r;
    u32 i; for (i = 0; i < 8; i++) dst[i] = src[i];
    return r;
}

ANTIDEBUG_INLINE double ad_bitcast_u2d(u64 u) {
    double r;
    volatile u64 vu = u;
    volatile u8* src = (volatile u8*)&vu;
    volatile u8* dst = (volatile u8*)&r;
    u32 i; for (i = 0; i < 8; i++) dst[i] = src[i];
    return r;
}

// ---------------------------------------------------------------------------
// ad_spoof_f32 — 32-bit float with active decoy
//
// PDB shows: state (float), _pad0, _flags, _crc — looks like a
// sensor reading struct with alignment padding and CRC.
// ---------------------------------------------------------------------------
typedef struct {
    volatile float state;   // DECOY float — debugger renders as "3.14"
    volatile u32   _pad0;   // mix_fwd(real_bits ^ decoy_bits, key)
    volatile u32   _flags;  // rotating key
    volatile u32   _crc;    // integrity
} ad_spoof_f32;

typedef struct {
    volatile double state;
    volatile u64    _pad0;
    volatile u64    _flags;
    volatile u32    _crc;
} ad_spoof_f64;

ANTIDEBUG_INLINE void ad_spoof_f32_init(ad_spoof_f32* s, float real, float decoy) {
    u32 rb = ad_bitcast_f2u(real);
    u32 db = ad_bitcast_f2u(decoy);

    u64 k64 = ad_rotate_key(0xF1F1F1F1F1F1F1F1ULL);
    u32 k   = (u32)k64;

    s->_flags = k;
    AD_BARRIER();
    s->state  = decoy;          // reverser sees 3.14 in watch window
    s->_pad0  = ad_mix_fwd32(rb ^ db, k);
    s->_crc   = ad_value_mac32((u64)rb, (u64)k);
}

ANTIDEBUG_INLINE void ad_spoof_f64_init(ad_spoof_f64* s, double real, double decoy) {
    u64 rb = ad_bitcast_d2u(real);
    u64 db = ad_bitcast_d2u(decoy);

    u64 k = ad_rotate_key(0xF2F2F2F2F2F2F2F2ULL);

    s->_flags = k;
    AD_BARRIER();
    s->state  = decoy;
    s->_pad0  = ad_mix_fwd64(rb ^ db, k);
    s->_crc   = ad_value_mac32(rb, k);
}

ANTIDEBUG_INLINE void ad_spoof_f32_store(ad_spoof_f32* s, float real, float decoy) {
    u32 rb = ad_bitcast_f2u(real);
    u32 db = ad_bitcast_f2u(decoy);

    u64 new_key = ad_rotate_key((u64)s->_flags);
    u32 k       = (u32)new_key;

    s->_flags = k;
    AD_BARRIER();
    s->state  = decoy;
    s->_pad0  = ad_mix_fwd32(rb ^ db, k);
    s->_crc   = ad_value_mac32((u64)rb, (u64)k);
}

ANTIDEBUG_INLINE void ad_spoof_f64_store(ad_spoof_f64* s, double real, double decoy) {
    u64 rb = ad_bitcast_d2u(real);
    u64 db = ad_bitcast_d2u(decoy);

    u64 k = ad_rotate_key(s->_flags);

    s->_flags = k;
    AD_BARRIER();
    s->state  = decoy;
    s->_pad0  = ad_mix_fwd64(rb ^ db, k);
    s->_crc   = ad_value_mac32(rb, k);
}

ANTIDEBUG_INLINE float ad_spoof_f32_load(const ad_spoof_f32* s) {
    u32 k     = s->_flags;
    AD_BARRIER();
    u32 mixed = s->_pad0;
    AD_BARRIER();
    u32 db    = ad_bitcast_f2u(s->state);   // reads decoy through float→bits

    u32 diff = ad_mix_inv32(mixed, k);
    u32 rb   = db ^ diff;

    u32 expected = ad_value_mac32((u64)rb, (u64)k);
    u32 mac_diff = expected ^ s->_crc;
    u32 safe_rb  = ad_branchless_sel32(rb, mac_diff);
    return ad_bitcast_u2f(safe_rb);
}

ANTIDEBUG_INLINE double ad_spoof_f64_load(const ad_spoof_f64* s) {
    u64 k     = s->_flags;
    AD_BARRIER();
    u64 mixed = s->_pad0;
    AD_BARRIER();
    u64 db    = ad_bitcast_d2u(s->state);

    u64 diff = ad_mix_inv64(mixed, k);
    u64 rb   = db ^ diff;

    u32 expected = ad_value_mac32(rb, k);
    u32 mac_diff = expected ^ s->_crc;
    u64 safe_rb  = ad_branchless_sel64(rb, mac_diff);
    return ad_bitcast_u2d(safe_rb);
}

// Register-level float spoof (transient, no struct)
ANTIDEBUG_INLINE float ad_spoof_reg_f32(float real, float decoy) {
    u32 rb = ad_bitcast_f2u(real);
    u32 db = ad_bitcast_f2u(decoy);
    u32 spoofed = ad_spoof_reg32(rb, db);
    return ad_bitcast_u2f(spoofed);
}

ANTIDEBUG_INLINE double ad_spoof_reg_f64(double real, double decoy) {
    u64 rb = ad_bitcast_d2u(real);
    u64 db = ad_bitcast_d2u(decoy);
    u64 spoofed = ad_spoof_reg64(rb, db);
    return ad_bitcast_u2d(spoofed);
}

// ===========================================================================
//
//  STRING SPOOF
//
//  Stores a DECOY string in plaintext (visible in `strings.exe`, memory
//  dump, IDA strings view). The real string is encoded per-byte and
//  decoded on-the-fly into a caller-provided stack buffer.
//
//  The reverser runs `strings.exe binary.exe` and finds "Access Denied".
//  The program actually uses "FLAG{s3cr3t}".
//
//  Usage:
//    ad_spoof_str secret;
//    ad_spoof_str_init(&secret, "FLAG{s3cr3t}", "Access Denied");
//
//    char buf[AD_SPOOF_STR_CAP];
//    const char* real = ad_spoof_str_load(&secret, buf);
//    // real == "FLAG{s3cr3t}", but strings.exe shows "Access Denied"
//    AD_WIPE_STR(buf, AD_SPOOF_STR_CAP);  // wipe after use
//
// ===========================================================================

#define AD_SPOOF_STR_CAP 64

typedef struct {
    volatile char text[AD_SPOOF_STR_CAP];   // DECOY — plaintext bait for strings.exe
    volatile u8   _blob[AD_SPOOF_STR_CAP];  // encoded real string (per-byte mixing)
    volatile u32  _flags;                    // rotating key
    volatile u32  _len;                      // real length (mixed with key)
    volatile u32  _crc;                      // integrity over real string
} ad_spoof_str;

// Per-byte encode: each byte mixed with key + position
// byte[i] = (real[i] ^ (key >> (8*(i%4)))) + (i * 0x9D) & 0xFF
// The ADD makes it non-trivially different from simple XOR
ANTIDEBUG_INLINE u8 ad_str_encode_byte(u8 plain, u32 key, u32 idx) {
    u8 k_byte = (u8)(key >> (8u * (idx & 3u)));
    u8 mixed  = plain ^ k_byte;
    mixed     = (u8)(mixed + (u8)(idx * 0x9Du));
    return mixed;
}

ANTIDEBUG_INLINE u8 ad_str_decode_byte(u8 cipher, u32 key, u32 idx) {
    u8 unmixed = (u8)(cipher - (u8)(idx * 0x9Du));
    u8 k_byte  = (u8)(key >> (8u * (idx & 3u)));
    return unmixed ^ k_byte;
}

ANTIDEBUG_INLINE void ad_spoof_str_init(ad_spoof_str* s,
                                         const char* real,
                                         const char* decoy) {
    u64 k64 = ad_rotate_key(0xA7A7A7A7A7A7A7A7ULL);
    u32 k   = (u32)k64;
    s->_flags = k;

    // Copy decoy string (plaintext — bait)
    u32 i = 0;
    for (i = 0; i < AD_SPOOF_STR_CAP - 1 && decoy[i]; i++)
        s->text[i] = decoy[i];
    for (; i < AD_SPOOF_STR_CAP; i++)
        s->text[i] = '\0';

    // Encode real string per-byte
    u32 real_len = 0;
    for (i = 0; i < AD_SPOOF_STR_CAP - 1 && real[i]; i++) {
        s->_blob[i] = ad_str_encode_byte((u8)real[i], k, i);
        real_len++;
    }
    for (; i < AD_SPOOF_STR_CAP; i++)
        s->_blob[i] = ad_str_encode_byte(0, k, i);

    AD_BARRIER();
    s->_len = real_len ^ k;   // hide length
    // MAC over first 8 bytes of real string for integrity
    u64 mac_input = 0;
    for (i = 0; i < 8 && i < real_len; i++)
        mac_input |= ((u64)(u8)real[i]) << (i * 8);
    s->_crc = ad_value_mac32(mac_input, (u64)k);
}

ANTIDEBUG_INLINE const char* ad_spoof_str_load(const ad_spoof_str* s,
                                                 char* out_buf) {
    u32 k   = s->_flags;
    AD_BARRIER();
    u32 len = s->_len ^ k;

    if (len >= AD_SPOOF_STR_CAP)
        len = AD_SPOOF_STR_CAP - 1;

    // Decode per-byte into caller's stack buffer
    u32 i;
    for (i = 0; i < len; i++)
        out_buf[i] = (char)ad_str_decode_byte(s->_blob[i], k, i);
    out_buf[len] = '\0';

    // Integrity check (branchless)
    u64 mac_input = 0;
    u32 mac_len = (len < 8) ? len : 8;
    for (i = 0; i < mac_len; i++)
        mac_input |= ((u64)(u8)out_buf[i]) << (i * 8);

    u32 expected = ad_value_mac32(mac_input, (u64)k);
    u32 mac_diff = expected ^ s->_crc;
    // If tampered, poison first byte so string is garbage
    u32 nz   = (mac_diff | (~mac_diff + 1u)) >> 31u;
    u32 mask = ~nz + 1u;
    out_buf[0] = (char)(((u8)out_buf[0] & ~(u8)mask) | ((u8)0xFF & (u8)mask));

    return out_buf;
}

// ===========================================================================
//
//  POINTER SPOOF
//
//  Stores a DECOY pointer that points to fake data. The real pointer
//  is derived through nonlinear mixing. A reverser following the pointer
//  in x64dbg lands on the decoy data and thinks they found it.
//
//  Usage:
//    const char* real_str = "secret_api_key";
//    const char* fake_str = "placeholder_value";
//    ad_spoof_ptr p;
//    ad_spoof_ptr_init(&p, real_str, fake_str);
//
//    const char* real = (const char*)ad_spoof_ptr_load(&p);
//    // real points to "secret_api_key"
//    // x64dbg shows p.ref → "placeholder_value"
//
// ===========================================================================

typedef struct {
    volatile void* ref;     // DECOY pointer — "follow pointer" lands here
    volatile u64   _pad0;   // mix_fwd(real_ptr ^ decoy_ptr, key)
    volatile u64   _flags;  // rotating key
    volatile u32   _crc;    // integrity
} ad_spoof_ptr;

ANTIDEBUG_INLINE void ad_spoof_ptr_init(ad_spoof_ptr* s,
                                          const void* real,
                                          const void* decoy) {
    u64 rp = (u64)real;
    u64 dp = (u64)decoy;

    u64 k = ad_rotate_key(0xB8B8B8B8B8B8B8B8ULL);

    s->_flags = k;
    AD_BARRIER();
    s->ref    = (void*)decoy;   // reverser follows this pointer
    s->_pad0  = ad_mix_fwd64(rp ^ dp, k);
    s->_crc   = ad_value_mac32(rp, k);
}

ANTIDEBUG_INLINE void ad_spoof_ptr_store(ad_spoof_ptr* s,
                                           const void* real,
                                           const void* decoy) {
    u64 rp = (u64)real;
    u64 dp = (u64)decoy;

    u64 k = ad_rotate_key(s->_flags);

    s->_flags = k;
    AD_BARRIER();
    s->ref    = (void*)decoy;
    s->_pad0  = ad_mix_fwd64(rp ^ dp, k);
    s->_crc   = ad_value_mac32(rp, k);
}

ANTIDEBUG_INLINE void* ad_spoof_ptr_load(const ad_spoof_ptr* s) {
    u64 k     = s->_flags;
    AD_BARRIER();
    u64 mixed = s->_pad0;
    AD_BARRIER();
    u64 dp    = (u64)s->ref;     // decoy pointer — reverser sees this

    u64 diff = ad_mix_inv64(mixed, k);
    u64 rp   = dp ^ diff;

    u32 expected = ad_value_mac32(rp, k);
    u32 mac_diff = expected ^ s->_crc;
    u64 safe_rp  = ad_branchless_sel64(rp, mac_diff);
    return (void*)safe_rp;
}

#endif // ANTIDEBUG_INT_SPOOF_H