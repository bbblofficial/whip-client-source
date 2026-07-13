// ===== file: antidebug/core/opaque.h =====
//
// Opaque predicates.
//
// A predicate is "opaque" if its outcome is known to us (it's fixed, e.g.
// always true) but hard to prove for a static analyzer or symbolic
// executor.  Every `if (score == 0)` wrapped in an opaque predicate
// becomes `if ((score == 0) | opaque_true())` — semantically identical
// for us, but the decompiler must reason about an arbitrary math
// expression before it can fold the condition.  Symbolic solvers walk
// both branches and cannot prune the dead one.
//
// Identities used
// ---------------
//   AD_OPAQUE_TRUE_A:   7*x*x + 1 is always odd → (expr & 1) == 1
//   AD_OPAQUE_TRUE_B:   (x | y) - (x & y) == (x ^ y)   (MBA identity)
//   AD_OPAQUE_TRUE_C:   n*(n+1) is always even → (expr & 1) == 0, inverted
//   AD_OPAQUE_FALSE_A:  x*x >= 0 for unsigned, but we produce an
//                        expression whose result is provably 0 via
//                        modular arithmetic
//
// Each call reads a volatile global (`ad_opaque_noise`) so the compiler
// cannot constant-fold the result.  The global is written once at init
// to a runtime value; subsequent reads see the same value but the
// compiler cannot prove it doesn't change.
//
#ifndef ANTIDEBUG_OPAQUE_H
#define ANTIDEBUG_OPAQUE_H

#include "types.h"
#include "macros.h"

#ifndef AD_OPAQUE_NOISE_DEFINED
#define AD_OPAQUE_NOISE_DEFINED
// Runtime-seeded noise.  Exact value is irrelevant — the predicates
// below hold for ANY integer value.  Seeded once at init so static
// constant-folding cannot collapse the expressions.
volatile u32 ad_opaque_noise = 0u;
#endif

ANTIDEBUG_INLINE void ad_opaque_seed(void) {
#if defined(_MSC_VER)
    ad_opaque_noise = (u32)__rdtsc();
#else
    ad_opaque_noise = 0xA55A5AA5u;
#endif
    if (ad_opaque_noise == 0u) ad_opaque_noise = 0xDEADBEEFu;
}

// ---------------------------------------------------------------------------
// Returns 1, always.  Proof: for any u32 x, 7*x*x + 1 is odd → low bit 1.
// Written so the compiler cannot constant-fold: the input is volatile.
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE u32 ad_opaque_true_a(void) {
    u32 x = ad_opaque_noise;
    u32 r = 7u * x * x + 1u;
    return r & 1u;
}

// Returns 1, always.  Proof: (x|y) - (x&y) == x^y for all x, y.  We set
// y = x, so x^y == 0, and we check ((x|y) - (x&y)) == 0 → true.
ANTIDEBUG_INLINE u32 ad_opaque_true_b(void) {
    u32 x = ad_opaque_noise;
    u32 y = x;
    u32 xor_via_mba = (x | y) - (x & y);   // == 0
    return (u32)(xor_via_mba == 0u ? 1u : 0u);
}

// Returns 1, always.  Proof: n*(n+1) is even → low bit 0 → inverted = 1.
ANTIDEBUG_INLINE u32 ad_opaque_true_c(void) {
    u32 n = ad_opaque_noise;
    u32 product = n * (n + 1u);
    return (u32)((~product) & 1u);
}

// Returns 0, always.  Proof: (x * x) mod 2 == (x mod 2) * (x mod 2) mod 2
// which is 0 if x even, 1 if x odd.  Either way, x * (x ^ 1u) is always
// even → low bit 0.
ANTIDEBUG_INLINE u32 ad_opaque_false_a(void) {
    u32 x = ad_opaque_noise;
    u32 r = x * (x ^ 1u);
    return r & 1u;
}

// Returns 0.  Proof: ((x << 1) + (x << 1)) & 1 is always 0 (even + even).
ANTIDEBUG_INLINE u32 ad_opaque_false_b(void) {
    u32 x = ad_opaque_noise;
    u32 r = (x << 1) + (x << 1);
    return r & 1u;
}

// ---------------------------------------------------------------------------
// Composite helpers — rotate between identities so static pattern
// recognition on "ad_opaque_true_a" doesn't one-shot the dead branches.
// ---------------------------------------------------------------------------
#define AD_OPAQUE_TRUE()   (ad_opaque_true_a()  | ad_opaque_true_b()  | ad_opaque_true_c())
#define AD_OPAQUE_FALSE()  (ad_opaque_false_a() & ad_opaque_false_b())

// Branch wrapper.  `if (AD_OPAQUE_IF(cond))` is semantically identical
// to `if (cond)` — AD_OPAQUE_TRUE() adds nothing to the logical result
// because it is OR'd with a concrete condition, and the optimizer
// cannot prove the OR is redundant.  The decompiler prints both
// operands.
#define AD_OPAQUE_IF(cond)     ((cond) | (AD_OPAQUE_TRUE() - 1u))
#define AD_OPAQUE_IF_NOT(cond) ((cond) & (AD_OPAQUE_TRUE() * 0xFFFFFFFFu))

// Dead-branch guard: `if (AD_OPAQUE_DEAD_BRANCH()) { ... }` — never
// executes at runtime, but a disassembler must trace into the block.
#define AD_OPAQUE_DEAD_BRANCH()    (AD_OPAQUE_FALSE() != 0u)

// Always-taken guard: `if (AD_OPAQUE_ALIVE_BRANCH()) { ... }` — always
// runs.  Useful paired with a DEAD branch that the decompiler must
// analyze.
#define AD_OPAQUE_ALIVE_BRANCH()   (AD_OPAQUE_TRUE() != 0u)

#endif // ANTIDEBUG_OPAQUE_H
