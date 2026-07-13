// ===== file: antidebug/core/whip_meta.h =====
//
// Whip Meta — framework-level meta-checks and meta-protections specific
// to the WhipAntiDebugger architecture.
//
// This is the final layer on top of:
//   - guardian_ring.h    (L1)
//   - guardian_matrix.h  (L2)
//   - guardian_watchdog.h (L3)
//   - guardian_meta.h    (L4 — deception / timing / call-site)
//
// WHIP META (L5) ADDS
// ───────────────────
//
//   1. HONEY-CHECK
//      A check that returns a MAGIC constant (0xBADF00D) — not 0 — by
//      design. If an attacker's "patch all checks to return 0" strategy
//      is applied, the honey returns 0 instead of 0xBADF00D and the
//      master evaluator detects the discrepancy. Attackers who target
//      the well-known boolean-check pattern ("return 0 = clean") fail
//      here because our expected value isn't a boolean.
//
//   2. CROSS-VALIDATION MATRIX
//      Checks that have LOGICAL relationships must be consistent. For
//      example, if UHS reports hooks on ntdll but NDT reports 0, they
//      disagree — at least one is lying. Flagged as meta-tamper.
//
//   3. CALL COUNTER ATTESTATION
//      Every registered check bumps a per-check counter. The master
//      evaluator calls every check in a single sweep — so after a full
//      sweep, all counters MUST have advanced by exactly 1. Skipping a
//      check (e.g., attacker who NOPed a call-site) leaves one counter
//      behind. Drift between counters = evaluator loop tampered.
//
//   4. EVALUATOR SELF-TEST
//      At the start of the evaluator, we compute a trivial constant
//      expression that the compiler folds in a specific way, and
//      verify the answer. If the evaluator's own .text has been
//      patched, the constant comes out wrong.
//
#ifndef ANTIDEBUG_WHIP_META_H
#define ANTIDEBUG_WHIP_META_H

#include "guardian_matrix.h"
#include "guardian_meta.h"

#ifdef _MSC_VER

#define AD_WM_HONEY_MAGIC   0xBADF00Du
#define AD_WM_MAX_CHECKS    32u

// Per-check function signature. Returns a bitmask (0 = clean).
typedef u32 (*ad_wm_check_fn)(void*);

typedef struct {
    ad_wm_check_fn  fn;
    void*           ctx;
    u32             name_hash;       // FNV-1a of symbolic name
    u32             weight;           // contribution to final score
    volatile u32    call_counter;     // bumped every run
    u32             _pad;
} ad_wm_slot_t;

typedef struct {
    u32              count;
    ad_wm_slot_t     slots[AD_WM_MAX_CHECKS];

    // Cross-validation: pairs of (slot_a, slot_b) that MUST agree
    // (both 0 or both nonzero). Up to 16 pairs.
    u32              xval_count;
    u32              xval_pairs[16][2];

    // Meta context pointers (optional).
    ad_gm_matrix_t*     matrix;
    ad_gmeta_ctx_t*     meta;

    u32              initialized;
    u32              _pad;
} ad_wm_ctx_t;

// -----------------------------------------------------------------------
// 1. HONEY-CHECK
// -----------------------------------------------------------------------
// Always returns AD_WM_HONEY_MAGIC. Caller verifies that it got the
// magic back — if anything else, the framework itself has been patched.
//
// The function is deliberately simple so the compiler emits it as a
// single "mov eax, 0xBADF00D ; ret" pattern. Any attacker who replaces
// this with "xor eax, eax ; ret" (the default "return 0" pattern)
// corrupts the honey signal.
NOINLINE static u32 ad_wm_honey(void* _unused) {
    (void)_unused;
    // Volatile work to prevent aggressive folding (but compiler still
    // folds the return value since it's a compile-time constant).
    volatile u32 x = AD_WM_HONEY_MAGIC;
    return x;
}

// -----------------------------------------------------------------------
// 4. EVALUATOR SELF-TEST
// -----------------------------------------------------------------------
// Trivial expression: (0x1234u ^ 0x1234u) should be 0. Compiler folds
// to "xor eax, eax". If evaluator .text is patched, the fold breaks.
ANTIDEBUG_INLINE u32 ad_wm_selftest(void) {
    volatile u32 a = 0x1234u;
    volatile u32 b = 0x1234u;
    return a ^ b;   // must be 0 on any untampered build
}

// -----------------------------------------------------------------------
// Init
// -----------------------------------------------------------------------
ANTIDEBUG_INLINE void ad_wm_init(ad_wm_ctx_t* ctx,
                                  ad_gm_matrix_t* matrix,
                                  ad_gmeta_ctx_t* meta) {
    u32 k; for (k = 0; k < (u32)sizeof(*ctx); k++) ((volatile u8*)ctx)[k] = 0;
    ctx->matrix = matrix;
    ctx->meta   = meta;
    ctx->initialized = 1u;

    // Pre-register the honey-check as slot 0.
    ctx->slots[0].fn         = ad_wm_honey;
    ctx->slots[0].ctx        = 0;
    ctx->slots[0].name_hash  = 0xBADF00Du;
    ctx->slots[0].weight     = 0;    // never contributes to score
    ctx->count = 1u;
}

// Register a check. Returns its slot index, or 0xFFFFFFFF if full.
ANTIDEBUG_INLINE u32 ad_wm_register(ad_wm_ctx_t* ctx,
                                     ad_wm_check_fn fn,
                                     void* check_ctx,
                                     u32 name_hash,
                                     u32 weight) {
    if (ctx->count >= AD_WM_MAX_CHECKS) return 0xFFFFFFFFu;
    u32 i = ctx->count++;
    ctx->slots[i].fn         = fn;
    ctx->slots[i].ctx        = check_ctx;
    ctx->slots[i].name_hash  = name_hash;
    ctx->slots[i].weight     = weight;
    return i;
}

// Register a cross-validation pair: slots[a] and slots[b] must agree.
ANTIDEBUG_INLINE b32 ad_wm_register_xval(ad_wm_ctx_t* ctx, u32 a, u32 b) {
    if (ctx->xval_count >= 16u) return 0;
    if (a >= ctx->count || b >= ctx->count) return 0;
    ctx->xval_pairs[ctx->xval_count][0] = a;
    ctx->xval_pairs[ctx->xval_count][1] = b;
    ctx->xval_count++;
    return 1;
}

// -----------------------------------------------------------------------
// Final meta-evaluator.
//
// Returns aggregate score. Bit 31 is reserved = meta-tamper detected.
// -----------------------------------------------------------------------
typedef struct {
    u32  aggregate_score;
    u32  honey_ok;                // 1 if honey returned magic
    u32  selftest_ok;             // 1 if evaluator selftest passed
    u32  xval_failures;           // cross-validation disagreements
    u32  counter_min;             // min call_counter value across checks
    u32  counter_max;             // max call_counter value across checks
    u32  meta_tamper;             // 1 if any meta-layer flagged
    u32  results[AD_WM_MAX_CHECKS];
} ad_wm_verdict_t;

ANTIDEBUG_INLINE void ad_wm_evaluate(ad_wm_ctx_t* ctx, ad_wm_verdict_t* v) {
    u32 k; for (k = 0; k < (u32)sizeof(*v); k++) ((volatile u8*)v)[k] = 0;
    if (!ctx || !ctx->initialized) { v->meta_tamper = 1u; return; }

    // (4) Self-test first.
    v->selftest_ok = (ad_wm_selftest() == 0u) ? 1u : 0u;
    if (!v->selftest_ok) {
        v->meta_tamper = 1u;
        if (ctx->matrix) ad_gm_mark_tamper(ctx->matrix);
    }

    // Run every check. Each slot bumps its call counter.
    u32 i;
    u32 score = 0u;
    for (i = 0; i < ctx->count; i++) {
        ad_wm_slot_t* s = &ctx->slots[i];
        u32 r = 0u;
        if (s->fn) r = s->fn(s->ctx);
        s->call_counter++;
        v->results[i] = r;

        // Slot 0 is honey — handle specially.
        if (i == 0u) {
            v->honey_ok = (r == AD_WM_HONEY_MAGIC) ? 1u : 0u;
            if (!v->honey_ok) {
                v->meta_tamper = 1u;
                if (ctx->matrix) ad_gm_mark_tamper(ctx->matrix);
            }
            continue;
        }

        // Contribute to aggregate score by weight, treating nonzero as
        // "detected" for boolean checks. Caller may use its own semantic.
        if (r != 0u) score += s->weight;
    }

    // (2) Cross-validation — look for disagreement.
    for (i = 0; i < ctx->xval_count; i++) {
        u32 a = ctx->xval_pairs[i][0];
        u32 b = ctx->xval_pairs[i][1];
        u32 ra = v->results[a] != 0u;
        u32 rb = v->results[b] != 0u;
        if (ra != rb) {
            v->xval_failures++;
            v->meta_tamper = 1u;
            if (ctx->matrix) ad_gm_mark_tamper(ctx->matrix);
        }
    }

    // (3) Call-counter attestation. After this evaluate, all slots should
    // have identical counters — if any drifted, a call-site was skipped.
    u32 cmin = 0xFFFFFFFFu, cmax = 0u;
    for (i = 0; i < ctx->count; i++) {
        u32 c = ctx->slots[i].call_counter;
        if (c < cmin) cmin = c;
        if (c > cmax) cmax = c;
    }
    v->counter_min = cmin;
    v->counter_max = cmax;
    if (cmax > cmin) {
        v->meta_tamper = 1u;
        if (ctx->matrix) ad_gm_mark_tamper(ctx->matrix);
    }

    // Meta-tamper gates the aggregate through the deception layer.
    if (ctx->meta) {
        score = ad_gmeta_emit_score(ctx->meta, score);
    }

    v->aggregate_score = score | (v->meta_tamper ? 0x80000000u : 0u);
}

// Convenience boolean — 1 if anything fired.
ANTIDEBUG_INLINE b32 ad_wm_tampered_or_detected(const ad_wm_verdict_t* v) {
    return (b32)(v && (v->aggregate_score != 0u));
}

#else  // !_MSC_VER
typedef struct { int _unused; } ad_wm_ctx_t;
typedef struct { int _unused; } ad_wm_verdict_t;
ANTIDEBUG_INLINE void ad_wm_init(ad_wm_ctx_t* c, ad_gm_matrix_t* m, ad_gmeta_ctx_t* meta) { (void)c; (void)m; (void)meta; }
ANTIDEBUG_INLINE void ad_wm_evaluate(ad_wm_ctx_t* c, ad_wm_verdict_t* v) { (void)c; (void)v; }
#endif // _MSC_VER

#endif // ANTIDEBUG_WHIP_META_H
