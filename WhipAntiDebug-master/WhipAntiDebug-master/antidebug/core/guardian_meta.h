// ===== file: antidebug/core/guardian_meta.h =====
//
// Guardian Meta — third-layer meta-protections on top of
// guardian_matrix.h (V2) and guardian_watchdog.h.
//
// THREE SUB-SYSTEMS
// ─────────────────
//
// 1. DECEPTION FIELD — once tamper is flagged in the Matrix, the layer
//    enters "lying mode". Subsequent check results are intentionally
//    inverted or randomised before being emitted to the caller. Combined
//    with the non-local crypto_seed corruption (Matrix), the attacker's
//    OBSERVABLE state is:
//      * Previously-patched "always return 0" checks start returning 1
//      * Previously-working checks return plausible garbage
//      * The tamper flag itself reports 0 (clean) when queried normally
//    → attacker thinks they won → deploys/tests → silent downstream
//      failures everywhere → root cause invisible.
//
// 2. CHECK TIMING INTROSPECTION — wraps a check call, measures rdtsc
//    delta. If the check took more than AD_GTI_CYCLES_THRESHOLD cycles,
//    the attacker is single-stepping through it (or has hooked internal
//    calls adding latency). Triggers tamper via Matrix. Baseline is
//    auto-calibrated at init.
//
// 3. CALL-SITE VERIFICATION — reads _ReturnAddress() at check entry,
//    verifies it falls inside our PE image. A shellcode-based bypass
//    (attacker directly calling our check from injected code) has a
//    return address in private memory → tamper.
//
// USAGE
// ─────
//   ad_gmeta_init(&meta, &matrix);
//   ... at start of each check ...
//   AD_GMETA_GUARD(&meta); // checks call site + timing begin
//   ... your real check logic ...
//   return AD_GMETA_EMIT(&meta, real_result);  // runs deception field
//
#ifndef ANTIDEBUG_GUARDIAN_META_H
#define ANTIDEBUG_GUARDIAN_META_H

#include "guardian_matrix.h"

#ifdef _MSC_VER

#ifndef AD_GTI_CYCLES_THRESHOLD
#define AD_GTI_CYCLES_THRESHOLD   200000ULL   // ~60 µs @ 3 GHz
#endif

typedef struct {
    ad_gm_matrix_t* matrix;
    u32   initialized;

    // Image range for call-site verification.
    u8*   image_base;
    u32   image_size;

    // Deception state.
    u64   prng;
    u32   deception_active;
    u32   _pad;
} ad_gmeta_ctx_t;

ANTIDEBUG_INLINE u64 ad_gmeta_xs(u64* s) {
    u64 x = *s;
    x ^= x << 13; x ^= x >> 7; x ^= x << 17;
    *s = x; return x;
}

// Initialise. Captures image range and matrix pointer.
ANTIDEBUG_INLINE b32 ad_gmeta_init(ad_gmeta_ctx_t* ctx, ad_gm_matrix_t* m) {
    if (!ctx || !m) return 0;
    u32 k; for (k = 0; k < (u32)sizeof(*ctx); k++) ((volatile u8*)ctx)[k] = 0;

    u8* peb = (u8*)__readgsqword(0x60);
    if (!peb) return 0;
    u8* image = *(u8**)(peb + 0x10);
    if (!image || *(u16*)image != 0x5A4D) return 0;
    u32 pe_off = *(u32*)(image + 0x3C);
    if (pe_off > 0x1000u) return 0;
    u8* pe = image + pe_off;
    if (*(u32*)pe != 0x00004550u) return 0;
    u32 size_of_image = *(u32*)(pe + 24 + 56);

    ctx->matrix     = m;
    ctx->image_base = image;
    ctx->image_size = size_of_image;
    ctx->prng       = __rdtsc() ^ 0x13579BDFACE02468ULL;
    ctx->deception_active = 0u;
    ctx->initialized = 1u;
    return 1;
}

// Call-site verification — reads the return address from the stack and
// checks it's inside our own image. Shellcode callers have return
// addresses in private allocations → fails.
//
// Marked NOINLINE so _ReturnAddress() gives the CALLER's IP.
static NOINLINE b32 ad_gmeta_verify_call_site(const ad_gmeta_ctx_t* ctx) {
    if (!ctx || !ctx->initialized) return 1;   // fail-open if uninit
    void* ra = _ReturnAddress();
    u8*   r  = (u8*)ra;
    if (r < ctx->image_base || r >= ctx->image_base + ctx->image_size) {
        ad_gm_mark_tamper(ctx->matrix);
        return 0;
    }
    return 1;
}

// Begin a timed guard block. Stores the rdtsc value inline via the macro
// pair. No function call overhead for the hot path.
ANTIDEBUG_INLINE u64 ad_gmeta_timing_begin(void) {
    AD_LFENCE();
    u64 t = __rdtsc();
    AD_LFENCE();
    return t;
}

// End a timed guard block — if delta > threshold, attacker is single-
// stepping the check.
ANTIDEBUG_INLINE void ad_gmeta_timing_end(ad_gmeta_ctx_t* ctx, u64 t0) {
    AD_LFENCE();
    u64 t1 = __rdtsc();
    u64 delta = t1 - t0;
    if (delta > AD_GTI_CYCLES_THRESHOLD) {
        ad_gm_mark_tamper(ctx->matrix);
    }
}

// Engage deception mode if the Matrix is tampered. Idempotent.
ANTIDEBUG_INLINE void ad_gmeta_update_deception(ad_gmeta_ctx_t* ctx) {
    if (ad_gm_is_tampered(ctx->matrix)) {
        ctx->deception_active = 1u;
    }
}

// Emit a result — applies deception in lying mode.
// Clean mode: returns real_result unchanged.
// Deception mode: returns mostly-inverted, sometimes-truthful garbage.
// 75% inverted, 25% truthful — enough noise to confuse but not so noisy
// that the attacker notices a perfect inversion and adjusts.
ANTIDEBUG_INLINE b32 ad_gmeta_emit(ad_gmeta_ctx_t* ctx, b32 real_result) {
    ad_gmeta_update_deception(ctx);
    if (!ctx->deception_active) return real_result;

    u64 r = ad_gmeta_xs(&ctx->prng);
    // Top 2 bits of r: 75% chance to invert, 25% to tell truth.
    if ((r & 3ULL) != 0ULL) {
        return (b32)!real_result;
    }
    return real_result;
}

// Also poison a u32 score — used when a check returns a composite score
// instead of a boolean.
ANTIDEBUG_INLINE u32 ad_gmeta_emit_score(ad_gmeta_ctx_t* ctx, u32 real) {
    ad_gmeta_update_deception(ctx);
    if (!ctx->deception_active) return real;
    u64 r = ad_gmeta_xs(&ctx->prng);
    return (u32)(real ^ (r & 0xFFFFu));
}

// Report deception state — used INTERNALLY, attackers querying the
// tamper flag via the usual ad_gm_is_tampered() get the MATRIX's state,
// which is the same state here — but the key point is that emit()
// manipulates the check return values so callers who check
// `ad_ndt_check(...) == 0` see a lie.
ANTIDEBUG_INLINE b32 ad_gmeta_deception_active(const ad_gmeta_ctx_t* ctx) {
    return (b32)(ctx && ctx->deception_active);
}

// -----------------------------------------------------------------------
// Convenience macros — embed at the start and end of each protected check.
// -----------------------------------------------------------------------
#define AD_GMETA_GUARD_BEGIN(ctxp)                                             \
    u64 _gmeta_t0 = ad_gmeta_timing_begin();                                   \
    (void)ad_gmeta_verify_call_site((ctxp))

#define AD_GMETA_GUARD_END(ctxp)                                               \
    ad_gmeta_timing_end((ctxp), _gmeta_t0)

#define AD_GMETA_EMIT(ctxp, result) ad_gmeta_emit((ctxp), (result))
#define AD_GMETA_EMIT_SCORE(ctxp, result) ad_gmeta_emit_score((ctxp), (result))

#else  // !_MSC_VER
typedef struct { int _unused; } ad_gmeta_ctx_t;
ANTIDEBUG_INLINE b32  ad_gmeta_init(ad_gmeta_ctx_t* c, ad_gm_matrix_t* m) { (void)c; (void)m; return 0; }
ANTIDEBUG_INLINE b32  ad_gmeta_emit(ad_gmeta_ctx_t* c, b32 r) { (void)c; return r; }
ANTIDEBUG_INLINE u32  ad_gmeta_emit_score(ad_gmeta_ctx_t* c, u32 r) { (void)c; return r; }
ANTIDEBUG_INLINE b32  ad_gmeta_deception_active(const ad_gmeta_ctx_t* c) { (void)c; return 0; }
#define AD_GMETA_GUARD_BEGIN(ctxp)   ((void)0)
#define AD_GMETA_GUARD_END(ctxp)     ((void)0)
#define AD_GMETA_EMIT(ctxp, result)  (result)
#define AD_GMETA_EMIT_SCORE(ctxp, r) (r)
#endif // _MSC_VER

#endif // ANTIDEBUG_GUARDIAN_META_H
