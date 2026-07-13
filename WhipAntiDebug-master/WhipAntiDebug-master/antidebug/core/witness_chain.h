// ===== file: antidebug/core/witness_chain.h =====
//
// Witness Chain — distributed execution integrity that crashes on skip.
//
// Problem
// -------
// `tamper_trip` defends against in-place byte patches: if a reverser writes
// a NOP over a CMP inside a check, the surrounding bytes hash differently
// and the trip-pointer goes wild. But what if the reverser does the OBVIOUS
// thing — NOPs the entire CALL site of the check from its caller? The
// check's bytes are untouched, so tamper_trip on the check itself never
// fires.
//
// Witness chain plugs this hole. Each protected check is given a unique
// 64-bit "witness constant". When the check executes, it XORs that constant
// into a global accumulator. A downstream consumer reconstructs a critical
// pointer from the accumulator. As long as every witness fires exactly once
// in the expected order, the accumulator equals the precomputed expected
// sum and the pointer is correct. If even ONE witness call site is NOPed,
// the accumulator is wrong, and the next AD_WITNESS_RESOLVE in any
// consuming function returns garbage that crashes the indirect call.
//
// Crucially, the witnesses live INSIDE the call sites of the checks, not
// inside the checks themselves. To kill them the reverser must either:
//   (a) Leave the call alive (defeating their patch goal), OR
//   (b) Replace the call with a synthetic ad_witness_fire(<constant>) that
//       reproduces the right XOR — which requires reading the constant out
//       of every call site by hand and replicating the chain.
//
// Either way, blanket NOPing of detection logic causes a hard crash later
// inside a totally unrelated function — exactly the misdirection we want.
//
// Properties
// ----------
//   * No conditional branches anywhere in the verification path. The
//     accumulator is XOR-only; the consumer is XOR-only. There is nothing
//     to bypass with a single CMOV.
//   * The expected accumulator value is computed at link time as the XOR
//     of all witness constants — no plaintext "magic" sitting in .rdata.
//   * Per-witness constants are stored as immediate operands inside each
//     call site, blending in with arbitrary integer literals.
//
// Usage
// -----
//   // 1. Pick a unique 64-bit constant for each protected check.
//   //    Anything random — these are just XOR keys.
//   #define WIT_PEB_CHECK    0x4F2A9D1C7B58E633ULL
//   #define WIT_RDTSC_CHECK  0x91C7E2A86B4F0D5BULL
//   #define WIT_INT3_CHECK   0xA82C5E91D74B30C7ULL
//
//   // 2. At init, register the expected accumulator (XOR of all witnesses)
//   //    and the protected target.
//   static ad_witness_chain_t g_wc;
//
//   void protect_init(void* target_fn) {
//       u64 expected = WIT_PEB_CHECK ^ WIT_RDTSC_CHECK ^ WIT_INT3_CHECK;
//       ad_witness_init(&g_wc, target_fn, expected);
//   }
//
//   // 3. Inside each check call site, fire the witness BEFORE acting on the
//   //    result. The XOR is unconditional; only the score update is gated
//   //    by the check.
//   if (run_peb_check())   { ad_witness_fire(&g_wc, WIT_PEB_CHECK);   score++; }
//   if (run_rdtsc_check()) { ad_witness_fire(&g_wc, WIT_RDTSC_CHECK); score++; }
//   if (run_int3_check())  { ad_witness_fire(&g_wc, WIT_INT3_CHECK);  score++; }
//
//   // 4. Downstream, resolve the protected pointer through the chain.
//   //    On a clean run the accumulator equals `expected`, and resolve
//   //    returns the original target. On any skipped witness, garbage.
//   typedef void (*FN_render)(int);
//   FN_render fn = (FN_render)ad_witness_resolve(&g_wc);
//   fn(42);   // crashes here if any witness was NOPed
//
// To make the trap close at the right time, fire EVERY witness during the
// init sequence under your control (even synthetically with a forced loop)
// so that the very first ad_witness_resolve in production code already
// runs against the full expected accumulator.
//
#ifndef ANTIDEBUG_WITNESS_CHAIN_H
#define ANTIDEBUG_WITNESS_CHAIN_H

#include "types.h"
#include "macros.h"

// ---------------------------------------------------------------------------
// Same fold64 used by tamper_trip — duplicated here so the two modules are
// independent. Multiplying through two odd 64-bit constants and swapping
// halves spreads any single-bit XOR change across ~32 bits of the pointer.
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE u64 ad_witness_fold64(u64 v) {
    u64 a = v * 0xC6BC279692B5C323ULL;
    u64 b = v * 0x9FB21C651E98DF25ULL;
    return a ^ ((b << 32) | (b >> 32));
}

// ---------------------------------------------------------------------------
// Chain descriptor — one per protected target.
//
// `xored` stores `target ^ fold64(expected_accumulator)`.
// `accum` is updated by every ad_witness_fire call.
// ad_witness_resolve recomputes `target` as `xored ^ fold64(accum)`.
// On a complete chain, accum == expected, the XORs cancel, and the
// recovered target is exact.
// ---------------------------------------------------------------------------
typedef struct {
    volatile u64 accum;     // running XOR of fired witness constants
    u64          xored;     // target ^ fold64(expected_accumulator)
    u64          _pad;
} ad_witness_chain_t;

// One-time setup. Caller must precompute expected as the XOR of every
// witness constant that will be fired during a clean run.
ANTIDEBUG_INLINE void ad_witness_init(ad_witness_chain_t* wc,
                                      void* target_fn,
                                      u64 expected_accumulator) {
    if (!wc) return;
    wc->accum = 0;
    wc->xored = (u64)target_fn ^ ad_witness_fold64(expected_accumulator);
    wc->_pad  = 0;
}

// Fire a witness — mix its constant into the running accumulator.
// Inlined so the constant appears as an immediate operand at the call site.
ANTIDEBUG_INLINE void ad_witness_fire(ad_witness_chain_t* wc, u64 witness_const) {
    if (!wc) return;
    // Volatile XOR — prevents the optimizer from precomputing the chain
    // when multiple fires are visible in a single basic block.
    u64 a = wc->accum;
    AD_BARRIER();
    a ^= witness_const;
    AD_BARRIER();
    wc->accum = a;
}

// Resolve the protected target using the current accumulator.
// On a complete chain → exact target. On a missing witness → wild pointer.
ANTIDEBUG_INLINE void* ad_witness_resolve(const ad_witness_chain_t* wc) {
    u64 mask = ad_witness_fold64(wc->accum);
    return (void*)(wc->xored ^ mask);
}

// Reset the accumulator. Useful if the chain runs once per frame / per
// request and you want to re-arm it for the next pass.
ANTIDEBUG_INLINE void ad_witness_reset(ad_witness_chain_t* wc) {
    if (wc) wc->accum = 0;
}

// ---------------------------------------------------------------------------
// Convenience: typed call through a witness chain.
//   AD_WITNESS_CALL(FN_render, &g_wc)(42);
// ---------------------------------------------------------------------------
#define AD_WITNESS_CALL(fn_type, chain_ptr) \
    ((fn_type)ad_witness_resolve((chain_ptr)))

// ---------------------------------------------------------------------------
// Bonus: pair a witness chain with a tamper trip on the same target. Even
// stronger — a reverser must avoid BOTH patching the bytes AND removing
// the call sites. Either failure mode crashes.
// ---------------------------------------------------------------------------
//
//   ad_trip_init(&s_trip, target, target, 256);
//   ad_witness_init(&s_wc, ad_trip_resolve(&s_trip), expected_accumulator);
//
// Now the witness chain is feeding off the trip-derived target, so a byte
// patch on the function itself ALSO ruins `wc->xored` indirectly through
// the trip's recomputed pointer. Two layers, single crash site.
//
#endif // ANTIDEBUG_WITNESS_CHAIN_H
