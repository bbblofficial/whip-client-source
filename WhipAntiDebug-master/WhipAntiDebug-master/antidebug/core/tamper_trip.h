// ===== file: antidebug/core/tamper_trip.h =====
//
// Tamper Trip — hash-derived function pointers that crash hard on patch.
//
// Idea
// ----
// Replace direct calls to critical functions with an indirect call through
// a pointer XOR'd against the hash of a watched code region. The math is:
//
//     stored = real_fn  ^  fold64(hash(watched_region_at_init))
//     callee = stored   ^  fold64(hash(watched_region_now))
//
// If the watched region is unmodified, the two hashes are identical, the
// XORs cancel, and `callee` == `real_fn`. The indirect call works perfectly
// and is indistinguishable from any legit C++ vtable call.
//
// If a reverser NOPs a single byte inside the watched region — typically
// the comparison or branch of one of our anti-debug checks — the runtime
// hash changes, the XORs no longer cancel, and `callee` becomes a wild
// 64-bit value. The very next `call rax` faults with EXCEPTION_ACCESS_
// VIOLATION at an arbitrary address with no symbol, no module, no clue.
//
// What the cracker sees in the dump
// ---------------------------------
//   First-chance exception at 0x00007FF82A491DEC (in their_app.exe):
//     0xC0000005: Access violation executing location 0x9B4C7F03A1E20055
//
// They will spend hours assuming heap/vtable corruption from their own
// patch on something completely unrelated. There is NO conditional branch
// to NOP, NO comparison to cmove past, and NO error message. The bug is
// the patch.
//
// Properties
// ----------
//   * Real crash, not "delayed weirdness". Faults on the first call after
//     the patch.
//   * Looks like a generic indirect call. IDA cannot tell this apart from
//     a normal function-pointer dispatch.
//   * Watched region and target function can be the same address: a check
//     can self-protect by guarding its own bytes.
//   * Multiple trips can watch the same region; each derives a different
//     pointer because the stored XOR is per-trip.
//
// Usage
// -----
//   typedef int (*FN_check)(void);
//
//   static int my_real_check(void) { ... }
//
//   static ad_trip_t s_check_trip;
//
//   void init_protection(void) {
//       ad_trip_init(&s_check_trip,
//                    (void*)&my_real_check,
//                    (const void*)&my_real_check, 256);
//   }
//
//   void hot_path(void) {
//       FN_check fn = (FN_check)ad_trip_resolve(&s_check_trip);
//       int score = fn();        // crashes here if my_real_check was patched
//       use(score);
//   }
//
#ifndef ANTIDEBUG_TAMPER_TRIP_H
#define ANTIDEBUG_TAMPER_TRIP_H

#include "types.h"
#include "macros.h"

// ---------------------------------------------------------------------------
// FNV-1a 32-bit over a raw byte region
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE u32 ad_trip_hash_region(const void* addr, u32 size) {
    const u8* p = (const u8*)addr;
    u32 h = 0x811C9DC5u;
    u32 i;
    for (i = 0; i < size; i++) {
        h ^= p[i];
        h *= 0x01000193u;
    }
    return h;
}

// Fold a 32-bit hash into a 64-bit XOR mask. Multiplying by a 64-bit
// odd constant spreads bits across both halves, so a 1-bit change in
// the hash flips ~32 bits in the resulting pointer.
ANTIDEBUG_INLINE u64 ad_trip_fold64(u32 h) {
    u64 a = (u64)h * 0xC6BC279692B5C323ULL;
    u64 b = (u64)h * 0x9FB21C651E98DF25ULL;
    return a ^ ((b << 32) | (b >> 32));
}

// ---------------------------------------------------------------------------
// Trip descriptor
// ---------------------------------------------------------------------------
typedef struct {
    u64       xored;        // real_fn ^ fold64(hash_at_init)
    const u8* watch_addr;
    u32       watch_size;
    u32       _pad;
} ad_trip_t;

// One-time setup. Snapshots the hash of the watched region and stores
// the XOR'd target pointer. After this returns, ad_trip_resolve() will
// reconstruct `fn` exactly as long as the region is unmodified.
ANTIDEBUG_INLINE void ad_trip_init(ad_trip_t* t,
                                   void* fn,
                                   const void* watch_addr,
                                   u32 watch_size) {
    if (!t) return;
    u32 h = ad_trip_hash_region(watch_addr, watch_size);
    t->xored      = (u64)fn ^ ad_trip_fold64(h);
    t->watch_addr = (const u8*)watch_addr;
    t->watch_size = watch_size;
    t->_pad       = 0;
}

// Hot-path resolver. Recomputes the hash and XORs it back out. Returns
// `fn` on a clean process; returns garbage if the watched region has
// been modified by even one byte. The intended use is a direct call:
//
//     ((fn_type)ad_trip_resolve(&trip))(args);
//
// On tamper that call crashes immediately with EXCEPTION_ACCESS_VIOLATION
// at the wild address.
ANTIDEBUG_INLINE void* ad_trip_resolve(const ad_trip_t* t) {
    u32 h = ad_trip_hash_region(t->watch_addr, t->watch_size);
    u64 mask = ad_trip_fold64(h);
    return (void*)(t->xored ^ mask);
}

// ---------------------------------------------------------------------------
// Convenience: a trip that watches its own target. Most useful pattern —
// every critical function self-protects against in-place patching.
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE void ad_trip_init_self(ad_trip_t* t, void* fn, u32 size) {
    ad_trip_init(t, fn, fn, size);
}

// ---------------------------------------------------------------------------
// Convenience: chain a trip onto a DATA pointer instead of a function.
// Useful when you want a config struct, jump table, or string buffer to
// become unreachable after a patch on an unrelated check.
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE void ad_trip_init_data(ad_trip_t* t,
                                        const void* data_ptr,
                                        const void* watch_addr,
                                        u32 watch_size) {
    ad_trip_init(t, (void*)data_ptr, watch_addr, watch_size);
}

ANTIDEBUG_INLINE const void* ad_trip_resolve_data(const ad_trip_t* t) {
    return (const void*)ad_trip_resolve(t);
}

// ---------------------------------------------------------------------------
// Macro for ergonomic typed call
//   AD_TRIP_CALL(FN_check, &s_check_trip)();
// expands to
//   ((FN_check)ad_trip_resolve(&s_check_trip))();
// ---------------------------------------------------------------------------
#define AD_TRIP_CALL(fn_type, trip_ptr) \
    ((fn_type)ad_trip_resolve((trip_ptr)))

#endif // ANTIDEBUG_TAMPER_TRIP_H
