// ===== file: antidebug/stack/cloaked_call.h =====
//
// C-facing interface to the CloakedCall asm trampolines.
//
// The trampolines (cloaked_call.asm) scramble the caller's return address
// on the stack with a per-call XOR key for the duration of the target's
// execution. A stack walker observing the process at any point inside the
// target sees garbage for the caller frame; the real address is
// reconstructed only as the trampoline itself is about to RET.
//
// Variants for 0..6 arguments cover the common case. For >6 args, pack
// into a struct and use CloakedCall1.
//
// Limitations: do NOT use around code that may raise an exception. The
// SEH unwinder walks the scrambled frame and fails to find a handler.
//
#ifndef ANTIDEBUG_CLOAKED_CALL_H
#define ANTIDEBUG_CLOAKED_CALL_H

#include "../core/types.h"

#ifdef __cplusplus
extern "C" {
#endif

// ---------------------------------------------------------------------------
// Variadic family — pick the variant matching your target's arity.
// ---------------------------------------------------------------------------
void* CloakedCall0(void* fn);                                                 // fn()
void* CloakedCall1(void* fn, void* a1);                                       // fn(a1)
void* CloakedCall2(void* fn, void* a1, void* a2);                             // fn(a1,a2)
void* CloakedCall3(void* fn, void* a1, void* a2, void* a3);                   // fn(a1,a2,a3)
void* CloakedCall4(void* fn, void* a1, void* a2, void* a3, void* a4);
void* CloakedCall5(void* fn, void* a1, void* a2, void* a3, void* a4, void* a5);
void* CloakedCall6(void* fn, void* a1, void* a2, void* a3, void* a4, void* a5, void* a6);

// Legacy alias for the 1-arg variant (predates the variadic family).
void* CloakedCall(void* fn, void* arg);   // == CloakedCall1

#ifdef __cplusplus
}
#endif

// ---------------------------------------------------------------------------
// CLOAK(fn, ...) — dispatch macro that picks the right CloakedCallN based
// on argument count. Up to 6 args supported.
//
// Usage:
//   CLOAK(my_fn);                        // CloakedCall0
//   CLOAK(my_fn, a);                     // CloakedCall1
//   CLOAK(my_fn, a, b, c);               // CloakedCall3
//
// All arguments are evaluated as expressions then cast to void* by the
// caller; pointer-sized integers fit. For ints < 64 bits, use (void*)(uintptr_t)x.
// ---------------------------------------------------------------------------
#define AD_CLOAK_NARG(...) \
    AD_CLOAK_NARG_(__VA_ARGS__, 6, 5, 4, 3, 2, 1, 0)
#define AD_CLOAK_NARG_(_0, _1, _2, _3, _4, _5, _6, N, ...) N

#define AD_CLOAK_CAT(a, b) AD_CLOAK_CAT_(a, b)
#define AD_CLOAK_CAT_(a, b) a##b

#define CLOAK(fn, ...) \
    AD_CLOAK_CAT(CloakedCall, AD_CLOAK_NARG(__VA_ARGS__))((void*)(fn), ##__VA_ARGS__)

#endif // ANTIDEBUG_CLOAKED_CALL_H
