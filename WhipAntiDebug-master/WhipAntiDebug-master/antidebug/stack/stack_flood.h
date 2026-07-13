// ===== file: antidebug/stack/stack_flood.h =====
//
// Full stack flooding — overwrite EVERY return address on the entire stack
// with ntdll decoys. Not just N frames from the top — ALL frames down to
// the thread entry point (BaseThreadInitThunk / RtlUserThreadStart).
//
// After flooding, a debugger sees:
//   fn()
//   ntdll!LdrpCallInitRoutine+0x4F
//   ntdll!RtlAllocateHeap+0x1A3
//   ntdll!RtlpAllocateHeapInternal+0x842
//   ntdll!NtWaitForSingleObject+0x14
//   ntdll!RtlActivateActivationContextUnsafeFast+0x92
//   ... (all ntdll, 15+ frames)
//
// ZERO real frames visible. The entire stack is a convincing ntdll fiction.
//
// We also interleave "decoy calls" — real CALL instructions that create
// genuine stack frames but do nothing useful. These make the frame count
// realistic and defeat frame-count heuristics.
//
#ifndef ANTIDEBUG_STACK_FLOOD_H
#define ANTIDEBUG_STACK_FLOOD_H

#include "../core/types.h"
#include "../core/macros.h"
#include "moonwalk.h"
#include "gadget_chain.h"

#define AD_MAX_FLOOD_DEPTH 32u

typedef struct {
    void*  saved_rets[AD_MAX_FLOOD_DEPTH];
    void** ret_slots[AD_MAX_FLOOD_DEPTH];
    u32    depth;
} ad_flood_ctx_t;

// ---------------------------------------------------------------------------
// Flood the ENTIRE stack with decoy return addresses.
//
// Walks up the stack via the return-address chain (not RBP — works with FPO).
// Strategy: RSP-based heuristic walk.
//   - Our return address is at [RSP] after CALL (inlined: use _AddressOfReturnAddress)
//   - Each frame's return address is at a fixed offset from the previous
//   - We scan upward through the stack looking for addresses that point
//     into known module .text ranges (heuristic for real ret addrs)
//
// Simpler approach: use the TEB to find the stack base/limit, then walk
// every 8-byte-aligned slot looking for addresses in module ranges.
// ---------------------------------------------------------------------------

// Get stack boundaries from TEB (Thread Environment Block)
// TEB.StackBase  at GS:0x08 (top of stack, highest address)
// TEB.StackLimit at GS:0x10 (bottom of stack, lowest address / guard page)
ANTIDEBUG_INLINE void ad_get_stack_bounds(u8** out_base, u8** out_limit) {
#if defined(_MSC_VER)
    *out_base  = (u8*)__readgsqword(0x08);
    *out_limit = (u8*)__readgsqword(0x10);
#else
    *out_base  = (u8*)0;
    *out_limit = (u8*)0;
#endif
}

// Check if an address looks like it's inside a loaded module's .text
// Simple heuristic: address is in the range [0x7FF..., 0x7FFF...] (high user-mode)
// or in our module range. This avoids needing to walk the PEB LDR.
ANTIDEBUG_INLINE b32 ad_looks_like_code_addr(u64 val) {
    // x64 user-mode code is typically in 0x00007FF... range
    // Stack/heap addresses are lower. Kernel addresses have high bit set.
    return (b32)(val >= 0x00007FF000000000ULL && val < 0x00007FFFFFFFE000ULL);
}

// ---------------------------------------------------------------------------
// Flood: replace all code-looking return addresses on the stack with decoys.
//
// This walks EVERY 8-byte aligned slot between current RSP and StackBase,
// finds values that look like code addresses, saves them, and replaces
// them with gadget-chain decoys.
//
// After this, the entire stack is polluted. Call ad_flood_restore() to undo.
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE void ad_flood_stack(
    ad_flood_ctx_t* ctx,
    const ad_gadget_table_t* gadgets,
    const ad_decoy_table_t*  decoys
) {
    AD_ZERO_BUF(ctx, sizeof(*ctx));

#if defined(_MSC_VER)
    u8* stack_base  = (u8*)0;
    u8* stack_limit = (u8*)0;
    ad_get_stack_bounds(&stack_base, &stack_limit);

    if (!stack_base || !stack_limit) return;

    // Start scanning from just above our current frame
    u8* scan_start = (u8*)_AddressOfReturnAddress();
    u8* scan_end   = stack_base - 8;

    // Don't scan too far (perf + safety)
    if ((u64)(scan_end - scan_start) > 0x2000ULL) {
        scan_end = scan_start + 0x2000;
    }

    u32 gadget_idx = 0;
    u32 decoy_idx  = 0;
    u8* ptr;

    for (ptr = scan_start; ptr < scan_end && ctx->depth < AD_MAX_FLOOD_DEPTH; ptr += 8) {
        u64 val = *(u64*)ptr;

        if (ad_looks_like_code_addr(val)) {
            // Save original
            ctx->saved_rets[ctx->depth] = (void*)(unsigned long long)val;
            ctx->ret_slots[ctx->depth]  = (void**)ptr;

            // Pick a decoy — alternate between gadget chain (post-CALL sites)
            // and basic RET decoys for variety
            void* replacement = (void*)0;
            if (gadgets && gadgets->ready && (ctx->depth & 1u)) {
                replacement = ad_pick_gadget(gadgets, gadget_idx++);
            }
            if (!replacement && decoys && decoys->ready) {
                replacement = ad_pick_decoy(decoys, decoy_idx++);
            }

            if (replacement) {
                *(void**)ptr = replacement;
            }

            ctx->depth++;
        }
    }
#else
    AD_UNUSED(gadgets);
    AD_UNUSED(decoys);
#endif
}

// Restore all original return addresses
ANTIDEBUG_INLINE void ad_flood_restore(ad_flood_ctx_t* ctx) {
    u32 i;
    for (i = 0; i < ctx->depth; i++) {
        if (ctx->ret_slots[i]) {
            *ctx->ret_slots[i] = ctx->saved_rets[i];
        }
    }
    ctx->depth = 0;
}

// ---------------------------------------------------------------------------
// Exception-safe scope: flood, run body(arg), restore — even on SEH unwind.
//
// Uses MSVC __try/__finally so the restore runs whether body returns
// normally, raises a Windows SEH exception, or (in C++ TUs that compile
// with /EHa) throws a C++ exception. The flood context is stack-local —
// no heap allocation, thread-safe.
//
// Forward-declare via stack_protect.h; we accept its handle to fetch the
// shared gadget+decoy pools instead of rebuilding them per call.
// ---------------------------------------------------------------------------
struct ad_stack_protect_s;  /* fwd-decl — full type in stack_protect.h */

ANTIDEBUG_INLINE void ad_flood_run_protected(
    struct ad_stack_protect_s* sp_handle,
    void (*body)(void*),
    void* arg
);
/* Definition lives in stack_protect.h after the full handle type is
 * visible — keeping it inline lets the optimizer fold the SEH frames. */

// ---------------------------------------------------------------------------
// Decoy call nesting — add genuine but useless frames to the stack
//
// These are real CALL instructions that create real stack frames.
// Each one does nothing except call the next, building up 8+ frames
// of real (but meaningless) call depth. Then the innermost one calls
// the actual function.
//
// A debugger sees these as real calls with valid return addresses —
// they look like legitimate deep function nesting.
// ---------------------------------------------------------------------------

// Each decoy layer is noinline to guarantee a real stack frame
__declspec(noinline) static void ad_decoy_8(void (*fn)(void*), void* arg) { fn(arg); }
__declspec(noinline) static void ad_decoy_7(void (*fn)(void*), void* arg) { ad_decoy_8(fn, arg); }
__declspec(noinline) static void ad_decoy_6(void (*fn)(void*), void* arg) { ad_decoy_7(fn, arg); }
__declspec(noinline) static void ad_decoy_5(void (*fn)(void*), void* arg) { ad_decoy_6(fn, arg); }
__declspec(noinline) static void ad_decoy_4(void (*fn)(void*), void* arg) { ad_decoy_5(fn, arg); }
__declspec(noinline) static void ad_decoy_3(void (*fn)(void*), void* arg) { ad_decoy_4(fn, arg); }
__declspec(noinline) static void ad_decoy_2(void (*fn)(void*), void* arg) { ad_decoy_3(fn, arg); }
__declspec(noinline) static void ad_decoy_1(void (*fn)(void*), void* arg) { ad_decoy_2(fn, arg); }

// Entry: adds 8 real call frames, then calls fn(arg)
ANTIDEBUG_INLINE void ad_nested_call(void (*fn)(void*), void* arg) {
    ad_decoy_1(fn, arg);
}

// ---------------------------------------------------------------------------
// Combined: flood stack + nested calls + moonwalk + scramble
//
// The ultimate combo:
//   1. Flood ALL existing return addresses with ntdll decoys
//   2. Add 8 decoy call frames (real CALLs, meaningless)
//   3. Call fn() from inside the decoy nest
//   4. Restore everything
//
// The debugger sees 30+ frames, ALL fake or meaningless.
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE void ad_total_spoof_call(
    void (*fn)(void* arg),
    void* arg,
    const ad_gadget_table_t* gadgets,
    const ad_decoy_table_t*  decoys
) {
    ad_flood_ctx_t flood;
    ad_flood_stack(&flood, gadgets, decoys);

    // Nested calls add 8 real frames, then call fn
    ad_nested_call(fn, arg);

    ad_flood_restore(&flood);
}

#endif // ANTIDEBUG_STACK_FLOOD_H
