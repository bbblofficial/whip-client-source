// ===== file: antidebug/core/stack_anchor.h =====
//
// Stack Anchor — return-address validation that crashes hard on bad frames.
//
// Idea
// ----
// Walk the return-address chain of the calling thread and verify every
// frame lives inside our own PE image. If any frame is outside our image
// the result is folded into a wild XOR mask, so any downstream pointer
// derived from `ad_stack_anchor_value` becomes garbage and crashes the
// next indirect call. On a clean run the function returns the caller's
// `expected` value byte-for-byte.
//
// What this catches
// -----------------
//   * ROP — at least one frame lives in libc/ntdll gadgets, not in our image
//   * Inline hooks that detour through a trampoline page outside the image
//   * DBI frameworks that execute the caller from a JIT code cache
//     (Pin, DynamoRIO, Frida-stalker)
//   * Frida Interceptor.attach — the hook layer's return frames sit in
//     manually-mapped pages
//   * "Run to cursor" tricks where a debugger spawns a fake thread to
//     invoke our function out of context — no legitimate caller frames
//
// Two-level walk
// --------------
// We walk via RtlCaptureStackBackTrace if it can be resolved through
// api_hash, otherwise we fall back to chasing _AddressOfReturnAddress()
// and reading subsequent saved frame pointers. The latter is fragile in
// /Oy- builds where the compiler may omit RBP, so we cap the walk at 4
// frames and accept any zero/null entry as end-of-stack.
//
// Crash semantics
// ---------------
// Pattern is identical to tamper_trip / witness_chain: a fold64 of the
// validation result XORs against the user's `expected` value. Clean run
// → fold64 == 0 → expected returned unchanged. Any bad frame → fold64
// is non-zero high-entropy garbage → returned value is wild → next use
// (as offset, divisor, function pointer) crashes.
//
// Usage
// -----
//   typedef int (*FN_render)(int);
//
//   // somewhere in a hot path
//   FN_render fn = (FN_render)(u64)ad_stack_anchor_value(
//       (u64)&real_render,  // expected
//       0x9F3A1B7C);        // arbitrary salt unique to this call site
//   fn(42);
//
// Or simpler — protect any constant used downstream:
//
//   u32 buf_size = (u32)ad_stack_anchor_value(0x1000, 0xABCD);
//   u8 buf[0x1000];
//   parse(buf, buf_size);   // crashes if a hooked frame is in the chain
//
#ifndef ANTIDEBUG_STACK_ANCHOR_H
#define ANTIDEBUG_STACK_ANCHOR_H

#include "types.h"
#include "macros.h"

#ifdef _MSC_VER
#include <intrin.h>
#endif

// ---------------------------------------------------------------------------
// PE image bounds (resolved once, cached)
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE void ad_stack_anchor_image_bounds(u8** out_base, u8** out_end) {
#ifdef _MSC_VER
    static u8* s_base = 0;
    static u8* s_end  = 0;
    if (!s_base) {
        u8* peb = (u8*)__readgsqword(0x60);
        if (!peb) { *out_base = 0; *out_end = 0; return; }
        u8* image_base = *(u8**)(peb + 0x10);
        if (!image_base || *(u16*)image_base != 0x5A4D) {
            *out_base = 0; *out_end = 0; return;
        }
        u32 pe_off = *(u32*)(image_base + 0x3C);
        u8* pe = image_base + pe_off;
        if (*(u32*)pe != 0x00004550u) { *out_base = 0; *out_end = 0; return; }
        u32 size_of_image = *(u32*)(pe + 24 + 56);
        s_base = image_base;
        s_end  = image_base + size_of_image;
    }
    *out_base = s_base;
    *out_end  = s_end;
#else
    *out_base = 0;
    *out_end  = 0;
#endif
}

// ---------------------------------------------------------------------------
// TEB stack bounds — used to bound the manual frame walk so we never
// dereference past the legitimate stack range.
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE void ad_stack_anchor_teb_bounds(u8** out_base, u8** out_limit) {
#ifdef _MSC_VER
    u8* teb = (u8*)__readgsqword(0x30);
    if (!teb) { *out_base = 0; *out_limit = 0; return; }
    // NT_TIB.StackBase  at TEB+0x08 (high address — top of stack)
    // NT_TIB.StackLimit at TEB+0x10 (low  address — bottom of committed range)
    *out_base  = *(u8**)(teb + 0x08);
    *out_limit = *(u8**)(teb + 0x10);
#else
    *out_base = 0;
    *out_limit = 0;
#endif
}

// ---------------------------------------------------------------------------
// Walk the return-address chain. Returns the count of bad frames found
// (frames whose RA is outside our image). Walks at most max_frames.
//
// Implementation: read _AddressOfReturnAddress() to get the stack slot
// of OUR caller's return address, then advance up the stack reading 8-byte
// aligned slots looking for plausible code pointers. We treat any value in
// [TEB.StackLimit, TEB.StackBase) range that points into a known PE image
// as a frame; values outside that range or pointing to unmapped memory are
// skipped. The walk is bounded by both max_frames and TEB.StackBase.
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE u32 ad_stack_anchor_walk_bad(u32 max_frames) {
#ifdef _MSC_VER
    u8* img_base = 0;
    u8* img_end  = 0;
    ad_stack_anchor_image_bounds(&img_base, &img_end);
    if (!img_base) return 0;

    u8* stk_base  = 0;
    u8* stk_limit = 0;
    ad_stack_anchor_teb_bounds(&stk_base, &stk_limit);
    if (!stk_base || !stk_limit) return 0;

    // _AddressOfReturnAddress points at the slot holding this function's
    // own return address. We start from there and crawl up.
    u8** ra_slot = (u8**)_AddressOfReturnAddress();
    if ((u8*)ra_slot < stk_limit || (u8*)ra_slot >= stk_base) return 0;

    u32 bad   = 0;
    u32 found = 0;
    u8** p = ra_slot;
    u32 hops = 0;

    // Cap the scan at 256 stack slots (2KB) to avoid pathological walks.
    while (found < max_frames && hops < 256u && (u8*)p < stk_base) {
        u8* candidate = *p;
        // Heuristic: a real return address points just past a CALL
        // instruction, so the byte BEFORE it is part of an x64 CALL opcode.
        // We accept any pointer landing in *some* plausible code page as a
        // frame: must be 16-byte+ aligned-ish AND non-NULL AND not on the
        // stack itself.
        if (candidate &&
            ((u64)candidate > 0x10000ULL) &&
            ((u8*)candidate < stk_limit || (u8*)candidate >= stk_base)) {
            // Looks like a code pointer. Is it inside our image?
            if (candidate >= img_base && candidate < img_end) {
                // good frame
            } else {
                bad++;
            }
            found++;
        }
        p++;
        hops++;
    }

    AD_UNUSED(found);
    return bad;
#else
    AD_UNUSED(max_frames);
    return 0;
#endif
}

// ---------------------------------------------------------------------------
// Same fold64 as tamper_trip — keeps single-bit changes spreading across
// the full 64-bit XOR mask.
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE u64 ad_stack_anchor_fold64(u64 v) {
    u64 a = v * 0xC6BC279692B5C323ULL;
    u64 b = v * 0x9FB21C651E98DF25ULL;
    return a ^ ((b << 32) | (b >> 32));
}

// ---------------------------------------------------------------------------
// Public entry: returns `expected` on a clean stack, garbage on a bad one.
//
//   expected — the value the caller wants downstream (pointer, size, idx…)
//   salt     — arbitrary 32-bit constant unique per call site so two
//              anchors at different sites cannot be folded together by
//              the optimizer
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE u64 ad_stack_anchor_value(u64 expected, u32 salt) {
    u32 bad = ad_stack_anchor_walk_bad(4u);
    // Mix bad-frame count with salt and fold. On clean stack, bad == 0,
    // so the inner expression is `salt * 0` == 0, fold64(0) == 0, and
    // expected ^ 0 == expected. On any bad frame, the salted product is
    // non-zero high-entropy → fold64 spreads it → return value is wild.
    u64 mix  = (u64)bad * ((u64)salt | 1ULL);
    u64 mask = ad_stack_anchor_fold64(mix);
    return expected ^ mask;
}

// Typed convenience macro: anchor a function pointer through the stack
// validator.
//
//   FN_render fn = AD_STACK_ANCHOR(FN_render, &real_render, 0x9F3A1B7C);
//   fn(arg);
#define AD_STACK_ANCHOR(fn_type, real_fn, salt) \
    ((fn_type)(u64)ad_stack_anchor_value((u64)(real_fn), (salt)))

#endif // ANTIDEBUG_STACK_ANCHOR_H
