// ===== file: antidebug/checks/advanced/btb_triangulate.h =====
//
// BTB Mispredict Triangulation — HWBP detection via side-effect, not via
// DR register inspection.
//
// Classical anti-HWBP calls NtGetContextThread and reads DR0-DR3. ScyllaHide,
// TitanHide and similar plugins intercept that query and return zeros. The
// check becomes useless.
//
// This module never touches DR*. Instead it builds a table of AD_BTB_GADGETS
// tiny executable gadgets in an RWX page, each at a known 16-byte-aligned
// address, and measures the per-gadget indirect-call latency. A hardware
// breakpoint armed on any gadget address produces one of two observable
// effects, BOTH detectable:
//
//   1. Debugger attached: when CPU fetches the armed gadget, #DB is raised
//      and delivered to the debugger's port. Round-trip back to user mode
//      takes tens of thousands of cycles — a massive outlier in the table.
//
//   2. No debugger but DR armed (rare — leftover from detached debugger,
//      or self-armed by another process via SetThreadContext): #DB falls
//      through to user-mode SEH as STATUS_SINGLE_STEP and the __except
//      filter fires.
//
// Either way the check returns 1. It never reads DR registers, so any
// DR-spoofing plugin sees nothing to spoof.
//
#ifndef ANTIDEBUG_BTB_TRIANGULATE_H
#define ANTIDEBUG_BTB_TRIANGULATE_H

#include "../../core/types.h"
#include "../../core/macros.h"
#include "../../core/syscall_bridge.h"
#include "../../core/string_encrypt.h"

#ifdef _MSC_VER

#ifndef EXCEPTION_EXECUTE_HANDLER
#define EXCEPTION_EXECUTE_HANDLER      1
#define EXCEPTION_CONTINUE_SEARCH      0
#define EXCEPTION_CONTINUE_EXECUTION (-1)
#endif

#define AD_BTB_GADGETS        32U     // power of two — used as ring mask
#define AD_BTB_STRIDE         16U     // bytes per gadget, 16-byte aligned
#define AD_BTB_PAGE_SIZE      4096U
#define AD_BTB_TRAIN_ITERS    512U
#define AD_BTB_MEASURE_ROUNDS 8U
#define AD_BTB_OUTLIER_MULT   4ULL    // latency > median * 4 = suspicious
#define AD_BTB_OUTLIER_FLOOR  500ULL  // absolute floor to avoid false pos on
                                      // tiny medians (100-cycle-range noise)

typedef void (*ad_btb_gadget_fn)(void);

typedef struct {
    u8*              page;
    ad_btb_gadget_fn targets[AD_BTB_GADGETS];
    u32              ready;
} ad_btb_state_t;

// Gadget body — 8 meaningful bytes padded with NOPs to AD_BTB_STRIDE.
//   endbr64      F3 0F 1E FA    (CET IBT landing pad — NOP on non-CET CPUs)
//   xor eax,eax  31 C0          (trivial work, no side effects)
//   ret          C3
static const u8 AD_BTB_GADGET_BYTES[AD_BTB_STRIDE] = {
    0xF3, 0x0F, 0x1E, 0xFA,
    0x31, 0xC0,
    0xC3,
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90
};

// Lazy initialisation — one RWX page, one gadget table. Safe to call from
// multiple threads; worst case is two races allocating twice. The syscall
// wrapper already returns STATUS_SUCCESS on the second commit when the
// region is already mapped, so the second allocation is harmless.
ANTIDEBUG_INLINE b32 ad_btb_init(ad_btb_state_t* s) {
    if (s->ready) return 1;

    static u16 s_alloc_ssn = AD_SSN_UNRESOLVED;
    AD_RESOLVE_SSN_ENC(s_alloc_ssn, NtAllocateVirtualMemory, 24);
    if (s_alloc_ssn == AD_SSN_FAILED) return 0;

    void* base = 0;
    u64   size = AD_BTB_PAGE_SIZE;
    ad_ntstatus_t st = (ad_ntstatus_t)(s64)SyscallStub(s_alloc_ssn,
        AD_CURRENT_PROCESS, &base, (void*)0, &size,
        (void*)(u64)0x3000,     // MEM_COMMIT | MEM_RESERVE
        (void*)(u64)0x40,       // PAGE_EXECUTE_READWRITE
        (void*)0, (void*)0, (void*)0, (void*)0, (void*)0
    );
    if (!AD_NT_SUCCESS(st) || !base) return 0;

    u8* p = (u8*)base;
    u32 g, b;
    for (g = 0u; g < AD_BTB_GADGETS; g++) {
        for (b = 0u; b < AD_BTB_STRIDE; b++) {
            p[g * AD_BTB_STRIDE + b] = AD_BTB_GADGET_BYTES[b];
        }
        s->targets[g] = (ad_btb_gadget_fn)(p + g * AD_BTB_STRIDE);
    }
    s->page  = p;
    s->ready = 1u;
    return 1;
}

// SEH-wrapped single measurement. Returns cycle delta, or (u64)-1 if a
// #DB fired and was caught by our filter — which itself is a positive
// signal (HWBP armed, debugger not intercepting).
//
// guard(nocf): the indirect call targets an RWX allocation that is not in
// the CFG valid-target bitmap, so with /guard:cf the call would fast-fail.
__declspec(guard(nocf))
static NOINLINE u64 ad_btb_time_gadget(ad_btb_gadget_fn g) {
    u64 t0 = 0, t1 = 0;
    u32 aux = 0;

    __try {
        AD_LFENCE();
        t0 = __rdtscp(&aux);
        AD_LFENCE();
        g();
        AD_LFENCE();
        t1 = __rdtscp(&aux);
        AD_LFENCE();
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return (u64)-1;
    }
    return t1 - t0;
}

// Core measurement pass — operates on a caller-supplied state. Used by
// the public check (via its own static state) and by test harnesses that
// need to inspect / mutate the gadget table directly.
//
// Set AD_BTB_DIAG=1 at build time to enable per-gadget latency printout
// via OutputDebugStringA (requires an extern put()).
__declspec(guard(nocf))
ANTIDEBUG_INLINE b32 ad_btb_triangulate_check_ex(ad_btb_state_t* s) {
    if (!ad_btb_init(s)) return 0;

    __try {
        u32 w;
        for (w = 0u; w < AD_BTB_TRAIN_ITERS; w++) {
            s->targets[w & (AD_BTB_GADGETS - 1u)]();
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return 1;
    }

    u64 lats[AD_BTB_GADGETS];
    u32 i, r;
    for (i = 0u; i < AD_BTB_GADGETS; i++) {
        u64 best = (u64)-1;
        for (r = 0u; r < AD_BTB_MEASURE_ROUNDS; r++) {
            u64 dt = ad_btb_time_gadget(s->targets[i]);
            if (dt == (u64)-1) return 1;
            if (dt < best) best = dt;
        }
        lats[i] = best;
    }

    u64 sorted[AD_BTB_GADGETS];
    u32 j, k;
    for (i = 0u; i < AD_BTB_GADGETS; i++) sorted[i] = lats[i];
    for (j = 1u; j < AD_BTB_GADGETS; j++) {
        u64 v = sorted[j];
        k = j;
        while (k > 0u && sorted[k - 1u] > v) {
            sorted[k] = sorted[k - 1u];
            k--;
        }
        sorted[k] = v;
    }
    u64 med = sorted[AD_BTB_GADGETS / 2u];
    if (med < 20ULL) med = 20ULL;

    u64 threshold = med * AD_BTB_OUTLIER_MULT;
    if (threshold < AD_BTB_OUTLIER_FLOOR) threshold = AD_BTB_OUTLIER_FLOOR;

    for (i = 0u; i < AD_BTB_GADGETS; i++) {
        if (lats[i] > threshold) return 1;
    }
    return 0;
}

// Public check — owns its private state so the master dispatcher doesn't
// have to thread one through. Returns 1 on HWBP-like perturbation.
__declspec(guard(nocf))
ANTIDEBUG_INLINE b32 ad_btb_triangulate_check(void) {
    static ad_btb_state_t s_state = {0};
    return ad_btb_triangulate_check_ex(&s_state);
}

// Diagnostic variant: fills caller-provided lats[AD_BTB_GADGETS] with the
// best observed latency per gadget. Does not return early on #DB — useful
// for harnesses that want to see the full distribution.
__declspec(guard(nocf))
ANTIDEBUG_INLINE void ad_btb_triangulate_lats(ad_btb_state_t* s, u64* lats_out) {
    if (!ad_btb_init(s)) { u32 i; for (i = 0; i < AD_BTB_GADGETS; i++) lats_out[i] = 0; return; }
    u32 w;
    for (w = 0u; w < AD_BTB_TRAIN_ITERS; w++) {
        __try { s->targets[w & (AD_BTB_GADGETS - 1u)](); } __except (EXCEPTION_EXECUTE_HANDLER) { break; }
    }
    u32 i, r;
    for (i = 0u; i < AD_BTB_GADGETS; i++) {
        u64 best = (u64)-1;
        for (r = 0u; r < AD_BTB_MEASURE_ROUNDS; r++) {
            u64 dt = ad_btb_time_gadget(s->targets[i]);
            if (dt == (u64)-1) { best = (u64)-2; break; }
            if (dt < best) best = dt;
        }
        lats_out[i] = best;
    }
}

#else  // !_MSC_VER

ANTIDEBUG_INLINE b32 ad_btb_triangulate_check(void) { return 0; }

#endif // _MSC_VER

#endif // ANTIDEBUG_BTB_TRIANGULATE_H