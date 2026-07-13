// ===== file: antidebug/checks/runtime/fake_hwbp.h =====
//
// Fake Hardware Breakpoints — squat DR0-DR3.
//
// x86-64 only has 4 hardware breakpoint slots (DR0-DR3). By filling all
// 4 with addresses inside our own (harmless) data and arming DR7, we
// PREVENT the reverser from setting their own hardware breakpoints —
// they'd have to clear ours, but our self-check immediately catches
// that.
//
// We arm them on a sentinel page that we never actually access in our
// hot path, so the trap never fires from our side.
//
#ifndef ANTIDEBUG_FAKE_HWBP_H
#define ANTIDEBUG_FAKE_HWBP_H

#include "../../core/types.h"
#include "../../core/macros.h"
#include "../../core/syscall_bridge.h"
#include "../../core/string_encrypt.h"

// Sentinel data — we never read these from hot paths.
static volatile u8 ad_fake_hwbp_sentinel[64] = {0};

ANTIDEBUG_INLINE b32 ad_fake_hwbp_install(void) {
#ifdef _MSC_VER
    static u16 s_set_ssn = AD_SSN_UNRESOLVED;
    AD_RESOLVE_SSN_ENC(s_set_ssn, NtSetContextThread, 19);
    if (s_set_ssn == AD_SSN_FAILED) return 0;

    AD_ALIGN(16) AD_CONTEXT ctx;
    AD_ZERO_BUF(&ctx, sizeof(ctx));
    ctx.ContextFlags = AD_CONTEXT_DEBUG_REGISTERS;

    u64 base = (u64)(uintptr_t)&ad_fake_hwbp_sentinel[0];
    ctx.Dr0 = base + 0x00ULL;
    ctx.Dr1 = base + 0x08ULL;
    ctx.Dr2 = base + 0x10ULL;
    ctx.Dr3 = base + 0x18ULL;
    // DR7: enable L0..L3 (local enable) for all 4 slots, length=1, type=00 (exec)
    // Each slot: Lx=bit (2*x). Length+Type at bits 16+(4*x).
    // For execute breakpoints we keep length=00 type=00, only set L0..L3.
    ctx.Dr7 = 0x55ULL;  // 0b01010101 — L0..L3 enabled

    ad_ntstatus_t st = (ad_ntstatus_t)(s64)AD_SYSCALL2(
        s_set_ssn, AD_CURRENT_THREAD, &ctx
    );
    return AD_NT_SUCCESS(st);
#else
    return 0;
#endif
}

// Verify our squat. NtSetContextThread on the pseudo handle of the
// CURRENT thread is silently a no-op on many Windows versions (the
// kernel cannot atomically suspend a running thread to set its DRs),
// so we cannot rely on the install having actually taken effect. We
// therefore accept three "clean" outcomes:
//   1. DRs are all zero → install was a no-op, no debugger present
//   2. DRs match our exact squat pattern → install worked, no debugger
//   3. (otherwise) DRs are nonzero and don't match → debugger took DRs
ANTIDEBUG_INLINE b32 ad_fake_hwbp_verify(void) {
#ifdef _MSC_VER
    static u16 s_get_ssn = AD_SSN_UNRESOLVED;
    AD_RESOLVE_SSN_ENC(s_get_ssn, NtGetContextThread, 19);
    if (s_get_ssn == AD_SSN_FAILED) return 0;

    AD_ALIGN(16) AD_CONTEXT ctx;
    AD_ZERO_BUF(&ctx, sizeof(ctx));
    ctx.ContextFlags = AD_CONTEXT_DEBUG_REGISTERS;

    ad_ntstatus_t st = (ad_ntstatus_t)(s64)AD_SYSCALL2(
        s_get_ssn, AD_CURRENT_THREAD, &ctx
    );
    if (!AD_NT_SUCCESS(st)) return 0;

    // All zero → install was a no-op, treat as clean.
    if ((ctx.Dr0 | ctx.Dr1 | ctx.Dr2 | ctx.Dr3) == 0ULL &&
        (ctx.Dr7 & 0xFFULL) == 0ULL) {
        return 0;
    }

    // Exact match of our squat pattern → install worked, clean.
    u64 base = (u64)(uintptr_t)&ad_fake_hwbp_sentinel[0];
    if (ctx.Dr0 == base + 0x00ULL &&
        ctx.Dr1 == base + 0x08ULL &&
        ctx.Dr2 == base + 0x10ULL &&
        ctx.Dr3 == base + 0x18ULL &&
        (ctx.Dr7 & 0xFFULL) == 0x55ULL) {
        return 0;
    }

    // Anything else → either debugger took DR slots, or our install
    // partially overlapped with a debugger's setup. Either way: caught.
    return 1;
#else
    return 0;
#endif
}

#endif // ANTIDEBUG_FAKE_HWBP_H
