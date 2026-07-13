// ===== file: antidebug/checks/breakpoints/hardware.h =====
//
// Hardware breakpoint detection via NtGetContextThread.
// Reads the debug registers DR0–DR3 (breakpoint addresses) and DR7 (control).
// Uses WhipSysCall — no ntdll IAT entry for GetThreadContext.
//
#ifndef ANTIDEBUG_HARDWARE_H
#define ANTIDEBUG_HARDWARE_H

#include "../../core/types.h"
#include "../../core/macros.h"
#include "../../core/syscall_bridge.h"
#include "../../core/string_encrypt.h"

// ---------------------------------------------------------------------------
// Check: hardware breakpoints via NtGetContextThread
//
// DR0–DR3: breakpoint linear addresses (non-zero = BP set)
// DR7:     control register — lower byte encodes local/global enable bits
//           bits 0,2,4,6 enable DR0–DR3 locally
//
// If any DR0–DR3 is non-zero, or DR7's enable bits are set, a hardware
// breakpoint is active. x64dbg and WinDbg use DR0–DR3 for "hardware BPs".
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE b32 ad_hardware_breakpoints(void) {
    static u16 s_ssn = AD_SSN_UNRESOLVED;
    AD_RESOLVE_SSN_ENC(s_ssn, NtGetContextThread, 19);
    if (s_ssn == AD_SSN_FAILED) return 0;

    // Stack-allocate a zero-initialised CONTEXT (16-byte aligned)
    AD_ALIGN(16) AD_CONTEXT ctx;
    AD_ZERO_BUF(&ctx, sizeof(ctx));
    ctx.ContextFlags = AD_CONTEXT_DEBUG_REGISTERS;

    ad_ntstatus_t st = AD_SYSCALL2(
        s_ssn,
        AD_CURRENT_THREAD,
        &ctx
    );

    if (!AD_NT_SUCCESS(st)) return 0;

    // Any BP address set?
    b32 addr_set = (b32)(ctx.Dr0 | ctx.Dr1 | ctx.Dr2 | ctx.Dr3);

    // DR7 local-enable bits (G0/L0..G3/L3 = bits 0,1,2,3,4,5,6,7)
    // Also check GD bit (bit 13) = general-detect enable
    b32 dr7_armed = (b32)((ctx.Dr7 & 0x00000000000000FFULL) != 0ULL);

    return (b32)(addr_set | dr7_armed);
}

#endif // ANTIDEBUG_HARDWARE_H
