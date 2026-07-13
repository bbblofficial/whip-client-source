// ===== file: antidebug/checks/exceptions/seh.h =====
//
// SEH (Structured Exception Handling) based anti-debug checks.
// Under a debugger, first-chance exceptions are intercepted before our handler
// runs. We exploit this asymmetry to detect the debugger's presence.
//
// Requires MSVC — __try/__except are compiler intrinsics, no CRT needed.
// All checks work on x64 (no inline asm; uses compiler intrinsics only).
//
#ifndef ANTIDEBUG_SEH_H
#define ANTIDEBUG_SEH_H

#include "../../core/types.h"
#include "../../core/macros.h"

#if defined(_MSC_VER)

// ---------------------------------------------------------------------------
// Check: __debugbreak() interception (EXCEPTION_BREAKPOINT 0x80000003)
//
// Without a debugger: __except fires, handled = 1.
// With a debugger that swallows first-chance BPs: execution resumes AFTER
// the __debugbreak() instruction, __except is never reached, handled stays 0.
//
// Debuggers that "pass to program": handled = 1 (false negative for this check).
// Combine with other checks — this is one signal among many.
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE b32 ad_seh_breakpoint(void) {
    volatile b32 handled = 0;
    __try {
        __debugbreak();       // INT 3 — raises EXCEPTION_BREAKPOINT
    }
    __except (1 /* EXCEPTION_EXECUTE_HANDLER */) {
        handled = 1;
    }
    return (b32)(handled == 0);
}

// ---------------------------------------------------------------------------
// Check: integer division by zero (EXCEPTION_INT_DIVIDE_BY_ZERO 0xC0000094)
//
// A debugger configured to handle arithmetic exceptions will intercept this
// before our __except block. Detection pattern: same as above.
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE b32 ad_seh_divide_by_zero(void) {
    volatile b32 handled = 0;
    __try {
        volatile u32 zero = 0u;
        volatile u32 val  = 1u / zero;
        AD_UNUSED(val);
    }
    __except (1) {
        handled = 1;
    }
    return (b32)(handled == 0);
}

// ---------------------------------------------------------------------------
// Check: access violation on near-null pointer (EXCEPTION_ACCESS_VIOLATION)
//
// Same interception logic: a debugger eating the AV before our handler
// leaves handled == 0. Address 0x1 is always unmapped.
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE b32 ad_seh_access_violation(void) {
    volatile b32 handled = 0;
    __try {
        volatile u8* bad = (volatile u8*)1;
        volatile u8  v   = *bad;
        AD_UNUSED(v);
    }
    __except (1) {
        handled = 1;
    }
    return (b32)(handled == 0);
}

// ---------------------------------------------------------------------------
// Check: __fastfail() guard
//
// __fastfail() raises a STATUS_STACK_BUFFER_OVERRUN (0xC0000409) exception
// via a direct INT 29h (no unwinding, non-continuable). A kernel debugger
// or WinDbg will catch this; user-mode SEH cannot suppress it cleanly.
// We use this as an ASYMMETRIC signal: we only call this if other checks
// are ALREADY suspicious (see dispatcher). It is NOT run by default.
//
// Usage: call manually when confidence is high.
// Returns 0 always (process dies if a kernel debugger is attached).
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE b32 ad_seh_fastfail_probe(void) {
    // __fastfail(1); // FAST_FAIL_RANGE_CHECK_FAILURE
    // Commented out because calling this unconditionally terminates the
    // process under WinDbg kernel debugging. Enable only after other checks
    // confirm a debugger is present.
    return 0;
}

#else  // Non-MSVC stubs

ANTIDEBUG_INLINE b32 ad_seh_breakpoint(void)       { return 0; }
ANTIDEBUG_INLINE b32 ad_seh_divide_by_zero(void)   { return 0; }
ANTIDEBUG_INLINE b32 ad_seh_access_violation(void)  { return 0; }
ANTIDEBUG_INLINE b32 ad_seh_fastfail_probe(void)    { return 0; }

#endif // _MSC_VER

#endif // ANTIDEBUG_SEH_H
