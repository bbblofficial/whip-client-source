// ===== file: antidebug/checks/breakpoints/int3_scan.h =====
//
// Software breakpoint detection via byte scanning.
// INT3 = 0xCC. When a debugger sets a software BP it overwrites one byte
// at the target address with 0xCC. Scanning code bytes catches this.
//
#ifndef ANTIDEBUG_INT3_SCAN_H
#define ANTIDEBUG_INT3_SCAN_H

#include "../../core/types.h"
#include "../../core/macros.h"
#include "../../core/config.h"

// ---------------------------------------------------------------------------
// Check: scan AD_INT3_SCAN_RANGE bytes from fn_ptr for 0xCC
//
// Call this with a pointer to a sensitive function to detect if a debugger
// has placed a software breakpoint at its entry point or prologue.
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE b32 ad_int3_scan(const void* fn_ptr) {
    if (!fn_ptr) return 0;

    const volatile u8* p = (const volatile u8*)fn_ptr;
    u32 i;
    for (i = 0u; i < (u32)AD_INT3_SCAN_RANGE; i++) {
        if (p[i] == (u8)0xCC) return 1;
    }
    return 0;
}

// ---------------------------------------------------------------------------
// Check: scan the caller's return address neighborhood for INT3
//
// Detects BPs placed around the call site of any function that calls us.
// Uses _ReturnAddress() (MSVC) to get the return address without stack walking.
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE b32 ad_caller_int3_scan(void) {
#if defined(_MSC_VER)
    const volatile u8* ret = (const volatile u8*)_ReturnAddress();
    u32 i;
    // Scan 8 bytes before the return address (the CALL instruction area)
    const volatile u8* before = ret - 8;
    for (i = 0u; i < 8u; i++) {
        if (before[i] == (u8)0xCC) return 1;
    }
    // Scan AD_INT3_SCAN_RANGE bytes starting at the return address
    for (i = 0u; i < (u32)AD_INT3_SCAN_RANGE; i++) {
        if (ret[i] == (u8)0xCC) return 1;
    }
    return 0;
#else
    return 0;
#endif
}

// ---------------------------------------------------------------------------
// Check: scan a raw byte range [base, base+len) for any 0xCC byte
//
// Used by the code-integrity subsystem over the full .text section.
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE b32 ad_int3_range_scan(const void* base, u32 len) {
    const volatile u8* p = (const volatile u8*)base;
    u32 i;
    for (i = 0u; i < len; i++) {
        if (p[i] == (u8)0xCC) return 1;
    }
    return 0;
}

#endif // ANTIDEBUG_INT3_SCAN_H
