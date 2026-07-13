// ===== file: antidebug/checks/integrity/critical_scan.h =====
//
// Critical function integrity scanner.
//
// Scans the first N bytes of caller-specified functions for:
//   - 0xCC (INT3 software breakpoint)
//   - 0xE9 (JMP rel32 — inline hook)
//   - FF 25 (JMP [rip+disp32] — indirect hook)
//
// Called JUST BEFORE a critical function (derive_key_stream, main, etc.)
// to catch breakpoints placed by a debugger at runtime. Unlike the
// static anti_patch.h checks, this is a point-in-time scan right before
// the call — catching BPs set after init.
//
// During the x64dbg bypass test, a single INT3 BP on derive_key_stream
// was invisible to existing checks. This module closes that gap.
//
#ifndef ANTIDEBUG_CRITICAL_SCAN_H
#define ANTIDEBUG_CRITICAL_SCAN_H

#include "../../core/types.h"
#include "../../core/macros.h"
#include "../../core/config.h"

#if defined(_MSC_VER)

// =========================================================================
// Scan a single function's prologue for suspicious bytes
// =========================================================================
//
// Returns the number of suspicious bytes found (0 = clean).
// Uses volatile reads to prevent the compiler from optimizing away.
// =========================================================================
ANTIDEBUG_INLINE u32 ad_critical_fn_scan(const void* fn_ptr, u32 scan_size) {
    if (!fn_ptr || scan_size == 0u) return 0u;

    const volatile u8* code = (const volatile u8*)fn_ptr;
    u32 suspicious = 0u;
    u32 i;

    for (i = 0u; i < scan_size; i++) {
        u8 b = code[i];

        // INT3 breakpoint (software BP)
        if (b == 0xCCu) {
            suspicious++;
        }
    }

    // Check first byte specifically for hook signatures
    {
        u8 b0 = code[0];
        // JMP rel32 (inline hook)
        if (b0 == 0xE9u) suspicious += 2u;
        // JMP [rip+disp32] (ScyllaHide-style hook)
        if (scan_size >= 2u && b0 == 0xFFu && code[1] == 0x25u) suspicious += 2u;
    }

    return suspicious;
}

// =========================================================================
// Batch scan: check an array of function pointers
// =========================================================================
//
// fn_array: array of function pointers to scan
// count:    number of entries
// Returns:  weighted score (each suspicious byte × 5)
// =========================================================================
ANTIDEBUG_INLINE u32 ad_critical_scan_master(const void* const* fn_array, u32 count) {
    if (!fn_array || count == 0u) return 0u;

    u32 total_suspicious = 0u;
    u32 i;

    for (i = 0u; i < count; i++) {
        if (!fn_array[i]) continue;
        // Scan first 64 bytes of each function
        total_suspicious += ad_critical_fn_scan(fn_array[i], 64u);
    }

    // Weight: each suspicious byte = 5 score points
    return total_suspicious * 5u;
}

#else  // Non-MSVC stubs

ANTIDEBUG_INLINE u32 ad_critical_fn_scan(const void* fn_ptr, u32 scan_size) {
    (void)fn_ptr; (void)scan_size; return 0u;
}
ANTIDEBUG_INLINE u32 ad_critical_scan_master(const void* const* fn_array, u32 count) {
    (void)fn_array; (void)count; return 0u;
}

#endif // _MSC_VER

#endif // ANTIDEBUG_CRITICAL_SCAN_H
