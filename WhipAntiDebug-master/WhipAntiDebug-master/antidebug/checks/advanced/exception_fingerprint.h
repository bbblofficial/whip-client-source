// ===== file: antidebug/checks/advanced/exception_fingerprint.h =====
//
// Exception Flow Fingerprinting — chain multiple exception types to build
// a fingerprint of the debugger. Each debugger handles exceptions differently
// (swallow, pass, modify). The resulting bit pattern identifies the debugger.
//
#ifndef ANTIDEBUG_EXCEPTION_FINGERPRINT_H
#define ANTIDEBUG_EXCEPTION_FINGERPRINT_H

#include "../../core/types.h"
#include "../../core/macros.h"

typedef enum {
    AD_DEBUGGER_NONE     = 0,
    AD_DEBUGGER_GENERIC  = 1,
} ad_debugger_id_t;

// ---------------------------------------------------------------------------
// Exception chain: fire 4 exception types, record which handlers execute.
// Build a 4-bit fingerprint.
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE u32 ad_exception_chain_fingerprint(void) {
#ifdef _MSC_VER
    volatile u32 fp = 0;

    // Bit 0: INT3 (EXCEPTION_BREAKPOINT)
    __try {
        __debugbreak();
    }
    __except (1) {
        fp |= 1u;
    }

    // Bit 1: Single-step via trap flag
    __try {
        __writeeflags(__readeflags() | 0x100ULL);
        __nop();
    }
    __except (1) {
        fp |= 2u;
    }

    // Bit 2: Access violation (read from NULL)
    __try {
        volatile u8 x = *(volatile u8*)0;
        (void)x;
    }
    __except (1) {
        fp |= 4u;
    }

    // Bit 3: Integer divide by zero
    __try {
        volatile u32 z = 0;
        volatile u32 r = 1u / z;
        (void)r;
    }
    __except (1) {
        fp |= 8u;
    }

    return fp;
#else
    return 0xFu;
#endif
}

// ---------------------------------------------------------------------------
// Nested exception check — fire exception inside exception handler.
// Debuggers often mishandle or break on nested exceptions.
// ---------------------------------------------------------------------------
// Note: ad_nested_exception_check already exists in exotic.h
// We reuse it via the existing function. This wrapper just calls the
// exception chain fingerprint for the advanced check.

// (nested exception check provided by exotic.h)

// ---------------------------------------------------------------------------
// Master exception fingerprint check
// Returns 1 if environment is suspicious
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE b32 ad_exception_fingerprint_check(void) {
    u32 fp = ad_exception_chain_fingerprint();
    // Clean environment: all 4 handlers fire → fp = 0x0F
    // Debugger: one or more exceptions consumed → fp < 0x0F
    b32 chain_suspicious = (b32)(fp != 0x0Fu);
    return chain_suspicious;
}

#endif // ANTIDEBUG_EXCEPTION_FINGERPRINT_H
