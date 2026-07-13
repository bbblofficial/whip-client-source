// ===== file: antidebug/checks/integrity/ept_split.h =====
//
// EPT (Extended Page Tables) split-page detection.
//
// Detects hypervisor-level hooks that use EPT to present different code
// for data reads vs. instruction execution.  This is used by hypervisor
// debuggers (DdiMon, HyperPlatform, hvpp) and stealthy inline hooks.
//
// Technique:
//   A canary function returns a known magic constant.  We call it (execution
//   path through EPT execute mapping), then read its bytes as data (data path
//   through EPT read mapping).  If the read bytes contain the expected
//   MOV EAX, <magic> encoding, the pages are consistent.  If the function
//   returned the correct value but the encoding is missing from the data
//   read, the execute and data pages differ — EPT split detected.
//
// No CRT, no imports.
//
#ifndef ANTIDEBUG_EPT_SPLIT_H
#define ANTIDEBUG_EPT_SPLIT_H

#include "../../core/types.h"
#include "../../core/macros.h"
#include "../../core/config.h"

#if defined(_MSC_VER)

// ---------------------------------------------------------------------------
// Magic constant — appears as: B8 37 13 FE CA  (mov eax, 0xCAFE1337)
// Chosen to be unlikely to occur naturally in surrounding code.
// ---------------------------------------------------------------------------
#define AD_EPT_CANARY_MAGIC  0xCAFE1337u

// ---------------------------------------------------------------------------
// Canary function — NOINLINE so it has its own code body we can scan.
//
// Must be simple: just return the magic constant.  The compiler will emit
// something like:
//   mov eax, 0xCAFE1337
//   ret
//
// We mark it NOINLINE + volatile return to prevent the optimizer from
// constant-folding the call away or inlining the body.
// ---------------------------------------------------------------------------
#pragma optimize("", off)
static NOINLINE u32 ad_ept_canary_fn(void) {
    return AD_EPT_CANARY_MAGIC;
}
#pragma optimize("", on)

// ---------------------------------------------------------------------------
// EPT split-page check
//
// Steps:
//   1. Call the canary function → capture return value (execution path)
//   2. Read the function's bytes as data (data path)
//   3. Scan for the MOV EAX, imm32 encoding: B8 xx xx xx xx
//      where xx xx xx xx = little-endian 0xCAFE1337 = 37 13 FE CA
//   4. Decision matrix:
//      - Returned correct + pattern found     → consistent (no split)
//      - Returned correct + pattern NOT found → EPT split detected
//        (data page shows different bytes than what was executed)
//      - Returned wrong value                 → execution page patched
//        (something modified the code that runs, also suspicious)
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE b32 ad_ept_split_check(void) {
    // Step 1: execute the canary (goes through EPT execute mapping)
    AD_BARRIER();
    volatile u32 ret_val = ad_ept_canary_fn();
    AD_BARRIER();

    // Step 2: read the function's bytes as data (goes through EPT read mapping)
    // We scan up to 64 bytes — more than enough for the tiny function body.
    const volatile u8* fn_bytes = (const volatile u8*)(void*)&ad_ept_canary_fn;
    u32 scan_len = 64u;

    // The pattern we expect: B8 37 13 FE CA
    // B8 = MOV EAX, imm32 opcode
    // 37 13 FE CA = 0xCAFE1337 in little-endian
    u8 pattern[5];
    pattern[0] = 0xB8u;
    pattern[1] = (u8)(AD_EPT_CANARY_MAGIC & 0xFFu);
    pattern[2] = (u8)((AD_EPT_CANARY_MAGIC >> 8) & 0xFFu);
    pattern[3] = (u8)((AD_EPT_CANARY_MAGIC >> 16) & 0xFFu);
    pattern[4] = (u8)((AD_EPT_CANARY_MAGIC >> 24) & 0xFFu);

    // Step 3: scan for the pattern in the data-read bytes
    b32 pattern_found = 0;
    u32 i, j;
    for (i = 0u; i + 5u <= scan_len; i++) {
        b32 match = 1;
        for (j = 0u; j < 5u; j++) {
            if (fn_bytes[i + j] != pattern[j]) {
                match = 0;
                break;
            }
        }
        if (match) {
            pattern_found = 1;
            break;
        }
    }

    AD_BARRIER();

    // Step 4: decision
    if (ret_val == AD_EPT_CANARY_MAGIC) {
        // Function returned the correct magic value (execution was fine).
        // If we can't find the encoding in the data read, the data page
        // shows different bytes — EPT split.
        return (b32)(!pattern_found);
    }

    // Function returned a WRONG value — the execution page itself was
    // patched (inline hook or code modification).  Also suspicious.
    return 1;
}

// ---------------------------------------------------------------------------
// Extended EPT check: dual-canary with different constants
//
// Uses a second canary function with a different magic to reduce the chance
// of a false positive from compiler code-gen variations (e.g., LEA-based
// constant materialization instead of MOV EAX, imm32).
// ---------------------------------------------------------------------------
#define AD_EPT_CANARY_MAGIC2  0xDEAD8008u

#pragma optimize("", off)
static NOINLINE u32 ad_ept_canary_fn2(void) {
    return AD_EPT_CANARY_MAGIC2;
}
#pragma optimize("", on)

ANTIDEBUG_INLINE b32 ad_ept_split_extended(void) {
    b32 split1 = 0;
    b32 split2 = 0;

    // --- Canary 1 ---
    AD_BARRIER();
    volatile u32 r1 = ad_ept_canary_fn();
    AD_BARRIER();
    {
        const volatile u8* fb = (const volatile u8*)(void*)&ad_ept_canary_fn;
        u8 pat[5];
        pat[0] = 0xB8u;
        pat[1] = (u8)(AD_EPT_CANARY_MAGIC & 0xFFu);
        pat[2] = (u8)((AD_EPT_CANARY_MAGIC >> 8) & 0xFFu);
        pat[3] = (u8)((AD_EPT_CANARY_MAGIC >> 16) & 0xFFu);
        pat[4] = (u8)((AD_EPT_CANARY_MAGIC >> 24) & 0xFFu);
        b32 found = 0;
        u32 i, j;
        for (i = 0u; i + 5u <= 64u; i++) {
            b32 m = 1;
            for (j = 0u; j < 5u; j++)
                if (fb[i + j] != pat[j]) { m = 0; break; }
            if (m) { found = 1; break; }
        }
        if (r1 == AD_EPT_CANARY_MAGIC && !found) split1 = 1;
        if (r1 != AD_EPT_CANARY_MAGIC)           split1 = 1;
    }

    // --- Canary 2 ---
    AD_BARRIER();
    volatile u32 r2 = ad_ept_canary_fn2();
    AD_BARRIER();
    {
        const volatile u8* fb = (const volatile u8*)(void*)&ad_ept_canary_fn2;
        u8 pat[5];
        pat[0] = 0xB8u;
        pat[1] = (u8)(AD_EPT_CANARY_MAGIC2 & 0xFFu);
        pat[2] = (u8)((AD_EPT_CANARY_MAGIC2 >> 8) & 0xFFu);
        pat[3] = (u8)((AD_EPT_CANARY_MAGIC2 >> 16) & 0xFFu);
        pat[4] = (u8)((AD_EPT_CANARY_MAGIC2 >> 24) & 0xFFu);
        b32 found = 0;
        u32 i, j;
        for (i = 0u; i + 5u <= 64u; i++) {
            b32 m = 1;
            for (j = 0u; j < 5u; j++)
                if (fb[i + j] != pat[j]) { m = 0; break; }
            if (m) { found = 1; break; }
        }
        if (r2 == AD_EPT_CANARY_MAGIC2 && !found) split2 = 1;
        if (r2 != AD_EPT_CANARY_MAGIC2)           split2 = 1;
    }

    // Flag if EITHER canary detects a split
    return (b32)(split1 | split2);
}

#else  // Non-MSVC stubs

ANTIDEBUG_INLINE b32 ad_ept_split_check(void)    { return 0; }
ANTIDEBUG_INLINE b32 ad_ept_split_extended(void)  { return 0; }

#endif // _MSC_VER

#endif // ANTIDEBUG_EPT_SPLIT_H
