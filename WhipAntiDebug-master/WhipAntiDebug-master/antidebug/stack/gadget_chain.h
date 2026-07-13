// ===== file: antidebug/stack/gadget_chain.h =====
//
// ROP-style gadget chain for realistic stack spoofing.
//
// Problem with basic moonwalk:
//   We write decoy addresses on the stack, but they're arbitrary points
//   inside ntdll. A smart analyst notices they don't form a plausible
//   call chain (e.g., the instruction at decoy[0] isn't a CALL site).
//
// Solution:
//   Scan ntdll for CALL instruction sites (E8 xx xx xx xx) and use the
//   address AFTER the CALL (the return address) as decoys. This creates
//   a stack that looks like a real call chain:
//     fn() ← "returned from" ntdll!RtlAllocateHeap+0x42 (right after a CALL)
//            ← "returned from" ntdll!LdrLoadDll+0x1A3 (right after a CALL)
//            ← kernel32!BaseThreadInitThunk+0x14
//
//   This fools both debuggers AND automated stack unwinders that validate
//   whether return addresses are actually preceded by CALL instructions.
//
#ifndef ANTIDEBUG_GADGET_CHAIN_H
#define ANTIDEBUG_GADGET_CHAIN_H

#include "../core/types.h"
#include "../core/macros.h"
#include "moonwalk.h"  // ad_ntdll_base, ad_find_text_section

#define AD_GADGET_TABLE_SIZE 16u

typedef struct {
    void* call_rets[AD_GADGET_TABLE_SIZE];  // addresses right after CALL instructions
    u32   count;
    b32   ready;
} ad_gadget_table_t;

// ---------------------------------------------------------------------------
// Scan ntdll .text for CALL instruction return sites.
//
// A near CALL on x64 is: E8 <rel32> (5 bytes)
// The "return address" is at CALL_addr + 5.
// We collect these as high-quality decoy addresses.
//
// We skip CALL sites that point outside ntdll (import calls) and prefer
// sites deep inside large functions (more plausible as real call chains).
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE void ad_gadget_table_init(ad_gadget_table_t* tbl) {
    AD_ZERO_BUF(tbl, sizeof(*tbl));

    void* ntdll = ad_ntdll_base();
    if (!ntdll) return;

    u8* text_start = (u8*)0;
    u32 text_len = ad_find_text_section(ntdll, &text_start);
    if (!text_len || !text_start) return;

    // Stride across .text to get spread-out gadgets
    u32 stride = text_len / (AD_GADGET_TABLE_SIZE * 2u);
    if (stride < 64u) stride = 64u;

    u32 found = 0;
    u32 offset;

    for (offset = 32u; offset < text_len - 8u && found < AD_GADGET_TABLE_SIZE; offset += stride) {
        // Scan forward from this offset for a CALL (E8)
        u32 scan;
        for (scan = offset; scan < offset + stride && scan < text_len - 5u; scan++) {
            if (text_start[scan] == 0xE8u) {
                // Verify the CALL target is within ntdll .text (not an import thunk)
                s32 rel = *(s32*)(text_start + scan + 1);
                u8* target = text_start + scan + 5 + rel;

                if (target >= text_start && target < text_start + text_len) {
                    // Good: internal call. The return address is scan+5.
                    tbl->call_rets[found] = (void*)(text_start + scan + 5);
                    found++;
                    break;  // next stride region
                }
            }
        }
    }

    tbl->count = found;
    tbl->ready = (found > 0) ? 1 : 0;
}

// Pick a gadget, wrapping around if needed
ANTIDEBUG_INLINE void* ad_pick_gadget(const ad_gadget_table_t* tbl, u32 n) {
    if (!tbl->ready || tbl->count == 0) return (void*)0;
    return tbl->call_rets[n % tbl->count];
}

// ---------------------------------------------------------------------------
// Build a plausible call chain from the gadget table.
//
// Returns an array of `depth` void* pointers suitable for MoonwalkCall
// or ad_stack_burn. Each entry is a real CALL return site in ntdll,
// so the stack looks like a genuine nested call chain.
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE u32 ad_build_call_chain(
    const ad_gadget_table_t* tbl,
    void** chain,
    u32    depth
) {
    u32 i;
    u32 max = (depth < AD_GADGET_TABLE_SIZE) ? depth : AD_GADGET_TABLE_SIZE;
    for (i = 0; i < max; i++) {
        chain[i] = ad_pick_gadget(tbl, i);
        if (!chain[i]) break;
    }
    return i;
}

#endif // ANTIDEBUG_GADGET_CHAIN_H
