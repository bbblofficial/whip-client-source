// ===== file: antidebug/stack/syscall_spoof.h =====
//
// Syscall return address spoofing.
//
// Problem:
//   When we do a SYSCALL, the kernel records the return address (RIP after
//   the SYSCALL instruction). ETW, Process Monitor, and kernel callbacks
//   can inspect this. If it doesn't point into ntdll, the call is flagged
//   as a direct syscall (red flag for EDR/anti-cheat).
//
// Solution:
//   Instead of doing SYSCALL from our own code (like WhipSysCall does),
//   we trampoline through a legitimate ntdll syscall stub:
//
//   1. Find a `syscall; ret` gadget inside ntdll (they all have this)
//   2. Set up the registers (RAX=SSN, R10=RCX, etc.) ourselves
//   3. JMP to the ntdll gadget — the SYSCALL instruction executes from
//      ntdll's .text, so the return address looks legitimate
//
//   This is the "indirect syscall" technique used by advanced malware.
//
#ifndef ANTIDEBUG_SYSCALL_SPOOF_H
#define ANTIDEBUG_SYSCALL_SPOOF_H

#include "../core/types.h"
#include "../core/macros.h"
#include "moonwalk.h"  // ad_ntdll_base, ad_find_text_section

// ---------------------------------------------------------------------------
// Find a "syscall; ret" gadget in ntdll .text
//
// Byte pattern: 0F 05 C3 (syscall; ret)
// We need this to trampoline through ntdll so the return address
// of the SYSCALL instruction is inside ntdll, not our module.
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE void* ad_find_syscall_ret_gadget(void) {
    void* ntdll = ad_ntdll_base();
    if (!ntdll) return (void*)0;

    u8* text_start = (u8*)0;
    u32 text_len = ad_find_text_section(ntdll, &text_start);
    if (!text_len || !text_start) return (void*)0;

    // Scan for: 0F 05 C3 (syscall; ret)
    u32 i;
    for (i = 0; i < text_len - 3u; i++) {
        if (text_start[i]     == 0x0Fu &&
            text_start[i + 1] == 0x05u &&
            text_start[i + 2] == 0xC3u) {
            return (void*)(text_start + i);
        }
    }
    return (void*)0;
}

// ---------------------------------------------------------------------------
// Find multiple syscall;ret gadgets for rotation
//
// Using the same gadget every time creates a pattern. We collect several
// and rotate between them to make pattern matching harder.
// ---------------------------------------------------------------------------
#define AD_SYSCALL_GADGET_COUNT 8u

typedef struct {
    void* gadgets[AD_SYSCALL_GADGET_COUNT];
    u32   count;
    u32   next_idx;  // round-robin index
} ad_syscall_gadget_table_t;

ANTIDEBUG_INLINE void ad_syscall_gadget_table_init(ad_syscall_gadget_table_t* tbl) {
    AD_ZERO_BUF(tbl, sizeof(*tbl));

    void* ntdll = ad_ntdll_base();
    if (!ntdll) return;

    u8* text_start = (u8*)0;
    u32 text_len = ad_find_text_section(ntdll, &text_start);
    if (!text_len || !text_start) return;

    u32 found = 0;
    u32 stride = text_len / (AD_SYSCALL_GADGET_COUNT * 4u);
    if (stride < 256u) stride = 256u;

    u32 offset;
    for (offset = 0; offset < text_len - 3u && found < AD_SYSCALL_GADGET_COUNT; offset += stride) {
        u32 scan;
        for (scan = offset; scan < offset + stride && scan < text_len - 3u; scan++) {
            if (text_start[scan]     == 0x0Fu &&
                text_start[scan + 1] == 0x05u &&
                text_start[scan + 2] == 0xC3u) {
                tbl->gadgets[found] = (void*)(text_start + scan);
                found++;
                break;
            }
        }
    }

    tbl->count = found;
}

// Pick the next gadget in round-robin fashion
ANTIDEBUG_INLINE void* ad_next_syscall_gadget(ad_syscall_gadget_table_t* tbl) {
    if (tbl->count == 0) return (void*)0;
    void* g = tbl->gadgets[tbl->next_idx % tbl->count];
    tbl->next_idx++;
    return g;
}

#endif // ANTIDEBUG_SYSCALL_SPOOF_H
