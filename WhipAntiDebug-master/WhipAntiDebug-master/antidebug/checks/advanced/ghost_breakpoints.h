// ===== file: antidebug/checks/advanced/ghost_breakpoints.h =====
//
// Ghost Breakpoint Detection — detect software breakpoints via Copy-on-Write
// page divergence. Compares code bytes through multiple access paths:
//   Path A: direct volatile memory read (sees CoW page with 0xCC)
//   Path B: NtReadVirtualMemory syscall (kernel reads physical backing)
// If they differ, a debugger has set a software breakpoint.
//
#ifndef ANTIDEBUG_GHOST_BREAKPOINTS_H
#define ANTIDEBUG_GHOST_BREAKPOINTS_H

#include "../../core/types.h"
#include "../../core/macros.h"
#include "../../core/syscall_bridge.h"
#include "../../core/string_encrypt.h"

// NtReadVirtualMemory macro is already defined in deep_checks.h
// We reuse it via AD_RESOLVE_SSN_ENC.

// ---------------------------------------------------------------------------
// Ghost breakpoint check: compare direct read vs kernel read
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE b32 ad_ghost_breakpoint_check(const void* code_addr, u32 scan_size) {
    if (!code_addr || scan_size == 0u) return 0;
    if (scan_size > 4096u) scan_size = 4096u;

    static u16 s_read_ssn = AD_SSN_UNRESOLVED;
    AD_RESOLVE_SSN_ENC(s_read_ssn, NtReadVirtualMemory, 20);
    if (s_read_ssn == AD_SSN_FAILED) return 0;

    // Kernel-read buffer on stack
    u8 kernel_buf[256];
    u32 chunk = scan_size < 256u ? scan_size : 256u;

    u64 bytes_read = 0;
    ad_ntstatus_t st = (ad_ntstatus_t)(s64)SyscallStub(s_read_ssn,
        AD_CURRENT_PROCESS,
        (void*)code_addr,
        (void*)kernel_buf,
        (void*)(u64)chunk,
        (void*)&bytes_read,
        (void*)0, (void*)0, (void*)0, (void*)0, (void*)0, (void*)0
    );

    if (!AD_NT_SUCCESS(st)) return 0;

    // Compare byte-by-byte: direct volatile read vs kernel read
    const volatile u8* direct = (const volatile u8*)code_addr;
    u32 divergence = 0;
    u32 i;
    AD_LFENCE();
    for (i = 0u; i < chunk; i++) {
        volatile u8 d = direct[i];
        AD_BARRIER();
        if (d != kernel_buf[i]) {
            divergence++;
        }
    }

    AD_ZERO_BUF(kernel_buf, sizeof(kernel_buf));
    return (b32)(divergence > 0u);
}

// ---------------------------------------------------------------------------
// Ghost breakpoint on ntdll .text — detect breakpoints on NT stubs
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE b32 ad_ghost_breakpoint_ntdll(void) {
    // Get ntdll base from PEB
    u8* peb = (u8*)__readgsqword(0x60);
    u8* ldr = *(u8**)(peb + 0x18);
    u8* head = *(u8**)(ldr + 0x10);
    u8* entry = *(u8**)(head);  // first module (exe)
    entry = *(u8**)(entry);     // second module (ntdll)
    u8* ntdll_base = *(u8**)(entry + 0x30);
    if (!ntdll_base) return 0;

    // Verify MZ
    if (*(u16*)ntdll_base != 0x5A4D) return 0;

    // Find .text section
    u32 pe_off = *(u32*)(ntdll_base + 0x3C);
    u8* pe = ntdll_base + pe_off;
    u16 n_sections = *(u16*)(pe + 6);
    u16 opt_size = *(u16*)(pe + 20);
    u8* sections = pe + 24 + opt_size;

    u8* text_addr = 0;
    u32 text_size = 0;
    u32 si;
    for (si = 0; si < n_sections; si++) {
        u8* sec = sections + si * 40;
        if (sec[0] == '.' && sec[1] == 't' && sec[2] == 'e' &&
            sec[3] == 'x' && sec[4] == 't') {
            text_size = *(u32*)(sec + 8);
            text_addr = ntdll_base + *(u32*)(sec + 12);
            break;
        }
    }

    if (!text_addr || text_size < 256u) return 0;

    // Sample multiple regions across ntdll .text
    u32 stride = text_size / 8u;
    u32 detected = 0;
    u32 ri;
    for (ri = 0; ri < 8u && !detected; ri++) {
        u32 offset = ri * stride;
        if (offset + 128u > text_size) break;
        detected |= (u32)ad_ghost_breakpoint_check(text_addr + offset, 128u);
    }

    return (b32)detected;
}

#endif // ANTIDEBUG_GHOST_BREAKPOINTS_H
