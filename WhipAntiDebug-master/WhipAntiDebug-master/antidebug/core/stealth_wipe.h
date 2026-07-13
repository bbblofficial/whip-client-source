// ===== file: antidebug/core/stealth_wipe.h =====
//
// Stealth Wipe — post-init PE header erasure & PEB.Ldr module unlinking.
//
// Purpose
// -------
// After a DLL has been manually mapped and initialized, its PE headers and
// PEB.Ldr entries are forensic evidence that memory dumpers, module enumerators,
// and analysis tools use to reconstruct the binary.
//
// This header provides two techniques to eliminate that evidence:
//
//   1. ad_erase_pe_headers(module_base)
//      Zero-wipes the DOS header, PE signature, COFF header, optional header,
//      and all section headers. Uses volatile writes so the optimizer cannot
//      dead-store-eliminate the zeroing. Page protection is toggled via a
//      direct syscall (NtProtectVirtualMemory resolved through the existing
//      api_hash.h PEB-walk pattern).
//
//   2. ad_unlink_module(module_base)
//      Removes the module from all three PEB.Ldr linked lists
//      (InLoadOrder, InMemoryOrder, InInitializationOrder) and zeros
//      the BaseDllName / FullDllName UNICODE_STRING buffers to erase
//      string evidence.
//
// No CRT, no imports — everything via PEB walk, syscall bridge, or intrinsics.
//
#ifndef ANTIDEBUG_STEALTH_WIPE_H
#define ANTIDEBUG_STEALTH_WIPE_H

#include "types.h"
#include "macros.h"
#include "syscall_bridge.h"
#include "string_encrypt.h"

#if defined(_MSC_VER)

// ---------------------------------------------------------------------------
// 1. PE Header Erasure
// ---------------------------------------------------------------------------
// After init the PE headers serve no runtime purpose. Zeroing them prevents
// memory dumpers (e.g. pe-sieve, Scylla) from reconstructing the module.
//
// Steps:
//   - Read e_lfanew from DOS header -> PE header offset
//   - Read SizeOfHeaders from the optional header (pe + 24 + 60 for PE32+)
//   - NtProtectVirtualMemory: set region to PAGE_READWRITE (0x04)
//   - Volatile-zero from module_base to module_base + SizeOfHeaders
//   - NtProtectVirtualMemory: set region to PAGE_READONLY (0x02)
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE b32 ad_erase_pe_headers(void* module_base) {
    if (!module_base) return 0;

    u8* base = (u8*)module_base;

    // Validate DOS signature before reading offsets
    if (*(u16*)base != 0x5A4D) return 0;

    // e_lfanew: offset to PE signature (at DOS header + 0x3C)
    u32 pe_off = *(u32*)(base + 0x3C);
    u8* pe = base + pe_off;

    // Validate PE signature
    if (*(u32*)pe != 0x00004550u) return 0;

    // SizeOfHeaders lives in the optional header.
    // Optional header starts at pe + 24.
    // For PE32+ (x64), SizeOfHeaders is at optional header offset 60.
    u32 size_of_headers = *(u32*)(pe + 24 + 60);
    if (size_of_headers == 0 || size_of_headers > 0x10000u) return 0;

    // Resolve NtProtectVirtualMemory SSN
    static u16 s_prot = AD_SSN_UNRESOLVED;
    AD_RESOLVE_SSN_ENC(s_prot, NtProtectVirtualMemory, 23);
    if (s_prot == AD_SSN_FAILED) return 0;

    // Flip to PAGE_READWRITE (0x04)
    void* prot_base = module_base;
    u64   prot_size = (u64)size_of_headers;
    u32   old_prot  = 0;
    ad_ntstatus_t st = AD_SYSCALL5(s_prot,
        AD_CURRENT_PROCESS, &prot_base, &prot_size,
        (u64)0x04UL, &old_prot);
    if (!AD_NT_SUCCESS(st)) return 0;

    AD_BARRIER();

    // Volatile-zero the entire header region to prevent optimizer elimination
    {
        volatile u8* p = (volatile u8*)base;
        u32 i;
        for (i = 0; i < size_of_headers; i++) {
            p[i] = 0;
        }
    }

    AD_BARRIER();

    // Flip to PAGE_READONLY (0x02) — headers should never be written again
    prot_base = module_base;
    prot_size = (u64)size_of_headers;
    old_prot  = 0;
    AD_SYSCALL5(s_prot,
        AD_CURRENT_PROCESS, &prot_base, &prot_size,
        (u64)0x02UL, &old_prot);

    return 1;
}

// ---------------------------------------------------------------------------
// 2. PEB.Ldr Module Unlinking
// ---------------------------------------------------------------------------
// The PEB.Ldr structure contains three doubly-linked lists that enumerate
// every loaded module. Tools like EnumProcessModules, Module32First, and
// debugger module views all walk these lists.
//
// Unlinking our entry from all three lists makes the module invisible to
// standard enumeration. We also zero the UNICODE_STRING buffers for
// BaseDllName and FullDllName to remove string evidence.
//
// LDR_DATA_TABLE_ENTRY layout (x64):
//   +0x00  LIST_ENTRY InLoadOrderLinks
//   +0x10  LIST_ENTRY InMemoryOrderLinks
//   +0x20  LIST_ENTRY InInitializationOrderLinks
//   +0x30  void*      DllBase
//   +0x38  void*      EntryPoint
//   +0x40  u64        SizeOfImage
//   +0x48  UNICODE_STRING FullDllName   (u16 Len, u16 MaxLen, pad, u16* Buf)
//   +0x58  UNICODE_STRING BaseDllName   (u16 Len, u16 MaxLen, pad, u16* Buf)
// ---------------------------------------------------------------------------

// Internal helper: unlink a single LIST_ENTRY node from its doubly-linked list.
ANTIDEBUG_INLINE void ad_unlink_list_entry(u8* entry_links) {
    // LIST_ENTRY: Flink at +0x00, Blink at +0x08
    u8** p_flink = (u8**)(entry_links + 0x00);
    u8** p_blink = (u8**)(entry_links + 0x08);

    u8* flink = *p_flink;
    u8* blink = *p_blink;

    if (!flink || !blink) return;

    // flink->Blink = blink
    *(u8**)(flink + 0x08) = blink;
    // blink->Flink = flink
    *(u8**)(blink + 0x00) = flink;

    // Point removed entry at itself (safe sentinel)
    *p_flink = entry_links;
    *p_blink = entry_links;
}

// Internal helper: zero a UNICODE_STRING buffer.
// UNICODE_STRING layout (x64): u16 Length, u16 MaximumLength, u32 _pad, u16* Buffer
ANTIDEBUG_INLINE void ad_wipe_unicode_string(u8* ustr_ptr) {
    u16  len_bytes = *(u16*)(ustr_ptr + 0x00);
    u16* buf       = *(u16**)(ustr_ptr + 0x08);

    if (buf && len_bytes > 0) {
        volatile u16* vbuf = (volatile u16*)buf;
        u32 char_count = (u32)(len_bytes / 2u);
        u32 i;
        for (i = 0; i < char_count; i++) {
            vbuf[i] = 0;
        }
    }

    // Zero the Length and MaximumLength fields
    *(volatile u16*)(ustr_ptr + 0x00) = 0;
    *(volatile u16*)(ustr_ptr + 0x02) = 0;
}

ANTIDEBUG_INLINE b32 ad_unlink_module(void* module_base) {
    if (!module_base) return 0;

#ifdef _MSC_VER
    u8* peb = (u8*)__readgsqword(0x60);
#else
    return 0;
#endif
    if (!peb) return 0;

    u8* ldr = *(u8**)(peb + 0x18);
    if (!ldr) return 0;

    // Walk InLoadOrderModuleList (Ldr + 0x10) — this is the most
    // straightforward list where LDR_DATA_TABLE_ENTRY starts at the
    // LIST_ENTRY itself (InLoadOrderLinks at offset 0x00 of the entry).
    u8* head_load = ldr + 0x10;
    u8* cur       = *(u8**)head_load;
    u32 walks     = 0;
    b32 found     = 0;

    while (cur && cur != head_load && walks < 512u) {
        // For InLoadOrderLinks, the LIST_ENTRY IS at offset 0x00 of
        // LDR_DATA_TABLE_ENTRY, so entry == cur.
        u8* entry = cur;
        void* dll_base = *(void**)(entry + 0x30);

        // Advance before unlinking (unlinking invalidates cur's links)
        u8* next = *(u8**)cur;

        if (dll_base == module_base) {
            // Unlink from all three lists
            ad_unlink_list_entry(entry + 0x00); // InLoadOrderLinks
            ad_unlink_list_entry(entry + 0x10); // InMemoryOrderLinks
            ad_unlink_list_entry(entry + 0x20); // InInitializationOrderLinks

            // Wipe FullDllName (+0x48) and BaseDllName (+0x58)
            ad_wipe_unicode_string(entry + 0x48);
            ad_wipe_unicode_string(entry + 0x58);

            AD_BARRIER();
            found = 1;
            break;
        }

        cur = next;
        walks++;
    }

    return found;
}

// ---------------------------------------------------------------------------
// Convenience: apply both techniques in one call
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE b32 ad_stealth_wipe(void* module_base) {
    b32 headers  = ad_erase_pe_headers(module_base);
    b32 unlinked = ad_unlink_module(module_base);
    return (b32)(headers | unlinked);
}

#else // !_MSC_VER

ANTIDEBUG_INLINE b32 ad_erase_pe_headers(void* module_base) {
    AD_UNUSED(module_base);
    return 0;
}
ANTIDEBUG_INLINE b32 ad_unlink_module(void* module_base) {
    AD_UNUSED(module_base);
    return 0;
}
ANTIDEBUG_INLINE b32 ad_stealth_wipe(void* module_base) {
    AD_UNUSED(module_base);
    return 0;
}

#endif // _MSC_VER

#endif // ANTIDEBUG_STEALTH_WIPE_H
