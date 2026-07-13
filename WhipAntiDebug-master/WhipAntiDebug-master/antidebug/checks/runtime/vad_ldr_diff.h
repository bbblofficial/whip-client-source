// ===== file: antidebug/checks/runtime/vad_ldr_diff.h =====
//
// VAD vs PEB.Ldr discrepancy.
//
// PEB.Ldr lists modules KNOWN to the loader. VAD (Virtual Address
// Descriptor tree) lists EVERY mapped section in the process address
// space — including manually-mapped DLLs the loader doesn't know about
// (Frida agents, ScyllaHide, manual-mapped reflective injectors).
//
// We walk both via NtQueryVirtualMemory(MemoryMappedFilenameInformation),
// striding through user-mode VAD, and check that every mapped image we
// find is also in PEB.Ldr.InMemoryOrderModuleList.
//
// Bonus: legitimate fonts and resource sections are skipped because they
// match MEM_MAPPED, not MEM_IMAGE.
//
#ifndef ANTIDEBUG_VAD_LDR_DIFF_H
#define ANTIDEBUG_VAD_LDR_DIFF_H

#include "../../core/types.h"
#include "../../core/macros.h"
#include "../../core/syscall_bridge.h"
#include "../../core/string_encrypt.h"
// AD_MEMORY_BASIC_INFO is already defined in anti_patch.h
#include "../integrity/anti_patch.h"

#define AD_VAD_MEMORY_BASIC_INFORMATION 0
#define AD_MEM_IMAGE                 0x1000000u
#define AD_MEMORY_REGION_SIZE_LIMIT  0x7FFFFFFF0000ULL

// PEB.Ldr layout (x64). _PEB_LDR_DATA at +0x18 in PEB. We need
// InMemoryOrderModuleList at +0x20 of LDR_DATA. Each LDR_DATA_TABLE_ENTRY
// has DllBase at +0x30 (counting from InMemoryOrderLinks).
ANTIDEBUG_INLINE b32 ad_vad_addr_in_ldr(void* addr) {
#ifdef _MSC_VER
    u8* peb = (u8*)__readgsqword(0x60);
    if (!peb) return 1;
    u8* ldr = *(u8**)(peb + 0x18);
    if (!ldr) return 1;

    // Walk InMemoryOrderModuleList. Head is at ldr+0x20 (LIST_ENTRY).
    u8* head = ldr + 0x20;
    u8* cur  = *(u8**)(head);  // Flink
    u32 walks = 0;

    while (cur && cur != head && walks < 256u) {
        // LDR_DATA_TABLE_ENTRY starts 0x10 bytes BEFORE InMemoryOrderLinks
        // (because InLoadOrderLinks is at +0x00). DllBase is at offset
        // +0x30 of LDR_DATA_TABLE_ENTRY, i.e. +0x20 from cur.
        u8* entry = cur - 0x10;
        void* dll_base = *(void**)(entry + 0x30);
        u32   size_of_image = *(u32*)(entry + 0x40);

        if (dll_base && size_of_image > 0) {
            u8* base = (u8*)dll_base;
            u8* end  = base + size_of_image;
            if ((u8*)addr >= base && (u8*)addr < end) {
                return 1;  // Found in Ldr
            }
        }

        cur = *(u8**)(cur);
        walks++;
    }
    return 0;
#else
    return 1;
#endif
}

// Returns 1 if the VAD walk found at least one MEM_IMAGE region whose
// AllocationBase is NOT registered in PEB.Ldr → manual-mapped DLL.
ANTIDEBUG_INLINE b32 ad_vad_ldr_diff_check(void) {
#ifdef _MSC_VER
    static u16 s_qvm_ssn = AD_SSN_UNRESOLVED;
    AD_RESOLVE_SSN_ENC(s_qvm_ssn, NtQueryVirtualMemory, 21);
    if (s_qvm_ssn == AD_SSN_FAILED) return 0;

    u64 addr = 0;
    u32 iters = 0;
    u32 hits = 0;
    void* last_alloc_base = (void*)0;

    while (addr < AD_MEMORY_REGION_SIZE_LIMIT && iters < 4096u) {
        AD_MEMORY_BASIC_INFO mbi;
        AD_ZERO_BUF(&mbi, sizeof(mbi));
        u64 ret_len = 0;

        ad_ntstatus_t st = (ad_ntstatus_t)(s64)AD_SYSCALL6(
            s_qvm_ssn,
            AD_CURRENT_PROCESS,
            (u64)addr,
            (u64)AD_VAD_MEMORY_BASIC_INFORMATION,
            &mbi,
            (u64)sizeof(mbi),
            &ret_len
        );
        if (!AD_NT_SUCCESS(st)) break;
        if (mbi.RegionSize == 0) break;

        // Only inspect MEM_IMAGE allocations (mapped DLLs/EXEs).
        if (mbi.Type == AD_MEM_IMAGE && mbi.AllocationBase != last_alloc_base) {
            last_alloc_base = mbi.AllocationBase;
            if (!ad_vad_addr_in_ldr(mbi.AllocationBase)) {
                hits++;
                if (hits >= 1u) return 1;
            }
        }

        addr += mbi.RegionSize;
        iters++;
    }
    return 0;
#else
    return 0;
#endif
}

#endif // ANTIDEBUG_VAD_LDR_DIFF_H
