// ===== file: antidebug/checks/runtime/private_exec_scan.h =====
//
// PRIVATE-executable VAD region scanner.
//
// In a clean WhipAntiDebugger binary every executable page in the
// process address space belongs to a mapped image (Type == MEM_IMAGE):
// our own .text, ntdll, kernel32, kernelbase, etc. We do not JIT, we
// do not VirtualAlloc PAGE_EXECUTE_*, we do not load any DLL that
// emits private code pages.
//
// Anything that produces a MEM_PRIVATE region with execute rights is
// therefore foreign code:
//
//   - x64dbg's stub patcher allocates a small (1-8 page) PRIVATE
//     PAGE_EXECUTE_READWRITE region next to ntdll when setting hardware
//     "memory" breakpoints, holding the original bytes
//   - ScyllaHide allocates a private trampoline region
//   - Frida-gum allocates several PRIVATE PAGE_EXECUTE_READ pages for
//     its instrumentation hooks
//   - Cheat Engine's auto-assembler allocates PRIVATE PAGE_EXECUTE_READWRITE
//     for assembled scripts
//   - any reflective DLL injection lands in PRIVATE pages by definition
//
// We walk the VAD via NtQueryVirtualMemory(MemoryBasicInformation) and
// count regions where:
//
//   State   == MEM_COMMIT
//   Type    == MEM_PRIVATE  (NOT MEM_IMAGE, NOT MEM_MAPPED)
//   Protect has any execute bit (0x10/0x20/0x40/0x80)
//
// Returns the count of suspicious regions. >= 1 = something is
// running foreign code in our address space.
//
#ifndef ANTIDEBUG_PRIVATE_EXEC_SCAN_H
#define ANTIDEBUG_PRIVATE_EXEC_SCAN_H

#include "../../core/types.h"
#include "../../core/macros.h"
#include "../../core/syscall_bridge.h"
#include "../../core/string_encrypt.h"
#include "../integrity/anti_patch.h"   // AD_MEMORY_BASIC_INFO

#define AD_PVS_MEM_BASIC_CLASS    0
#define AD_PVS_MEM_COMMIT         0x1000u
#define AD_PVS_MEM_PRIVATE        0x20000u
#define AD_PVS_PAGE_EXEC_MASK     (0x10u | 0x20u | 0x40u | 0x80u)
#define AD_PVS_REGION_LIMIT       0x7FFFFFFF0000ULL

ANTIDEBUG_INLINE u32 ad_private_exec_scan(void) {
#ifdef _MSC_VER
    static u16 s_qvm = AD_SSN_UNRESOLVED;
    AD_RESOLVE_SSN_ENC(s_qvm, NtQueryVirtualMemory, 21);
    if (s_qvm == AD_SSN_FAILED) return 0u;

    u64 addr = 0;
    u32 iters = 0;
    u32 hits  = 0;

    while (addr < AD_PVS_REGION_LIMIT && iters < 4096u) {
        AD_MEMORY_BASIC_INFO mbi;
        AD_ZERO_BUF(&mbi, sizeof(mbi));
        u64 ret_len = 0;

        ad_ntstatus_t st = (ad_ntstatus_t)(s64)AD_SYSCALL6(
            s_qvm,
            AD_CURRENT_PROCESS,
            (u64)addr,
            (u64)AD_PVS_MEM_BASIC_CLASS,
            &mbi,
            (u64)sizeof(mbi),
            &ret_len
        );
        if (!AD_NT_SUCCESS(st)) break;
        if (mbi.RegionSize == 0) break;

        if (mbi.State == AD_PVS_MEM_COMMIT &&
            mbi.Type  == AD_PVS_MEM_PRIVATE &&
            (mbi.Protect & AD_PVS_PAGE_EXEC_MASK) != 0u) {
            hits++;
        }

        addr += mbi.RegionSize;
        iters++;
    }
    return hits;
#else
    return 0u;
#endif
}

ANTIDEBUG_INLINE b32 ad_private_exec_check(void) {
    return (b32)(ad_private_exec_scan() > 0u);
}

#endif // ANTIDEBUG_PRIVATE_EXEC_SCAN_H
