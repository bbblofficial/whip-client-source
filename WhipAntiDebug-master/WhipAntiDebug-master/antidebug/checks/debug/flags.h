// ===== file: antidebug/checks/debug/flags.h =====
//
// Heap flags check via PEB.ProcessHeap.
// Accesses raw memory offsets — no WinAPI, no imports.
//
#ifndef ANTIDEBUG_FLAGS_H
#define ANTIDEBUG_FLAGS_H

#include "../../core/types.h"
#include "../../core/macros.h"

// ---------------------------------------------------------------------------
// Check: PEB.ProcessHeap flags (x64 offsets)
//
// Under a debugger, the default heap's Flags and ForceFlags fields are set
// to non-standard values by the loader:
//
//   Normal:      Flags = 0x00000002, ForceFlags = 0x00000000
//   Debugger:    Flags = 0x50000062, ForceFlags = 0x40000060
//                (HEAP_TAIL_CHECKING_ENABLED | HEAP_FREE_CHECKING_ENABLED |
//                 HEAP_SKIP_VALIDATION_CHECKS | HEAP_VALIDATE_PARAMETERS_ENABLED)
//
// x64 PEB layout:
//   PEB + 0x30 → ProcessHeap (PVOID)
// x64 Heap layout (HEAP structure internal):
//   Win 7 x64:     Heap + 0x40 → Flags,     Heap + 0x44 → ForceFlags
//   Win 8.1+ x64:  Heap + 0x70 → Flags,     Heap + 0x74 → ForceFlags  ← used here
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE b32 ad_heap_flags(void) {
#if defined(_MSC_VER)
    u8* peb  = (u8*)__readgsqword(0x60);
#else
    u8* peb;
    __asm__ __volatile__("movq %%gs:0x60, %0" : "=r"(peb));
#endif
    // Gate on NtGlobalFlag: bits 0x70 are only set by the loader when a debugger
    // is present (FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK |
    // FLG_HEAP_VALIDATE_PARAMETERS). Win11 security heap may set other heap flags
    // without a debugger, so checking heap flags alone causes false positives.
    u32 nt_global_flag = *(u32*)(peb + 0xBC);
    if ((nt_global_flag & 0x70u) == 0u) return 0;

    u8* heap = *(u8**)(peb + 0x30);
    if (!heap) return 0;

    u32 flags       = *(u32*)(heap + 0x70);
    u32 force_flags = *(u32*)(heap + 0x74);

    // Anything beyond the HEAP_GROWABLE (0x2) base flag is suspicious
    b32 flags_suspicious       = (b32)((flags & ~2u) != 0u);
    b32 force_flags_suspicious = (b32)(force_flags != 0u);

    return (b32)(flags_suspicious | force_flags_suspicious);
}

#endif // ANTIDEBUG_FLAGS_H
