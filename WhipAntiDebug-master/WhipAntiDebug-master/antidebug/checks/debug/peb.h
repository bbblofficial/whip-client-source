// ===== file: antidebug/checks/debug/peb.h =====
//
// PEB-based anti-debug checks.
// Technique: read PEB fields directly via GS segment register (x64).
// No imports, no WinAPI, zero IAT footprint.
//
#ifndef ANTIDEBUG_PEB_H
#define ANTIDEBUG_PEB_H

#include "../../core/types.h"
#include "../../core/macros.h"

// ---------------------------------------------------------------------------
// Internal: raw PEB pointer from GS:0x60 (x64 only)
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE u8* ad_peb_ptr(void) {
#if defined(_MSC_VER)
    return (u8*)__readgsqword(0x60);
#elif defined(__GNUC__) || defined(__clang__)
    u8* peb;
    __asm__ __volatile__("movq %%gs:0x60, %0" : "=r"(peb));
    return peb;
#else
#  error "Unsupported compiler for GS segment access"
#endif
}

// ---------------------------------------------------------------------------
// Check: PEB.BeingDebugged (offset 0x002, BYTE)
//
// Windows sets this byte to 1 when a user-mode debugger is attached.
// x64dbg, OllyDbg, WinDbg (user-mode) all set this.
// Kernel debuggers do NOT set it.
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE b32 ad_peb_being_debugged(void) {
    return (b32)(ad_peb_ptr()[0x02] != 0);
}

// ---------------------------------------------------------------------------
// Check: PEB.NtGlobalFlag (offset 0xBC on x64, DWORD)
//
// Under a debugger: flags include 0x70:
//   FLG_HEAP_ENABLE_TAIL_CHECK    (0x10)
//   FLG_HEAP_ENABLE_FREE_CHECK    (0x20)
//   FLG_HEAP_VALIDATE_PARAMETERS  (0x40)
// Normal (no debugger): 0x00 or platform-specific clean value.
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE b32 ad_peb_nt_global_flag(void) {
    u32 flags = *(u32*)(ad_peb_ptr() + 0xBC);
    return (b32)((flags & AD_HEAP_DEBUG_FLAGS) != 0);
}

// ---------------------------------------------------------------------------
// Check: PEB.ImageBaseAddress (offset 0x10 on x64)
// Not a debug check per se, but useful to retrieve our own module base
// without imports (used by integrity checks).
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE void* ad_peb_image_base(void) {
    return *(void**)(ad_peb_ptr() + 0x10);
}

#endif // ANTIDEBUG_PEB_H
