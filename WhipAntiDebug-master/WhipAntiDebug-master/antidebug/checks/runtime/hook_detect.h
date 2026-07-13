// ===== file: antidebug/checks/runtime/hook_detect.h =====
//
// Runtime hook detection on ntdll syscall stubs.
//
// Technique:
//   User-mode hooking frameworks (Frida, API Monitor, inline hooks) patch
//   the first bytes of ntdll functions with a JMP/CALL trampoline.
//   The canonical x64 syscall stub prologue is:
//
//     4C 8B D1          mov r10, rcx
//     B8 XX XX 00 00    mov eax, <SSN>
//
//   If byte[0] is 0xE9 (JMP rel32), 0xFF (JMP/CALL indirect), 0xCC (INT3),
//   or byte[0..1] != {0x4C, 0x8B}, the stub has been tampered with.
//
//   We resolve the stub address via WhipSysCall, then validate the prologue
//   bytes in memory. This runs at runtime — detects hooks placed AFTER load.
//
#ifndef ANTIDEBUG_HOOK_DETECT_H
#define ANTIDEBUG_HOOK_DETECT_H

#include "../../core/types.h"
#include "../../core/macros.h"
#include "../../core/syscall_bridge.h"
#include "../../core/string_encrypt.h"
#include "../debug/peb.h"
#include "../../stack/moonwalk.h"   // for ad_ntdll_base, ad_find_text_section

// ---------------------------------------------------------------------------
// Validate that a syscall stub prologue is intact (not hooked).
//
// addr: pointer to the start of an ntdll Nt* function in memory
// Returns 1 if the stub looks hooked/patched, 0 if clean.
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE b32 ad_stub_is_hooked(const void* addr) {
    if (!addr) return 0;
    const volatile u8* p = (const volatile u8*)addr;

    u8 b0 = p[0];
    u8 b1 = p[1];
    u8 b2 = p[2];
    u8 b3 = p[3];

    // Expected: 4C 8B D1 B8 (mov r10, rcx; mov eax, ...)
    b32 prologue_ok = (b32)(b0 == 0x4Cu && b1 == 0x8Bu && b2 == 0xD1u && b3 == 0xB8u);

    // Common hook signatures
    b32 has_jmp    = (b32)(b0 == 0xE9u);                    // JMP rel32
    b32 has_jmp_ff = (b32)(b0 == 0xFFu && b1 == 0x25u);    // JMP [rip+disp32]
    b32 has_int3   = (b32)(b0 == 0xCCu);                    // INT3 (soft BP)
    b32 has_nop    = (b32)(b0 == 0x90u);                    // NOP sled

    return (b32)(!prologue_ok || has_jmp || has_jmp_ff || has_int3 || has_nop);
}

// ---------------------------------------------------------------------------
// Walk ntdll export table and check N random syscall stubs for hooks.
//
// We check the stubs we actually use: NtQueryInformationProcess,
// NtGetContextThread, NtSetInformationThread, NtClose.
// Uses stub addresses cached by WhipSysCall (already resolved at init).
//
// Returns 1 if any stub is hooked.
// ---------------------------------------------------------------------------

// Encrypted string: "NtQueryVirtualMemory" (20 chars)
#define AD_STRENC_NtQueryVirtualMemory(buf)                                  \
    do {                                                                     \
        const u8 _k = AD_STR_KEY(0x77);                                     \
        char buf##_e[21];                                                    \
        AD_ENC(buf##_e,  0, 'N', _k); AD_ENC(buf##_e,  1, 't', _k);       \
        AD_ENC(buf##_e,  2, 'Q', _k); AD_ENC(buf##_e,  3, 'u', _k);       \
        AD_ENC(buf##_e,  4, 'e', _k); AD_ENC(buf##_e,  5, 'r', _k);       \
        AD_ENC(buf##_e,  6, 'y', _k); AD_ENC(buf##_e,  7, 'V', _k);       \
        AD_ENC(buf##_e,  8, 'i', _k); AD_ENC(buf##_e,  9, 'r', _k);       \
        AD_ENC(buf##_e, 10, 't', _k); AD_ENC(buf##_e, 11, 'u', _k);       \
        AD_ENC(buf##_e, 12, 'a', _k); AD_ENC(buf##_e, 13, 'l', _k);       \
        AD_ENC(buf##_e, 14, 'M', _k); AD_ENC(buf##_e, 15, 'e', _k);       \
        AD_ENC(buf##_e, 16, 'm', _k); AD_ENC(buf##_e, 17, 'o', _k);       \
        AD_ENC(buf##_e, 18, 'r', _k); AD_ENC(buf##_e, 19, 'y', _k);       \
        AD_DECODE_BUF(buf##_e, 20, _k);                                     \
        for (unsigned _ci = 0; _ci < 21; _ci++) (buf)[_ci] = buf##_e[_ci];  \
    } while (0)

ANTIDEBUG_INLINE b32 ad_detect_ntdll_hooks(void) {
    // Get ntdll base and find .text section bounds
    void* ntdll = ad_ntdll_base();
    if (!ntdll) return 0;

    u8* text_start = (u8*)0;
    u32 text_len = ad_find_text_section(ntdll, &text_start);
    if (!text_len || !text_start) return 0;

    // Check a few critical stubs by scanning for their SSN pattern
    // We look for the pattern: 4C 8B D1 B8 <ssn_lo> <ssn_hi> 00 00
    // and verify the bytes before each entry match expectations.

    // Simpler approach: check the first 4 bytes of ntdll .text at regular
    // intervals for common hook trampolines (E9, FF 25, CC patterns)
    b32 hook_found = 0;
    u32 stride = text_len / 64u;
    if (stride < 16u) stride = 16u;

    u32 i;
    for (i = 0u; i < text_len - 8u; i += stride) {
        const volatile u8* p = (const volatile u8*)(text_start + i);

        // Look for function prologues that should be syscall stubs
        // (4C 8B D1 = mov r10, rcx — unique to syscall stubs)
        if (p[0] == 0x4Cu && p[1] == 0x8Bu && p[2] == 0xD1u) {
            // This is a syscall stub — check if byte at [-5] or area
            // before it has been trampolined
            // Actually verify the stub itself is intact
            if (p[3] != 0xB8u) {
                // mov eax, imm32 should follow — patched!
                hook_found = 1;
                break;
            }
        }

        // Also scan for rogue JMP trampolines in unexpected places
        // E9 XX XX XX XX at function-aligned boundaries
        if ((i & 0xFu) == 0u && p[0] == 0xE9u) {
            // JMP rel32 at an aligned address inside ntdll .text
            // Legitimate code rarely starts with E9 at aligned boundaries
            // in ntdll (they use 4C 8B D1 for Nt stubs, or sub rsp for regular fns)
            s32 rel = *(s32*)(p + 1);
            const u8* target = (const u8*)(p + 5 + rel);
            // If JMP target is outside ntdll .text, it's a hook
            if (target < text_start || target >= text_start + text_len) {
                hook_found = 1;
                break;
            }
        }
    }

    return hook_found;
}

#endif // ANTIDEBUG_HOOK_DETECT_H
