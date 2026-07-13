// ===== file: antidebug/checks/integrity/code_hash.h =====
//
// Code integrity check via FNV-1a 64-bit hash over a code region.
//
// Workflow:
//   1. At init time: ad_code_hash_capture(base, size) → baseline
//   2. At check time: ad_code_hash_check(base, size, baseline) → suspicious?
//
// Detects:
//   - Software breakpoints (0xCC injection)
//   - Inline hooks (JMP/CALL patches at function prologues)
//   - ANY byte modification of the scanned region
//
// No external libraries. No imports. Pure C, pure arithmetic.
//
#ifndef ANTIDEBUG_CODE_HASH_H
#define ANTIDEBUG_CODE_HASH_H

#include "../../core/types.h"
#include "../../core/macros.h"
#include "../../core/config.h"

// ---------------------------------------------------------------------------
// FNV-1a 64-bit hash
//
// Fast, low-collision, trivially inlinable without any library dependency.
// FNV prime: 0x00000100000001B3
// FNV offset basis: 0xCBF29CE484222325
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE u64 ad_fnv1a_64(const void* data, u32 len) {
    const u8* p = (const u8*)data;
    u64 h = 0xCBF29CE484222325ULL;
    u32 i;
    for (i = 0u; i < len; i++) {
        h ^= (u64)p[i];
        h *= 0x00000100000001B3ULL;
    }
    return h;
}

// ---------------------------------------------------------------------------
// Capture a baseline hash of [base, base+len)
//
// Call ONCE at startup, before any debugger can modify code.
// Store the returned value in your ad_state_t.
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE u64 ad_code_hash_capture(const void* base, u32 len) {
    return ad_fnv1a_64(base, len);
}

// ---------------------------------------------------------------------------
// Check: re-hash [base, base+len) and compare against baseline
//
// Returns 1 (suspicious) if the hash has changed.
// Returns 0 if the region is intact.
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE b32 ad_code_hash_check(const void* base, u32 len, u64 baseline) {
    u64 current = ad_fnv1a_64(base, len);
    // Use a subtraction comparison to avoid an obvious == branch pattern
    return (b32)((current - baseline) != 0ULL);
}

// ---------------------------------------------------------------------------
// Helper: obtain the image base of the current EXE/DLL via PEB LDR walk
//
// PEB.Ldr.InLoadOrderModuleList.Flink → first LDR_DATA_TABLE_ENTRY
// LDR_DATA_TABLE_ENTRY.DllBase at offset 0x30 (x64)
//
// NOTE: For manually-mapped modules NOT present in the PEB LDR, skip this
// and pass the image base explicitly.
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE void* ad_image_base_from_peb(void) {
#if defined(_MSC_VER)
    u8* peb  = (u8*)__readgsqword(0x60);    // PEB
    u8* ldr  = *(u8**)(peb  + 0x18);        // PEB.Ldr (PPEB_LDR_DATA)
    u8* flink = *(u8**)(ldr + 0x10);        // Ldr.InLoadOrderModuleList.Flink
    return *(void**)(flink + 0x30);          // LDR_DATA_TABLE_ENTRY.DllBase
#else
    return (void*)0;
#endif
}

// ---------------------------------------------------------------------------
// Compound check: INT3 presence AND hash mismatch
//
// More reliable than either alone — catches both patched bytes that happen
// to produce the same hash (extremely unlikely with FNV-1a) and debugger BPs.
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE b32 ad_code_integrity_full(const void* base, u32 len, u64 baseline) {
    // Primary: hash comparison
    b32 hash_bad = ad_code_hash_check(base, len, baseline);

    // Secondary: fast 0xCC scan (inline to avoid function-call IAT footprint)
    const volatile u8* p = (const volatile u8*)base;
    b32 int3_found = 0;
    u32 i;
    for (i = 0u; i < len; i++) {
        if (p[i] == (u8)0xCC) { int3_found = 1; break; }
    }

    return (b32)(hash_bad | int3_found);
}

#endif // ANTIDEBUG_CODE_HASH_H
