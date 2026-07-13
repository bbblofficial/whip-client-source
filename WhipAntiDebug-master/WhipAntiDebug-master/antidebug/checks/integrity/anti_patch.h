// ===== file: antidebug/checks/integrity/anti_patch.h =====
//
// Advanced anti-patch / anti-tamper system.
//
// Layers:
//
//   1. CRC32 HARDWARE — Intel SSE4.2 _mm_crc32 on our .text section.
//      Much faster than FNV-1a, and the intrinsic makes it harder to
//      emulate/hook (it's a single CPU instruction, not a function call).
//
//   2. FUNCTION PROLOGUE VALIDATION — check that our critical functions
//      still start with expected byte sequences (not JMP/NOP/INT3 hooks).
//
//   3. PAGE PROTECTION MONITORING — verify our .text section is still
//      PAGE_EXECUTE_READ. If someone changed it to PAGE_EXECUTE_READWRITE
//      to patch us, detect it.
//
//   4. BREAKPOINT DENSITY SCAN — count 0xCC bytes in our code. A few
//      might be compiler-generated padding, but 3+ in a short range
//      means software breakpoints.
//
//   5. CONTINUOUS SELF-HASH — re-hash critical functions at runtime and
//      compare against baselines captured at init. Detects inline hooks,
//      byte patches, and 0xCC injection.
//
#ifndef ANTIDEBUG_ANTI_PATCH_H
#define ANTIDEBUG_ANTI_PATCH_H

#include "../../core/types.h"
#include "../../core/macros.h"
#include "../../core/config.h"
#include "../../core/syscall_bridge.h"
#include "../../core/string_encrypt.h"
#include "../../core/value_guard.h"

#if defined(_MSC_VER)
#include <nmmintrin.h>  // SSE4.2: _mm_crc32_u8, _mm_crc32_u32, _mm_crc32_u64
#endif

// ---------------------------------------------------------------------------
// 1. Hardware CRC32 of a memory region (SSE4.2)
//
// Uses the CRC32C instruction directly — single-cycle throughput on modern
// CPUs, impossible to hook (it's not a function call).
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE u32 ad_hw_crc32(const void* data, u32 len) {
#if defined(_MSC_VER)
    const u8* p = (const u8*)data;
    u32 crc = 0xFFFFFFFFu;
    u32 i;

    // Process 8 bytes at a time using 64-bit CRC if possible
    u32 chunks = len / 8u;
    u32 remainder = len % 8u;

    for (i = 0; i < chunks; i++) {
        crc = (u32)_mm_crc32_u64((u64)crc, *(const u64*)(p + i * 8u));
    }

    // Process remaining bytes
    const u8* tail = p + chunks * 8u;
    for (i = 0; i < remainder; i++) {
        crc = _mm_crc32_u8(crc, tail[i]);
    }

    return crc ^ 0xFFFFFFFFu;
#else
    AD_UNUSED(data); AD_UNUSED(len);
    return 0;
#endif
}

// ---------------------------------------------------------------------------
// 2. Function prologue validation
//
// Check that critical functions haven't been hooked with:
//   - JMP rel32 (E9 xx xx xx xx) — inline hook
//   - JMP [rip+disp] (FF 25 xx xx xx xx) — IAT-style hook
//   - INT3 (CC) — software breakpoint
//   - NOP (90) — NOP sled from patching
//   - MOV RAX, imm64; JMP RAX (48 B8 ... FF E0) — trampoline hook
//
// We check the first 8 bytes of each function against known-bad patterns.
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE b32 ad_check_prologue(const void* fn_addr) {
    if (!fn_addr) return 0;
    const volatile u8* p = (const volatile u8*)fn_addr;

    u8 b0 = p[0];
    u8 b1 = p[1];

    // JMP rel32
    if (b0 == 0xE9u) return 1;
    // JMP [rip+disp32]
    if (b0 == 0xFFu && b1 == 0x25u) return 1;
    // INT3 at function start
    if (b0 == 0xCCu) return 1;
    // NOP sled (2+ NOPs at start)
    if (b0 == 0x90u && b1 == 0x90u) return 1;
    // MOV RAX, imm64 (48 B8) — common trampoline
    if (b0 == 0x48u && b1 == 0xB8u) {
        // Check if followed by JMP RAX (FF E0) or CALL RAX (FF D0)
        u8 b10 = p[10];
        u8 b11 = p[11];
        if (b10 == 0xFFu && (b11 == 0xE0u || b11 == 0xD0u)) return 1;
    }

    return 0;
}

// Check multiple function prologues at once
ANTIDEBUG_INLINE u32 ad_check_prologues(const void** fn_addrs, u32 count) {
    u32 hooked = 0;
    u32 i;
    for (i = 0; i < count; i++) {
        if (ad_check_prologue(fn_addrs[i])) {
            hooked++;
        }
    }
    return hooked;
}

// ---------------------------------------------------------------------------
// 3. Page protection monitoring via NtQueryVirtualMemory
//
// Our .text section should be PAGE_EXECUTE_READ (0x20).
// If someone changed it to PAGE_EXECUTE_READWRITE (0x40) or
// PAGE_EXECUTE_WRITECOPY (0x80) to patch our code, detect it.
// ---------------------------------------------------------------------------

// Simplified MEMORY_BASIC_INFORMATION
#ifndef AD_MEMORY_BASIC_INFO_DEFINED
#define AD_MEMORY_BASIC_INFO_DEFINED
typedef struct {
    void* BaseAddress;
    void* AllocationBase;
    u32   AllocationProtect;
    u16   PartitionId;
    u16   _pad0;
    u64   RegionSize;
    u32   State;
    u32   Protect;          // Current protection — THIS is what we check
    u32   Type;
    u32   _pad1;
} AD_MEMORY_BASIC_INFO;
#endif

#define AD_MEM_INFO_CLASS_BASIC  0
#define AD_PAGE_EXECUTE_READ     0x20u
#define AD_PAGE_EXECUTE_READWRITE 0x40u
#define AD_PAGE_EXECUTE_WRITECOPY 0x80u

// Encrypted string: "NtQueryVirtualMemory" (20 chars) — reuse from hook_detect
#ifndef AD_STRENC_NtQueryVirtualMemory_DEFINED
#define AD_STRENC_NtQueryVirtualMemory_DEFINED

// Already defined in hook_detect.h — but guard for standalone use
#ifndef AD_STRENC_NtQueryVirtualMemory
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
#endif
#endif

ANTIDEBUG_INLINE b32 ad_check_page_protection(const void* code_addr) {
    static u16 s_ssn = AD_SSN_UNRESOLVED;
    AD_RESOLVE_SSN_ENC(s_ssn, NtQueryVirtualMemory, 21);
    if (s_ssn == AD_SSN_FAILED) return 0;

    AD_MEMORY_BASIC_INFO mbi;
    AD_ZERO_BUF(&mbi, sizeof(mbi));
    u64 ret_len = 0;

    // NtQueryVirtualMemory(ProcessHandle, BaseAddress, MemInfoClass, Buffer, Length, RetLen)
    ad_ntstatus_t st = AD_SYSCALL6(
        s_ssn,
        AD_CURRENT_PROCESS,
        (u64)code_addr,
        (u64)AD_MEM_INFO_CLASS_BASIC,
        &mbi,
        (u64)sizeof(mbi),
        &ret_len
    );

    if (!AD_NT_SUCCESS(st)) return 0;

    // .text should be PAGE_EXECUTE_READ (0x20).
    // If it's RWX or WRITECOPY, someone changed it to patch our code.
    u32 prot = mbi.Protect;

    b32 is_writable = (b32)(
        (prot & AD_PAGE_EXECUTE_READWRITE) ||
        (prot & AD_PAGE_EXECUTE_WRITECOPY) ||
        (prot == 0x04u)   // PAGE_READWRITE (not even execute — very suspicious)
    );

    return is_writable;
}

// ---------------------------------------------------------------------------
// 4. Breakpoint density scan
//
// Count 0xCC (INT3) bytes in a region. Compiler padding uses 0xCC between
// functions, but INSIDE a function, 0xCC = software breakpoint.
// We scan inside known function boundaries only.
//
// Returns the number of 0xCC bytes found.
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE u32 ad_count_int3(const void* start, u32 len) {
    const volatile u8* p = (const volatile u8*)start;
    u32 count = 0;
    u32 i;
    for (i = 0; i < len; i++) {
        // Use volatile read + XOR check to make this harder to patch
        u8 b = p[i];
        u8 check = b ^ 0xCCu;
        count += (check == 0u) ? 1u : 0u;
    }
    return count;
}

// ---------------------------------------------------------------------------
// 5. Continuous self-hash — hash critical functions and compare to baseline
//
// Store CRC32 of N critical functions at init. Re-check at runtime.
// If any changed, someone patched our code.
// ---------------------------------------------------------------------------
#define AD_SELF_HASH_MAX_FUNCS 16u
#define AD_SELF_HASH_SCAN_SIZE 64u  // hash first 64 bytes of each function

typedef struct {
    const void* fn_addrs[AD_SELF_HASH_MAX_FUNCS];
    u32         baselines[AD_SELF_HASH_MAX_FUNCS];
    u32         count;
    b32         ready;
} ad_self_hash_table_t;

ANTIDEBUG_INLINE void ad_self_hash_init(
    ad_self_hash_table_t* tbl,
    const void** fn_addrs,
    u32 count
) {
    AD_ZERO_BUF(tbl, sizeof(*tbl));

    u32 n = (count < AD_SELF_HASH_MAX_FUNCS) ? count : AD_SELF_HASH_MAX_FUNCS;
    u32 i;
    for (i = 0; i < n; i++) {
        tbl->fn_addrs[i]  = fn_addrs[i];
        tbl->baselines[i] = ad_hw_crc32(fn_addrs[i], AD_SELF_HASH_SCAN_SIZE);
    }
    tbl->count = n;
    tbl->ready = 1;
}

// Returns number of functions whose hash has changed (= patched)
ANTIDEBUG_INLINE u32 ad_self_hash_check(const ad_self_hash_table_t* tbl) {
    if (!tbl->ready) return 0;

    u32 mismatches = 0;
    u32 i;
    for (i = 0; i < tbl->count; i++) {
        u32 current = ad_hw_crc32(tbl->fn_addrs[i], AD_SELF_HASH_SCAN_SIZE);
        // Use XOR + OR instead of != to avoid a branch
        u32 diff = current ^ tbl->baselines[i];
        mismatches += (diff != 0u) ? 1u : 0u;
    }
    return mismatches;
}

// ---------------------------------------------------------------------------
// 6. Combined anti-patch check — runs all layers
//
// Returns a severity score:
//   0     = clean
//   1-3   = minor (might be false positive)
//   4+    = definitely tampered
// ---------------------------------------------------------------------------
typedef struct {
    u32 enabled;
    u32 page_rwx;
    u32 prologues_hooked;
    u32 self_hash_patched;
    u32 int3_count;
    u32 int3_added;
} ad_dbg_patch_t;
static volatile ad_dbg_patch_t ad_dbg_patch = {0};

ANTIDEBUG_INLINE u32 ad_anti_patch_full(
    const void* code_section,
    u32 code_size,
    const ad_self_hash_table_t* hash_tbl,
    const void** critical_fns,
    u32 n_critical_fns
) {
    u32 severity = 0;
    u32 d_page = 0, d_hooked = 0, d_patched = 0, d_int3 = 0, d_int3_added = 0;

    // Layer 1: Page protection (RWX = someone patching us)
    if (code_section) {
        b32 writable = ad_check_page_protection(code_section);
        d_page = writable ? 4u : 0u;
        severity += d_page;
    }

    // Layer 2: Prologue validation
    if (critical_fns && n_critical_fns > 0) {
        u32 hooked = ad_check_prologues(critical_fns, n_critical_fns);
        d_hooked = hooked * 3u;
        severity += d_hooked;
    }

    // Layer 3: Self-hash CRC32
    if (hash_tbl && hash_tbl->ready) {
        u32 patched = ad_self_hash_check(hash_tbl);
        d_patched = patched * 2u;
        severity += d_patched;
    }

    // Layer 4: INT3 density in our code.
    // A legitimate patch/inline-hook is typically a short CONTIGUOUS run
    // of 0xCC (e.g. an int3 trap or a pre-patched 5+ byte slot). Counting
    // isolated 0xCC bytes produces massive false positives on Debug
    // builds because MSVC fills function padding with 0xCC and Debug
    // prologues contain individual CC bytes (e.g. RUNTIME_CHECKS).
    // Only flag runs of >= 3 consecutive 0xCC bytes that are clearly
    // abnormal, and require a high total before escalating.
    if (code_section && code_size > 0) {
        u32 scan_size = (code_size < 4096u) ? code_size : 4096u;
        const u8* p = (const u8*)code_section;
        u32 run = 0, long_runs = 0, total = 0;
        u32 ii;
        for (ii = 0; ii < scan_size; ii++) {
            if (p[ii] == 0xCCu) {
                run++;
                total++;
                if (run == 3u) long_runs++;
            } else {
                run = 0;
            }
        }
        d_int3 = total;
        // Only contribute if there are multiple suspiciously long runs.
        // A single 3+ byte CC fill is normal padding; multiple suggests
        // actual patching.
        if (long_runs >= 4u) {
            d_int3_added = long_runs * 2u;
            severity += d_int3_added;
        }
    }

    if (ad_dbg_patch.enabled) {
        ad_dbg_patch.page_rwx          = d_page;
        ad_dbg_patch.prologues_hooked  = d_hooked;
        ad_dbg_patch.self_hash_patched = d_patched;
        ad_dbg_patch.int3_count        = d_int3;
        ad_dbg_patch.int3_added        = d_int3_added;
    }

    return severity;
}

#endif // ANTIDEBUG_ANTI_PATCH_H
