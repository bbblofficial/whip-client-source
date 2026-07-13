// ===== file: antidebug/checks/integrity/memory_bp_detect.h =====
//
// Memory breakpoint detection and ntdll page protection audit.
//
// Checks:
//
//   1. ad_memory_bp_timing()
//      Detect PAGE_GUARD-based memory breakpoints by measuring RDTSC timing
//      over sequential reads of ntdll .text. PAGE_GUARD triggers a
//      STATUS_GUARD_PAGE_VIOLATION exception on first access, costing ~5000+
//      cycles per guarded page. Clean reads of 4096 cached bytes take < 10000
//      cycles total; guarded pages push this past 50000.
//
//   2. ad_ntdll_page_protection_check()
//      Scan the first 16 pages (0x10000 bytes) of ntdll .text via
//      NtQueryVirtualMemory and verify each page is PAGE_EXECUTE_READ (0x20).
//      Inline-hooking tools must flip pages to PAGE_EXECUTE_READWRITE (0x40)
//      or PAGE_READWRITE (0x04) before patching — this detects that.
//
//   3. ad_memory_integrity_master()
//      Weighted composite: timing=5, page_protection=8.
//
#ifndef ANTIDEBUG_MEMORY_BP_DETECT_H
#define ANTIDEBUG_MEMORY_BP_DETECT_H

#include "../../core/types.h"
#include "../../core/macros.h"
#include "../../core/syscall_bridge.h"
#include "../../core/string_encrypt.h"
#include "../../stack/moonwalk.h"    // ad_ntdll_base(), ad_find_text_section()

#if defined(_MSC_VER)

// =========================================================================
// 1. Memory breakpoint timing detection
// =========================================================================
//
// PAGE_GUARD breakpoints (used by Cheat Engine, x64dbg memory BPs) set
// the PAGE_GUARD attribute on code pages. The first read from a guarded
// page raises STATUS_GUARD_PAGE_VIOLATION — the debugger catches this,
// logs the access, re-arms the guard, and resumes. This adds thousands
// of cycles per page hit.
//
// We measure the cost of sequentially reading 4096 bytes from ntdll
// .text. On a clean system the data is in L1/L2 cache and each byte
// read is ~1 cycle. With memory BPs the cost is orders of magnitude
// higher.
//
// We run the measurement twice and take the minimum to reduce noise
// from interrupts/context switches.
// =========================================================================
ANTIDEBUG_INLINE b32 ad_memory_bp_timing(void) {
    void* ntdll = ad_ntdll_base();
    if (!ntdll) return 0;

    u8* text_start = (u8*)0;
    u32 text_len   = ad_find_text_section(ntdll, &text_start);
    if (!text_start || text_len < 4096u) return 0;

    u64 best = ~0ULL;  // minimum across iterations
    u32 iter;

    for (iter = 0u; iter < 2u; iter++) {
        volatile u8 sink = 0u;
        u32 i;

        AD_BARRIER();
        AD_LFENCE();
        u64 t0 = __rdtsc();
        AD_LFENCE();

        for (i = 0u; i < 4096u; i++) {
            sink = *(volatile u8*)(text_start + i);
        }

        AD_LFENCE();
        u64 t1 = __rdtsc();
        AD_LFENCE();

        AD_UNUSED(sink);

        u64 elapsed = t1 - t0;
        if (elapsed < best) best = elapsed;
    }

    // Threshold: 50000 cycles for 4096 byte reads.
    // Clean: < 10000    (cached reads, ~1-2 cycles each)
    // Guarded: > 50000  (exception + re-arm per page hit)
    return (b32)(best > 50000ULL);
}

// =========================================================================
// 2. ntdll page protection audit
// =========================================================================
//
// Inline hooking requires making code pages writable. Tools like
// MinHook / Detours call VirtualProtect(PAGE_EXECUTE_READWRITE) before
// writing the JMP, then may or may not restore the original protection.
//
// We scan the first 16 pages of ntdll .text and flag any page that is
// not PAGE_EXECUTE_READ (0x20). Writable code pages in ntdll are a
// strong indicator of usermode hooks.
// =========================================================================

// Guard: AD_MEMORY_BASIC_INFO may already be defined by anti_patch.h
#ifndef AD_MEMORY_BASIC_INFO_DEFINED
#define AD_MEMORY_BASIC_INFO_DEFINED
typedef struct {
    void* BaseAddress;
    void* AllocationBase;
    u32   AllocationProtect;
    u16   PartitionId;
    u16   _pad;
    u64   RegionSize;
    u32   State;
    u32   Protect;
    u32   Type;
    u32   _pad2;
} AD_MEMORY_BASIC_INFO;
#endif

// Guard: page protection constants may already be defined by anti_patch.h
#ifndef AD_PAGE_EXECUTE_READ
#define AD_PAGE_EXECUTE_READ      0x20u
#endif
#ifndef AD_PAGE_EXECUTE_READWRITE
#define AD_PAGE_EXECUTE_READWRITE 0x40u
#endif
#ifndef AD_PAGE_READWRITE
#define AD_PAGE_READWRITE         0x04u
#endif

// Guard: NtQueryVirtualMemory encrypted string may already be defined
#ifndef AD_STRENC_NtQueryVirtualMemory_DEFINED
#define AD_STRENC_NtQueryVirtualMemory_DEFINED
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

ANTIDEBUG_INLINE b32 ad_ntdll_page_protection_check(void) {
    static u16 s_ssn_qvm = AD_SSN_UNRESOLVED;
    AD_RESOLVE_SSN_ENC(s_ssn_qvm, NtQueryVirtualMemory, 21);
    if (s_ssn_qvm == AD_SSN_FAILED) return 0;

    void* ntdll = ad_ntdll_base();
    if (!ntdll) return 0;

    u8* text_start = (u8*)0;
    u32 text_len   = ad_find_text_section(ntdll, &text_start);
    if (!text_start || text_len == 0u) return 0;

    // Clamp scan to 16 pages (0x10000 bytes) or actual .text size
    u32 scan_size = text_len;
    if (scan_size > 0x10000u) scan_size = 0x10000u;

    u32 page;
    for (page = 0u; page < scan_size; page += 0x1000u) {
        u8* addr = text_start + page;

        AD_MEMORY_BASIC_INFO mbi;
        AD_ZERO_BUF(&mbi, sizeof(mbi));
        u64 ret_len = 0;

        // NtQueryVirtualMemory(ProcessHandle, BaseAddress, MemInfoClass, Buffer, Length, RetLen)
        ad_ntstatus_t st = AD_SYSCALL6(
            s_ssn_qvm,
            AD_CURRENT_PROCESS,
            (u64)addr,
            (u64)0,     // MemoryBasicInformation = class 0
            &mbi,
            (u64)sizeof(mbi),
            &ret_len
        );

        if (!AD_NT_SUCCESS(st)) continue;

        u32 prot = mbi.Protect;

        // Normal ntdll .text: PAGE_EXECUTE_READ (0x20)
        // Hooked pages: PAGE_EXECUTE_READWRITE (0x40) or PAGE_READWRITE (0x04)
        if (prot == AD_PAGE_EXECUTE_READWRITE || prot == AD_PAGE_READWRITE) {
            return 1;  // hooks installed
        }
    }

    return 0;
}

// =========================================================================
// MEMORY INTEGRITY MASTER
// =========================================================================
//
// Composite score from both checks:
//   - memory_bp_timing:        weight 5
//   - ntdll_page_protection:   weight 8
// =========================================================================
ANTIDEBUG_INLINE u32 ad_memory_integrity_master(void) {
    u32 score = 0u;

    // Memory breakpoint timing detection (PAGE_GUARD)
    { b32 v = 0; __try { v = ad_memory_bp_timing(); } __except(1){} if (v) score += 5u; }

    // ntdll page protection audit (inline hooks)
    { b32 v = 0; __try { v = ad_ntdll_page_protection_check(); } __except(1){} if (v) score += 8u; }

    return score;
}

#else  // Non-MSVC stubs

ANTIDEBUG_INLINE b32 ad_memory_bp_timing(void) { return 0; }
ANTIDEBUG_INLINE b32 ad_ntdll_page_protection_check(void) { return 0; }
ANTIDEBUG_INLINE u32 ad_memory_integrity_master(void) { return 0u; }

#endif // _MSC_VER

#endif // ANTIDEBUG_MEMORY_BP_DETECT_H
