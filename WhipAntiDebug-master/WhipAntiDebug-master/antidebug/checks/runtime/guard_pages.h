// ===== file: antidebug/checks/runtime/guard_pages.h =====
//
// Guard page trap — runtime debugger detection.
//
// Technique:
//   Allocate a memory page with PAGE_GUARD protection. Accessing it raises
//   STATUS_GUARD_PAGE_VIOLATION (0x80000001). The OS delivers this as a
//   single-shot exception: the guard bit is cleared after the first access.
//
//   A debugger that intercepts exceptions will consume the guard page
//   violation BEFORE our SEH handler sees it. Detection:
//     - No debugger: our __except handler fires → guard_triggered = 1
//     - Debugger swallows it: handler never fires → guard_triggered = 0
//
//   This is DIFFERENT from the NtClose trap: it tests the debugger's
//   exception dispatch policy for a different exception class.
//
//   Uses NtAllocateVirtualMemory + NtProtectVirtualMemory + NtFreeVirtualMemory
//   via direct syscall — zero IAT.
//
#ifndef ANTIDEBUG_GUARD_PAGES_H
#define ANTIDEBUG_GUARD_PAGES_H

#include "../../core/types.h"
#include "../../core/macros.h"
#include "../../core/syscall_bridge.h"
#include "../../core/string_encrypt.h"

// NT constants
#define AD_MEM_COMMIT       0x00001000UL
#define AD_MEM_RESERVE      0x00002000UL
#define AD_MEM_RELEASE      0x00008000UL
#define AD_PAGE_RW          0x04UL
#define AD_PAGE_GUARD       0x100UL

// ---------------------------------------------------------------------------
// Encrypted strings
// ---------------------------------------------------------------------------

// "NtAllocateVirtualMemory" (23 chars) — guarded against the canonical
// definition in core/string_encrypt.h
#ifndef AD_STRENC_NtAllocateVirtualMemory
#define AD_STRENC_NtAllocateVirtualMemory(buf)                               \
    do {                                                                     \
        const u8 _k = AD_STR_KEY(0x4D);                                     \
        char buf##_e[24];                                                    \
        AD_ENC(buf##_e,  0, 'N', _k); AD_ENC(buf##_e,  1, 't', _k);       \
        AD_ENC(buf##_e,  2, 'A', _k); AD_ENC(buf##_e,  3, 'l', _k);       \
        AD_ENC(buf##_e,  4, 'l', _k); AD_ENC(buf##_e,  5, 'o', _k);       \
        AD_ENC(buf##_e,  6, 'c', _k); AD_ENC(buf##_e,  7, 'a', _k);       \
        AD_ENC(buf##_e,  8, 't', _k); AD_ENC(buf##_e,  9, 'e', _k);       \
        AD_ENC(buf##_e, 10, 'V', _k); AD_ENC(buf##_e, 11, 'i', _k);       \
        AD_ENC(buf##_e, 12, 'r', _k); AD_ENC(buf##_e, 13, 't', _k);       \
        AD_ENC(buf##_e, 14, 'u', _k); AD_ENC(buf##_e, 15, 'a', _k);       \
        AD_ENC(buf##_e, 16, 'l', _k); AD_ENC(buf##_e, 17, 'M', _k);       \
        AD_ENC(buf##_e, 18, 'e', _k); AD_ENC(buf##_e, 19, 'm', _k);       \
        AD_ENC(buf##_e, 20, 'o', _k); AD_ENC(buf##_e, 21, 'r', _k);       \
        AD_ENC(buf##_e, 22, 'y', _k);                                       \
        AD_DECODE_BUF(buf##_e, 23, _k);                                     \
        for (unsigned _ci = 0; _ci < 24; _ci++) (buf)[_ci] = buf##_e[_ci];  \
    } while (0)
#endif

// "NtFreeVirtualMemory" (19 chars)
#ifndef AD_STRENC_NtFreeVirtualMemory
#define AD_STRENC_NtFreeVirtualMemory(buf)                                   \
    do {                                                                     \
        const u8 _k = AD_STR_KEY(0x61);                                     \
        char buf##_e[20];                                                    \
        AD_ENC(buf##_e,  0, 'N', _k); AD_ENC(buf##_e,  1, 't', _k);       \
        AD_ENC(buf##_e,  2, 'F', _k); AD_ENC(buf##_e,  3, 'r', _k);       \
        AD_ENC(buf##_e,  4, 'e', _k); AD_ENC(buf##_e,  5, 'e', _k);       \
        AD_ENC(buf##_e,  6, 'V', _k); AD_ENC(buf##_e,  7, 'i', _k);       \
        AD_ENC(buf##_e,  8, 'r', _k); AD_ENC(buf##_e,  9, 't', _k);       \
        AD_ENC(buf##_e, 10, 'u', _k); AD_ENC(buf##_e, 11, 'a', _k);       \
        AD_ENC(buf##_e, 12, 'l', _k); AD_ENC(buf##_e, 13, 'M', _k);       \
        AD_ENC(buf##_e, 14, 'e', _k); AD_ENC(buf##_e, 15, 'm', _k);       \
        AD_ENC(buf##_e, 16, 'o', _k); AD_ENC(buf##_e, 17, 'r', _k);       \
        AD_ENC(buf##_e, 18, 'y', _k);                                       \
        AD_DECODE_BUF(buf##_e, 19, _k);                                     \
        for (unsigned _ci = 0; _ci < 20; _ci++) (buf)[_ci] = buf##_e[_ci];  \
    } while (0)
#endif

// "NtProtectVirtualMemory" — reuse from anti_dump.h if both included,
// otherwise define here
#ifndef AD_STRENC_NtProtectVirtualMemory
#define AD_STRENC_NtProtectVirtualMemory(buf)                                \
    do {                                                                     \
        const u8 _k = AD_STR_KEY(0x3B);                                     \
        char buf##_e[23];                                                    \
        AD_ENC(buf##_e,  0, 'N', _k); AD_ENC(buf##_e,  1, 't', _k);       \
        AD_ENC(buf##_e,  2, 'P', _k); AD_ENC(buf##_e,  3, 'r', _k);       \
        AD_ENC(buf##_e,  4, 'o', _k); AD_ENC(buf##_e,  5, 't', _k);       \
        AD_ENC(buf##_e,  6, 'e', _k); AD_ENC(buf##_e,  7, 'c', _k);       \
        AD_ENC(buf##_e,  8, 't', _k); AD_ENC(buf##_e,  9, 'V', _k);       \
        AD_ENC(buf##_e, 10, 'i', _k); AD_ENC(buf##_e, 11, 'r', _k);       \
        AD_ENC(buf##_e, 12, 't', _k); AD_ENC(buf##_e, 13, 'u', _k);       \
        AD_ENC(buf##_e, 14, 'a', _k); AD_ENC(buf##_e, 15, 'l', _k);       \
        AD_ENC(buf##_e, 16, 'M', _k); AD_ENC(buf##_e, 17, 'e', _k);       \
        AD_ENC(buf##_e, 18, 'm', _k); AD_ENC(buf##_e, 19, 'o', _k);       \
        AD_ENC(buf##_e, 20, 'r', _k); AD_ENC(buf##_e, 21, 'y', _k);       \
        AD_DECODE_BUF(buf##_e, 22, _k);                                     \
        for (unsigned _ci = 0; _ci < 23; _ci++) (buf)[_ci] = buf##_e[_ci];  \
    } while (0)
#endif

// ---------------------------------------------------------------------------
// Check: Guard page exception trap
//
// Returns 1 (suspicious) if the guard page violation was swallowed by a
// debugger before our handler could see it.
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE b32 ad_guard_page_trap(void) {
    // Resolve syscalls
    static u16 s_ssn_alloc   = AD_SSN_UNRESOLVED;
    static u16 s_ssn_protect = AD_SSN_UNRESOLVED;
    static u16 s_ssn_free    = AD_SSN_UNRESOLVED;

    AD_RESOLVE_SSN_ENC(s_ssn_alloc,   NtAllocateVirtualMemory, 24);
    AD_RESOLVE_SSN_ENC(s_ssn_protect, NtProtectVirtualMemory,  23);
    AD_RESOLVE_SSN_ENC(s_ssn_free,    NtFreeVirtualMemory,     20);

    if (s_ssn_alloc == AD_SSN_FAILED || s_ssn_protect == AD_SSN_FAILED) return 0;

    // Step 1: Allocate a page
    void* base_addr  = (void*)0;
    u64   region_size = 0x1000ULL;

    ad_ntstatus_t st = AD_SYSCALL6(
        s_ssn_alloc,
        AD_CURRENT_PROCESS,
        &base_addr,
        (u64)0,              // ZeroBits
        &region_size,
        (u64)(AD_MEM_COMMIT | AD_MEM_RESERVE),
        (u64)AD_PAGE_RW
    );
    if (!AD_NT_SUCCESS(st) || !base_addr) return 0;

    // Write a known value so the page is committed
    *(volatile u8*)base_addr = 0x42;

    // Step 2: Set PAGE_GUARD
    u32 old_protect = 0;
    void* prot_addr = base_addr;
    u64   prot_size = 0x1000ULL;

    st = AD_SYSCALL5(
        s_ssn_protect,
        AD_CURRENT_PROCESS,
        &prot_addr,
        &prot_size,
        (u64)(AD_PAGE_RW | AD_PAGE_GUARD),
        &old_protect
    );

    b32 detected = 0;

    if (AD_NT_SUCCESS(st)) {
        // Step 3: Touch the page — should raise STATUS_GUARD_PAGE_VIOLATION
#if defined(_MSC_VER)
        volatile b32 handler_fired = 0;
        __try {
            volatile u8 val = *(volatile u8*)base_addr;
            AD_UNUSED(val);
        }
        __except (1) {  // EXCEPTION_EXECUTE_HANDLER
            handler_fired = 1;
        }
        // If handler didn't fire, debugger ate the exception
        detected = (b32)(handler_fired == 0);
#endif
    }

    // Cleanup: free the page
    if (s_ssn_free != AD_SSN_FAILED && base_addr) {
        void* free_addr = base_addr;
        u64   free_size = 0ULL;
        AD_SYSCALL4(
            s_ssn_free,
            AD_CURRENT_PROCESS,
            &free_addr,
            &free_size,
            (u64)AD_MEM_RELEASE
        );
    }

    return detected;
}

#endif // ANTIDEBUG_GUARD_PAGES_H
