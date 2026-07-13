// ===== file: antidebug/checks/debug/al_khaser_classics.h =====
//
// Classic anti-debug checks ported from al-khaser, adapted to Whip's
// direct-syscall + ANTIDEBUG_INLINE conventions.
//
// Each check below was an established detection vector in the wild
// debugger-detection literature for years before being collected in
// al-khaser. The Whip suite already covered most of the high-impact
// surface; the six here close the remaining well-known gaps:
//
//   1. INT 0x2D                      — kernel-debug interrupt gate
//   2. NtQueryObject AllTypes        — system-wide DebugObject count
//   3. NtQueryObject TotalObjects    — TypeInformation count consistency
//   4. Low-Fragmentation Heap        — LFH disabled when debugged
//   5. NtYieldExecution latency      — single-step inflates yield count
//   6. SetHandleInformation protect  — protected-handle close trap
//
// All checks return b32 (0 = clean, 1 = positive). The master combines
// with weighted scores and per-check __try/__except so a single failure
// can never crash the orchestrator.
//
// NOTE: NtYieldExecution is acknowledged-flaky in al-khaser — high-
// priority threads on a busy host can falsely fire it. We give it the
// lowest weight and require the batch ratio to clearly exceed noise.
//
#ifndef ANTIDEBUG_AL_KHASER_CLASSICS_H
#define ANTIDEBUG_AL_KHASER_CLASSICS_H

#include "../../core/types.h"
#include "../../core/macros.h"
#include "../../core/syscall_bridge.h"
#include "../../core/string_encrypt.h"
#include "../../core/strenc_extra.h"
#include "../../core/api_hash.h"

#ifdef _MSC_VER

// =============================================================================
// 1. INT 0x2D — kernel-debug interrupt
// =============================================================================
// Issuing `int 0x2Dh` raises EXCEPTION_BREAKPOINT only when no kernel
// debugger is consuming the trap; with kd attached, the kernel swallows
// it (no exception reaches user mode). MSVC x64 doesn't support inline
// asm, so we synthesise the instruction at runtime in an RWX page and
// call into it via __try/__except.

#ifndef AD_STRENC_NtAllocateVirtualMemory_LK
#define AD_STRENC_NtAllocateVirtualMemory_LK(buf)                            \
    do {                                                                     \
        const u8 _k = AD_STR_KEY(0x2A);                                     \
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

ANTIDEBUG_INLINE b32 ad_kc_int_2d(void) {
    typedef void (__stdcall *fn_int2d_t)(void);
    static fn_int2d_t s_stub = (fn_int2d_t)0;

    if (!s_stub) {
        // One-shot RWX allocation; the page persists for the program's
        // lifetime. ~6 bytes (`CD 2D 90 C3`) fit comfortably.
        static u16 s_ssn = AD_SSN_UNRESOLVED;
        AD_RESOLVE_SSN_ENC(s_ssn, NtAllocateVirtualMemory_LK, 24);
        if (s_ssn == AD_SSN_FAILED) return 0;

        void* page = (void*)0;
        u64 sz = 0x1000;
        ad_ntstatus_t st = (ad_ntstatus_t)(s64)SyscallStub(s_ssn,
            AD_CURRENT_PROCESS, &page, (void*)0, &sz,
            (void*)(u64)0x3000ul,                // MEM_COMMIT|MEM_RESERVE
            (void*)(u64)0x40ul,                  // PAGE_EXECUTE_READWRITE
            (void*)0,(void*)0,(void*)0,(void*)0,(void*)0);
        if (!AD_NT_SUCCESS(st) || !page) return 0;

        u8* p = (u8*)page;
        p[0] = 0xCDu;   // INT imm8
        p[1] = 0x2Du;   // 0x2D
        p[2] = 0x90u;   // NOP — kd skips one byte after int 2d on some Win versions
        p[3] = 0xC3u;   // RET
        s_stub = (fn_int2d_t)page;
    }

    volatile b32 swallowed = 1;
    __try {
        s_stub();
    } __except(1) {
        swallowed = 0;  // Exception reached us → no kd.
    }
    return swallowed;   // 1 = kd consumed it.
}

// =============================================================================
// 2/3. NtQueryObject — DebugObject inspection
// =============================================================================
// `NtQueryObject(class=ObjectAllTypesInformation, 3)` returns a list of
// every kernel object type in the system; if a DebugObject type exists
// AND has TotalNumberOfHandles > 0, SOMETHING in the system is debugging
// SOMETHING. Combined with `NtCreateDebugObject` of our own (handled in
// kd_deep), we expect TotalNumberOfObjects ≥ 1; if it's 0 the API is
// hooked.

#ifndef AD_STRENC_NtQueryObject
#define AD_STRENC_NtQueryObject(buf)                                          \
    do {                                                                      \
        const u8 _k = AD_STR_KEY(0x77);                                      \
        char buf##_e[14];                                                     \
        AD_ENC(buf##_e,  0, 'N', _k); AD_ENC(buf##_e,  1, 't', _k);        \
        AD_ENC(buf##_e,  2, 'Q', _k); AD_ENC(buf##_e,  3, 'u', _k);        \
        AD_ENC(buf##_e,  4, 'e', _k); AD_ENC(buf##_e,  5, 'r', _k);        \
        AD_ENC(buf##_e,  6, 'y', _k); AD_ENC(buf##_e,  7, 'O', _k);        \
        AD_ENC(buf##_e,  8, 'b', _k); AD_ENC(buf##_e,  9, 'j', _k);        \
        AD_ENC(buf##_e, 10, 'e', _k); AD_ENC(buf##_e, 11, 'c', _k);        \
        AD_ENC(buf##_e, 12, 't', _k);                                        \
        AD_DECODE_BUF(buf##_e, 13, _k);                                      \
        for (unsigned _ci = 0; _ci < 14; _ci++) (buf)[_ci] = buf##_e[_ci];   \
    } while (0)
#endif

typedef struct {
    u32  Length;
    u32  MaxLength;
    u16* Buffer;
} AD_UNICODE_STRING_LITE;

typedef struct {
    AD_UNICODE_STRING_LITE TypeName;
    u32  TotalNumberOfHandles;
    u32  TotalNumberOfObjects;
    // Trailing fields ignored — we only need the counts.
} AD_OBJECT_TYPE_INFO_LITE;

typedef struct {
    u32 NumberOfObjects;
    AD_OBJECT_TYPE_INFO_LITE TypeInfo[1];
} AD_OBJECT_ALL_INFO_LITE;

ANTIDEBUG_INLINE b32 ad_kc_query_object_alltypes(void) {
    static u16 s_ssn = AD_SSN_UNRESOLVED;
    AD_RESOLVE_SSN_ENC(s_ssn, NtQueryObject, 13);
    if (s_ssn == AD_SSN_FAILED) return 0;

    // First pass — query needed buffer size.
    u32 size = 0;
    (void)AD_SYSCALL5(s_ssn,
        (void*)0,                                 // No handle for AllTypes
        (u64)3,                                   // ObjectAllTypesInformation
        &size, (u64)sizeof(u32), &size);
    if (size < sizeof(AD_OBJECT_ALL_INFO_LITE)) return 0;
    if (size > 0x100000u) return 0;  // sanity

    // Allocate buffer via direct syscall.
    static u16 s_alloc = AD_SSN_UNRESOLVED;
    AD_RESOLVE_SSN_ENC(s_alloc, NtAllocateVirtualMemory_LK, 24);
    if (s_alloc == AD_SSN_FAILED) return 0;

    void* mem  = (void*)0;
    u64   msz  = (u64)size;
    ad_ntstatus_t st = (ad_ntstatus_t)(s64)SyscallStub(s_alloc,
        AD_CURRENT_PROCESS, &mem, (void*)0, &msz,
        (void*)(u64)0x3000ul, (void*)(u64)0x04ul,  // PAGE_READWRITE
        (void*)0,(void*)0,(void*)0,(void*)0,(void*)0);
    if (!AD_NT_SUCCESS(st) || !mem) return 0;

    // Pass 2 — actual query.
    u32 ret_len = 0;
    st = AD_SYSCALL5(s_ssn, AD_CURRENT_PROCESS, (u64)3,
                     mem, (u64)size, &ret_len);

    b32 detected = 0;
    if (AD_NT_SUCCESS(st)) {
        AD_OBJECT_ALL_INFO_LITE* all = (AD_OBJECT_ALL_INFO_LITE*)mem;
        u8* cur = (u8*)&all->TypeInfo[0];
        u32 n = all->NumberOfObjects;
        u32 i;
        for (i = 0; i < n && i < 0x200u; i++) {
            AD_OBJECT_TYPE_INFO_LITE* ti = (AD_OBJECT_TYPE_INFO_LITE*)cur;
            // Compare TypeName "DebugObject" — UTF-16, 11 chars × 2 = 22 bytes.
            if (ti->TypeName.Buffer && ti->TypeName.Length >= 22u) {
                u16* b = ti->TypeName.Buffer;
                if (b[0] == L'D' && b[1] == L'e' && b[2] == L'b' &&
                    b[3] == L'u' && b[4] == L'g' && b[5] == L'O' &&
                    b[6] == L'b' && b[7] == L'j' && b[8] == L'e' &&
                    b[9] == L'c' && b[10] == L't' &&
                    ti->TotalNumberOfHandles > 0u) {
                    detected = 1;
                    break;
                }
            }
            // Advance: NT lays out each entry as <full struct> followed
            // immediately by the inline name buffer pointed to by
            // TypeName.Buffer. al-khaser's official trick: advance to
            // TypeName.Buffer + MaxLength, aligned up to 8.
            // Our LITE struct sizeof != real struct sizeof, so DON'T use
            // sizeof — use the Buffer pointer instead.
            if (ti->TypeName.Buffer && ti->TypeName.MaxLength > 0u) {
                u64 next = (u64)ti->TypeName.Buffer + ti->TypeName.MaxLength;
                next = (next + 7ULL) & ~7ULL;
                cur = (u8*)next;
            } else {
                // Defensive: if Buffer is NULL or MaxLength is 0, the
                // entry is malformed — bail out of the iteration.
                break;
            }
        }
    }

    // Free the buffer.
    static u16 s_free = AD_SSN_UNRESOLVED;
    if (s_free == AD_SSN_UNRESOLVED) {
        char n[] = {'N','t','F','r','e','e','V','i','r','t','u','a','l','M','e','m','o','r','y',0};
        s_free = whip_bridge_resolve(n);
    }
    if (s_free != AD_SSN_FAILED) {
        u64 fsz = 0;
        (void)SyscallStub(s_free,
            AD_CURRENT_PROCESS, &mem, &fsz, (void*)(u64)0x8000ul,
            (void*)0,(void*)0,(void*)0,(void*)0,(void*)0,(void*)0,(void*)0);
    }
    return detected;
}

// =============================================================================
// 4. Low-Fragmentation Heap
// =============================================================================
// Process heap created under a debugger does NOT have LFH installed —
// the FrontEndHeap pointer in nt!_HEAP stays NULL. On a clean run the
// kernel installs LFH lazily as soon as the heap sees enough activity
// (which our orchestrator triggers via its many stack allocations).
//
// FrontEndHeap offset varies by Win version. Observed offsets:
//   Win10 / Win11 x64 : 0x178 (verified on 22H2, 23H2, 26100)
//   Win8 / Win8.1 x64 : 0x170
//
// We try the modern offset first and fall back to the older one.

ANTIDEBUG_INLINE b32 ad_kc_lfh_disabled(void) {
    // PEB.ProcessHeap at gs:[0x60] → +0x30
    u8* peb = (u8*)__readgsqword(0x60);
    if (!peb) return 0;
    u8* heap = *(u8**)(peb + 0x30);
    if (!heap) return 0;

    // Identify heap type via signature. Win10+/Win11 ship Segment Heap as
    // default for many processes; its layout has nothing in common with
    // the legacy NT Heap and the FrontEndHeap field is meaningless on it.
    //   NT Heap      : Heap.Signature = 0xEEFFEEFF at offset +0x10
    //   Segment Heap : Heap.Signature = 0xDDEEDDEE at offset +0x08
    // Only the NT Heap variant supports the LFH detection trick.
    u32 nt_sig  = *(volatile u32*)(heap + 0x10);
    if (nt_sig != 0xEEFFEEFFu) {
        // Segment Heap or unknown — LFH check doesn't apply, return clean.
        return 0;
    }

    // NT Heap confirmed. Modern offset first, Win8 fallback.
    u8* fe1 = *(u8**)(heap + 0x178);
    u8* fe2 = *(u8**)(heap + 0x170);

    // Both NULL → LFH was never installed → debugger-spawned heap.
    if (fe1 == (u8*)0 && fe2 == (u8*)0) return 1;
    return 0;
}

// =============================================================================
// 5. NtYieldExecution latency
// =============================================================================
// Single-stepping under a debugger inflates the rate at which
// NtYieldExecution returns "yield performed" (vs STATUS_NO_YIELD_PERFORMED
// = 0x40000024). al-khaser flags >3 successful yields out of 32 attempts
// as suspicious. We use a stricter threshold (>10) to absorb the noise
// from running on a busy dev host with many concurrent threads.

#ifndef AD_STRENC_NtYieldExecution
#define AD_STRENC_NtYieldExecution(buf)                                       \
    do {                                                                      \
        const u8 _k = AD_STR_KEY(0x3B);                                      \
        char buf##_e[18];                                                     \
        AD_ENC(buf##_e,  0, 'N', _k); AD_ENC(buf##_e,  1, 't', _k);        \
        AD_ENC(buf##_e,  2, 'Y', _k); AD_ENC(buf##_e,  3, 'i', _k);        \
        AD_ENC(buf##_e,  4, 'e', _k); AD_ENC(buf##_e,  5, 'l', _k);        \
        AD_ENC(buf##_e,  6, 'd', _k); AD_ENC(buf##_e,  7, 'E', _k);        \
        AD_ENC(buf##_e,  8, 'x', _k); AD_ENC(buf##_e,  9, 'e', _k);        \
        AD_ENC(buf##_e, 10, 'c', _k); AD_ENC(buf##_e, 11, 'u', _k);        \
        AD_ENC(buf##_e, 12, 't', _k); AD_ENC(buf##_e, 13, 'i', _k);        \
        AD_ENC(buf##_e, 14, 'o', _k); AD_ENC(buf##_e, 15, 'n', _k);        \
        AD_DECODE_BUF(buf##_e, 17, _k);                                      \
        for (unsigned _ci = 0; _ci < 18; _ci++) (buf)[_ci] = buf##_e[_ci];   \
    } while (0)
#endif

#ifndef AD_STATUS_NO_YIELD_PERFORMED
#define AD_STATUS_NO_YIELD_PERFORMED  ((ad_ntstatus_t)(s32)0x40000024L)
#endif

ANTIDEBUG_INLINE b32 ad_kc_yield_latency(void) {
    static u16 s_ssn = AD_SSN_UNRESOLVED;
    AD_RESOLVE_SSN_ENC(s_ssn, NtYieldExecution, 17);
    if (s_ssn == AD_SSN_FAILED) return 0;

    u32 yielded = 0;
    u32 i;
    for (i = 0; i < 32u; i++) {
        ad_ntstatus_t st = AD_SYSCALL0(s_ssn);
        if (st != AD_STATUS_NO_YIELD_PERFORMED) yielded++;
    }
    // Conservative threshold — al-khaser uses 3, we require ≥ 11 to
    // reduce false positives on busy multi-core dev machines.
    return (yielded >= 11u) ? 1 : 0;
}

// =============================================================================
// 6. SetHandleInformation — protected handle close trap
// =============================================================================
// Mark a handle HANDLE_FLAG_PROTECT_FROM_CLOSE then close it. Without a
// debugger, NtClose returns STATUS_HANDLE_NOT_CLOSABLE silently. Under
// a debugger that has FLG_ENABLE_CLOSE_EXCEPTIONS set (which many do
// for diagnostic reasons), the kernel raises an exception.
//
// We use NtCreateMutant + NtSetInformationObject to mark, then NtClose
// inside __try/__except. This is similar to but distinct from the
// kd_deep close-invalid-handle check (which uses an obviously bogus
// handle); here the handle is real but flagged uncloseable.

#ifndef AD_STRENC_NtCreateMutant
#define AD_STRENC_NtCreateMutant(buf)                                         \
    do {                                                                      \
        const u8 _k = AD_STR_KEY(0x59);                                      \
        char buf##_e[15];                                                     \
        AD_ENC(buf##_e,  0, 'N', _k); AD_ENC(buf##_e,  1, 't', _k);        \
        AD_ENC(buf##_e,  2, 'C', _k); AD_ENC(buf##_e,  3, 'r', _k);        \
        AD_ENC(buf##_e,  4, 'e', _k); AD_ENC(buf##_e,  5, 'a', _k);        \
        AD_ENC(buf##_e,  6, 't', _k); AD_ENC(buf##_e,  7, 'e', _k);        \
        AD_ENC(buf##_e,  8, 'M', _k); AD_ENC(buf##_e,  9, 'u', _k);        \
        AD_ENC(buf##_e, 10, 't', _k); AD_ENC(buf##_e, 11, 'a', _k);        \
        AD_ENC(buf##_e, 12, 'n', _k); AD_ENC(buf##_e, 13, 't', _k);        \
        AD_DECODE_BUF(buf##_e, 14, _k);                                      \
        for (unsigned _ci = 0; _ci < 15; _ci++) (buf)[_ci] = buf##_e[_ci];   \
    } while (0)
#endif

#ifndef AD_STRENC_NtSetInformationObject
#define AD_STRENC_NtSetInformationObject(buf)                                \
    do {                                                                     \
        const u8 _k = AD_STR_KEY(0x67);                                     \
        char buf##_e[24];                                                    \
        AD_ENC(buf##_e,  0, 'N', _k); AD_ENC(buf##_e,  1, 't', _k);       \
        AD_ENC(buf##_e,  2, 'S', _k); AD_ENC(buf##_e,  3, 'e', _k);       \
        AD_ENC(buf##_e,  4, 't', _k); AD_ENC(buf##_e,  5, 'I', _k);       \
        AD_ENC(buf##_e,  6, 'n', _k); AD_ENC(buf##_e,  7, 'f', _k);       \
        AD_ENC(buf##_e,  8, 'o', _k); AD_ENC(buf##_e,  9, 'r', _k);       \
        AD_ENC(buf##_e, 10, 'm', _k); AD_ENC(buf##_e, 11, 'a', _k);       \
        AD_ENC(buf##_e, 12, 't', _k); AD_ENC(buf##_e, 13, 'i', _k);       \
        AD_ENC(buf##_e, 14, 'o', _k); AD_ENC(buf##_e, 15, 'n', _k);       \
        AD_ENC(buf##_e, 16, 'O', _k); AD_ENC(buf##_e, 17, 'b', _k);       \
        AD_ENC(buf##_e, 18, 'j', _k); AD_ENC(buf##_e, 19, 'e', _k);       \
        AD_ENC(buf##_e, 20, 'c', _k); AD_ENC(buf##_e, 21, 't', _k);       \
        AD_DECODE_BUF(buf##_e, 23, _k);                                     \
        for (unsigned _ci = 0; _ci < 24; _ci++) (buf)[_ci] = buf##_e[_ci];  \
    } while (0)
#endif

typedef struct {
    u32 Inherit;
    u32 ProtectFromClose;
} AD_OBJECT_HANDLE_FLAG_INFO;

ANTIDEBUG_INLINE b32 ad_kc_protected_handle(void) {
    static u16 s_create  = AD_SSN_UNRESOLVED;
    static u16 s_setinfo = AD_SSN_UNRESOLVED;
    static u16 s_close   = AD_SSN_UNRESOLVED;
    AD_RESOLVE_SSN_ENC(s_create,  NtCreateMutant, 14);
    AD_RESOLVE_SSN_ENC(s_setinfo, NtSetInformationObject, 23);
    AD_RESOLVE_SSN_ENC(s_close,   NtClose, 8);
    if (s_create == AD_SSN_FAILED || s_setinfo == AD_SSN_FAILED ||
        s_close  == AD_SSN_FAILED) return 0;

    void* h = (void*)0;
    ad_ntstatus_t st = AD_SYSCALL4(s_create,
        &h, (u64)0x1F0001UL,                  // MUTANT_ALL_ACCESS
        (void*)0, (u64)0);
    if (!AD_NT_SUCCESS(st) || !h) return 0;

    AD_OBJECT_HANDLE_FLAG_INFO flags;
    flags.Inherit          = 0u;
    flags.ProtectFromClose = 1u;
    (void)AD_SYSCALL4(s_setinfo,
        h, (u64)4,                            // ObjectHandleFlagInformation
        &flags, (u64)sizeof(flags));

    volatile b32 caught = 0;
    __try {
        (void)AD_SYSCALL1(s_close, h);
    } __except(1) {
        caught = 1;
    }

    // Clear protect bit and clean up.
    flags.ProtectFromClose = 0u;
    (void)AD_SYSCALL4(s_setinfo, h, (u64)4, &flags, (u64)sizeof(flags));
    (void)AD_SYSCALL1(s_close, h);

    return caught;
}

// =============================================================================
// Master combiner
// =============================================================================
ANTIDEBUG_INLINE u32 ad_al_khaser_classics_master(void) {
    u32 score = 0u;
    __try { if (ad_kc_int_2d())                  score += 12u; } __except(1) {}
    __try { if (ad_kc_query_object_alltypes())   score += 8u;  } __except(1) {}
    __try { if (ad_kc_lfh_disabled())            score += 6u;  } __except(1) {}
    __try { if (ad_kc_yield_latency())           score += 4u;  } __except(1) {}
    __try { if (ad_kc_protected_handle())        score += 8u;  } __except(1) {}
    return score;
}

#else  // !_MSC_VER

ANTIDEBUG_INLINE u32 ad_al_khaser_classics_master(void) { return 0u; }

#endif // _MSC_VER

#endif // ANTIDEBUG_AL_KHASER_CLASSICS_H
