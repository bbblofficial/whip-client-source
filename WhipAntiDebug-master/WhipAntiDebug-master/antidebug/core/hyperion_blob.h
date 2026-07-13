// ===== file: antidebug/core/hyperion_blob.h =====
//
// Hyperion-style runtime code mutation.
//
// At rest the binary contains an encrypted byte array — the .rdata
// section shows scrambled bytes that disassemble to garbage. At call
// time we:
//
//   1. NtAllocateVirtualMemory      → PAGE_READWRITE region (private)
//   2. memcpy + XOR-decrypt          → real x64 instructions in memory
//   3. NtProtectVirtualMemory        → PAGE_EXECUTE_READ
//   4. cast and call                 → executes the real code
//   5. NtProtectVirtualMemory        → PAGE_READWRITE
//   6. zero the bytes                → wipes the decrypted form
//   7. NtFreeVirtualMemory           → releases the page
//
// Net effect: the real code lives in memory for ~microseconds, in a
// PRIVATE region that did not exist before the call and disappears
// after. A static dump of the binary shows only the encrypted blob in
// .rdata. A memory dump captured at random has a vanishingly small
// chance of catching the function in its decrypted form.
//
// What the protected function does
// --------------------------------
// We embed a small `mov eax, MAGIC; ret` stub that returns a constant.
// The constant is folded into the score derivation in main_example —
// if the Hyperion runtime path is broken or the decrypt key is wrong,
// the constant comes back wrong and the flag is corrupted.
//
// The reverser must reproduce the entire alloc/decrypt/exec/free
// dance to get the constant out, OR pause execution at exactly the
// right moment between protect-RX and protect-RW to read the bytes.
// Both are far harder than NOPing a check.
//
#ifndef ANTIDEBUG_HYPERION_BLOB_H
#define ANTIDEBUG_HYPERION_BLOB_H

#include "types.h"
#include "macros.h"
#include "syscall_bridge.h"
#include "string_encrypt.h"
#include "strenc_extra.h"

// Page protection constants (Win32)
#ifndef AD_HYP_PAGE_READWRITE
#define AD_HYP_PAGE_READWRITE      0x04u
#endif
#ifndef AD_HYP_PAGE_EXECUTE_READ
#define AD_HYP_PAGE_EXECUTE_READ   0x20u
#endif
#ifndef AD_HYP_MEM_COMMIT
#define AD_HYP_MEM_COMMIT          0x1000u
#endif
#ifndef AD_HYP_MEM_RESERVE
#define AD_HYP_MEM_RESERVE         0x2000u
#endif
#ifndef AD_HYP_MEM_RELEASE
#define AD_HYP_MEM_RELEASE         0x8000u
#endif

// Magic the embedded stub returns. Folded into the score, so any
// disagreement corrupts the flag.
#define AD_HYPERION_MAGIC 0xDEADBEEFu

// Encryption key for the blob — chosen to avoid 0x00 / 0xFF runs.
#define AD_HYPERION_KEY   0xA5u

// Size of the embedded stub.
#define AD_HYPERION_LEN   6u

// The encrypted bytes of:
//
//   mov eax, 0xDEADBEEF      ; B8 EF BE AD DE
//   ret                       ; C3
//
// XOR'd byte-by-byte with 0xA5 so the .rdata blob disassembles as
// garbage to a static analyser. Re-derived at compile time as a const
// array — no rdata strings, no function-name hints.
#ifndef AD_HYPERION_BLOB_DEFINED
#define AD_HYPERION_BLOB_DEFINED
static const u8 ad_hyperion_blob[AD_HYPERION_LEN] = {
    0xB8u ^ 0xA5u,   // 0x1D
    0xEFu ^ 0xA5u,   // 0x4A
    0xBEu ^ 0xA5u,   // 0x1B
    0xADu ^ 0xA5u,   // 0x08
    0xDEu ^ 0xA5u,   // 0x7B
    0xC3u ^ 0xA5u    // 0x66
};
#endif

// "NtAllocateVirtualMemory" / "NtProtectVirtualMemory" / "NtFreeVirtualMemory"
// macros are pulled in from core/string_encrypt.h via strenc_extra.h.

typedef u32 (*ad_hyperion_fn_t)(void);

// ---------------------------------------------------------------------------
// Hot path: allocate, decrypt, execute, wipe, free.
//
// Returns AD_HYPERION_MAGIC on success, 0 on any error. A return of
// 0 from the caller's point of view is indistinguishable from a
// silent kernel-side syscall failure, so we never expose WHY the
// call failed — every failure mode looks the same.
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE u32 ad_hyperion_run(void) {
#ifdef _MSC_VER
    static u16 s_alloc = AD_SSN_UNRESOLVED;
    static u16 s_prot  = AD_SSN_UNRESOLVED;
    static u16 s_free  = AD_SSN_UNRESOLVED;
    AD_RESOLVE_SSN_ENC(s_alloc, NtAllocateVirtualMemory, 24);
    AD_RESOLVE_SSN_ENC(s_prot,  NtProtectVirtualMemory,  23);
    AD_RESOLVE_SSN_ENC(s_free,  NtFreeVirtualMemory,     20);
    if (s_alloc == AD_SSN_FAILED) return 0;
    if (s_prot  == AD_SSN_FAILED) return 0;
    if (s_free  == AD_SSN_FAILED) return 0;

    // Step 1: NtAllocateVirtualMemory(0x1000 RW, MEM_COMMIT|RESERVE)
    void* base   = (void*)0;
    u64   region = 0x1000ULL;
    ad_ntstatus_t st = (ad_ntstatus_t)(s64)AD_SYSCALL6(
        s_alloc,
        AD_CURRENT_PROCESS,
        &base,
        (u64)0,
        &region,
        (u64)(AD_HYP_MEM_COMMIT | AD_HYP_MEM_RESERVE),
        (u64)AD_HYP_PAGE_READWRITE
    );
    if (!AD_NT_SUCCESS(st) || !base) return 0;

    // Step 2: copy + XOR-decrypt the blob into the new page.
    {
        volatile u8* dst = (volatile u8*)base;
        unsigned i;
        for (i = 0; i < AD_HYPERION_LEN; i++) {
            dst[i] = (u8)(ad_hyperion_blob[i] ^ AD_HYPERION_KEY);
        }
    }

    // Step 3: flip protection to PAGE_EXECUTE_READ.
    {
        void* addr = base;
        u64   sz   = (u64)AD_HYPERION_LEN;
        u32   old  = 0;
        st = (ad_ntstatus_t)(s64)AD_SYSCALL5(
            s_prot,
            AD_CURRENT_PROCESS,
            &addr,
            &sz,
            (u64)AD_HYP_PAGE_EXECUTE_READ,
            &old
        );
        if (!AD_NT_SUCCESS(st)) {
            // Cleanup on failure: free the region and return 0.
            void* fb = base; u64 fs = 0ULL;
            (void)AD_SYSCALL4(s_free, AD_CURRENT_PROCESS, &fb, &fs,
                              (u64)AD_HYP_MEM_RELEASE);
            return 0;
        }
    }

    // Step 4: cast + call. The stub returns AD_HYPERION_MAGIC in eax.
    u32 result = 0;
    {
        ad_hyperion_fn_t fn = (ad_hyperion_fn_t)base;
        result = fn();
    }

    // Step 5: flip back to RW so we can wipe.
    {
        void* addr = base;
        u64   sz   = (u64)AD_HYPERION_LEN;
        u32   old  = 0;
        (void)AD_SYSCALL5(
            s_prot,
            AD_CURRENT_PROCESS,
            &addr,
            &sz,
            (u64)AD_HYP_PAGE_READWRITE,
            &old
        );
    }

    // Step 6: zero the decrypted bytes so a memory snapshot taken AFTER
    // the call but BEFORE the free has nothing to recover.
    {
        volatile u8* dst = (volatile u8*)base;
        unsigned i;
        for (i = 0; i < AD_HYPERION_LEN; i++) dst[i] = 0;
    }

    // Step 7: NtFreeVirtualMemory MEM_RELEASE.
    {
        void* fb = base;
        u64   fs = 0ULL;
        (void)AD_SYSCALL4(
            s_free,
            AD_CURRENT_PROCESS,
            &fb,
            &fs,
            (u64)AD_HYP_MEM_RELEASE
        );
    }

    return result;
#else
    return 0u;
#endif
}

// Returns 1 if the Hyperion runtime path produced the wrong magic.
// Use this directly in score derivation: a clean run contributes 0,
// any tampering with the alloc/protect/exec sequence contributes ≠ 0.
ANTIDEBUG_INLINE b32 ad_hyperion_check(void) {
    return (b32)(ad_hyperion_run() != AD_HYPERION_MAGIC);
}

#endif // ANTIDEBUG_HYPERION_BLOB_H
