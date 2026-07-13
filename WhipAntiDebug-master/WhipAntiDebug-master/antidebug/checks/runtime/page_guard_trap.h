// ===== file: antidebug/checks/runtime/page_guard_trap.h =====
//
// PAGE_GUARD sentinel — catch debugger memory window reads.
//
// Allocate a small page, fill it with a "secret-looking" pattern, mark
// it PAGE_GUARD. Any access (read OR write) raises STATUS_GUARD_PAGE
// _VIOLATION on the FIRST access only — and the OS auto-clears the
// guard. We never touch the page from our own code, so the only thing
// that can trip it is a debugger's memory inspection window opening on
// it (or a script reading process memory).
//
// We poll periodically by re-applying PAGE_GUARD and checking if it
// was already cleared (= someone read it).
//
#ifndef ANTIDEBUG_PAGE_GUARD_TRAP_H
#define ANTIDEBUG_PAGE_GUARD_TRAP_H

#include "../../core/types.h"
#include "../../core/macros.h"
#include "../../core/syscall_bridge.h"
#include "../../core/string_encrypt.h"

#define AD_PG_PAGE_READWRITE  0x04u
#define AD_PG_PAGE_GUARD      0x100u
#define AD_PG_MEM_COMMIT      0x1000u
#define AD_PG_MEM_RESERVE     0x2000u
#define AD_PG_MEM_RELEASE     0x8000u

typedef struct {
    void* addr;
    u32   armed;
} ad_page_guard_t;

ANTIDEBUG_INLINE b32 ad_page_guard_init(ad_page_guard_t* pg) {
#ifdef _MSC_VER
    if (!pg) return 0;
    pg->addr = 0;
    pg->armed = 0;

    static u16 s_alloc_ssn = AD_SSN_UNRESOLVED;
    AD_RESOLVE_SSN_ENC(s_alloc_ssn, NtAllocateVirtualMemory, 24);
    // (NtAllocateVirtualMemory strenc lives elsewhere — see guard_pages.h)
    if (s_alloc_ssn == AD_SSN_FAILED) return 0;

    void* base = 0;
    u64 size = 4096;
    ad_ntstatus_t st = (ad_ntstatus_t)(s64)AD_SYSCALL6(
        s_alloc_ssn,
        AD_CURRENT_PROCESS,
        &base,
        (u64)0,
        &size,
        (u64)(AD_PG_MEM_COMMIT | AD_PG_MEM_RESERVE),
        (u64)AD_PG_PAGE_READWRITE
    );
    if (!AD_NT_SUCCESS(st) || !base) return 0;

    // Fill with bait: looks like an AES key + flag header.
    u8* p = (u8*)base;
    static const u8 bait[] = {
        'F','L','A','G','{','f','a','k','e','_','b','a','i','t','_','k',
        'e','y','=','D','E','A','D','B','E','E','F','C','A','F','E','B',
        'A','B','E','9','9','9','9','}','\0'
    };
    u32 i;
    for (i = 0; i < sizeof(bait); i++) p[i] = bait[i];
    for (; i < 4096u; i++) p[i] = (u8)(0xC3u ^ (i & 0xFF));

    pg->addr = base;
    return 1;
#else
    (void)pg;
    return 0;
#endif
}

ANTIDEBUG_INLINE b32 ad_page_guard_arm(ad_page_guard_t* pg) {
#ifdef _MSC_VER
    if (!pg || !pg->addr) return 0;
    static u16 s_prot_ssn = AD_SSN_UNRESOLVED;
    AD_RESOLVE_SSN_ENC(s_prot_ssn, NtProtectVirtualMemory, 23);
    if (s_prot_ssn == AD_SSN_FAILED) return 0;

    void* base = pg->addr;
    u64 size = 4096;
    u32 old_prot = 0;
    ad_ntstatus_t st = (ad_ntstatus_t)(s64)AD_SYSCALL5(
        s_prot_ssn,
        AD_CURRENT_PROCESS,
        &base,
        &size,
        (u64)(AD_PG_PAGE_READWRITE | AD_PG_PAGE_GUARD),
        &old_prot
    );
    if (!AD_NT_SUCCESS(st)) return 0;
    pg->armed = 1;
    return 1;
#else
    (void)pg;
    return 0;
#endif
}

// Check whether the guard was tripped. We do this by re-querying the
// protection: if PAGE_GUARD bit is gone but armed=1, someone touched it.
ANTIDEBUG_INLINE b32 ad_page_guard_check(ad_page_guard_t* pg) {
#ifdef _MSC_VER
    if (!pg || !pg->addr || !pg->armed) return 0;

    static u16 s_qvm_ssn = AD_SSN_UNRESOLVED;
    AD_RESOLVE_SSN_ENC(s_qvm_ssn, NtQueryVirtualMemory, 21);
    if (s_qvm_ssn == AD_SSN_FAILED) return 0;

    // MEMORY_BASIC_INFORMATION layout (48 bytes)
    struct {
        void* BaseAddress;
        void* AllocationBase;
        u32   AllocationProtect;
        u32   _pad0;
        u64   RegionSize;
        u32   State;
        u32   Protect;
        u32   Type;
        u32   _pad1;
    } mbi;
    AD_ZERO_BUF(&mbi, sizeof(mbi));
    u64 ret_len = 0;

    ad_ntstatus_t st = (ad_ntstatus_t)(s64)AD_SYSCALL6(
        s_qvm_ssn,
        AD_CURRENT_PROCESS,
        (u64)(uintptr_t)pg->addr,
        (u64)0,  // MemoryBasicInformation
        &mbi,
        (u64)sizeof(mbi),
        &ret_len
    );
    if (!AD_NT_SUCCESS(st)) return 0;

    // If PAGE_GUARD bit is gone → someone (or we) touched it.
    // We never touch it from our code → it must be a debugger.
    b32 guard_present = (b32)((mbi.Protect & AD_PG_PAGE_GUARD) != 0u);
    if (!guard_present) {
        pg->armed = 0;
        return 1;
    }
    return 0;
#else
    (void)pg;
    return 0;
#endif
}

#endif // ANTIDEBUG_PAGE_GUARD_TRAP_H
