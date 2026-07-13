// ===== file: antidebug/checks/advanced/working_set_probe.h =====
//
// Working Set Probe — kernel-metadata Copy-on-Write detector.
//
// Idea
// ----
// When ntdll is loaded, every .text page is section-mapped from the on-disk
// image. The kernel marks each PFN entry with two flags exposed via
// NtQueryVirtualMemory(MemoryWorkingSetExInformation):
//   - Shared          (bit 15): the page is currently shared with the section
//   - SharedOriginal  (bit 30): the page has NEVER been forked
//
// The instant a debugger plants a 0xCC, ScyllaHide writes an FF25 trampoline,
// or any tool patches a stub, the page is forked into a private CoW copy:
// SharedOriginal flips to 0 and stays 0 forever — the kernel cannot un-fork
// a page. We detect this without ever reading the bytes themselves, so the
// detection is invisible to read-redirect hooks (the same trick that
// defeats ad_ghost_breakpoint_check on some hide layers).
//
// We sample 8 page-aligned probes spread across ntdll .text. ntdll is
// system-mapped and never relocates, so on a clean system every probe
// returns Valid=1, Shared=1, SharedOriginal=1. Any single divergence is
// a hard positive.
//
#ifndef ANTIDEBUG_WORKING_SET_PROBE_H
#define ANTIDEBUG_WORKING_SET_PROBE_H

#include "../../core/types.h"
#include "../../core/macros.h"
#include "../../core/syscall_bridge.h"
#include "../../core/string_encrypt.h"

// MEMORY_INFORMATION_CLASS::MemoryWorkingSetExInformation
#define AD_MEMORY_WORKING_SET_EX_INFORMATION    4

// MEMORY_WORKING_SET_EX_BLOCK bit masks (x64 ULONG_PTR layout)
#define AD_WSEX_VALID_BIT          (1ULL << 0)
#define AD_WSEX_SHARED_BIT         (1ULL << 15)
#define AD_WSEX_SHAREDORIGINAL_BIT (1ULL << 30)

typedef struct {
    void* VirtualAddress;
    u64   VirtualAttributes;  // union { block; ULONG_PTR Long; }
} ad_wsex_info_t;

// Returns 1 if any sampled ntdll .text page has been Copy-on-Write forked
// (Valid=1 but SharedOriginal=0), indicating an in-memory patch.
ANTIDEBUG_INLINE b32 ad_working_set_probe_check(void) {
#ifdef _MSC_VER
    static u16 s_qvm_ssn = AD_SSN_UNRESOLVED;
    AD_RESOLVE_SSN_ENC(s_qvm_ssn, NtQueryVirtualMemory, 21);
    if (s_qvm_ssn == AD_SSN_FAILED) return 0;

    // ----- Locate ntdll base via PEB.Ldr (same walk as ghost_breakpoints) ---
    u8* peb = (u8*)__readgsqword(0x60);
    if (!peb) return 0;
    u8* ldr = *(u8**)(peb + 0x18);
    if (!ldr) return 0;
    u8* head  = *(u8**)(ldr + 0x10);   // InLoadOrderModuleList head
    if (!head) return 0;
    u8* entry = *(u8**)(head);          // first module (exe)
    if (!entry) return 0;
    entry = *(u8**)(entry);             // second module (ntdll)
    if (!entry) return 0;
    u8* ntdll_base = *(u8**)(entry + 0x30);
    if (!ntdll_base) return 0;
    if (*(u16*)ntdll_base != 0x5A4D) return 0;  // 'MZ'

    // ----- Find .text section ----------------------------------------------
    u32 pe_off = *(u32*)(ntdll_base + 0x3C);
    u8* pe = ntdll_base + pe_off;
    u16 n_sections = *(u16*)(pe + 6);
    u16 opt_size   = *(u16*)(pe + 20);
    u8* sections   = pe + 24 + opt_size;

    u8* text_addr = 0;
    u32 text_size = 0;
    u32 si;
    for (si = 0; si < n_sections; si++) {
        u8* sec = sections + si * 40;
        if (sec[0] == '.' && sec[1] == 't' && sec[2] == 'e' &&
            sec[3] == 'x' && sec[4] == 't') {
            text_size = *(u32*)(sec + 8);
            text_addr = ntdll_base + *(u32*)(sec + 12);
            break;
        }
    }
    if (!text_addr || text_size < 0x2000u) return 0;

    // ----- Build 8 page-aligned probes spread across .text ------------------
    enum { AD_WS_PROBE_COUNT = 8 };
    ad_wsex_info_t probes[AD_WS_PROBE_COUNT];
    u32 stride = (text_size / AD_WS_PROBE_COUNT) & ~0xFFFu;
    if (stride < 0x1000u) stride = 0x1000u;

    u32 i;
    for (i = 0; i < AD_WS_PROBE_COUNT; i++) {
        u64 va = (u64)(text_addr + i * stride);
        va &= ~0xFFFULL;  // page align
        // Touch the page so the kernel marks it Valid for the probe.
        volatile u8 sink = *(volatile u8*)va;
        AD_UNUSED(sink);
        probes[i].VirtualAddress    = (void*)va;
        probes[i].VirtualAttributes = 0;
    }

    // ----- One syscall fills VirtualAttributes for every probe --------------
    u64 ret_len = 0;
    ad_ntstatus_t st = (ad_ntstatus_t)(s64)AD_SYSCALL6(
        s_qvm_ssn,
        AD_CURRENT_PROCESS,
        (u64)0,                                // BaseAddress unused for class 4
        (u64)AD_MEMORY_WORKING_SET_EX_INFORMATION,
        probes,
        (u64)sizeof(probes),
        &ret_len
    );
    if (!AD_NT_SUCCESS(st)) {
        AD_ZERO_BUF(probes, sizeof(probes));
        return 0;
    }

    // ----- Inspect attributes -----------------------------------------------
    u32 divergence = 0;
    for (i = 0; i < AD_WS_PROBE_COUNT; i++) {
        u64 attr = probes[i].VirtualAttributes;
        if ((attr & AD_WSEX_VALID_BIT) == 0) continue;     // not paged in
        // ntdll .text must always be Shared & SharedOriginal on a clean box.
        if ((attr & AD_WSEX_SHAREDORIGINAL_BIT) == 0) {
            divergence++;
        }
    }

    AD_ZERO_BUF(probes, sizeof(probes));
    return (b32)(divergence > 0u);
#else
    return 0;
#endif
}

#endif // ANTIDEBUG_WORKING_SET_PROBE_H
