// ===== file: antidebug/checks/debug/process_scan.h =====
//
// Detect known debugger executables among ALL running processes.
//
// Extends ad_parent_is_debugger() (parent_process.h) which only checks the
// direct parent PID. This check scans every process via
// NtQuerySystemInformation(SystemProcessInformation=5) and compares
// image names against the same debugger blacklist.
//
// Even if a reverser re-parents the process (spoofs PPID), their debugger
// exe is still running and visible in the process list.
//
// Debugger list (case-insensitive suffix match against ImageName):
//   x64dbg, x32dbg, windbg, windbgx, ollydbg, ida, ida64, idag, idag64,
//   idaw64, dnspy, radare2, cutter, immunity debugger, cheatengine-x86_64
//
#ifndef ANTIDEBUG_PROCESS_SCAN_H
#define ANTIDEBUG_PROCESS_SCAN_H

#include "../../core/types.h"
#include "../../core/macros.h"
#include "../../core/syscall_bridge.h"
#include "../../core/string_encrypt.h"

#if defined(_MSC_VER)

// ---------------------------------------------------------------------------
// Minimal SYSTEM_PROCESS_INFORMATION layout (x64)
// ---------------------------------------------------------------------------
// The struct is a linked list; each entry's NextEntryOffset gives the byte
// offset to the next one from the start of the current entry (0 = last).
typedef struct {
    u32  NextEntryOffset;       // +0
    u32  NumberOfThreads;       // +4
    u8   _timing[0x30];         // +8  (timing/counters, not needed)
    // +0x038: UNICODE_STRING ImageName
    u16  ImgLen;                // +0x038  bytes (not chars)
    u16  ImgMaxLen;             // +0x03A
    u32  _img_pad;              // +0x03C
    u16* ImgBuffer;             // +0x040
    // +0x048: BasePriority (s32) ...
    u8   _rest[8];              // +0x048
    void* UniqueProcessId;      // +0x050
} AD_PROC_INFO;

// ---------------------------------------------------------------------------
// Case-insensitive wide-char suffix comparison (no CRT)
// Returns 1 if [path+path_n-suf_n .. path+path_n) matches suf[0..suf_n)
// (replicates ad_wstr_ends_ci from parent_process.h without duplicating it
//  by checking at call site; declared static so each TU gets its own copy)
// ---------------------------------------------------------------------------
#ifndef AD_PROC_SCAN_HELPERS
#define AD_PROC_SCAN_HELPERS
static __forceinline b32 ad_ps_wlower_eq(u16 a, u16 b) {
    if (a >= 'A' && a <= 'Z') a = (u16)(a + 32u);
    if (b >= 'A' && b <= 'Z') b = (u16)(b + 32u);
    return (b32)(a == b);
}
static __forceinline b32 ad_ps_ends_ci(
    const u16* path, u32 path_n,
    const u16* suf,  u32 suf_n)
{
    if (suf_n == 0u || path_n < suf_n) return 0;
    u32 off = path_n - suf_n;
    u32 i;
    for (i = 0u; i < suf_n; i++) {
        if (!ad_ps_wlower_eq(path[off + i], suf[i])) return 0;
    }
    return 1;
}
#endif // AD_PROC_SCAN_HELPERS

ANTIDEBUG_INLINE b32 ad_process_scan(void) {
    static u16 s_ssn_qsi   = AD_SSN_UNRESOLVED; // NtQuerySystemInformation
    static u16 s_ssn_alloc = AD_SSN_UNRESOLVED;
    static u16 s_ssn_free  = AD_SSN_UNRESOLVED;

    AD_RESOLVE_SSN_ENC(s_ssn_qsi,   NtQuerySystemInformation, 25);
    AD_RESOLVE_SSN_ENC(s_ssn_alloc, NtAllocateVirtualMemory,  24);
    AD_RESOLVE_SSN_ENC(s_ssn_free,  NtFreeVirtualMemory,      20);

    if (s_ssn_qsi   == AD_SSN_FAILED) return 0;
    if (s_ssn_alloc == AD_SSN_FAILED) return 0;
    if (s_ssn_free  == AD_SSN_FAILED) return 0;

    // ── Known debugger suffixes (no .exe, case-insensitive) ──────────────
    static const u16 dbg_x64dbg[]   = {'x','6','4','d','b','g','.','e','x','e'};
    static const u16 dbg_x32dbg[]   = {'x','3','2','d','b','g','.','e','x','e'};
    static const u16 dbg_windbg[]   = {'w','i','n','d','b','g','.','e','x','e'};
    static const u16 dbg_windbgx[]  = {'w','i','n','d','b','g','x','.','e','x','e'};
    static const u16 dbg_olly[]     = {'o','l','l','y','d','b','g','.','e','x','e'};
    static const u16 dbg_ida[]      = {'i','d','a','.','e','x','e'};
    static const u16 dbg_ida64[]    = {'i','d','a','6','4','.','e','x','e'};
    static const u16 dbg_idag[]     = {'i','d','a','g','.','e','x','e'};
    static const u16 dbg_idag64[]   = {'i','d','a','g','6','4','.','e','x','e'};
    static const u16 dbg_idaw64[]   = {'i','d','a','w','6','4','.','e','x','e'};
    static const u16 dbg_dnspy[]    = {'d','n','s','p','y','.','e','x','e'};
    static const u16 dbg_radare[]   = {'r','a','d','a','r','e','2','.','e','x','e'};
    static const u16 dbg_cutter[]   = {'c','u','t','t','e','r','.','e','x','e'};
    static const u16 dbg_ce[]       = {'c','h','e','a','t','e','n','g','i','n','e',
                                       '-','x','8','6','_','6','4','.','e','x','e'};

    // ---- Memory dumpers / DMA tools / kernel-driver loaders ------------
    static const u16 dbg_ksdumper[]    = {'k','s','d','u','m','p','e','r','.','e','x','e'};
    static const u16 dbg_ksdumpercli[] = {'k','s','d','u','m','p','e','r','c','l','i','e','n','t','.','e','x','e'};
    static const u16 dbg_pcileech[]    = {'p','c','i','l','e','e','c','h','.','e','x','e'};
    static const u16 dbg_memprocfs[]   = {'m','e','m','p','r','o','c','f','s','.','e','x','e'};
    static const u16 dbg_kdmapper[]    = {'k','d','m','a','p','p','e','r','.','e','x','e'};
    static const u16 dbg_capcom[]      = {'c','a','p','c','o','m','.','e','x','e'};
    static const u16 dbg_debugview[]   = {'d','b','g','v','i','e','w','.','e','x','e'};
    static const u16 dbg_procmon[]     = {'p','r','o','c','m','o','n','6','4','.','e','x','e'};
    static const u16 dbg_procexp[]     = {'p','r','o','c','e','x','p','6','4','.','e','x','e'};
    static const u16 dbg_petools[]     = {'p','e','t','o','o','l','s','.','e','x','e'};
    static const u16 dbg_scylla[]      = {'s','c','y','l','l','a','.','e','x','e'};
    static const u16 dbg_scyllahide[]  = {'s','c','y','l','l','a','h','i','d','e','.','e','x','e'};

    typedef struct { const u16* s; u32 n; } entry_t;
    static const entry_t dbglist[] = {
        // Debuggers
        { dbg_x64dbg,  10u }, { dbg_x32dbg,  10u }, { dbg_windbg,   9u },
        { dbg_windbgx, 11u }, { dbg_olly,    10u }, { dbg_ida,       7u },
        { dbg_ida64,    9u }, { dbg_idag,     9u }, { dbg_idag64,   11u },
        { dbg_idaw64,  11u }, { dbg_dnspy,   10u }, { dbg_radare,   12u },
        { dbg_cutter,  10u }, { dbg_ce,      24u },
        // Memory dumpers / DMA tools / kernel loaders / live PE editors
        { dbg_ksdumper,    12u }, { dbg_ksdumpercli, 18u },
        { dbg_pcileech,    12u }, { dbg_memprocfs,   13u },
        { dbg_kdmapper,    12u }, { dbg_capcom,       10u },
        { dbg_debugview,   11u }, { dbg_procmon,      13u },
        { dbg_procexp,     13u }, { dbg_petools,      11u },
        { dbg_scylla,      10u }, { dbg_scyllahide,   14u },
    };
    static const u32 dbglist_count = 26u;

    // ── Allocate buffer for process list ─────────────────────────────────
    void* buf       = (void*)0;
    u64   buf_size  = 0x80000ULL;   // 512 KB — enough for most systems
    u32   retries   = 0u;
    b32   ok        = 0;
    ad_ntstatus_t st;

    while (retries < 4u) {
        void* tmp   = (void*)0;
        u64   tmp_sz = buf_size;
        st = AD_SYSCALL6(s_ssn_alloc,
            AD_CURRENT_PROCESS, &tmp, (u64)0, &tmp_sz,
            (u64)(0x1000UL | 0x2000UL), (u64)0x04UL);
        if (!AD_NT_SUCCESS(st)) return 0;
        buf = tmp;

        u32 needed = 0u;
        st = AD_SYSCALL4(s_ssn_qsi,
            (u64)5,   // SystemProcessInformation
            buf, (u64)buf_size, &needed);

        if (AD_NT_SUCCESS(st)) { ok = 1; break; }

        void* fb = buf; u64 fs = 0ULL;
        AD_SYSCALL4(s_ssn_free, AD_CURRENT_PROCESS, &fb, &fs, (u64)0x8000UL);
        buf = (void*)0;

        if ((u32)st == 0xC0000004UL) {  // STATUS_INFO_LENGTH_MISMATCH
            buf_size = (needed > 0u) ? ((u64)needed + 0x10000ULL) : (buf_size * 2ULL);
        } else { break; }
        retries++;
    }

    if (!ok || !buf) return 0;

    // ── Walk process list ─────────────────────────────────────────────────
    b32 found = 0;
    u32 our_pid = (u32)(u64)__readgsqword(0x040);
    u8* ptr = (u8*)buf;

    u32 guard = 0u;
    while (guard < 1024u) {
        guard++;
        const AD_PROC_INFO* p = (const AD_PROC_INFO*)ptr;

        u32  n_chars = (u32)(p->ImgLen / 2u);
        const u16* img = p->ImgBuffer;

        if (img && n_chars > 0u) {
            u32 pid = (u32)(u64)p->UniqueProcessId;
            if (pid != our_pid && pid != 0u && pid != 4u) {
                u32 d;
                for (d = 0u; d < dbglist_count && !found; d++) {
                    if (ad_ps_ends_ci(img, n_chars, dbglist[d].s, dbglist[d].n)) {
                        found = 1;
                    }
                }
            }
        }

        if (p->NextEntryOffset == 0u) break;
        ptr += p->NextEntryOffset;
    }

    // ── Free buffer ───────────────────────────────────────────────────────
    {
        void* fb = buf; u64 fs = 0ULL;
        AD_SYSCALL4(s_ssn_free, AD_CURRENT_PROCESS, &fb, &fs, (u64)0x8000UL);
    }

    return found;
}

#else
ANTIDEBUG_INLINE b32 ad_process_scan(void) { return 0; }
#endif // _MSC_VER

#endif // ANTIDEBUG_PROCESS_SCAN_H