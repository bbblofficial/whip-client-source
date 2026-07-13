// ===== file: antidebug/checks/debug/parent_process.h =====
//
// Parent process debugger detection — improved from al-khaser ParentProcess.cpp.
//
// Three independent detection layers:
//
//   Layer 1 — Image name match:
//     Query PPID via ProcessBasicInformation, open parent with
//     PROCESS_QUERY_LIMITED_INFORMATION, read ProcessImageFileName(27),
//     compare filename suffix against extended known-debugger list.
//
//   Layer 2 — PPID creation time spoof detection:
//     A reverser can call NtCreateUserProcess with a spoofed PPID pointing to
//     explorer.exe. This is detectable: the spoofed "parent" process was born
//     BEFORE us (CreateTime < ours). If the reported parent's CreateTime >
//     our CreateTime, the PID was recycled after we started — PPID spoof.
//     Uses ProcessTimes (class 4) on both our handle and the parent handle.
//
//   Layer 3 — Dead parent check:
//     A PPID pointing to an already-terminated process (ExitTime != 0) means
//     the PID was recently recycled or the spoof target has since exited.
//     Legitimate parent processes don't terminate while children run normally.
//
//   Returns 1 if ANY of the three layers fires.
//
#ifndef ANTIDEBUG_PARENT_PROCESS_H
#define ANTIDEBUG_PARENT_PROCESS_H

#include "../../core/types.h"
#include "../../core/macros.h"
#include "../../core/syscall_bridge.h"
#include "../../core/string_encrypt.h"

// ProcessImageFileName = 27
#define AD_PROCESS_IMAGE_FILE_NAME  27UL
// ProcessTimes = 4
#define AD_PROCESS_TIMES_CLASS       4UL

// PROCESS_QUERY_LIMITED_INFORMATION — enough to get image name + times
#define AD_PROCESS_QUERY_LIMITED   0x1000UL

// Minimal KERNEL_USER_TIMES layout (4 × LARGE_INTEGER = 4 × 8 bytes)
typedef struct {
    u64 CreateTime;   // +0   (100-ns intervals since Jan 1, 1601)
    u64 ExitTime;     // +8   (0 = still running)
    u64 KernelTime;   // +16
    u64 UserTime;     // +24
} AD_KERNEL_USER_TIMES;


#if defined(_MSC_VER)

// ---------------------------------------------------------------------------
// Wide-string case-insensitive suffix comparison (no CRT, no imports).
// Returns 1 if the last suffix_len u16s of path match suffix (case-insensitive
// ASCII only — sufficient for Windows executable names).
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE b32 ad_wstr_ends_ci(
    const u16* path, u32 n_chars,
    const u16* suffix, u32 suffix_len)
{
    if (n_chars < suffix_len) return 0;
    const u16* p = path + (n_chars - suffix_len);
    u32 i;
    for (i = 0u; i < suffix_len; i++) {
        u16 a = p[i];
        u16 b = suffix[i];
        if (a >= (u16)'a' && a <= (u16)'z') a = (u16)(a - 0x20u);
        if (b >= (u16)'a' && b <= (u16)'z') b = (u16)(b - 0x20u);
        if (a != b) return 0;
    }
    return 1;
}

// ---------------------------------------------------------------------------
// Check: is the current process's parent a known debugger?
//
// Layer 1 — name match (extended list, case-insensitive):
//   x64dbg, x32dbg, windbg, windbgx, ollydbg, ida, ida64, idag, idag64,
//   idaw64, dnspy, radare2, cutter, immunity debugger, cheatengine-x86_64,
//   reclass64, processhacker, procexp64, apimonitor-x64, binaryninja,
//   pestudio, hollows_hunter, pe-sieve64, dbgview64
//
// Layer 2 — PPID creation time spoof:
//   parent.CreateTime > our.CreateTime → PID was recycled / PPID was forged
//
// Layer 3 — dead parent:
//   parent.ExitTime != 0 → reported parent already exited
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE b32 ad_parent_is_debugger(void) {
    static u16 s_ssn_qip   = AD_SSN_UNRESOLVED;
    static u16 s_ssn_op    = AD_SSN_UNRESOLVED;
    static u16 s_ssn_close = AD_SSN_UNRESOLVED;

    AD_RESOLVE_SSN_ENC(s_ssn_qip,   NtQueryInformationProcess, 26);
    AD_RESOLVE_SSN_ENC(s_ssn_op,    NtOpenProcess,             14);
    AD_RESOLVE_SSN_ENC(s_ssn_close, NtClose,                    8);

    if (s_ssn_qip == AD_SSN_FAILED || s_ssn_op == AD_SSN_FAILED) return 0;

    // ── Get our own creation time (Layer 2 baseline) ─────────────────────
    AD_KERNEL_USER_TIMES our_times;
    AD_ZERO_BUF(&our_times, sizeof(our_times));
    {
        u32 rlen = 0u;
        AD_SYSCALL5(s_ssn_qip, AD_CURRENT_PROCESS,
            (u64)AD_PROCESS_TIMES_CLASS,
            &our_times, (u64)sizeof(our_times), &rlen);
    }

    // ── Step 1: Get PPID via ProcessBasicInformation (class 0) ──────────
    AD_PROCESS_BASIC_INFO pbi;
    AD_ZERO_BUF(&pbi, sizeof(pbi));
    u32 ret_len = 0u;

    ad_ntstatus_t st = AD_SYSCALL5(
        s_ssn_qip, AD_CURRENT_PROCESS,
        (u64)0, &pbi, (u64)sizeof(pbi), &ret_len);
    if (!AD_NT_SUCCESS(st)) return 0;

    void* ppid = pbi.InheritedFromUniqueProcessId;
    if (!ppid) return 0;

    // ── Step 2: Open parent ──────────────────────────────────────────────
    AD_CLIENT_ID cid;
    AD_ZERO_BUF(&cid, sizeof(cid));
    cid.UniqueProcess = ppid;

    AD_OBJECT_ATTRIBUTES oa;
    AD_ZERO_BUF(&oa, sizeof(oa));
    oa.Length = (u32)sizeof(oa);

    ad_handle_t parent_handle = (ad_handle_t)0;
    st = AD_SYSCALL4(s_ssn_op,
        &parent_handle, (u64)AD_PROCESS_QUERY_LIMITED, &oa, &cid);
    if (!AD_NT_SUCCESS(st) || !parent_handle) return 0;

    // ── Layer 2 + 3: creation time and exit time checks ─────────────────
    b32 time_spoof = 0;
    {
        AD_KERNEL_USER_TIMES pt;
        AD_ZERO_BUF(&pt, sizeof(pt));
        u32 rlen = 0u;
        st = AD_SYSCALL5(s_ssn_qip, parent_handle,
            (u64)AD_PROCESS_TIMES_CLASS,
            &pt, (u64)sizeof(pt), &rlen);
        if (AD_NT_SUCCESS(st)) {
            // Layer 2: parent born AFTER us → PID was recycled / PPID forged
            if (our_times.CreateTime != 0ULL &&
                pt.CreateTime > our_times.CreateTime)
                time_spoof = 1;
            // Layer 3: parent already exited
            if (pt.ExitTime != 0ULL)
                time_spoof = 1;
        }
    }

    // ── Step 3: Get parent image path (ProcessImageFileName = 27) ───────
    u8 img_buf[528];
    AD_ZERO_BUF(img_buf, sizeof(img_buf));
    u32 img_rlen = 0u;

    st = AD_SYSCALL5(s_ssn_qip, parent_handle,
        (u64)AD_PROCESS_IMAGE_FILE_NAME,
        img_buf, (u64)sizeof(img_buf), &img_rlen);

    if (s_ssn_close != AD_SSN_FAILED)
        AD_SYSCALL1(s_ssn_close, (u64)parent_handle);

    if (time_spoof) {
        AD_ZERO_BUF(img_buf, sizeof(img_buf));
        return 1;
    }

    if (!AD_NT_SUCCESS(st)) return 0;

    u16 path_bytes = *(u16*)img_buf;
    if (path_bytes < 2u || path_bytes > 512u) return 0;

    const u16* wpath  = (const u16*)(img_buf + 16u);
    u32        nchars = (u32)(path_bytes / 2u);

    // ── Step 4: Extended debugger name list ──────────────────────────────
    // Original entries
    static const u16 dbg_x64dbg[]   = {'X','6','4','D','B','G','.','E','X','E'};
    static const u16 dbg_x32dbg[]   = {'X','3','2','D','B','G','.','E','X','E'};
    static const u16 dbg_windbg[]   = {'W','I','N','D','B','G','.','E','X','E'};
    static const u16 dbg_windbgx[]  = {'W','I','N','D','B','G','X','.','E','X','E'};
    static const u16 dbg_ollydbg[]  = {'O','L','L','Y','D','B','G','.','E','X','E'};
    static const u16 dbg_ida[]      = {'I','D','A','.','E','X','E'};
    static const u16 dbg_ida64[]    = {'I','D','A','6','4','.','E','X','E'};
    static const u16 dbg_idag[]     = {'I','D','A','G','.','E','X','E'};
    static const u16 dbg_idag64[]   = {'I','D','A','G','6','4','.','E','X','E'};
    static const u16 dbg_idaw64[]   = {'I','D','A','W','6','4','.','E','X','E'};
    static const u16 dbg_dnspy[]    = {'D','N','S','P','Y','.','E','X','E'};
    static const u16 dbg_radare2[]  = {'R','A','D','A','R','E','2','.','E','X','E'};
    static const u16 dbg_cutter[]   = {'C','U','T','T','E','R','.','E','X','E'};
    static const u16 dbg_immunity[] = {'I','M','M','U','N','I','T','Y',
                                       'D','E','B','U','G','G','E','R','.','E','X','E'};
    static const u16 dbg_cheat[]    = {'C','H','E','A','T','E','N','G','I','N','E',
                                       '-','X','8','6','_','6','4','.','E','X','E'};
    // New entries
    static const u16 dbg_reclass[]  = {'R','E','C','L','A','S','S','6','4','.','E','X','E'};
    static const u16 dbg_ph[]       = {'P','R','O','C','E','S','S','H','A','C','K','E','R',
                                       '.','E','X','E'};
    static const u16 dbg_ph3[]      = {'P','R','O','C','E','S','S','H','A','C','K','E','R',
                                       '3','.','E','X','E'};
    static const u16 dbg_procexp[]  = {'P','R','O','C','E','X','P','6','4','.','E','X','E'};
    static const u16 dbg_apimon[]   = {'A','P','I','M','O','N','I','T','O','R','-',
                                       'X','6','4','.','E','X','E'};
    static const u16 dbg_binja[]    = {'B','I','N','A','R','Y','N','I','N','J','A',
                                       '.','E','X','E'};
    static const u16 dbg_pestudio[] = {'P','E','S','T','U','D','I','O','.','E','X','E'};
    static const u16 dbg_hollow[]   = {'H','O','L','L','O','W','S','_','H','U','N','T','E','R',
                                       '.','E','X','E'};
    static const u16 dbg_pesieve[]  = {'P','E','-','S','I','E','V','E','6','4','.','E','X','E'};
    static const u16 dbg_dbgview[]  = {'D','B','G','V','I','E','W','6','4','.','E','X','E'};

#define AD_MATCH(arr) ad_wstr_ends_ci(wpath, nchars, (arr), \
                          (u32)(sizeof(arr) / sizeof(u16)))

    b32 found =
        AD_MATCH(dbg_x64dbg)   | AD_MATCH(dbg_x32dbg)   |
        AD_MATCH(dbg_windbg)   | AD_MATCH(dbg_windbgx)  |
        AD_MATCH(dbg_ollydbg)  | AD_MATCH(dbg_ida)       |
        AD_MATCH(dbg_ida64)    | AD_MATCH(dbg_idag)      |
        AD_MATCH(dbg_idag64)   | AD_MATCH(dbg_idaw64)    |
        AD_MATCH(dbg_dnspy)    | AD_MATCH(dbg_radare2)   |
        AD_MATCH(dbg_cutter)   | AD_MATCH(dbg_immunity)  |
        AD_MATCH(dbg_cheat)    | AD_MATCH(dbg_reclass)   |
        AD_MATCH(dbg_ph)       | AD_MATCH(dbg_ph3)       |
        AD_MATCH(dbg_procexp)  | AD_MATCH(dbg_apimon)    |
        AD_MATCH(dbg_binja)    | AD_MATCH(dbg_pestudio)  |
        AD_MATCH(dbg_hollow)   | AD_MATCH(dbg_pesieve)   |
        AD_MATCH(dbg_dbgview);

#undef AD_MATCH

    AD_ZERO_BUF(img_buf, sizeof(img_buf));
    return found;
}

#else  // Non-MSVC stub
ANTIDEBUG_INLINE b32 ad_parent_is_debugger(void) { return 0; }
#endif // _MSC_VER

#endif // ANTIDEBUG_PARENT_PROCESS_H