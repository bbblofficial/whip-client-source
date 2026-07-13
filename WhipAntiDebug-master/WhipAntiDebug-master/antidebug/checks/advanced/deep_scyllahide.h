// ===== file: antidebug/checks/advanced/deep_scyllahide.h =====
//
// Deep ScyllaHide detection — second-order behavioral analysis that
// catches ScyllaHide even when first-order checks (stub hooks, ICB)
// are somehow bypassed or disabled.
//
// These checks exploit the SEMANTIC SIDE EFFECTS of ScyllaHide's hooks
// rather than looking at the hooks themselves.
//
#ifndef ANTIDEBUG_DEEP_SCYLLAHIDE_H
#define ANTIDEBUG_DEEP_SCYLLAHIDE_H

#include "../../core/types.h"
#include "../../core/macros.h"
#include "../../core/syscall_bridge.h"
#include "../../core/string_encrypt.h"
#include "../../stack/moonwalk.h"
#include "../runtime/write_watch.h"

#if defined(_MSC_VER)

// =========================================================================
// 1. DebugObject handle count divergence
// =========================================================================
//
// ScyllaHide hooks NtQuerySystemInformation(SystemExtendedHandleInformation)
// to REMOVE handles whose ObjectTypeIndex matches DebugObject. Via direct
// syscall we see the real handle count; via hooked path, DebugObject
// handles are filtered out.
//
// Instead of parsing the full handle table (huge), we use a simpler
// approach: NtQueryInformationProcess(ProcessDebugObjectHandle) via
// HOOKED path should return STATUS_PORT_NOT_SET. If the EXISTING
// ad_sh_debug_object_divergence already covers this, this check adds
// a different angle: count TOTAL handles via both paths.
// =========================================================================

// SystemHandleInformation class
#define AD_SYSTEM_HANDLE_INFO           16u
#define AD_SYSTEM_EXTENDED_HANDLE_INFO  64u

ANTIDEBUG_INLINE b32 ad_dsh_handle_count_divergence(void) {
    static u16 s_ssn_qsi = AD_SSN_UNRESOLVED;
    AD_RESOLVE_SSN_ENC(s_ssn_qsi, NtQuerySystemInformation, 25);
    if (s_ssn_qsi == AD_SSN_FAILED) return 0;

    void* ntdll = ad_ntdll_base();
    if (!ntdll) return 0;

    typedef ad_ntstatus_t (*FN_NtQSI)(u32, void*, u32, u32*);
    FN_NtQSI fn_qsi = (FN_NtQSI)ad_pe_find_export(
        (const u8*)ntdll, "NtQuerySystemInformation");
    if (!fn_qsi) return 0;

    // Query required buffer size via BOTH paths
    u32 needed_direct = 0u;
    u32 needed_hooked = 0u;

    // Direct syscall
    AD_SYSCALL4(s_ssn_qsi,
        (u64)AD_SYSTEM_EXTENDED_HANDLE_INFO,
        (u64)0,
        (u64)0,
        &needed_direct);

    // Hooked path
    fn_qsi(AD_SYSTEM_EXTENDED_HANDLE_INFO, (void*)0, 0u, &needed_hooked);

    // ScyllaHide removes entries → hooked size < direct size
    // Allow 10% tolerance for timing differences
    if (needed_direct > 0u && needed_hooked > 0u) {
        if (needed_direct > needed_hooked + (needed_hooked / 10u))
            return 1;
    }

    return 0;
}

// =========================================================================
// 2. Injected thread detection
// =========================================================================
//
// ScyllaHide injects HookLibraryx64.dll via CreateRemoteThread or
// NtCreateThreadEx. The injected thread's start address points into
// the hook DLL which resides in MEM_PRIVATE memory. We enumerate all
// threads and check if any start address is in MEM_PRIVATE+EXECUTE.
//
// Clean processes only have threads starting in known modules (ntdll,
// kernel32, our exe).
// =========================================================================
ANTIDEBUG_INLINE u32 ad_dsh_injected_thread_count(void) {
    static u16 s_ssn_qsi = AD_SSN_UNRESOLVED;
    AD_RESOLVE_SSN_ENC(s_ssn_qsi, NtQuerySystemInformation, 25);
    if (s_ssn_qsi == AD_SSN_FAILED) return 0u;

    // Get our PID
    static u16 s_ssn_qip = AD_SSN_UNRESOLVED;
    AD_RESOLVE_SSN_ENC(s_ssn_qip, NtQueryInformationProcess, 26);
    if (s_ssn_qip == AD_SSN_FAILED) return 0u;

    AD_PROCESS_BASIC_INFO pbi;
    AD_ZERO_BUF(&pbi, sizeof(pbi));
    u32 ret_len = 0u;
    AD_SYSCALL5(s_ssn_qip, AD_CURRENT_PROCESS, (u64)0, &pbi,
                (u64)sizeof(pbi), &ret_len);
    u64 our_pid = (u64)(u64)pbi.UniqueProcessId;
    if (our_pid == 0ULL) return 0u;

    // Get ntdll and exe base for comparison
    void* ntdll_base = ad_ntdll_base();
    volatile u8* peb = (volatile u8*)(u64)__readgsqword(0x60);
    void* exe_base = peb ? *(void**)(peb + 0x10) : (void*)0;  // PEB+0x10 = ImageBaseAddress

    // Query thread list via NtQuerySystemInformation(SystemProcessInformation=5)
    // Use a static buffer to avoid stack overflow
    enum { BUF_SIZE = 65536 };
    static u8 s_buf[BUF_SIZE];
    AD_ZERO_BUF(s_buf, sizeof(s_buf));
    u32 needed = 0u;

    ad_ntstatus_t st = AD_SYSCALL4(s_ssn_qsi,
        (u64)5u,  // SystemProcessInformation
        s_buf,
        (u64)BUF_SIZE,
        &needed);
    if (!AD_NT_SUCCESS(st)) return 0u;

    // Walk process entries to find ours
    u8* entry = s_buf;
    u32 guard = 0u;
    u32 suspicious_threads = 0u;

    while (entry && guard < 512u) {
        guard++;
        u32 next_offset = *(u32*)entry;
        u32 num_threads = *(u32*)(entry + 4);
        void* pid = *(void**)(entry + 0x50);

        if ((u64)(u64)pid == our_pid && num_threads > 0u) {
            // Found our process. Thread entries start at entry + 0xF8 (varies)
            // SYSTEM_THREAD_INFORMATION is 80 bytes on x64
            // StartAddress at offset +0x28 within each thread entry
            u8* thread_base = entry + 0xF8;  // after SYSTEM_PROCESS_INFORMATION
            u32 ti;
            for (ti = 0u; ti < num_threads && ti < 64u; ti++) {
                u8* thread_entry = thread_base + (ti * 80u);
                void* start_addr = *(void**)(thread_entry + 0x28);

                if (!start_addr) continue;

                // Check if start address is in a known module
                u64 addr = (u64)(u64)start_addr;
                b32 in_known = 0;

                // In our exe? (roughly: base to base + 1MB)
                if (exe_base) {
                    u64 exe = (u64)(u64)exe_base;
                    if (addr >= exe && addr < exe + 0x100000ULL) in_known = 1;
                }
                // In ntdll? (roughly: base to base + 2MB)
                if (ntdll_base) {
                    u64 nt = (u64)(u64)ntdll_base;
                    if (addr >= nt && addr < nt + 0x300000ULL) in_known = 1;
                }
                // In kernel32? Check via PEB LDR
                // (simplified: any address in the high range 0x7FFA-0x7FFF is likely system DLL)
                if (addr >= 0x7FF800000000ULL) in_known = 1;

                if (!in_known) suspicious_threads++;
            }
            break;
        }

        if (next_offset == 0u) break;
        entry += next_offset;
    }

    AD_ZERO_BUF(s_buf, sizeof(s_buf));
    return suspicious_threads;
}

// =========================================================================
// 3. DbgUiRemoteBreakin restoration check
// =========================================================================
//
// The anti_breakin module patches DbgUiRemoteBreakin with a trampoline
// that calls NtTerminateProcess. ScyllaHide may RESTORE the original
// bytes after our patch, allowing remote attach.
//
// We re-read DbgUiRemoteBreakin and check if our trampoline is still
// there. If the bytes changed since install → ScyllaHide restored them.
// =========================================================================
ANTIDEBUG_INLINE b32 ad_dsh_breakin_restored(void) {
    void* ntdll = ad_ntdll_base();
    if (!ntdll) return 0;

    const u8* breakin = (const u8*)ad_pe_find_export(
        (const u8*)ntdll, "DbgUiRemoteBreakin");
    if (!breakin) return 0;

    // Our anti_breakin_install writes 0xCC (INT3) or a JMP at the entry.
    // If ScyllaHide restored the original bytes, we'll see the normal
    // prologue: 65 48 8B 04 25 (mov rax, gs:[...]) or sub rsp, XX
    volatile u8 b0 = breakin[0];

    // Normal (unpatched): 0x65 (gs: prefix) or 0x48 (rex.W)
    // Our patch: 0xCC (int3) or 0xE9 (jmp) or 0xC3 (ret)
    // If we see normal bytes AND anti_breakin_install was called → restored
    if (b0 == 0x65u || b0 == 0x48u || b0 == 0x40u) {
        // Looks like original bytes — someone restored our patch
        return 1;
    }

    return 0;
}

// =========================================================================
// 4. KUSER_SHARED_DATA timing sanity
// =========================================================================
//
// KUSER_SHARED_DATA.SystemTime and .TickCount are updated by the kernel
// and cannot be hooked from usermode. ScyllaHide freezes the HOOKED
// NtQuerySystemTime/GetTickCount but CANNOT freeze KUSER_SHARED_DATA.
//
// If hooked time is frozen but KUSD time advances → ScyllaHide.
// This check reads KUSD twice with a busy-wait between and verifies
// time actually advances (sanity check that we're not in a sandbox
// that freezes KUSD too).
// =========================================================================
#define AD_KUSD_SYSTIME_PTR ((volatile u32*)(0x7FFE0000ULL + 0x14u))

ANTIDEBUG_INLINE b32 ad_dsh_kusd_time_advances(void) {
    u32 t0 = *AD_KUSD_SYSTIME_PTR;

    // Busy-wait ~1ms worth of iterations
    volatile u32 dummy = 0u;
    u32 i;
    for (i = 0u; i < 100000u; i++) {
        dummy += i;
    }
    AD_UNUSED(dummy);

    u32 t1 = *AD_KUSD_SYSTIME_PTR;

    // If time didn't advance at all after busy-wait → suspicious
    // BUT: the low 32 bits of SystemTime (100ns units) may not change
    // in such a short window on some systems. Only flag if delta is
    // implausible (went backwards or stayed same after long wait).
    // Disabled: too many false positives from timer resolution.
    AD_UNUSED(t0);
    AD_UNUSED(t1);
    return 0;
}

// =========================================================================
// 5. Foreign process handle to us
// =========================================================================
//
// When a debugger attaches, it opens handles to our process with
// PROCESS_ALL_ACCESS or similar rights. ScyllaHide filters DebugObject
// handles but may NOT filter regular Process handles from the debugger.
//
// We enumerate handles via direct syscall and count Process handles
// to our PID from foreign PIDs.
// =========================================================================
ANTIDEBUG_INLINE u32 ad_dsh_foreign_process_handles(void) {
    static u16 s_ssn_qsi = AD_SSN_UNRESOLVED;
    AD_RESOLVE_SSN_ENC(s_ssn_qsi, NtQuerySystemInformation, 25);
    if (s_ssn_qsi == AD_SSN_FAILED) return 0u;

    // Get our PID
    static u16 s_ssn_qip = AD_SSN_UNRESOLVED;
    AD_RESOLVE_SSN_ENC(s_ssn_qip, NtQueryInformationProcess, 26);
    if (s_ssn_qip == AD_SSN_FAILED) return 0u;

    AD_PROCESS_BASIC_INFO pbi;
    AD_ZERO_BUF(&pbi, sizeof(pbi));
    u32 ret_len = 0u;
    AD_SYSCALL5(s_ssn_qip, AD_CURRENT_PROCESS, (u64)0, &pbi,
                (u64)sizeof(pbi), &ret_len);
    u64 our_pid = (u64)(u64)pbi.UniqueProcessId;
    if (our_pid == 0ULL) return 0u;

    // Query SystemHandleInformation (class 16)
    // SYSTEM_HANDLE_INFORMATION has:
    //   +0x00: NumberOfHandles (ULONG)
    //   +0x08: Handles[] array, each entry 32 bytes on x64
    // Entry layout (SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX):
    //   +0x00: Object (void*)
    //   +0x08: UniqueProcessId (ULONG_PTR)
    //   +0x10: HandleValue (ULONG_PTR)
    //   +0x18: GrantedAccess (ULONG)
    //   +0x1C: CreatorBackTraceIndex (USHORT)
    //   +0x1E: ObjectTypeIndex (USHORT)
    //   +0x20: HandleAttributes (ULONG)
    //   +0x24: Reserved (ULONG)

    // We need a LARGE buffer for the full handle table
    // Use 256KB static buffer
    enum { HANDLE_BUF = 262144 };
    static u8 s_hbuf[HANDLE_BUF];
    AD_ZERO_BUF(s_hbuf, sizeof(s_hbuf));
    u32 needed = 0u;

    ad_ntstatus_t st = AD_SYSCALL4(s_ssn_qsi,
        (u64)AD_SYSTEM_EXTENDED_HANDLE_INFO,
        s_hbuf,
        (u64)HANDLE_BUF,
        &needed);

    if (!AD_NT_SUCCESS(st)) {
        AD_ZERO_BUF(s_hbuf, sizeof(s_hbuf));
        return 0u;
    }

    // Parse handle table
    u64 num_handles = *(u64*)s_hbuf;  // NumberOfHandles (ULONG_PTR)
    u8* entries = s_hbuf + 16;         // Skip header (varies, usually 16 bytes)

    u32 foreign_count = 0u;
    u64 hi;
    u64 max_entries = num_handles;
    if (max_entries > 8000ULL) max_entries = 8000ULL;  // cap for safety

    for (hi = 0ULL; hi < max_entries; hi++) {
        u8* e = entries + (hi * 40u);  // each entry ~40 bytes
        if (e + 40u > s_hbuf + HANDLE_BUF) break;

        u64 handle_pid = *(u64*)(e + 8);
        u32 access = *(u32*)(e + 0x18);

        // Foreign PID has a handle with high access to our process
        // (GrantedAccess includes PROCESS_VM_READ, PROCESS_VM_WRITE, etc.)
        if (handle_pid != our_pid && handle_pid != 0ULL && handle_pid != 4ULL) {
            // Check if this handle's Object matches our process
            // Simplified: just count high-access handles from foreign PIDs
            // that aren't System (PID 4) or Idle (PID 0)
            if (access & 0x1FFFFFu) {  // any significant access rights
                // We can't easily tell if this handle is to US, but
                // a large number of high-access foreign handles is suspicious
                foreign_count++;
            }
        }
    }

    AD_ZERO_BUF(s_hbuf, sizeof(s_hbuf));

    // On a clean system, foreign_count varies widely (csrss, lsass, svchost)
    // Under a debugger: significantly more from debugger process
    // Use high baseline to avoid false positives
    if (foreign_count > 50u) return foreign_count - 50u;
    return 0u;
}

// =========================================================================
// DEEP SCYLLAHIDE MASTER
// =========================================================================
ANTIDEBUG_INLINE u32 ad_deep_scyllahide_master(void) {
    u32 score = 0u;

    { b32 v = 0; __try { v = ad_dsh_handle_count_divergence(); } __except(1){}  if (v) score += 10u; }
    // breakin_restored: only valid if ad_anti_breakin_install succeeded.
    // If the install was a no-op (e.g. NtProtectVirtualMemory failed),
    // the bytes are still "original" and this check false-positives.
    // Disabled for now — the ad_anti_breakin_verify() in extra_master covers this.
    // { b32 v = 0; __try { v = ad_dsh_breakin_restored(); } __except(1){}  if (v) score += 8u; }
    { u32 t = 0; __try { t = ad_dsh_injected_thread_count();   } __except(1){}  score += t * 6u; }
    { u32 h = 0; __try { h = ad_dsh_foreign_process_handles(); } __except(1){}  score += h * 2u; }

    return score;
}

#else  // Non-MSVC stubs

ANTIDEBUG_INLINE b32 ad_dsh_handle_count_divergence(void) { return 0; }
ANTIDEBUG_INLINE u32 ad_dsh_injected_thread_count(void)   { return 0u; }
ANTIDEBUG_INLINE b32 ad_dsh_breakin_restored(void)        { return 0; }
ANTIDEBUG_INLINE b32 ad_dsh_kusd_time_advances(void)      { return 0; }
ANTIDEBUG_INLINE u32 ad_dsh_foreign_process_handles(void)  { return 0u; }
ANTIDEBUG_INLINE u32 ad_deep_scyllahide_master(void)       { return 0u; }

#endif // _MSC_VER

#endif // ANTIDEBUG_DEEP_SCYLLAHIDE_H
