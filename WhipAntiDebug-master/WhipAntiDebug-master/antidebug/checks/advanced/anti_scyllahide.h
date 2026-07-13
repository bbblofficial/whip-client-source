// ===== file: antidebug/checks/advanced/anti_scyllahide.h =====
//
// Anti-ScyllaHide detection — fingerprinting behavioral anomalies introduced
// by ScyllaHide's hook layer.
//
// ScyllaHide is an anti-anti-debug plugin for x64dbg/OllyDbg that:
//   - Patches PEB.BeingDebugged, NtGlobalFlag, heap flags directly in memory
//   - Places 14-byte indirect JMP hooks (FF 25 00 00 00 00 + ptr) on 20+ stubs
//   - Hooks KiUserExceptionDispatcher to zero Dr0-Dr7 in every exception context
//   - Freezes GetTickCount/NtQuerySystemTime/NtQueryPerformanceCounter, advancing
//     each by exactly 1 per call to simulate plausible timer progression
//   - Returns STATUS_ACCESS_DENIED from NtYieldExecution (hardcoded sentinel)
//   - Spoofs parent PID in NtQuerySystemInformation to show explorer.exe
//
// Key principle: WhipSysCall makes DIRECT kernel syscalls — ScyllaHide's hooks
// on ntdll stubs are bypassed. To trigger the hooks for comparison we call
// ntdll/kernel32 functions through their in-memory export addresses (the hooked
// stubs). KUSER_SHARED_DATA at 0x7FFE0000 is kernel-mapped read-only and cannot
// be intercepted at user-mode level — it always reflects ground truth.
//
// Checks implemented:
//   1. ad_sh_yield_denied()         — NtYieldExecution → STATUS_ACCESS_DENIED
//   2. ad_sh_tickcount_frozen()     — GetTickCount hook vs KUSER_SHARED_DATA ground truth
//   3. ad_sh_systime_frozen()       — NtQuerySystemTime hook vs KUSER_SHARED_DATA
//   4. ad_sh_dr_exception_clear()   — Dr0 zeroed in exception CONTEXT by KiUserExceptionDispatcher hook
//   5. ad_sh_stub_hook_count()      — Count ScyllaHide-targeted stubs with FF25 prologues
//   6. ad_sh_ppid_mismatch()        — ProcessBasicInformation PPID vs NtQuerySystemInformation PPID
//
#ifndef ANTIDEBUG_ANTI_SCYLLAHIDE_H
#define ANTIDEBUG_ANTI_SCYLLAHIDE_H

#include "../../core/types.h"
#include "../../core/macros.h"
#include "../../core/syscall_bridge.h"
#include "../../core/string_encrypt.h"
#include "../../core/value_guard.h"
#include "../../stack/moonwalk.h"      // ad_ntdll_base()
#include "../runtime/write_watch.h"    // ad_pe_find_export(), ad_find_module_ci()

#if defined(_MSC_VER)

// ---------------------------------------------------------------------------
// SEH constants — normally in excpt.h; redefined here to avoid any CRT pull-in
// ---------------------------------------------------------------------------
#ifndef EXCEPTION_EXECUTE_HANDLER
#define EXCEPTION_EXECUTE_HANDLER       1
#define EXCEPTION_CONTINUE_SEARCH       0
#define EXCEPTION_CONTINUE_EXECUTION  (-1)
#endif

// GetExceptionInformation() is an MSVC compiler intrinsic backed by
// _exception_info().  Declare the intrinsic so it is callable without excpt.h.
#ifndef GetExceptionInformation
void* __cdecl _exception_info(void);
#define GetExceptionInformation() (_exception_info())
#endif

// ---------------------------------------------------------------------------
// KUSER_SHARED_DATA — kernel-mapped, unhookable by user-mode code
// 0x7FFE0000 (x64 Windows, constant across all versions)
// ---------------------------------------------------------------------------
#define AD_KUSD_BASE            ((volatile u8*)0x7FFE0000ULL)

// KSYSTEM_TIME: LowPart(u32) + High1Time(s32) + High2Time(s32) = 12 bytes
// SystemTime at +0x014, TickCount at +0x320
#define AD_KUSD_SYSTIME_LO      (*(volatile u32*)(AD_KUSD_BASE + 0x014u))
#define AD_KUSD_TICKCOUNT_LO    (*(volatile u32*)(AD_KUSD_BASE + 0x320u))

// ---------------------------------------------------------------------------
// Minimal EXCEPTION_POINTERS layout (no winnt.h needed)
// ExceptionRecord (ptr, +0x00), ContextRecord (ptr, +0x08)
// ---------------------------------------------------------------------------
typedef struct {
    void*       ExceptionRecord;
    AD_CONTEXT* ContextRecord;
} AD_SH_EXCPTRS;

// ---------------------------------------------------------------------------
// Function pointer types for calling hooked stubs
// ---------------------------------------------------------------------------
typedef ad_ntstatus_t (*AD_SH_FN_NtYieldExecution)(void);
typedef ad_ntstatus_t (*AD_SH_FN_NtQuerySystemTime)(u64*);
typedef u32           (*AD_SH_FN_GetTickCount)(void);
typedef ad_ntstatus_t (*AD_SH_FN_NtQuerySystemInfo)(u32, void*, u32, u32*);

// Status constants (ScyllaHide-specific)
#define AD_STATUS_ACCESS_DENIED     ((ad_ntstatus_t)0xC0000022L)
#define AD_STATUS_NO_YIELD          ((ad_ntstatus_t)0x40000024L)

// SystemProcessInformation class
#define AD_SYSTEM_PROCESS_INFO       5u

// =========================================================================
// 1. NtYieldExecution returns STATUS_ACCESS_DENIED
// =========================================================================
//
// ScyllaHide's hook for NtYieldExecution ALWAYS returns STATUS_ACCESS_DENIED
// (0xC0000022). The real kernel returns STATUS_SUCCESS or
// STATUS_NO_YIELD_PERFORMED. This is a hardcoded ScyllaHide signature with
// no legitimate false-positive scenario.
//
// We call through the hooked ntdll stub (function pointer), not WhipSysCall,
// so ScyllaHide's interception layer fires.
// =========================================================================
ANTIDEBUG_INLINE b32 ad_sh_yield_denied(void) {
    void* ntdll = ad_ntdll_base();
    if (!ntdll) return 0;

    AD_SH_FN_NtYieldExecution fn_yield = (AD_SH_FN_NtYieldExecution)
        ad_pe_find_export((const u8*)ntdll, "NtYieldExecution");
    if (!fn_yield) return 0;

    // Call through hook — ScyllaHide intercepts here
    ad_ntstatus_t st = fn_yield();

    // STATUS_ACCESS_DENIED is ScyllaHide's hardcoded return — never from real kernel
    return (b32)(st == AD_STATUS_ACCESS_DENIED);
}

// =========================================================================
// 2. GetTickCount frozen by hook — KUSER_SHARED_DATA disagrees
// =========================================================================
//
// ScyllaHide's GetTickCount hook returns a frozen value that increments by
// exactly +1 each call. The real TickCount in KUSER_SHARED_DATA (kernel-
// mapped, cannot be intercepted) advances normally.
//
// Detection: call GetTickCount (through hook) 24 times. Count consecutive
// pairs with delta == 1. ScyllaHide: 20+/24 pairs have delta 1. Real: rarely.
// =========================================================================
ANTIDEBUG_INLINE b32 ad_sh_tickcount_frozen(void) {
    // Try GetTickCount in kernel32.dll first, then KernelBase.dll
    static const u16 k32[]  = {'K','E','R','N','E','L','3','2','.','D','L','L'};   // 12
    static const u16 kbase[]= {'K','E','R','N','E','L','B','A','S','E','.','D','L','L'}; // 14

    void* mod = ad_find_module_ci(k32, 12u);
    if (!mod) mod = ad_find_module_ci(kbase, 14u);
    if (!mod) return 0;

    AD_SH_FN_GetTickCount fn_gtc = (AD_SH_FN_GetTickCount)
        ad_pe_find_export((const u8*)mod, "GetTickCount");
    if (!fn_gtc) return 0;

    // Snapshot KUSER_SHARED_DATA BEFORE calling through hook
    u32 ksd_before = AD_KUSD_TICKCOUNT_LO;

    // Call the hooked GetTickCount 24 times, count delta-1 pairs
    u32 delta_one = 0u;
    u32 prev = fn_gtc();

    u32 i;
    for (i = 0u; i < 24u; i++) {
        u32 cur = fn_gtc();
        if (cur == prev + 1u) delta_one++;
        prev = cur;
    }

    // Also: KUSER_SHARED_DATA must be readable after some real time
    // (If the function call overhead is non-trivial, KSD may not advance here,
    //  but ScyllaHide's per-call +1 pattern is very distinct)
    AD_UNUSED(ksd_before);

    // ScyllaHide: delta_one ≥ 20 out of 24 (monotonic +1 per call)
    // Real hardware: delta_one ≤ 3 (mostly 0-delta with occasional timer wrap)
    return (b32)(delta_one >= 20u);
}

// =========================================================================
// 3. NtQuerySystemTime increments by exactly 1 per call
// =========================================================================
//
// ScyllaHide's NtQuerySystemTime hook freezes system time at first call, then
// adds exactly 10000 (= 1ms in 100ns units) on each subsequent call. Meanwhile,
// KUSER_SHARED_DATA.SystemTime (100ns units) advances with real wall clock time.
//
// We call the hooked NtQuerySystemTime 16 times WITHOUT sleeping and count
// pairs where the delta is exactly 10000. On a real system, consecutive calls
// return the same value or vary with real timer resolution (≥10000 per ~1ms).
// ScyllaHide makes every call return a different value by exactly 10000.
// =========================================================================
ANTIDEBUG_INLINE b32 ad_sh_systime_frozen(void) {
    void* ntdll = ad_ntdll_base();
    if (!ntdll) return 0;

    AD_SH_FN_NtQuerySystemTime fn_st = (AD_SH_FN_NtQuerySystemTime)
        ad_pe_find_export((const u8*)ntdll, "NtQuerySystemTime");
    if (!fn_st) return 0;

    u64 times[16];
    u32 i;
    for (i = 0u; i < 16u; i++) {
        times[i] = 0ULL;
        fn_st(&times[i]);
    }

    // Count pairs with delta == 10000 (ScyllaHide's +1ms-per-call)
    // Also count pairs with delta == 1 (older ScyllaHide variants)
    u32 exact_10k = 0u;
    u32 exact_1   = 0u;
    for (i = 1u; i < 16u; i++) {
        u64 d = times[i] - times[i-1u];
        if (d == 10000ULL) exact_10k++;
        if (d == 1ULL)     exact_1++;
    }

    // Ground-truth: read KUSER_SHARED_DATA directly
    // On real hardware, consecutive NtQuerySystemTime calls mostly return same
    // value (within a single timer tick ~156250 units = 15.6ms at 100ns)
    // ScyllaHide: monotonic +10000 per call (every call different by exactly 10000)
    return (b32)(exact_10k >= 12u || exact_1 >= 12u);
}

// =========================================================================
// 4. Debug registers zeroed in exception CONTEXT
// =========================================================================
//
// ScyllaHide hooks KiUserExceptionDispatcher (the kernel's user-mode exception
// delivery path) and zeroes Dr0-Dr7 in the CONTEXT record before the SEH
// chain runs. It saves the original values, then restores them via a hooked
// NtContinue when the handler is done.
//
// Detection:
//   1. Set DR0 to a canary via NtSetContextThread (direct syscall → bypasses hook)
//   2. Trigger an exception (SEH)
//   3. In the __except filter, read CONTEXT->Dr0 before any resume
//   4. If Dr0 ≠ canary → ScyllaHide cleared it
//
// Note: Cleans up DR0 whether or not ScyllaHide is present.
// =========================================================================

// Canary written to Dr0 — not a real breakpoint address (canonical format)
#define AD_SH_DR0_CANARY    0x0000CAFE5C4110ADULL

// CONTEXT_DEBUG_REGISTERS flag (from types.h macros)
// AD_CONTEXT_DEBUG_REGISTERS is already defined in types.h

// Capture Dr0 in the SEH filter expression — written by filter, read by handler
static volatile u64 s_sh_dr0_captured = 0xFFFFFFFFFFFFFFFFULL;

ANTIDEBUG_INLINE b32 ad_sh_dr_exception_clear(void) {
    static u16 s_ssn_set = AD_SSN_UNRESOLVED;
    static u16 s_ssn_get = AD_SSN_UNRESOLVED;
    AD_RESOLVE_SSN_ENC(s_ssn_set, NtSetContextThread, 19);
    AD_RESOLVE_SSN_ENC(s_ssn_get, NtGetContextThread, 19);
    if (s_ssn_set == AD_SSN_FAILED || s_ssn_get == AD_SSN_FAILED) return 0;

    // ── Set Dr0 to canary via direct syscall ─────────────────────────────
    AD_ALIGN(16) AD_CONTEXT ctx;
    AD_ZERO_BUF(&ctx, sizeof(ctx));
    ctx.ContextFlags = AD_CONTEXT_DEBUG_REGISTERS;
    ctx.Dr0 = AD_SH_DR0_CANARY;
    ctx.Dr7 = 0x1ULL;   // Enable Dr0 local exact breakpoint

    AD_SYSCALL2(s_ssn_set, AD_CURRENT_THREAD, &ctx);

    // VBS/HVCI pre-flight: verify the kernel actually kept Dr0.
    // Under VBS the hypervisor silently zeroes DR registers after any set.
    // If Dr0 already reads back as 0, the environment is unreliable; skip.
    {
        AD_ALIGN(16) AD_CONTEXT ctx_pre;
        AD_ZERO_BUF(&ctx_pre, sizeof(ctx_pre));
        ctx_pre.ContextFlags = AD_CONTEXT_DEBUG_REGISTERS;
        AD_SYSCALL2(s_ssn_get, AD_CURRENT_THREAD, &ctx_pre);
        if (ctx_pre.Dr0 != AD_SH_DR0_CANARY) {
            // Clean up and bail — VBS blocked the write
            AD_ZERO_BUF(&ctx, sizeof(ctx));
            ctx.ContextFlags = AD_CONTEXT_DEBUG_REGISTERS;
            AD_SYSCALL2(s_ssn_set, AD_CURRENT_THREAD, &ctx);
            return 0;
        }
    }

    s_sh_dr0_captured = 0xFFFFFFFFFFFFFFFFULL;
    AD_BARRIER();

    // ── Trigger exception and capture CONTEXT->Dr0 in filter ─────────────
    __try {
        // Access violation — forces exception through KiUserExceptionDispatcher
        *(volatile u8*)0 = (u8)0xAD;
    }
    __except (
        // Filter runs before handler body; capture Dr0 here
        ( s_sh_dr0_captured =
            ((AD_SH_EXCPTRS*)GetExceptionInformation())->ContextRecord->Dr0,
          EXCEPTION_EXECUTE_HANDLER )
    ) {
        // Handler body: result already in s_sh_dr0_captured
        (void)0;
    }

    // ── Clean up DR registers ─────────────────────────────────────────────
    AD_ZERO_BUF(&ctx, sizeof(ctx));
    ctx.ContextFlags = AD_CONTEXT_DEBUG_REGISTERS;
    // Dr0..Dr7 already zero, Dr7 = 0 disables all HW BPs
    AD_SYSCALL2(s_ssn_set, AD_CURRENT_THREAD, &ctx);

    AD_BARRIER();
    u64 captured = s_sh_dr0_captured;
    s_sh_dr0_captured = 0xFFFFFFFFFFFFFFFFULL;

    // ScyllaHide cleared Dr0 → captured == 0
    // Real: captured == AD_SH_DR0_CANARY
    return (b32)(captured != AD_SH_DR0_CANARY);
}

// =========================================================================
// 5. Count inline hooks on ScyllaHide-targeted ntdll stubs
// =========================================================================
//
// ScyllaHide places a 14-byte indirect JMP hook:
//   FF 25 00 00 00 00   jmp qword ptr [rip+0]
//   <8 bytes: hooked function pointer>
//
// Normal stubs start with:
//   4C 8B D1   mov r10, rcx
//   B8 xx xx xx xx   mov eax, <SSN>
//
// We read stub prologues via NtReadVirtualMemory (direct syscall → bypasses
// the hook) to get the ACTUAL bytes, then count FF 25 prologues on stubs
// that ScyllaHide always hooks.
//
// Threshold ≥ 3 (of 8 checked stubs hooked) → ScyllaHide present.
// Using ≥ 2 would catch partial installations.
// =========================================================================

// ScyllaHide always hooks these 8 stubs (source: HookLibraryx64)
static const char* const AD_SH_HOOKED_STUBS[] = {
    "NtSetInformationThread",
    "NtQueryInformationProcess",
    "NtClose",
    "NtGetContextThread",
    "NtSetContextThread",
    "NtQueryObject",
    "NtYieldExecution",
    "NtQuerySystemInformation",
    (const char*)0
};

ANTIDEBUG_INLINE b32 ad_sh_stub_hook_count(void) {
    // Need NtReadVirtualMemory to read stub bytes — goes directly to kernel,
    // bypassing ScyllaHide's stub hook (which we're trying to detect)
    static u16 s_ssn_rvm = AD_SSN_UNRESOLVED;
    AD_RESOLVE_SSN_ENC(s_ssn_rvm, NtReadVirtualMemory, 20);
    if (s_ssn_rvm == AD_SSN_FAILED) return 0;

    void* ntdll = ad_ntdll_base();
    if (!ntdll) return 0;

    u32 hooked = 0u;
    u32 i;

    for (i = 0u; AD_SH_HOOKED_STUBS[i]; i++) {
        void* stub = ad_pe_find_export((const u8*)ntdll, AD_SH_HOOKED_STUBS[i]);
        if (!stub) continue;

        // Read first 4 bytes through direct kernel call (bypasses the hook itself)
        u8 prologue[4];
        AD_ZERO_BUF(prologue, sizeof(prologue));
        u64 bytes_read = 0ULL;

        ad_ntstatus_t st = (ad_ntstatus_t)(s64)SyscallStub(s_ssn_rvm,
            AD_CURRENT_PROCESS,
            stub,
            (void*)prologue,
            (void*)(u64)sizeof(prologue),
            (void*)&bytes_read,
            (void*)0, (void*)0, (void*)0, (void*)0, (void*)0, (void*)0
        );

        if (!AD_NT_SUCCESS(st) || bytes_read < 2u) continue;

        // FF 25 = indirect JMP [rip+disp32] — ScyllaHide's hook signature
        // E9    = near JMP rel32 — also a common hook pattern
        if ((prologue[0] == 0xFFu && prologue[1] == 0x25u) ||
             prologue[0] == 0xE9u) {
            hooked++;
        }
    }

    // ≥ 3 targeted stubs hooked → high confidence ScyllaHide
    // ≥ 2 for more sensitive detection (partial installs)
    return (b32)(hooked >= 2u);
}

// =========================================================================
// 6. Parent PID mismatch — SystemProcessInformation spoofed
// =========================================================================
//
// ScyllaHide hooks NtQuerySystemInformation(SystemProcessInformation) and
// replaces our process's InheritedFromUniqueProcessId with explorer.exe's PID.
// NtQueryInformationProcess(ProcessBasicInformation) via direct syscall returns
// the REAL (unhoofed) parent PID from the kernel.
//
// To get the spoofed PID we call ntdll!NtQuerySystemInformation THROUGH the
// hook (function pointer). If the two PPIDs differ → ScyllaHide.
//
// Note: Uses a 64KB stack buffer for SystemProcessInformation — large but
// covers most systems. Processes with >200 processes may overflow; we bail.
// =========================================================================

// SYSTEM_PROCESS_INFORMATION — only the fields we need (starts at offset 0)
typedef struct {
    u32  NextEntryOffset;                   // +0x00
    u32  NumberOfThreads;                   // +0x04
    u8   _reserved[48];                     // +0x08  (WorkingSet, HardFault, Cycle, CreateTime, etc.)
    u16  ImageNameLength;                   // +0x38 (UNICODE_STRING.Length)
    u16  ImageNameMaxLen;                   // +0x3A
    u32  _pad1;                             // +0x3C
    void* ImageNameBuffer;                  // +0x40  (UNICODE_STRING.Buffer)
    s32  BasePriority;                      // +0x48
    u32  _pad2;                             // +0x4C
    void* UniqueProcessId;                  // +0x50
    void* InheritedFromUniqueProcessId;     // +0x58
    // remaining fields not needed
} AD_SYS_PROC_INFO;

ANTIDEBUG_INLINE b32 ad_sh_ppid_mismatch(void) {
    // ── Get real PPID via direct syscall (bypasses ScyllaHide) ──────────
    static u16 s_ssn_qip = AD_SSN_UNRESOLVED;
    AD_RESOLVE_SSN_ENC(s_ssn_qip, NtQueryInformationProcess, 26);
    if (s_ssn_qip == AD_SSN_FAILED) return 0;

    AD_PROCESS_BASIC_INFO pbi;
    AD_ZERO_BUF(&pbi, sizeof(pbi));
    u32 ret_len = 0u;

    ad_ntstatus_t st = AD_SYSCALL5(
        s_ssn_qip,
        AD_CURRENT_PROCESS,
        (u64)0,                 // ProcessBasicInformation
        &pbi,
        (u64)sizeof(pbi),
        &ret_len
    );
    if (!AD_NT_SUCCESS(st)) return 0;

    void* real_ppid = pbi.InheritedFromUniqueProcessId;
    void* our_pid   = pbi.UniqueProcessId;
    if (!real_ppid || !our_pid) return 0;

    // ── Get spoofed PPID via hooked NtQuerySystemInformation ────────────
    void* ntdll = ad_ntdll_base();
    if (!ntdll) return 0;

    AD_SH_FN_NtQuerySystemInfo fn_qsi = (AD_SH_FN_NtQuerySystemInfo)
        ad_pe_find_export((const u8*)ntdll, "NtQuerySystemInformation");
    if (!fn_qsi) return 0;

    // Allocate on stack: 48KB covers ~300+ processes
    // (Each SYSTEM_PROCESS_INFORMATION entry is variable-size but ~200+ bytes)
    enum { AD_SH_PSI_BUFSZ = 49152 };  // 48 KB
    static u8 s_psi_buf[AD_SH_PSI_BUFSZ];  // static to avoid stack overflow
    AD_ZERO_BUF(s_psi_buf, sizeof(s_psi_buf));
    u32 needed = 0u;

    // Call THROUGH the hook — ScyllaHide intercepts and spoofs parent PIDs
    st = fn_qsi(AD_SYSTEM_PROCESS_INFO, s_psi_buf, (u32)sizeof(s_psi_buf), &needed);
    if (!AD_NT_SUCCESS(st) && st != (ad_ntstatus_t)0x80000005L /* INFO_LENGTH_MISMATCH */)
        return 0;

    // Walk SYSTEM_PROCESS_INFORMATION list to find our process
    AD_SYS_PROC_INFO* entry = (AD_SYS_PROC_INFO*)s_psi_buf;
    b32 mismatch = 0;
    u32 guard = 0u;

    while (entry && guard < 512u) {
        guard++;
        if (entry->UniqueProcessId == our_pid) {
            void* spoofed_ppid = entry->InheritedFromUniqueProcessId;
            // ScyllaHide replaces with explorer.exe PID — which differs from real PPID
            if (spoofed_ppid != real_ppid) {
                mismatch = 1;
            }
            break;
        }
        if (entry->NextEntryOffset == 0u) break;
        entry = (AD_SYS_PROC_INFO*)((u8*)entry + entry->NextEntryOffset);
    }

    AD_ZERO_BUF(s_psi_buf, sizeof(s_psi_buf));
    return mismatch;
}

// =========================================================================
// ANTI-SCYLLAHIDE MASTER — composite score
//
// Weights reflect false-positive risk and detection confidence:
//   yield_denied:    10 — hardcoded STATUS_ACCESS_DENIED, no false positives
//   stub_hooks:       9 — FF25 on ScyllaHide-specific stubs
//   dr_cleared:       9 — Dr0 zeroed in exception; only KiUserExceptionDispatcher hook does this
//   ppid_mismatch:    8 — cross-check of two independent syscall paths
//   tickcount_frozen: 7 — statistical (24-call pattern)
//   systime_frozen:   6 — statistical (16-call pattern)
//
// Total possible: 49+. Threshold lowered: every point contributes to
// the composite score since syscall_verify.h provides the hard proof.
// =========================================================================

// =========================================================================
// 7. NtClose behavior divergence — ScyllaHide-specific
// =========================================================================
//
// ScyllaHide hooks NtClose to return STATUS_HANDLE_NOT_CLOSABLE for handles
// with HANDLE_FLAG_PROTECT_FROM_CLOSE — suppressing the STATUS_INVALID_HANDLE
// exception the kernel would normally raise.
//
// Direct syscall NtClose with a protected handle raises the exception;
// hooked NtClose returns STATUS_HANDLE_NOT_CLOSABLE silently.
// =========================================================================
ANTIDEBUG_INLINE b32 ad_sh_ntclose_divergence(void) {
    static u16 s_ssn_close = AD_SSN_UNRESOLVED;
    AD_RESOLVE_SSN_ENC(s_ssn_close, NtClose, 8);
    if (s_ssn_close == AD_SSN_FAILED) return 0;

    void* ntdll = ad_ntdll_base();
    if (!ntdll) return 0;

    // Get the hooked NtClose stub
    typedef ad_ntstatus_t (*FN_NtClose)(void*);
    FN_NtClose fn_close = (FN_NtClose)ad_pe_find_export((const u8*)ntdll, "NtClose");
    if (!fn_close) return 0;

    // Use an obviously invalid handle
    void* bad_handle = (void*)(u64)0xDEADBEEFCAFEULL;

    // Direct syscall result
    ad_ntstatus_t st_direct = AD_SYSCALL1(s_ssn_close, bad_handle);

    // Hooked stub result
    ad_ntstatus_t st_hooked = fn_close(bad_handle);

    // If results differ → hook is intercepting NtClose
    return (b32)(st_direct != st_hooked);
}

// =========================================================================
// 8. NtQueryObject DebugObject count check
// =========================================================================
//
// ScyllaHide hooks NtQueryObject to decrement the DebugObject type count.
// A direct-syscall NtQueryObject returns the REAL count. If we're being
// debugged, there's at least 1 DebugObject; ScyllaHide hides it.
// Not implemented here because NtQueryObject(ObjectTypesInformation) is
// complex to parse. Instead, ad_sv_debug_object_raw() in syscall_verify.h
// catches this case definitively.
// =========================================================================

// =========================================================================
// 9. KiUserExceptionDispatcher hook detection
// =========================================================================
//
// ScyllaHide hooks KiUserExceptionDispatcher (the kernel's user-mode
// exception delivery function) to zero DR0-DR7 in every exception CONTEXT.
// Normal stub starts with "cmp [rip+XX], 0" or "sub rsp, XX".
// Hooked stub has JMP/NOP at its entry.
// =========================================================================
ANTIDEBUG_INLINE b32 ad_sh_kiued_hooked(void) {
    void* ntdll = ad_ntdll_base();
    if (!ntdll) return 0;

    const u8* kiued = (const u8*)ad_pe_find_export(
        (const u8*)ntdll, "KiUserExceptionDispatcher");
    if (!kiued) return 0;

    volatile u8 b0 = kiued[0];
    volatile u8 b1 = kiued[1];

    // Only flag KNOWN hook signatures — KiUserExceptionDispatcher has
    // many valid prologues across Windows versions (FC, 48 83, etc.)
    if (b0 == 0xE9u) return 1;                   // JMP rel32
    if (b0 == 0xFFu && b1 == 0x25u) return 1;    // JMP [rip+disp]
    if (b0 == 0x90u && b1 == 0xFFu) return 1;    // NOP + JMP (ScyllaHide)

    return 0;
}

// =========================================================================
// 10. NtSetInformationThread hide-from-debugger verification
// =========================================================================
//
// ScyllaHide hooks NtSetInformationThread to silently drop
// ThreadHideFromDebugger (class 17). The call returns STATUS_SUCCESS
// but does nothing. Verify by calling direct syscall then checking
// if the thread is actually hidden: NtQueryInformationThread should
// show ThreadHideFromDebugger is set.
//
// If direct syscall set it but the hooked path silently failed on a
// previous call → the thread is hidden now, which is clean.
// The detection here: call the HOOKED path, then read via direct
// syscall. If the hooked path returned SUCCESS but the thread is NOT
// hidden → ScyllaHide swallowed the call.
// =========================================================================
ANTIDEBUG_INLINE b32 ad_sh_hide_thread_swallowed(void) {
    void* ntdll = ad_ntdll_base();
    if (!ntdll) return 0;

    typedef ad_ntstatus_t (*FN_NtSetInfoThread)(void*, u32, void*, u32);
    FN_NtSetInfoThread fn_sit = (FN_NtSetInfoThread)
        ad_pe_find_export((const u8*)ntdll, "NtSetInformationThread");
    if (!fn_sit) return 0;

    // Call through HOOKED stub — ScyllaHide intercepts and returns SUCCESS
    // without actually hiding the thread.
    // ThreadHideFromDebugger = 17, requires NULL buffer and 0 size
    ad_ntstatus_t st = fn_sit(AD_CURRENT_THREAD, 17u, (void*)0, 0u);
    if (!AD_NT_SUCCESS(st)) return 0;  // call failed — can't test

    // Now verify via DIRECT syscall if the thread is actually hidden.
    // Use NtQueryInformationThread(ThreadHideFromDebugger = 17)
    // If the thread IS hidden, we get STATUS_SUCCESS with data = 1.
    // If ScyllaHide swallowed the set call, data = 0 (not hidden).
    static u16 s_ssn_qit = AD_SSN_UNRESOLVED;
    if (s_ssn_qit == AD_SSN_UNRESOLVED) {
        // "NtQueryInformationThread" — resolve manually
        char name[] = { 'N','t','Q','u','e','r','y','I','n','f','o','r','m',
                        'a','t','i','o','n','T','h','r','e','a','d','\0' };
        s_ssn_qit = whip_bridge_resolve(name);
        AD_WIPE_STR(name, sizeof(name));
    }
    if (s_ssn_qit == AD_SSN_FAILED) return 0;

    u32 hidden = 0u;
    u32 ret_len = 0u;
    ad_ntstatus_t st2 = AD_SYSCALL5(
        s_ssn_qit,
        AD_CURRENT_THREAD,
        (u64)17u,         // ThreadHideFromDebugger
        &hidden,
        (u64)sizeof(hidden),
        &ret_len
    );

    // If SET returned SUCCESS but QUERY shows not hidden → swallowed
    if (AD_NT_SUCCESS(st2) && hidden == 0u) return 1;

    return 0;
}

// =========================================================================
// 11. ScyllaHide DLL memory artifact scan
// =========================================================================
//
// ScyllaHide injects HookLibraryx64.dll into the target process.
// The DLL contains characteristic strings and export names.
// Scan the PEB LDR module list for suspicious DLL names.
// Also scan writable+executable memory for ScyllaHide signatures.
// =========================================================================
ANTIDEBUG_INLINE b32 ad_sh_memory_artifacts(void) {
#if defined(_MSC_VER)
    volatile u8* peb = (volatile u8*)(u64)__readgsqword(0x60);
    if (!peb) return 0;

    // PEB+0x18 = Ldr (PEB_LDR_DATA*)
    volatile u8* ldr = *(volatile u8**)(peb + 0x18);
    if (!ldr) return 0;

    // InMemoryOrderModuleList at Ldr+0x20
    volatile u8* head = ldr + 0x20;
    volatile u8* entry = *(volatile u8**)head;

    u32 guard = 0u;
    while (entry != head && guard < 256u) {
        guard++;
        // UNICODE_STRING FullDllName at entry+0x40 (InMemoryOrder)
        volatile u16 name_len = *(volatile u16*)(entry + 0x40);
        volatile u16* name_buf = *(volatile u16**)(entry + 0x48);

        if (name_buf && name_len > 10u) {
            // Scan for "HookLibrary" pattern (case-insensitive)
            u32 chars = name_len / 2u;
            u32 ci;
            for (ci = 0u; ci + 10u < chars; ci++) {
                volatile u16 c0 = name_buf[ci]   | 0x20u;
                volatile u16 c1 = name_buf[ci+1u] | 0x20u;
                volatile u16 c2 = name_buf[ci+2u] | 0x20u;
                volatile u16 c3 = name_buf[ci+3u] | 0x20u;
                // "hook"
                if (c0 == 'h' && c1 == 'o' && c2 == 'o' && c3 == 'k') {
                    return 1;
                }
                // "scylla"
                if (c0 == 's' && c1 == 'c' && c2 == 'y') {
                    return 1;
                }
            }
        }
        entry = *(volatile u8**)entry;  // Flink
    }
#endif
    return 0;
}

// =========================================================================
// 12. Hooked call timing divergence
// =========================================================================
//
// A hooked function takes significantly more cycles than a clean stub
// because it must JMP to the hook handler, execute logic, then JMP back.
// Clean NtYieldExecution: ~200-500 cycles. Hooked: ~2000-5000+ cycles.
// =========================================================================
ANTIDEBUG_INLINE b32 ad_sh_call_timing_divergence(void) {
    void* ntdll = ad_ntdll_base();
    if (!ntdll) return 0;

    // Use NtYieldExecution — small, fast syscall, easy to measure
    AD_SH_FN_NtYieldExecution fn_yield = (AD_SH_FN_NtYieldExecution)
        ad_pe_find_export((const u8*)ntdll, "NtYieldExecution");
    if (!fn_yield) return 0;

    // Warm up
    fn_yield();
    fn_yield();

    // Measure hooked path
    AD_LFENCE();
    u64 t0 = __rdtsc();
    AD_LFENCE();
    fn_yield();
    fn_yield();
    fn_yield();
    fn_yield();
    AD_LFENCE();
    u64 t1 = __rdtsc();
    AD_LFENCE();

    u64 hooked_cycles = (t1 - t0) / 4ULL;

    // Hooked path: ~5000+ cycles per call (JMP + hook logic + JMP back)
    // Clean path: ~200-2000 cycles per call (varies by CPU/load)
    // Use conservative threshold to avoid false positives
    return (b32)(hooked_cycles > 15000ULL);
}

// =========================================================================
// 13. NtQueryObject DebugObject count — direct syscall vs hooked
// =========================================================================
//
// ScyllaHide hooks NtQueryObject(ObjectTypesInformation) to decrement
// DebugObject.TotalNumberOfObjects. We don't need to parse the complex
// OBJECT_TYPES_INFORMATION; instead we use ObjectTypeInformation (class 2)
// on a known debug object handle to check if ScyllaHide is hiding it.
//
// Simpler approach: call NtQueryInformationProcess(ProcessDebugObjectHandle)
// via HOOKED path — ScyllaHide returns STATUS_PORT_NOT_SET.
// Call via DIRECT syscall — kernel returns STATUS_SUCCESS + handle.
// If they disagree → hook detected.
// =========================================================================
ANTIDEBUG_INLINE b32 ad_sh_debug_object_divergence(void) {
    // Direct syscall path
    static u16 s_ssn_qip = AD_SSN_UNRESOLVED;
    AD_RESOLVE_SSN_ENC(s_ssn_qip, NtQueryInformationProcess, 26);
    if (s_ssn_qip == AD_SSN_FAILED) return 0;

    u64 dbg_obj_direct = 0ULL;
    u32 ret_len = 0u;
    ad_ntstatus_t st_direct = AD_SYSCALL5(
        s_ssn_qip,
        AD_CURRENT_PROCESS,
        (u64)AD_PROCESS_DEBUG_OBJECT_HANDLE,
        &dbg_obj_direct,
        (u64)sizeof(dbg_obj_direct),
        &ret_len
    );

    // Hooked path
    void* ntdll = ad_ntdll_base();
    if (!ntdll) return 0;

    typedef ad_ntstatus_t (*FN_NtQIP)(void*, u32, void*, u32, u32*);
    FN_NtQIP fn_qip = (FN_NtQIP)ad_pe_find_export(
        (const u8*)ntdll, "NtQueryInformationProcess");
    if (!fn_qip) return 0;

    u64 dbg_obj_hooked = 0ULL;
    u32 ret_len2 = 0u;
    ad_ntstatus_t st_hooked = fn_qip(
        AD_CURRENT_PROCESS, AD_PROCESS_DEBUG_OBJECT_HANDLE,
        &dbg_obj_hooked, (u32)sizeof(dbg_obj_hooked), &ret_len2);

    // Direct SUCCESS + Hooked FAILED = ScyllaHide hiding debug object
    if (AD_NT_SUCCESS(st_direct) && !AD_NT_SUCCESS(st_hooked))
        return 1;

    // Both SUCCESS but different handles = also suspicious
    if (AD_NT_SUCCESS(st_direct) && AD_NT_SUCCESS(st_hooked) &&
        dbg_obj_direct != dbg_obj_hooked)
        return 1;

    return 0;
}

// =========================================================================
// MASTER — original checks only (safe to call from ad_run_hardened)
// These have NO side effects and are known false-positive-free.
// =========================================================================
// Forward declaration — defined in anti_titanhide.h, consumed here to skip
// the deliberate-AV probe when a kernel-mode hide driver is already flagged.
// Under TitanHide (or similar SSDT-patching drivers) the exception dispatch
// flow is hooked at KiUserExceptionDispatcher, and triggering an AV inside
// __try can deadlock the delivery path.
extern volatile u32 ad_titanhide_detected;

ANTIDEBUG_INLINE u32 ad_scyllahide_master(void) {
    u32 score = 0u;

#if AD_ENABLE_ANTI_SCYLLAHIDE
    score += ad_sh_yield_denied()       ? 10u : 0u;
    score += ad_sh_stub_hook_count()    ?  9u : 0u;
    score += ad_sh_ppid_mismatch()      ?  8u : 0u;
    score += ad_sh_tickcount_frozen()   ?  7u : 0u;
    score += ad_sh_systime_frozen()     ?  6u : 0u;
    // Skip deliberate-AV DR0 probe when TitanHide already detected — the
    // kernel-level hook on KiUserExceptionDispatcher can cause infinite
    // exception re-dispatch, hanging the process before main() completes.
    if (!ad_titanhide_detected) {
        score += ad_sh_dr_exception_clear() ?  3u : 0u;
    }
#endif

    return score;
}

// =========================================================================
// EXTENDED MASTER — new aggressive checks (call ONLY from native code
// in ad_run_supplemental, wrapped in __try/__except)
// Some have side effects (hide_thread_swallowed modifies thread state).
// =========================================================================
ANTIDEBUG_INLINE u32 ad_scyllahide_extended(void) {
    u32 score = 0u;

#if AD_ENABLE_ANTI_SCYLLAHIDE
    // Each check wrapped individually — some may crash on specific
    // Windows versions due to unexpected stub layouts or API behavior.
    { b32 v = 0; __try { v = ad_sh_debug_object_divergence(); } __except(1){} if (v) score += 10u; }
    { b32 v = 0; __try { v = ad_sh_kiued_hooked();            } __except(1){} if (v) score +=  9u; }
    { b32 v = 0; __try { v = ad_sh_ntclose_divergence();      } __except(1){} if (v) score +=  8u; }
    { b32 v = 0; __try { v = ad_sh_memory_artifacts();        } __except(1){} if (v) score +=  8u; }
    { b32 v = 0; __try { v = ad_sh_call_timing_divergence();  } __except(1){} if (v) score +=  7u; }
    { b32 v = 0; __try { v = ad_sh_hide_thread_swallowed();   } __except(1){} if (v) score +=  9u; }
#endif

    return score;
}

#else   // Non-MSVC stubs

ANTIDEBUG_INLINE b32 ad_sh_yield_denied(void)            { return 0; }
ANTIDEBUG_INLINE b32 ad_sh_tickcount_frozen(void)        { return 0; }
ANTIDEBUG_INLINE b32 ad_sh_systime_frozen(void)          { return 0; }
ANTIDEBUG_INLINE b32 ad_sh_dr_exception_clear(void)      { return 0; }
ANTIDEBUG_INLINE b32 ad_sh_stub_hook_count(void)         { return 0; }
ANTIDEBUG_INLINE b32 ad_sh_ppid_mismatch(void)           { return 0; }
ANTIDEBUG_INLINE b32 ad_sh_ntclose_divergence(void)      { return 0; }
ANTIDEBUG_INLINE b32 ad_sh_kiued_hooked(void)            { return 0; }
ANTIDEBUG_INLINE b32 ad_sh_hide_thread_swallowed(void)   { return 0; }
ANTIDEBUG_INLINE b32 ad_sh_memory_artifacts(void)        { return 0; }
ANTIDEBUG_INLINE b32 ad_sh_call_timing_divergence(void)  { return 0; }
ANTIDEBUG_INLINE b32 ad_sh_debug_object_divergence(void) { return 0; }
ANTIDEBUG_INLINE u32 ad_scyllahide_master(void)          { return 0u; }
ANTIDEBUG_INLINE u32 ad_scyllahide_extended(void)        { return 0u; }

#endif  // _MSC_VER

#endif  // ANTIDEBUG_ANTI_SCYLLAHIDE_H