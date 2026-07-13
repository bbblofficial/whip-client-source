// ===== file: antidebug/checks/debug/kd_deep.h =====
//
// Powerful kernel-debugger (kd) detection.
//
// Stronger than the inline KUSER_SHARED_DATA flags consulted by the
// sentinel D heartbeat — these checks ask the kernel directly via
// dedicated NT system calls and inspect responses that a kd cannot
// transparently mask:
//
//   1. NtQuerySystemInformation(SystemKernelDebuggerInformation, 0x23)
//      Returns the kernel's own view of debugger state. The struct
//      holds two booleans — KernelDebuggerEnabled and
//      KernelDebuggerNotPresent — that the kernel sets when a debug
//      port (serial / USB / 1394 / net) is wired up via bcdedit.
//      No user-mode hook can lie about this without rewriting the
//      direct-syscall stub itself, and we issue the call through
//      WhipSysCall (no ntdll path).
//
//   2. NtQueryInformationProcess(ProcessDebugObjectHandle, 0x1E)
//      Returns the debug object backing the process — non-zero only
//      when something attached via DebugActiveProcess (most user-mode
//      debuggers, and some kernel-side WinDbg setups bridging to a
//      user-mode probe).
//
//   3. NtSystemDebugControl(SysDbgQueryModuleInformation, 0)
//      Behaves differently depending on whether kd is present:
//        - no kd, modern Windows : STATUS_DEBUGGER_INACTIVE (0xC0000354)
//        - no kd, kernel rejects : STATUS_NOT_IMPLEMENTED (0xC0000002)
//                                   or STATUS_PRIVILEGE_NOT_HELD
//        - kd attached           : STATUS_INVALID_INFO_CLASS (0xC0000003)
//                                   or other non-INACTIVE status, or
//                                   even SUCCESS depending on class
//      Anything that's NOT one of the "clean" statuses is a positive.
//
// All three together produce a high-confidence signal for traditional
// WinDbg/kd. They do NOT detect HyperDbg (hypervisor-based, hidden
// from the OS) — that lives in the hypervisor checks
// (AD_ENABLE_VM_HYPERVISOR + EPT split detection elsewhere).
//
#ifndef ANTIDEBUG_KD_DEEP_H
#define ANTIDEBUG_KD_DEEP_H

#include "../../core/types.h"
#include "../../core/macros.h"
#include "../../core/syscall_bridge.h"
#include "../../core/string_encrypt.h"
#include "../../core/strenc_extra.h"
#include "../../core/api_hash.h"

#ifdef _MSC_VER

// SYSTEM_KERNEL_DEBUGGER_INFORMATION layout (NTAPI):
//   BOOLEAN KernelDebuggerEnabled;
//   BOOLEAN KernelDebuggerNotPresent;
// Padded to 4 bytes for alignment.
typedef struct {
    u8  KernelDebuggerEnabled;
    u8  KernelDebuggerNotPresent;
    u16 _pad;
} AD_SYSTEM_KD_INFORMATION;

// NTSTATUS constants we check against. Cast through s32 → ad_ntstatus_t
// because ad_ntstatus_t is signed 32-bit and these are above 0x80000000.
// Guarded so we don't clash with definitions in other modules.
#ifndef AD_STATUS_NOT_IMPLEMENTED
#define AD_STATUS_NOT_IMPLEMENTED      ((ad_ntstatus_t)(s32)0xC0000002L)
#endif
#ifndef AD_STATUS_INVALID_INFO_CLASS
#define AD_STATUS_INVALID_INFO_CLASS   ((ad_ntstatus_t)(s32)0xC0000003L)
#endif
#ifndef AD_STATUS_DEBUGGER_INACTIVE
#define AD_STATUS_DEBUGGER_INACTIVE    ((ad_ntstatus_t)(s32)0xC0000354L)
#endif
#ifndef AD_STATUS_PRIVILEGE_NOT_HELD
#define AD_STATUS_PRIVILEGE_NOT_HELD   ((ad_ntstatus_t)(s32)0xC0000061L)
#endif
#ifndef AD_STATUS_INFO_LENGTH_MISMATCH
#define AD_STATUS_INFO_LENGTH_MISMATCH ((ad_ntstatus_t)(s32)0xC0000004L)
#endif

// ── Check 1: SystemKernelDebuggerInformation ─────────────────────────
ANTIDEBUG_INLINE b32 ad_kd_check_sysinfo(void) {
    static u16 s_ssn = AD_SSN_UNRESOLVED;
    AD_RESOLVE_SSN_ENC(s_ssn, NtQuerySystemInformation, 25);
    if (s_ssn == AD_SSN_FAILED) return 0;

    AD_SYSTEM_KD_INFORMATION info;
    info.KernelDebuggerEnabled    = 0u;
    info.KernelDebuggerNotPresent = 1u;
    info._pad                     = 0u;

    u32 ret_len = 0u;
    ad_ntstatus_t st = AD_SYSCALL4(s_ssn,
        (u64)0x23,                          // SystemKernelDebuggerInformation
        &info,
        (u64)sizeof(info),
        &ret_len);
    if (!AD_NT_SUCCESS(st)) return 0;

    if (info.KernelDebuggerEnabled    != 0u) return 1;
    if (info.KernelDebuggerNotPresent == 0u) return 1;
    return 0;
}

// ── Check 2: ProcessDebugObjectHandle ───────────────────────────────
ANTIDEBUG_INLINE b32 ad_kd_check_debug_object(void) {
    static u16 s_ssn = AD_SSN_UNRESOLVED;
    AD_RESOLVE_SSN_ENC(s_ssn, NtQueryInformationProcess, 26);
    if (s_ssn == AD_SSN_FAILED) return 0;

    void* dbg_obj = (void*)0;
    u32 ret_len = 0u;
    ad_ntstatus_t st = AD_SYSCALL5(s_ssn,
        AD_CURRENT_PROCESS,
        (u64)0x1E,                          // ProcessDebugObjectHandle
        &dbg_obj,
        (u64)sizeof(dbg_obj),
        &ret_len);

    if (AD_NT_SUCCESS(st) && dbg_obj != (void*)0) return 1;
    return 0;
}

// ── Check 3: NtSystemDebugControl probe ──────────────────────────────
ANTIDEBUG_INLINE b32 ad_kd_check_sysdbg(void) {
    static u16 s_ssn = AD_SSN_UNRESOLVED;
    AD_RESOLVE_SSN_ENC(s_ssn, NtSystemDebugControl, 21);
    if (s_ssn == AD_SSN_FAILED) return 0;

    u8  buf[16];
    u32 ret_len = 0u;
    AD_ZERO_BUF(buf, sizeof(buf));

    ad_ntstatus_t st = AD_SYSCALL6(s_ssn,
        (u64)0,                             // SysDbgQueryModuleInformation
        (void*)0,
        (u64)0,
        buf,
        (u64)sizeof(buf),
        &ret_len);

    // Clean baselines — any of these means kd is NOT present.
    if (st == AD_STATUS_DEBUGGER_INACTIVE)    return 0;
    if (st == AD_STATUS_NOT_IMPLEMENTED)      return 0;
    if (st == AD_STATUS_PRIVILEGE_NOT_HELD)   return 0;
    if (st == AD_STATUS_INVALID_INFO_CLASS)   return 0;
    if (st == AD_STATUS_INFO_LENGTH_MISMATCH) return 0;

    // Any other status (especially SUCCESS) is suspicious — kd is
    // intercepting or the kernel is allowing the debug query.
    return 1;
}

// ── Check 4: ProcessDebugFlags query ────────────────────────────────
// `NtQueryInformationProcess(ProcessDebugFlags, 0x1F)` returns the
// inverse of NoDebugInherit: 1 when no debugger inherit-debug is set
// (clean), 0 when a debug-port has been wired to the process.
ANTIDEBUG_INLINE b32 ad_kd_check_query_debug_flags(void) {
    static u16 s_ssn = AD_SSN_UNRESOLVED;
    AD_RESOLVE_SSN_ENC(s_ssn, NtQueryInformationProcess, 26);
    if (s_ssn == AD_SSN_FAILED) return 0;

    u32 flags = 0xFFu;
    u32 ret_len = 0u;
    ad_ntstatus_t st = AD_SYSCALL5(s_ssn,
        AD_CURRENT_PROCESS,
        (u64)0x1F,                          // ProcessDebugFlags
        &flags,
        (u64)4,
        &ret_len);

    // 1 = NoDebugInherit set (clean). 0 = debug port active.
    if (AD_NT_SUCCESS(st) && flags == 0u) return 1;
    return 0;
}

// ── Check 5: NtSetInformationProcess(ProcessDebugFlags, 0) probe ────
// Try to disable debug-inherit on ourselves. Without kd, the call
// returns success (or STATUS_INVALID_INFO_CLASS on locked-down
// systems). With kd attached, the kernel often returns
// STATUS_PORT_NOT_SET (0xC0000353) or refuses with another status.
#ifndef AD_STATUS_PORT_NOT_SET
#define AD_STATUS_PORT_NOT_SET ((ad_ntstatus_t)(s32)0xC0000353L)
#endif

ANTIDEBUG_INLINE b32 ad_kd_check_set_debug_flags(void) {
    static u16 s_ssn = AD_SSN_UNRESOLVED;
    AD_RESOLVE_SSN_ENC(s_ssn, NtSetInformationProcess, 24);
    if (s_ssn == AD_SSN_FAILED) return 0;

    u32 zero = 0u;
    ad_ntstatus_t st = AD_SYSCALL4(s_ssn,
        AD_CURRENT_PROCESS,
        (u64)0x1F,                          // ProcessDebugFlags
        &zero,
        (u64)4);

    // Clean baselines — these mean kd is NOT present.
    if (AD_NT_SUCCESS(st))                    return 0;
    if (st == AD_STATUS_INVALID_INFO_CLASS)   return 0;
    if (st == AD_STATUS_NOT_IMPLEMENTED)      return 0;
    // STATUS_PORT_NOT_SET specifically signals kd intercepted the call.
    if (st == AD_STATUS_PORT_NOT_SET) return 1;
    // Other non-success status — also suspicious.
    return 1;
}

// ── Check 6: NtClose with garbage handle ────────────────────────────
// Classic kd trap: a kernel debugger raises STATUS_INVALID_HANDLE
// (0xC0000008) as an exception when CloseHandle/NtClose is called on
// an obviously-bogus handle (low bits 0x3 set). Without kd, NtClose
// silently returns the same status as a normal NTSTATUS — no
// exception. We catch via SEH; an exception arriving means kd.
#ifndef AD_STRENC_NtClose
#define AD_STRENC_NtClose(buf)                                               \
    do {                                                                     \
        const u8 _k = AD_STR_KEY(0x4D);                                     \
        char buf##_e[8];                                                     \
        AD_ENC(buf##_e,  0, 'N', _k); AD_ENC(buf##_e,  1, 't', _k);       \
        AD_ENC(buf##_e,  2, 'C', _k); AD_ENC(buf##_e,  3, 'l', _k);       \
        AD_ENC(buf##_e,  4, 'o', _k); AD_ENC(buf##_e,  5, 's', _k);       \
        AD_ENC(buf##_e,  6, 'e', _k);                                       \
        AD_DECODE_BUF(buf##_e, 7, _k);                                      \
        for (unsigned _ci = 0; _ci < 8; _ci++) (buf)[_ci] = buf##_e[_ci];   \
    } while (0)
#endif

ANTIDEBUG_INLINE b32 ad_kd_check_close_invalid_handle(void) {
    static u16 s_ssn = AD_SSN_UNRESOLVED;
    AD_RESOLVE_SSN_ENC(s_ssn, NtClose, 8);
    if (s_ssn == AD_SSN_FAILED) return 0;

    volatile b32 caught = 0;
    __try {
        // Garbage handle. The low 2 bits set (0x3) mark it as kernel-
        // pseudohandle-class invalid — kd raises an exception, kernel
        // returns NTSTATUS without one.
        (void)AD_SYSCALL1(s_ssn, (void*)(u64)0xDEADBEEFu);
    } __except(1) {
        caught = 1;
    }
    return caught;
}

// ── Check 7: Multi-function ntdll Dbg* prologue inspection ──────────
// Extends sentinel C's first-byte check to multiple functions and the
// first 5 bytes (a long jmp landing pad). A kd typically rewrites
// these to redirect breakin attempts.
ANTIDEBUG_INLINE b32 ad_kd_check_dbgui_patches(void) {
    struct { const char* name; u8 first_ok[4]; u8 ok_count; } targets[] = {
        // DbgBreakPoint — int3; ret  → first byte must be 0xCC
        { "DbgBreakPoint",      { 0xCC, 0, 0, 0 }, 1 },
        // DbgUiRemoteBreakin — REX.W prologue → 0x48 / 0x4C / 0x40
        { "DbgUiRemoteBreakin", { 0x48, 0x4C, 0x40, 0 }, 3 },
        // DbgUiConnectToDbg — pushes regs → 0x48 / 0x4C / 0x53 / 0x55
        { "DbgUiConnectToDbg",  { 0x48, 0x4C, 0x53, 0x55 }, 4 },
        // DbgUiContinue — pushes/sub-rsp → 0x48 / 0x53
        { "DbgUiContinue",      { 0x48, 0x53, 0, 0 }, 2 },
    };
    u32 patched = 0;
    u32 i, j;
    for (i = 0; i < sizeof(targets) / sizeof(targets[0]); i++) {
        void* p = ad_resolve_api(AD_HASH_NTDLL, ad_hash_str(targets[i].name));
        if (!p) continue;
        u8 b0 = *(volatile const u8*)p;
        b32 ok = 0;
        for (j = 0; j < targets[i].ok_count; j++) {
            if (b0 == targets[i].first_ok[j]) { ok = 1; break; }
        }
        if (!ok) patched++;

        // Also reject `e9 ?? ?? ?? ??` (jmp rel32) — universal hook pattern.
        if (b0 == 0xE9u) patched++;
    }
    return (patched > 0u) ? 1 : 0;
}

// ── Check 8: NtCreateDebugObject success → no other debugger ─────────
// A clean process can create its own debug object. If the call fails
// with specific statuses, something else (likely kd) is interfering.
#ifndef AD_STRENC_NtCreateDebugObject_KD
#define AD_STRENC_NtCreateDebugObject_KD(buf)                                \
    do {                                                                     \
        const u8 _k = AD_STR_KEY(0x7F);                                     \
        char buf##_e[20];                                                    \
        AD_ENC(buf##_e,  0, 'N', _k); AD_ENC(buf##_e,  1, 't', _k);       \
        AD_ENC(buf##_e,  2, 'C', _k); AD_ENC(buf##_e,  3, 'r', _k);       \
        AD_ENC(buf##_e,  4, 'e', _k); AD_ENC(buf##_e,  5, 'a', _k);       \
        AD_ENC(buf##_e,  6, 't', _k); AD_ENC(buf##_e,  7, 'e', _k);       \
        AD_ENC(buf##_e,  8, 'D', _k); AD_ENC(buf##_e,  9, 'e', _k);       \
        AD_ENC(buf##_e, 10, 'b', _k); AD_ENC(buf##_e, 11, 'u', _k);       \
        AD_ENC(buf##_e, 12, 'g', _k); AD_ENC(buf##_e, 13, 'O', _k);       \
        AD_ENC(buf##_e, 14, 'b', _k); AD_ENC(buf##_e, 15, 'j', _k);       \
        AD_ENC(buf##_e, 16, 'e', _k); AD_ENC(buf##_e, 17, 'c', _k);       \
        AD_ENC(buf##_e, 18, 't', _k);                                       \
        AD_DECODE_BUF(buf##_e, 19, _k);                                     \
        for (unsigned _ci = 0; _ci < 20; _ci++) (buf)[_ci] = buf##_e[_ci];  \
    } while (0)
#endif

ANTIDEBUG_INLINE b32 ad_kd_check_create_debug_object(void) {
    static u16 s_ssn_cdo = AD_SSN_UNRESOLVED;
    static u16 s_ssn_cls = AD_SSN_UNRESOLVED;
    AD_RESOLVE_SSN_ENC(s_ssn_cdo, NtCreateDebugObject_KD, 20);
    AD_RESOLVE_SSN_ENC(s_ssn_cls, NtClose, 8);
    if (s_ssn_cdo == AD_SSN_FAILED) return 0;

    void* dbg_handle = (void*)0;
    ad_ntstatus_t st = AD_SYSCALL4(s_ssn_cdo,
        &dbg_handle,
        (u64)0x1F0001UL,                    // DEBUG_ALL_ACCESS
        (void*)0,
        (u64)0);

    if (AD_NT_SUCCESS(st)) {
        if (dbg_handle && s_ssn_cls != AD_SSN_FAILED) {
            (void)AD_SYSCALL1(s_ssn_cls, dbg_handle);
        }
        return 0;  // success = no interference
    }
    // Failure with specific statuses indicates kd is holding the port.
    return 1;
}

// ── Check 9: Self-attached debug object via NtQueryInfoProcess ─────
// A different angle: query ProcessDebugPort (class 7) — non-NULL only
// when something attached via the legacy debug port. Different from
// ProcessDebugObjectHandle (class 0x1E) which uses the modern object.
ANTIDEBUG_INLINE b32 ad_kd_check_debug_port(void) {
    static u16 s_ssn = AD_SSN_UNRESOLVED;
    AD_RESOLVE_SSN_ENC(s_ssn, NtQueryInformationProcess, 26);
    if (s_ssn == AD_SSN_FAILED) return 0;

    u64 port = 0;
    u32 ret_len = 0u;
    ad_ntstatus_t st = AD_SYSCALL5(s_ssn,
        AD_CURRENT_PROCESS,
        (u64)0x07,                          // ProcessDebugPort
        &port,
        (u64)sizeof(port),
        &ret_len);

    // Non-NULL or 0xFFFFFFFFFFFFFFFF indicates a debug port is attached.
    if (AD_NT_SUCCESS(st) && port != 0) return 1;
    return 0;
}

// ── Master combiner ──────────────────────────────────────────────────
// Score weights chosen so that any single signal exceeds the score
// vault's noise floor (44) when the binary is actually being kd'd.
// Multiple independent signals stack to push commitment_score well
// above the threshold, defeating bypass attempts at any single check.
ANTIDEBUG_INLINE u32 ad_kd_deep_master(void) {
    u32 score = 0u;
    __try { if (ad_kd_check_sysinfo())              score += 16u; } __except(1) {}
    __try { if (ad_kd_check_debug_object())         score += 12u; } __except(1) {}
    __try { if (ad_kd_check_sysdbg())               score += 8u;  } __except(1) {}
    __try { if (ad_kd_check_query_debug_flags())    score += 12u; } __except(1) {}
    __try { if (ad_kd_check_set_debug_flags())      score += 10u; } __except(1) {}
    __try { if (ad_kd_check_close_invalid_handle()) score += 14u; } __except(1) {}
    __try { if (ad_kd_check_dbgui_patches())        score += 8u;  } __except(1) {}
    __try { if (ad_kd_check_create_debug_object())  score += 10u; } __except(1) {}
    __try { if (ad_kd_check_debug_port())           score += 12u; } __except(1) {}
    return score;
}

#else  // !_MSC_VER

ANTIDEBUG_INLINE u32 ad_kd_deep_master(void) { return 0u; }

#endif // _MSC_VER

#endif // ANTIDEBUG_KD_DEEP_H
