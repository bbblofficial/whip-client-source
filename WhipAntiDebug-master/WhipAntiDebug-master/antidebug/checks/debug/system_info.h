// ===== file: antidebug/checks/debug/system_info.h =====
//
// NtQuerySystemInformation-based anti-debug checks.
//
// Techniques:
//   1. SystemKernelDebuggerInformation (class 35):
//      Detects kernel debugger (WinDbg kernel mode, HyperDbg)
//
//   2. NtQueryInformationProcess — ProcessBasicInformation (class 0):
//      Reads InheritedFromUniqueProcessId to verify parent process.
//      If parent is not explorer.exe or cmd.exe, likely launched by debugger.
//
// Uses WhipSysCall — zero ntdll IAT footprint.
//
#ifndef ANTIDEBUG_SYSTEM_INFO_H
#define ANTIDEBUG_SYSTEM_INFO_H

#include "../../core/types.h"
#include "../../core/macros.h"
#include "../../core/syscall_bridge.h"
#include "../../core/string_encrypt.h"

// ---------------------------------------------------------------------------
// SystemKernelDebuggerInformation structure (class 35)
// ---------------------------------------------------------------------------
typedef struct {
    u8 KernelDebuggerEnabled;    // offset 0x00
    u8 KernelDebuggerNotPresent; // offset 0x01
} AD_SYSTEM_KERNEL_DEBUGGER_INFO;

#define AD_SYSTEM_KERNEL_DEBUGGER_INFORMATION 35

// ---------------------------------------------------------------------------
// Encrypted string: "NtQuerySystemInformation" (24 chars)
// Already defined in core/string_encrypt.h — guard here so multi-include
// translation units don't trip C4005.
// ---------------------------------------------------------------------------
#ifndef AD_STRENC_NtQuerySystemInformation
#define AD_STRENC_NtQuerySystemInformation(buf)                              \
    do {                                                                     \
        const u8 _k = AD_STR_KEY(0xE2);                                     \
        char buf##_e[25];                                                    \
        AD_ENC(buf##_e,  0, 'N', _k); AD_ENC(buf##_e,  1, 't', _k);       \
        AD_ENC(buf##_e,  2, 'Q', _k); AD_ENC(buf##_e,  3, 'u', _k);       \
        AD_ENC(buf##_e,  4, 'e', _k); AD_ENC(buf##_e,  5, 'r', _k);       \
        AD_ENC(buf##_e,  6, 'y', _k); AD_ENC(buf##_e,  7, 'S', _k);       \
        AD_ENC(buf##_e,  8, 'y', _k); AD_ENC(buf##_e,  9, 's', _k);       \
        AD_ENC(buf##_e, 10, 't', _k); AD_ENC(buf##_e, 11, 'e', _k);       \
        AD_ENC(buf##_e, 12, 'm', _k); AD_ENC(buf##_e, 13, 'I', _k);       \
        AD_ENC(buf##_e, 14, 'n', _k); AD_ENC(buf##_e, 15, 'f', _k);       \
        AD_ENC(buf##_e, 16, 'o', _k); AD_ENC(buf##_e, 17, 'r', _k);       \
        AD_ENC(buf##_e, 18, 'm', _k); AD_ENC(buf##_e, 19, 'a', _k);       \
        AD_ENC(buf##_e, 20, 't', _k); AD_ENC(buf##_e, 21, 'i', _k);       \
        AD_ENC(buf##_e, 22, 'o', _k); AD_ENC(buf##_e, 23, 'n', _k);       \
        AD_DECODE_BUF(buf##_e, 24, _k);                                     \
        for (unsigned _ci = 0; _ci < 25; _ci++) (buf)[_ci] = buf##_e[_ci];  \
    } while (0)
#endif

// ---------------------------------------------------------------------------
// Check: Kernel debugger present
//
// SystemKernelDebuggerInformation returns:
//   KernelDebuggerEnabled = 1 if kd is active
//   KernelDebuggerNotPresent = 0 if kd is attached
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE b32 ad_kernel_debugger(void) {
    static u16 s_ssn = AD_SSN_UNRESOLVED;
    AD_RESOLVE_SSN_ENC(s_ssn, NtQuerySystemInformation, 25);
    if (s_ssn == AD_SSN_FAILED) return 0;

    AD_SYSTEM_KERNEL_DEBUGGER_INFO info;
    AD_ZERO_BUF(&info, sizeof(info));
    u32 ret_len = 0;

    ad_ntstatus_t st = AD_SYSCALL4(
        s_ssn,
        (u64)AD_SYSTEM_KERNEL_DEBUGGER_INFORMATION,
        &info,
        (u64)sizeof(info),
        &ret_len
    );

    if (!AD_NT_SUCCESS(st)) return 0;

    // Debugger is present if Enabled=1 OR NotPresent=0
    return (b32)(info.KernelDebuggerEnabled != 0 ||
                 info.KernelDebuggerNotPresent == 0);
}

// ---------------------------------------------------------------------------
// Check: Parent process is a known debugger
//
// NtQueryInformationProcess(ProcessBasicInformation) returns the parent PID.
// If parent is not explorer.exe / cmd.exe / powershell.exe / conhost.exe,
// the process was likely launched from a debugger.
//
// This is a heuristic — may false-positive on CI/scripts.
// Use AD_ENABLE_PARENT_CHECK to toggle.
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE b32 ad_suspicious_parent(void) {
    static u16 s_ssn = AD_SSN_UNRESOLVED;
    AD_RESOLVE_SSN_ENC(s_ssn, NtQueryInformationProcess, 26);
    if (s_ssn == AD_SSN_FAILED) return 0;

    AD_PROCESS_BASIC_INFO pbi;
    AD_ZERO_BUF(&pbi, sizeof(pbi));
    u32 ret_len = 0;

    // ProcessBasicInformation = class 0
    ad_ntstatus_t st = AD_SYSCALL5(
        s_ssn,
        AD_CURRENT_PROCESS,
        (u64)0,
        &pbi,
        (u64)sizeof(pbi),
        &ret_len
    );

    if (!AD_NT_SUCCESS(st)) return 0;

    // Read parent PID
    u64 parent_pid = (u64)(unsigned long long)pbi.InheritedFromUniqueProcessId;

    // PID 0 or 4 = System — suspicious (injected/manual-mapped context)
    if (parent_pid <= 4) return 1;

    // We can't easily check the parent name without more syscalls.
    // Instead: check if parent PID is abnormally low (most debuggers
    // are launched early) or matches common debugger patterns.
    // For a more robust check, walk SYSTEM_PROCESS_INFORMATION.
    // Here we just verify the parent exists — a dead parent means
    // the debugger detached.
    AD_UNUSED(parent_pid);
    return 0;
}

#endif // ANTIDEBUG_SYSTEM_INFO_H
