// ===== file: antidebug/checks/debug/debugger_behavior.h =====
//
// Detect debuggers by OUR OWN process state, not by the debugger's name.
//
// Problem: process_scan and window_scan match debugger processes by name.
// Renaming x64dbg.exe to notepad.exe (2 seconds) bypasses both checks.
//
// Solution: query our own debug state via NtQueryInformationProcess. These
// checks are unfakeable by renaming because they examine OUR process object
// in the kernel, not the debugger's file name.
//
// Checks and scoring:
//   1. ProcessDebugPort       (class 7)  != 0       -> +5
//   2. ProcessDebugObjectHandle (class 30) exists    -> +5
//   3. ProcessDebugFlags      (class 31) == 0       -> +3
//   4. PEB.BeingDebugged inconsistent across 3 reads
//      with lfence barriers (race condition / timing) -> +4
//
// Returns a composite score (0 = clean, max 17 = highly suspicious).
// Designed to feed into ad_extra_master() alongside the existing checks.
//
#ifndef ANTIDEBUG_DEBUGGER_BEHAVIOR_H
#define ANTIDEBUG_DEBUGGER_BEHAVIOR_H

#include "../../core/types.h"
#include "../../core/macros.h"
#include "../../core/syscall_bridge.h"
#include "../../core/string_encrypt.h"

#if defined(_MSC_VER)

// ---------------------------------------------------------------------------
// ad_self_debug_state_check
//
// Queries 4 independent debug indicators on OUR OWN process.
// None of these depend on the debugger's executable name or window class.
// Returns a weighted suspicion score (0..17).
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE u32 ad_self_debug_state_check(void) {
    u32 score = 0u;

    // ---- SSN resolution ----
    static u16 s_ssn_qip = AD_SSN_UNRESOLVED;
    AD_RESOLVE_SSN_ENC(s_ssn_qip, NtQueryInformationProcess, 26);
    if (s_ssn_qip == AD_SSN_FAILED) return 0u;

    // ---- Check 1: ProcessDebugPort (class 7) ----
    // Non-zero debug port = user-mode debugger attached.
    {
        u64 port    = 0ULL;
        u32 ret_len = 0u;
        ad_ntstatus_t st = AD_SYSCALL5(
            s_ssn_qip,
            AD_CURRENT_PROCESS,
            (u64)AD_PROCESS_DEBUG_PORT,      // 7
            &port,
            (u64)sizeof(port),
            &ret_len
        );
        if (AD_NT_SUCCESS(st) && port != 0ULL) {
            score += 5u;
        }
    }

    AD_BARRIER();

    // ---- Check 2: ProcessDebugObjectHandle (class 30) ----
    // If NtQueryInformationProcess succeeds, a debug object handle exists.
    // STATUS_PORT_NOT_SET (0xC0000353) = no debug object = clean.
    {
        void* obj   = (void*)0;
        u32 ret_len = 0u;
        ad_ntstatus_t st = AD_SYSCALL5(
            s_ssn_qip,
            AD_CURRENT_PROCESS,
            (u64)AD_PROCESS_DEBUG_OBJECT_HANDLE,  // 30
            &obj,
            (u64)sizeof(obj),
            &ret_len
        );
        if (AD_NT_SUCCESS(st) && obj != (void*)0) {
            score += 5u;
        }
    }

    AD_BARRIER();

    // ---- Check 3: ProcessDebugFlags (class 31) ----
    // flags == 0 means NoDebugInherit is NOT set. On modern Windows the
    // default is 0 for many process creation paths, so this check alone
    // is unreliable. Only flag if ProcessDebugPort ALSO confirms debug.
    {
        u32 flags   = 1u;
        u32 ret_len = 0u;
        ad_ntstatus_t st = AD_SYSCALL5(
            s_ssn_qip,
            AD_CURRENT_PROCESS,
            (u64)AD_PROCESS_DEBUG_FLAGS,          // 31
            &flags,
            (u64)sizeof(flags),
            &ret_len
        );
        if (AD_NT_SUCCESS(st) && flags == 0u) {
            // Cross-check with DebugPort before scoring
            u64 dbg_port = 0;
            u32 rl2 = 0;
            ad_ntstatus_t st2 = AD_SYSCALL5(s_ssn_qip,
                AD_CURRENT_PROCESS, (u64)AD_PROCESS_DEBUG_PORT,
                &dbg_port, (u64)sizeof(dbg_port), &rl2);
            if (AD_NT_SUCCESS(st2) && dbg_port != 0)
                score += 3u;
        }
    }

    AD_BARRIER();

    // ---- Check 4: PEB.BeingDebugged consistency ----
    // Read PEB.BeingDebugged 3 times with lfence barriers.
    // A debugger (or ScyllaHide) that patches this byte in a race window
    // may leave inconsistent reads. On clean systems all 3 reads match.
    // If any read differs from the others, a race condition is detected.
    //
    // PEB is at GS:[0x60]. BeingDebugged is at PEB+0x02.
    {
        volatile u8* peb = (volatile u8*)__readgsqword(0x60);
        volatile u8  r1, r2, r3;

        r1 = *(peb + 0x02);
        AD_LFENCE();

        // Small delay via volatile spin to open a race window
        volatile u32 spin = 0u;
        for (spin = 0u; spin < 37u; spin++) { AD_BARRIER(); }

        r2 = *(peb + 0x02);
        AD_LFENCE();

        for (spin = 0u; spin < 53u; spin++) { AD_BARRIER(); }

        r3 = *(peb + 0x02);
        AD_LFENCE();

        // Inconsistency detection: all three must be identical on a clean system
        if (r1 != r2 || r2 != r3 || r1 != r3) {
            score += 4u;
        }

        if (r1 | r2 | r3) {
            score += 4u;
        }

        // Contradiction: PEB.BeingDebugged == 0 consistently but
        // PEB.NtGlobalFlag still carries the heap debug bits (0x70).
        // ScyllaHide patches BeingDebugged aggressively but sometimes
        // leaves NtGlobalFlag intact — this catches that gap.
        // PEB.NtGlobalFlag is at PEB+0x68 (x64).
        if ((r1 | r2 | r3) == 0u) {
            volatile u32 ntgf = *(volatile u32*)(peb + 0x68);
            AD_LFENCE();
            if (ntgf & 0x70u) {  // FLG_HEAP_ENABLE_TAIL_CHECK | FREE_CHECK | VALIDATE_PARAMS
                score += 6u;
            }
        }
    }

    return score;
}

// ---------------------------------------------------------------------------
// Boolean wrapper for simple integration into extra_master
// Returns 1 if any behavioral debugger indicator fires.
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE b32 ad_detect_debugger_by_behavior(void) {
    return (b32)(ad_self_debug_state_check() > 0u);
}

#else
ANTIDEBUG_INLINE u32 ad_self_debug_state_check(void) { return 0u; }
ANTIDEBUG_INLINE b32 ad_detect_debugger_by_behavior(void) { return 0; }
#endif // _MSC_VER

#endif // ANTIDEBUG_DEBUGGER_BEHAVIOR_H
