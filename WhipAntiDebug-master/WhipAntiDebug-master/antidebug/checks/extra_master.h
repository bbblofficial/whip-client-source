// ===== file: antidebug/checks/extra_master.h =====
//
// Extra anti-debug checks master — 6 new detection layers:
//
//   1. ad_dbgui_patch_check()    — DbgUiRemoteBreakin/DbgBreakPoint/NtCreateDebugObject hook
//   2. ad_handle_scan()          — Foreign process handles to our process (SystemExtendedHandleInfo)
//   3. ad_suspicious_dlls_check()— Known debugger/injector DLLs in our PEB LDR list
//   4. ad_process_scan()         — Known debugger executables among all running processes
//   5. ad_etw_hook_detect()      — EtwEventWrite / EtwEventWriteFull hook detection
//   6. ad_trap_flag_single_step()— EFLAGS.TF single-step exception interception
//   7. ad_trap_flag_context_leak()— TF preserved in exception CONTEXT (emulator bug)
//
// Returns a composite weighted score; not gated through the 32-bit dispatcher
// bitmask — feeds directly into ad_run_hardened()'s aggregate.
//
#ifndef ANTIDEBUG_EXTRA_MASTER_H
#define ANTIDEBUG_EXTRA_MASTER_H

#include "../core/config.h"
#include "debug/dbgui_patch.h"
#include "debug/handle_scan.h"
#include "debug/suspicious_dlls.h"
#include "debug/process_scan.h"
#include "debug/process_sig_scan.h"
#include "runtime/etw_detect.h"
#include "exceptions/trap_flag.h"
// New tier-S/A/B checks
#include "runtime/anti_attach.h"
#include "runtime/drop_privs.h"
#include "runtime/fake_hwbp.h"
#include "runtime/frida_thread_scan.h"
#include "runtime/vad_ldr_diff.h"
#include "runtime/page_guard_trap.h"
#include "runtime/tls_check.h"
#include "timing/cross_timer.h"
#include "integrity/stack_unwind_check.h"
#include "exceptions/veh_decoy.h"
#include "integrity/critical_scan.h"
#include "timing/total_elapsed.h"
#include "vm/anti_emulation.h"
#include "vm/vm_master.h"
#include "debug/remote_debug.h"
#include "debug/process_sig_scan.h"
#include "debug/window_scan.h"
#include "debug/sandbox_checks.h"
#include "integrity/memory_bp_detect.h"
#include "debug/debugger_behavior.h"
#include "timing/tsc_qpc_drift.h"
#include "runtime/wireshark_detect.h"

// Per-extra-check debug breakdown captured for diagnostics.
typedef struct {
    u32 tls;
    u32 fake_hwbp;
    u32 anti_attach;
    u32 frida;
    u32 cross_timer;
    u32 vad_ldr;
    u32 stack_unwind;
    u32 veh;
    u32 dbgui_patch;
    u32 handle_scan;
    u32 dlls;
    u32 process_scan;
    u32 etw;
    u32 trap_flag_ss;
    u32 trap_flag_ctx;
    u32 page_guard_sentinel;
    // undiagnosed checks
    u32 f_remote;
    u32 f_window;
    u32 f_ods;
    u32 f_ifeo;
    u32 f_job;
    u32 f_uef;
    u32 f_dbg_filter;
    u32 f_mem_bp;
    u32 f_ntdll_page;
    u32 f_behavior;
    u32 f_delta;
    u32 tsc_drift;
    u32 wireshark;
} ad_dbg_extras_t;
static volatile ad_dbg_extras_t ad_dbg_extras = {0};

// File-scope page-guard sentinel state (init/arm from main, check here).
static ad_page_guard_t g_ad_page_guard = {0};

// Diagnostic counters for the two scores currently uncategorised in [X] dump
volatile u32 ad_dbg_emu_score = 0;
volatile u32 ad_dbg_vmfull_score = 0;

// TSC/QPC drift context — calibrated once at init (main_example.c case 13).
static ad_tsc_qpc_ctx_t g_tsc_qpc_ctx = {0};

ANTIDEBUG_INLINE u32 ad_extra_master(void) {
    u32 score = 0u;

#if AD_ENABLE_DBGUI_PATCH
    { b32 v = ad_dbgui_patch_check(); if (v) score += 9u; ad_dbg_extras.dbgui_patch = (u32)v; }
#endif

#if AD_ENABLE_HANDLE_SCAN
    { b32 v = ad_handle_scan(); if (v) score += 8u; ad_dbg_extras.handle_scan = (u32)v; }
#endif

#if AD_ENABLE_DEBUGGER_DLLS
    { b32 v = ad_suspicious_dlls_check(); if (v) score += 7u; ad_dbg_extras.dlls = (u32)v; }
#endif

#if AD_ENABLE_PROCESS_SCAN
    { b32 v = ad_process_scan(); if (v) score += 6u; ad_dbg_extras.process_scan = (u32)v; }
#endif

#if AD_ENABLE_PROCESS_SIG_SCAN
    { b32 v = ad_process_sig_scan(); if (v) score += 7u; }
#endif

#if AD_ENABLE_ETW_HOOK
    { b32 v = ad_etw_hook_detect(); if (v) score += 6u; ad_dbg_extras.etw = (u32)v; }
#endif

#if AD_ENABLE_TRAP_FLAG
    { b32 v = ad_trap_flag_single_step(); if (v) score += 4u; ad_dbg_extras.trap_flag_ss = (u32)v; }
    { b32 v = ad_trap_flag_context_leak(); if (v) score += 3u; ad_dbg_extras.trap_flag_ctx = (u32)v; }
#endif

    // ── Tier-S checks (passive verifiers only) ──────────────────────────
    {
        u32 v = ad_tls_check();
        score += v;
        ad_dbg_extras.tls = v;
    }

    // Fake-HW-BP squat verifier
    {
        b32 v = ad_fake_hwbp_verify();
        if (v) score += 7u;
        ad_dbg_extras.fake_hwbp = (u32)v;
    }

    // Anti-attach (NoDebugInherit) verifier
    {
        b32 v = ad_anti_attach_verify();
        if (v) score += 6u;
        ad_dbg_extras.anti_attach = (u32)v;
    }

    // Frida / DBI thread name scanner
    {
        b32 v = ad_frida_thread_scan();
        if (v) score += 9u;
        ad_dbg_extras.frida = (u32)v;
    }

    // Cross-timer triangulation
    {
        b32 v = ad_cross_timer_check();
        if (v) score += 6u;
        ad_dbg_extras.cross_timer = (u32)v;
    }

    // VAD vs PEB.Ldr discrepancy
    {
        b32 v = ad_vad_ldr_diff_check();
        if (v) score += 8u;
        ad_dbg_extras.vad_ldr = (u32)v;
    }

    // Stack unwinding consistency.
    // Tolerance: up to 4 unknown frames are expected on a clean run because
    // the project deliberately strips main's .pdata entry, runs the
    // orchestrator on an anonymous RWX trampoline page, pivots RSP onto a
    // fake stack with random fill, and forges saved-RA slots in latent
    // sentinel threads. Each of those shows up as an "unknown" frame to
    // RtlLookupFunctionEntry. Only flag SURPLUS frames above the baseline.
    {
        u32 unknown = ad_stack_unwind_check();
        u32 surplus = (unknown > 4u) ? (unknown - 4u) : 0u;
        if (surplus > 0u) score += surplus * 3u;
        ad_dbg_extras.stack_unwind = unknown;
    }

    // VEH decoy chain
    {
        b32 v = ad_veh_check();
        if (v) score += 5u;
        ad_dbg_extras.veh = (u32)v;
    }

#if AD_ENABLE_PAGE_GUARD_SENTINEL
    // PAGE_GUARD sentinel: if the bait page was touched → debugger memory window
    {
        b32 v = ad_page_guard_check(&g_ad_page_guard);
        if (v) score += 8u;
        ad_dbg_extras.page_guard_sentinel = (u32)v;
        // Re-arm for next check cycle
        if (v) ad_page_guard_arm(&g_ad_page_guard);
    }
#endif

#if AD_ENABLE_ANTI_EMULATION
    {
        u32 v = ad_emu_master();
        score += v;
        ad_dbg_extras.f_remote += 0u;  // pad to keep field count stable
        // tracked separately below for diagnostics
        extern volatile u32 ad_dbg_emu_score;
        ad_dbg_emu_score = v;
    }
#endif

    // ── VM deep detection — all 9 sub-modules ─────────────────────────
    {
        u32 v = ad_vm_full_master();
        score += v;
        extern volatile u32 ad_dbg_vmfull_score;
        ad_dbg_vmfull_score = v;
    }

#if AD_ENABLE_REMOTE_DEBUG
    { b32 v = ad_remote_debug_check(); if (v) score += 8u; ad_dbg_extras.f_remote = (u32)v; }
#endif

#if AD_ENABLE_WINDOW_SCAN
    { b32 v = ad_find_debugger_window(); if (v) score += 6u; ad_dbg_extras.f_window = (u32)v; }
#endif

#if AD_ENABLE_ODS_TIMING
    { b32 v = ad_output_debug_string_timing(); if (v) score += 4u; ad_dbg_extras.f_ods = (u32)v; }
#endif

#if AD_ENABLE_IFEO_CHECK
    { b32 v = ad_ifeo_debugger_check(); if (v) score += 8u; ad_dbg_extras.f_ifeo = (u32)v; }
#endif

#if AD_ENABLE_JOB_CHECK
    { b32 v = ad_job_object_check(); if (v) score += 5u; ad_dbg_extras.f_job = (u32)v; }
#endif

#if AD_ENABLE_UEF_CHECK
    { b32 v = ad_unhandled_exception_filter_check(); if (v) score += 6u; ad_dbg_extras.f_uef = (u32)v; }
#endif

#if AD_ENABLE_DEBUG_FILTER
    { b32 v = ad_debug_filter_state_check(); if (v) score += 7u; ad_dbg_extras.f_dbg_filter = (u32)v; }
#endif

#if AD_ENABLE_MEMORY_BP_TIMING
    { b32 v = ad_memory_bp_timing(); if (v) score += 5u; ad_dbg_extras.f_mem_bp = (u32)v; }
#endif

#if AD_ENABLE_NTDLL_PAGE_CHECK
    { b32 v = ad_ntdll_page_protection_check(); if (v) score += 8u; ad_dbg_extras.f_ntdll_page = (u32)v; }
#endif

#if AD_ENABLE_DEBUGGER_BEHAVIOR
    { u32 v = ad_self_debug_state_check(); score += v; ad_dbg_extras.f_behavior = v; }
#endif

#if AD_ENABLE_REMOTE_DEBUG
    { b32 v = ad_remote_debug_delta(); if (v) score += 9u; ad_dbg_extras.f_delta = (u32)v; }
#endif

#if AD_ENABLE_TSC_QPC_DRIFT
    { b32 v = ad_tsc_qpc_drift_check(&g_tsc_qpc_ctx);
      if (v) score += 8u; ad_dbg_extras.tsc_drift = (u32)v; }
#endif

#if AD_ENABLE_WIRESHARK
    { u32 v = ad_wireshark_score();
      score += v; ad_dbg_extras.wireshark = v; }
#endif

    return score;
}

#endif // ANTIDEBUG_EXTRA_MASTER_H