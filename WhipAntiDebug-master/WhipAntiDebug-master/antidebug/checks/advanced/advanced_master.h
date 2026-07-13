// ===== file: antidebug/checks/advanced/advanced_master.h =====
//
// Advanced Anti-Debug Master — orchestrates all 10 new advanced checks
// and returns a composite weighted score.
//
#ifndef ANTIDEBUG_ADVANCED_MASTER_H
#define ANTIDEBUG_ADVANCED_MASTER_H

#include "btb_triangulate.h"
#include "ghost_breakpoints.h"
#include "pipeline_desync.h"
#include "scheduler_sync.h"
#include "exception_fingerprint.h"
#include "impossible_states.h"
#include "selfmod_race.h"
#include "pressure_test.h"
#include "temporal_traps.h"
#include "cross_process.h"
#include "heisenberg.h"
#include "anti_scyllahide.h"
#include "anti_titanhide.h"
#include "syscall_verify.h"
#include "working_set_probe.h"
#include "exception_rip_anchor.h"
#include "../../core/config.h"
#include "../integrity/ept_split.h"

// Per-advanced-check debug breakdown
typedef struct {
    u32 ghost_bp_code, ghost_bp_ntdll;
    u32 working_set, exception_rip, cross_process;
    u32 selfmod, scheduler, temporal, pipeline, heisenberg;
    u32 exception_fp, impossible, pressure, scyllahide, titanhide;
    u32 btb;
} ad_dbg_advanced_t;
static volatile ad_dbg_advanced_t ad_dbg_adv = {0};

ANTIDEBUG_INLINE u32 ad_advanced_master(
    const void* code_addr,
    u32 code_size,
    ad_temporal_ctx_t* temporal,
    ad_heisenberg_ctx_t* heisenberg,
    const ad_memkey_t* mk,
    u64 init_tsc)
{
    u32 score = 0;
    AD_ZERO_BUF((void*)&ad_dbg_adv, sizeof(ad_dbg_adv));

#if AD_ENABLE_GHOST_BREAKPOINTS
    { b32 v = ad_ghost_breakpoint_check(code_addr, code_size > 256u ? 256u : code_size);
      if (v) score += 10u; ad_dbg_adv.ghost_bp_code = (u32)v; }
    { b32 v = ad_ghost_breakpoint_ntdll();
      if (v) score += 10u; ad_dbg_adv.ghost_bp_ntdll = (u32)v; }
#endif

#if AD_ENABLE_WORKING_SET_PROBE
    { b32 v = ad_working_set_probe_check();
      if (v) score += 10u; ad_dbg_adv.working_set = (u32)v; }
#endif

#if AD_ENABLE_EXCEPTION_RIP_ANCHOR
    { b32 v = ad_exception_rip_anchor_check();
      if (v) score += 10u; ad_dbg_adv.exception_rip = (u32)v; }
#endif

#if AD_ENABLE_CROSS_PROCESS
    { ad_cross_proc_ctx_t cross_ctx;
      b32 v = ad_cross_process_validate(&cross_ctx);
      if (v) score += 10u; ad_dbg_adv.cross_process = (u32)v; }
#endif

#if AD_ENABLE_SELFMOD_RACE
    { b32 v = ad_selfmod_race_check();
      if (v) score += 9u; ad_dbg_adv.selfmod = (u32)v; }
#endif

#if AD_ENABLE_SCHEDULER_SYNC
    { b32 v = ad_scheduler_sync_check();
      if (v) score += 8u; ad_dbg_adv.scheduler = (u32)v; }
#endif

#if AD_ENABLE_TEMPORAL_TRAPS
    if (temporal && mk) {
        b32 v = ad_temporal_trap_verify(temporal, mk);
        if (v) score += 8u; ad_dbg_adv.temporal = (u32)v;
    }
#endif

#if AD_ENABLE_PIPELINE_DESYNC
    { b32 v = ad_pipeline_desync_check();
      if (v) score += 7u; ad_dbg_adv.pipeline = (u32)v; }
#endif

#if AD_ENABLE_HEISENBERG
    if (heisenberg && mk) {
        b32 v = ad_heisenberg_check(heisenberg, mk);
        if (v) score += 7u; ad_dbg_adv.heisenberg = (u32)v;
    }
#endif

#if AD_ENABLE_EXCEPTION_FINGERPRINT
    { b32 v = ad_exception_fingerprint_check();
      if (v) score += 6u; ad_dbg_adv.exception_fp = (u32)v; }
#endif

#if AD_ENABLE_IMPOSSIBLE_STATES
    { b32 v = ad_impossible_states_check();
      if (v) score += 5u; ad_dbg_adv.impossible = (u32)v; }
#endif

#if AD_ENABLE_PRESSURE_TEST
    { b32 v = ad_pressure_test_check();
      if (v) score += 4u; ad_dbg_adv.pressure = (u32)v; }
#endif

    // TitanHide first — its checks are side-effect-free and record the
    // detection before any risky ScyllaHide probe (e.g. deliberate AV for
    // DR0 capture) that can deadlock under kernel-mode exception hooks.
#if AD_ENABLE_ANTI_TITANHIDE
    { u32 v = ad_titanhide_master();
      score += v; ad_dbg_adv.titanhide = v; }
#endif

#if AD_ENABLE_ANTI_SCYLLAHIDE
    { u32 v = ad_scyllahide_master();
      score += v; ad_dbg_adv.scyllahide = v; }
#endif

#if AD_ENABLE_EPT_SPLIT
    { b32 v = ad_ept_split_check();
      if (v) score += 10u; }
#endif

#if AD_ENABLE_BTB_TRIANGULATE
    { b32 v = ad_btb_triangulate_check();
      if (v) score += 10u; ad_dbg_adv.btb = (u32)v; }
#endif

    // NOTE: ad_sv_master() and ad_scyllahide_master() are called from
    // ad_run_supplemental() in main_example.c instead, because they need
    // native code execution (not VMP Virtualization). The ScyllaHide master
    // above (line 108) is the EXISTING call from before our changes.

    return score;
}

#endif // ANTIDEBUG_ADVANCED_MASTER_H
