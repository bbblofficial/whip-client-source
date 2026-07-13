// ===== file: antidebug/static_analysis_orchestrator.c =====
//
// Façade unique : isole les inclusions <windows.h>-lourdes des modules
// anti-static dans cette TU dédiée pour ne pas polluer main_example.c.
//

#include "static_analysis_orchestrator.h"

// Tous les modules détaillés tirent windows.h, tlhelp32.h, psapi.h, etc.
// On les confine ici.
#include "static_analysis_detection.h"
#include "advanced_static_traps.h"
#include "basic_static_checks.h"
#include "ai_confusion_tricks.h"
#include "comprehensive_static_detection.h"
#include "binary_integrity_paranoid.h"
#include "sandbox_analysis_detection.h"
#include "bypass_detection_ultimate.h"
#include "additional_static_checks.h"

// Per-module scores, exposed for diagnostics in test mode
u32 g_ad_static_score_basic    = 0u;
u32 g_ad_static_score_traps    = 0u;
u32 g_ad_static_score_analysis = 0u;
u32 g_ad_static_score_compre   = 0u;
u32 g_ad_static_score_intgr    = 0u;
u32 g_ad_static_score_sandbox  = 0u;
u32 g_ad_static_score_bypass   = 0u;
u32 g_ad_static_score_addl     = 0u;
u32 g_ad_addl_pdata = 0u, g_ad_addl_cc = 0u, g_ad_addl_kshared = 0u;
u32 g_ad_addl_pdata_ratio = 0u, g_ad_addl_pdata_entries = 0u, g_ad_addl_pdata_oot = 0u;
u32 g_ad_addl_pdata_unsorted = 0u;

static u32 ad_addl_master_traced(void) {
    u32 t = 0u;
    g_ad_addl_pdata   = ad_check_pdata_coverage();   t += g_ad_addl_pdata;
    g_ad_addl_cc      = ad_check_cc_island();        t += g_ad_addl_cc;
    g_ad_addl_kshared = ad_check_kuser_kdebug();     t += g_ad_addl_kshared;
    return t;
}

// Granular bypass breakdown
u32 g_ad_byp_inject  = 0u;
u32 g_ad_byp_hook    = 0u;
u32 g_ad_byp_struct  = 0u;
u32 g_ad_byp_byte    = 0u;
u32 g_ad_byp_tools   = 0u;
u32 g_ad_byp_syscall = 0u;

// Granular comprehens / basic / traps / sandbox breakdown
u32 g_ad_co_envvar = 0u, g_ad_co_reg = 0u, g_ad_co_files = 0u;
u32 g_ad_co_svc = 0u, g_ad_co_bgproc = 0u, g_ad_co_dlls = 0u, g_ad_co_hooks = 0u;
u32 g_ad_ba_entropy = 0u, g_ad_ba_patches = 0u, g_ad_ba_imports = 0u;
u32 g_ad_ba_extsec = 0u, g_ad_ba_pehdr = 0u, g_ad_ba_consist = 0u;
u32 g_ad_tr_ts = 0u, g_ad_tr_fakeexp = 0u, g_ad_tr_tools = 0u;
u32 g_ad_tr_selfv = 0u, g_ad_tr_hidbp = 0u, g_ad_tr_aiconf = 0u;

static u32 ad_compre_master_traced(void) {
    u32 t = 0;
    g_ad_co_envvar = ad_detect_analysis_environment_vars();    t += g_ad_co_envvar;
    g_ad_co_reg    = ad_detect_registry_traces();              t += g_ad_co_reg;
    g_ad_co_files  = ad_detect_analysis_file_traces();         t += g_ad_co_files;
    g_ad_co_svc    = ad_detect_debugging_services();           t += g_ad_co_svc;
    g_ad_co_bgproc = ad_detect_background_analysis_processes(); t += g_ad_co_bgproc;
    g_ad_co_dlls   = ad_detect_analysis_dlls();                t += g_ad_co_dlls;
    g_ad_co_hooks  = ad_detect_system_hooks();                 t += g_ad_co_hooks;
    return t;
}

static u32 ad_basic_master_traced(void) {
    u32 t = 0;
    g_ad_ba_entropy  = ad_check_code_entropy();           t += g_ad_ba_entropy;
    g_ad_ba_patches  = ad_check_simple_patches();         t += g_ad_ba_patches;
    g_ad_ba_imports  = ad_check_suspicious_imports();     t += g_ad_ba_imports;
    g_ad_ba_extsec   = ad_check_extra_sections();         t += g_ad_ba_extsec;
    g_ad_ba_pehdr    = ad_check_pe_header_integrity();    t += g_ad_ba_pehdr;
    g_ad_ba_consist  = ad_general_consistency_check();    t += g_ad_ba_consist;
    return t;
}

static u32 ad_traps_master_traced(void) {
    u32 t = 0;
    g_ad_tr_ts      = ad_check_file_timestamps();         t += g_ad_tr_ts;
    g_ad_tr_fakeexp = ad_fake_export_trap();              t += g_ad_tr_fakeexp;
    g_ad_tr_tools   = ad_detect_analysis_tools();         t += g_ad_tr_tools;
    g_ad_tr_selfv   = ad_self_verifying_code();           t += g_ad_tr_selfv;
    g_ad_tr_hidbp   = ad_detect_hidden_breakpoints();     t += g_ad_tr_hidbp;
    g_ad_tr_aiconf  = ad_confuse_ai_analysis();           t += g_ad_tr_aiconf;
    ad_fake_decryption_algorithm();
    return t;
}

static u32 ad_bypass_master_traced(void) {
    volatile u32 t = 0u;
    __try {
        u32 s;
        s = ad_detect_code_injection_techniques();   g_ad_byp_inject  = s; t += s;
        s = ad_detect_advanced_api_hooking();        g_ad_byp_hook    = s; t += s;
        s = ad_detect_structure_manipulation();      g_ad_byp_struct  = s; t += s;
        s = ad_detect_bytecode_patching();           g_ad_byp_byte    = s; t += s;
        s = ad_detect_automatic_patching_tools();    g_ad_byp_tools   = s; t += s;
        s = ad_detect_syscall_table_modification();  g_ad_byp_syscall = s; t += s;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        t += 300u;
    }
    return t;
}

u32 ad_static_analysis_full_master(void) {
    volatile u32 total = 0u;

    __try {
        u32 s;
        s = ad_basic_master_traced();                 g_ad_static_score_basic    = s; total += s;
        s = ad_traps_master_traced();                 g_ad_static_score_traps    = s; total += s;
        s = ad_static_analysis_master();              g_ad_static_score_analysis = s; total += s;
        s = ad_compre_master_traced();                g_ad_static_score_compre   = s; total += s;
        s = ad_binary_integrity_paranoid_master();    g_ad_static_score_intgr    = s; total += s;
        s = ad_sandbox_analysis_detection_master();   g_ad_static_score_sandbox  = s; total += s;
        s = ad_bypass_master_traced();                g_ad_static_score_bypass   = s; total += s;
        s = ad_addl_master_traced();                  g_ad_static_score_addl     = s; total += s;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        total += 250u;
    }

    return total;
}

void ad_static_deploy_confusion(void) {
    __try {
        ad_deploy_confusion_layer();
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
}

void ad_static_confuse_ai(void) {
    __try {
        ad_confuse_ai_message();
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
}
