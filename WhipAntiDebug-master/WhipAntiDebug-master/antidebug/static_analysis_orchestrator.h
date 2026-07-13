// ===== file: antidebug/static_analysis_orchestrator.h =====
//
// Façade pour la suite anti-analyse statique. Tous les modules détaillés
// (static_analysis_detection, advanced_static_traps, basic_static_checks,
// comprehensive_static_detection, binary_integrity_paranoid,
// sandbox_analysis_detection, bypass_detection_ultimate) tirent <windows.h>
// et entrent en conflit avec les prototypes manuels du projet (RtlCaptureContext,
// RaiseException, etc.). On les regroupe dans `static_analysis_orchestrator.c`
// et on expose une seule fonction propre au reste du projet.
//

#ifndef ANTIDEBUG_STATIC_ANALYSIS_ORCHESTRATOR_H
#define ANTIDEBUG_STATIC_ANALYSIS_ORCHESTRATOR_H

#include "core/types.h"

#ifdef __cplusplus
extern "C" {
#endif

// Run la batterie complète anti-analyse statique. Retourne un score cumulatif
// — non-zéro = analyse statique probable, à additionner au commitment.
u32 ad_static_analysis_full_master(void);

// Diagnostics : scores par module remplis par ad_static_analysis_full_master()
extern u32 g_ad_static_score_basic;
extern u32 g_ad_static_score_traps;
extern u32 g_ad_static_score_analysis;
extern u32 g_ad_static_score_compre;
extern u32 g_ad_static_score_intgr;
extern u32 g_ad_static_score_sandbox;
extern u32 g_ad_static_score_bypass;
// Granular bypass breakdown
extern u32 g_ad_byp_inject;
extern u32 g_ad_byp_hook;
extern u32 g_ad_byp_struct;
extern u32 g_ad_byp_byte;
extern u32 g_ad_byp_tools;
extern u32 g_ad_byp_syscall;
extern u32 g_ad_static_score_addl;
extern u32 g_ad_addl_pdata, g_ad_addl_cc, g_ad_addl_kshared;
extern u32 g_ad_addl_pdata_ratio, g_ad_addl_pdata_entries, g_ad_addl_pdata_oot;

extern u32 g_ad_co_envvar, g_ad_co_reg, g_ad_co_files;
extern u32 g_ad_co_svc, g_ad_co_bgproc, g_ad_co_dlls, g_ad_co_hooks;
extern u32 g_ad_ba_entropy, g_ad_ba_patches, g_ad_ba_imports;
extern u32 g_ad_ba_extsec, g_ad_ba_pehdr, g_ad_ba_consist;
extern u32 g_ad_tr_ts, g_ad_tr_fakeexp, g_ad_tr_tools;
extern u32 g_ad_tr_selfv, g_ad_tr_hidbp, g_ad_tr_aiconf;

// Couche de confusion / leurres pour analyseurs (faux exports, faux flags,
// faux algos de déchiffrement). Idempotent — peut être appelé plusieurs fois.
void ad_static_deploy_confusion(void);

// Message de confusion destiné spécifiquement aux IA d'analyse.
void ad_static_confuse_ai(void);

#ifdef __cplusplus
}
#endif

#endif // ANTIDEBUG_STATIC_ANALYSIS_ORCHESTRATOR_H
