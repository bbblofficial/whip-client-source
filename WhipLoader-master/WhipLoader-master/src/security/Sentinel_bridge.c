// Bridge C pour le framework WhipAntiDebugger.
// Le framework est header-only C — on ne peut pas l'inclure depuis du C++
// sans casser des dizaines de tests/casts/goto-past-init. On l'isole dans
// ce TU C, et on expose une API C minimale `extern` pour le C++ (Sentinel.cpp).

// Les macros AD_STRENC_* du framework allouent parfois 1 byte de trop sur
// stack pour les noms encodés. Inoffensif en pratique mais MSVC /RTC1 le
// flag en Debug ("Stack around the variable '_name_buf' was corrupted").
// On désactive RTC pour ce TU uniquement — Release est déjà sans RTC.
#pragma runtime_checks("scu", off)

// /GS- aussi pour éviter le cookie de protection stack qui peut faire
// remonter la même alerte sur certaines macros.
#pragma strict_gs_check(off)

#define AD_ENABLE_POLY_JIT
#define AD_ENABLE_POLY_TRANSIENT

// ─── False-positive suppression for the WhipLoader environment ───────────────
// The framework's defaults assume a clean prod box. WhipLoader runs on dev
// machines with antivirus/EDR/overlays/IDE that legitimately do all the
// "suspicious" things these checks look for. Each disable below has a
// concrete false-positive trigger that produces non-zero score on a
// debugger-free run → Sentinel::taint corrupts auth tokens → server
// rejects → loader unusable.
//
// AV/EDR ntdll user-mode hooks (Defender, Norton, Kaspersky, ESET, …):
#define AD_ENABLE_HOOK_DETECT       0
#define AD_ENABLE_NTDLL_PAGE_CHECK  0
// DBGUI_PATCH disabled: empirically fires on Win11 build 26200 — one of
// DbgUiRemoteBreakin / DbgBreakPoint / NtCreateDebugObject has a first
// byte matching the hook-detection pattern (likely Defender/Win11 25H2+
// inserted a stub on these). Score = 9 on every clean run → FP.
#define AD_ENABLE_DBGUI_PATCH       0
#define AD_ENABLE_ETW_HOOK          0
// AV/EDR DLL injection + module footprint (Defender amsi.dll, EDR shims, …):
// DEBUGGER_DLLS re-enabled: blacklist targets x64dbg/scyllahide/ollydbg names,
// not AV DLLs → clean unless an actual debugger DLL is loaded.
#define AD_ENABLE_DEBUGGER_DLLS     1
#define AD_ENABLE_SUSPICIOUS_MODULES 0
// AV/EDR holds debug-class handles to user processes for telemetry:
#define AD_ENABLE_HANDLE_SCAN       0
// Process list scan: AV agents and dev tools have process names that match
// or fuzz against the debugger blacklist:
#define AD_ENABLE_PROCESS_SCAN      0
#define AD_ENABLE_PROCESS_SIG_SCAN  0
// Steam/Discord/IDE/RTSS opening localhost listeners after init:
#define AD_ENABLE_REMOTE_DEBUG      0
// IDE windows (CLion etc.) with debug-related class names:
#define AD_ENABLE_WINDOW_SCAN       0
// We install our own SetUnhandledExceptionFilter (main.cpp:74 crashHandler) —
// the UEF audit would always flag it as a hook on us:
#define AD_ENABLE_UEF_CHECK         0
// Parent process: if launched from CLion/IDE/console, parent is benign:
#define AD_ENABLE_PARENT_PROCESS    0
// Anti-emulation: flaky on Win11 26200 — first cycle returns 0, subsequent
// cycles intermittently return 1 (CPUID/FPU/RDTSC edge cases). This caused
// Sentinel::taint to corrupt the HWID on the second auth attempt and the
// server reset the connection. Disabled until the underlying flaky sub-check
// is identified and fixed in the framework.
#define AD_ENABLE_ANTI_EMULATION    0

#ifdef WHIP_BYPASS_MODE
// ── Faux positifs spécifiques au contexte bypass (manual-map dans Electron) ──
// Ces checks produisent score > 0 sur toute run propre dans Lunar Client ;
// les builds prod (non-bypass) les gardent actifs car ils détectent de vraies
// menaces sur un box client standard.

// exception_rip_anchor: le loader est toujours manual-mapped (PEB.Ldr absent).
// Le check capture l'adresse de fault et cherche le module dans PEB.Ldr →
// ne le trouve pas → retourne 1 ("DBI détecté") → +10 systématique.
#define AD_ENABLE_EXCEPTION_RIP_ANCHOR 0

// working_set_probe: Windows Defender / EDR patche les stubs ntdll → CoW fork
// → SharedOriginal=0 → +10 sur chaque run propre avec AV actif.
#define AD_ENABLE_WORKING_SET_PROBE    0

// tls_check: g_ad_tls_ran doit être posé par le TLS callback AVANT ad_init().
// En manual-map le mapper doit appeler ExecuteTlsCallbacks explicitement ;
// s'il le fait après DllMain (ou pas du tout) → +8 faux positif.
#define AD_ENABLE_TLS_CHECK            0

// vad_ldr_diff: commentaire dans extra_master.h : "FP when the loader is
// manual-mapped (the host process doesn't ldr-register us so VAD always shows
// entries Ldr doesn't know about)." → +8 sur toute run bypass.
#define AD_ENABLE_VAD_LDR_DIFF         0

// veh_decoy: le probe VEH est perturbé par les handlers CLR/V8 installés
// avant le nôtre dans Electron → faux positif (+5).
#define AD_ENABLE_VEH_DECOY            0

// stack_unwind: le trampoline manual-map + fake RSP + thread noise crée des
// frames inconnues au-dessus du baseline 4 → surplus * 3 points FP.
#define AD_ENABLE_STACK_UNWIND         0

// re_tools: ad_re_score() scanne tous les processus — sur les machines dev
// (PH, Rider, outils Sysinternals, etc.) → extra += 1000 par outil détecté.
#define AD_ENABLE_RE_TOOLS             0

// frida_thread_scan: Node.js / V8 crée des threads worker dont les noms
// peuvent matcher les patterns Frida → faux positif.
#define AD_ENABLE_FRIDA_SCAN           0

// memory_bp_timing: check basé sur les timings mémoire — peu fiable sur les
// machines modernes avec CPU throttling / power states.
#define AD_ENABLE_MEMORY_BP_TIMING     0

// job_check: Lunar Client peut tourner dans un job object Windows
// (job du launcher ou AppContainer) → faux positif (+5).
#define AD_ENABLE_JOB_CHECK            0

// cross_timer: triangulation multi-timer — VMware / Hyper-V / WSL2 font
// diverger les timers → faux positif sur toute machine avec hyperviseur.
#define AD_ENABLE_CROSS_TIMER          0
#endif // WHIP_BYPASS_MODE

#include "antidebug/core/syscall_bridge.h"
#include "antidebug/dispatcher/dispatcher.h"
// thread_noise.h pour ad_noise_swarm_stop (kill les noise threads cachés au
// shutdown — sinon ils tournent toujours quand le process exit / quand la
// mapper restore le PEB en manual-map mode).
#include "antidebug/stack/thread_noise.h"

// MSVC-supplied symbol that always resolves to the actual loaded base of
// THIS module — survives manual mapping, ASLR, and rebase relocation. Used
// instead of NULL in ad_init so the framework's code_hash / anti_patch /
// page_rwx checks inspect WhipLoader's own image, not the host EXE that
// PEB.ImageBase happens to point at when MM'd by WhipPeLoader.
extern char __ImageBase;

// PAS d'include <windows.h> ici : le framework déclare ses propres
// prototypes pour RtlCaptureContext, RaiseException, etc. — un include de
// winnt.h/errhandlingapi.h provoquerait des conflits de linkage. On vit
// avec les types et helpers déjà fournis par le framework.

#include <intrin.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

// ────────────────────────────────────────────────────────────────────────────
// State global (chiffré). Stocké dans .bss puis encrypted via vault.
// ────────────────────────────────────────────────────────────────────────────
static ad_state_t g_state;

// Score chiffré (XOR avec g_score_key). Re-rolled à chaque store pour
// empêcher un dump mémoire de retrouver le score par diff entre snapshots.
static volatile unsigned __int64 g_score_enc = 0;
static volatile unsigned __int64 g_score_key = 0;

// Init flag chiffré. 0 = pas init. Si reverser le force, ad_init n'est jamais
// appelé donc canary == 0 → score sera toujours énorme via self_poison.
static volatile unsigned int g_initialized_enc = 0;
static volatile unsigned int g_initialized_key = 0;

// Last cycle check counters — updated by run_one_cycle(), read by
// sentinel_bridge_checks_run/hit() for the REVERSE_DETECTED packet.
static volatile unsigned int g_checks_run = 0;
static volatile unsigned int g_checks_hit = 0;

// RE tool hit mask from the last sentinel_bridge_re_detect() call.
// Bit layout matches the sentinel_th32_scan() hit_mask constants:
//   0x001 = x64dbg/x32dbg   0x002 = CheatEngine   0x004 = Fiddler
//   0x008 = IDA/Ghidra       0x010 = Wireshark      0x020 = Cutter
//   0x040 = OllyDbg          0x080 = WinDbg         0x200 = Charles
static volatile unsigned int g_redetect_mask = 0;

#define INIT_MAGIC 0xC0DEC0DEu
#define BAD_SCORE  0xDEADBEEFu

// ────────────────────────────────────────────────────────────────────────────
// Helpers internes
// ────────────────────────────────────────────────────────────────────────────
static __inline void store_score(unsigned int score) {
    unsigned __int64 key = __rdtsc() ^ ((unsigned __int64)(uintptr_t)&g_score_key << 17);
    g_score_key = key;
    g_score_enc = (unsigned __int64)score ^ key;
}

static __inline unsigned int load_score(void) {
    return (unsigned int)(g_score_enc ^ g_score_key);
}

static __inline void store_initialized(unsigned int v) {
    unsigned int key = (unsigned int)__rdtsc();
    g_initialized_key = key;
    g_initialized_enc = v ^ key;
}

static __inline unsigned int load_initialized(void) {
    return g_initialized_enc ^ g_initialized_key;
}

// SplitMix64 — diffusion bit-mixing rapide pour générer keystream.
static __inline unsigned __int64 mix64(unsigned __int64 x) {
    x += 0x9E3779B97F4A7C15ULL;
    x = (x ^ (x >> 30)) * 0xBF58476D1CE4E5B9ULL;
    x = (x ^ (x >> 27)) * 0x94D049BB133111EBULL;
    return x ^ (x >> 31);
}

// Forward declarations — bodies defined later in this file.
static void sentinel_log_score(const char* ctx_label, unsigned int score);

static volatile unsigned int g_log_cycle = 0;

static void log_detections(const ad_result_t* r, int patched) {
    // File-log disabled — no on-disk detection trace.
    g_log_cycle++;
    (void)r; (void)patched;
}

// Run un cycle complet de checks et stocke le score.
// noinline pour que VMP puisse virtualiser tout le body.
static __declspec(noinline) void run_one_cycle(void) {
    ad_dbg_layers.enabled = 1;
    ad_result_t r = ad_run_hardened(&g_state);
    AD_DECRYPT_RESULT(r);

    // Verify le dispatcher n'a pas été patché pour retourner zero.
    // ad_verify_dispatcher_alive returns 1 = tampered, 0 = clean.
    // Si patch détecté → score énorme silencieux (taint corrompt tout).
    if (ad_verify_result(&r)) {
        log_detections(&r, 1);
        store_score(BAD_SCORE);
        return;
    }

    log_detections(&r, 0);
    g_checks_run = r.checks_run;
    g_checks_hit = r.checks_hit;
    /* Keep the maximum score ever seen — never overwrite a high score with a
     * lower one. One-shot checks (JIT warmup, timing spike) fire during init;
     * subsequent recheck() cycles produce score=0 for the same check and must
     * NOT erase the earlier detection. */
    {
        unsigned int prev = load_score();
        unsigned int s = r.score > prev ? r.score : prev;
        store_score(s);
    }
}

// ────────────────────────────────────────────────────────────────────────────
// API C exposée au C++
// ────────────────────────────────────────────────────────────────────────────
void sentinel_bridge_init(void) {
    // Pass &__ImageBase so the framework's code_hash / anti_patch / page_rwx
    // checks scan THIS module. NULL would fall back to PEB.ImageBase which,
    // for a manual-mapped loader (WhipPeLoader → WhipLoader), points at the
    // host EXE — wrong target, score sautille at every host rebuild.
    ad_init(&g_state, (void*)&__ImageBase, 0u);

    // ── Install state that ad_extra_master verifies ─────────────────────
    // Without these calls the corresponding verifiers fire on every clean
    // run as false positives:
    //   - ad_anti_attach_set_no_inherit() clears ProcessDebugFlags so
    //     ad_anti_attach_verify() reads 0 (= NoDebugInherit set, clean).
    //     Without this call the flag stays at default 1 → +6.
    //   - ad_veh_install() registers 4 vectored exception handlers that
    //     ad_veh_check() probes via a magic RaiseException. Without this
    //     the probe finds zero counters → +5.
    ad_anti_attach_set_no_inherit();
    ad_veh_install();

    store_initialized(INIT_MAGIC);
    run_one_cycle();
    sentinel_log_score("init:after_first_cycle", load_score());
}

void sentinel_bridge_cleanup(void) {
    // Kill the noise swarm started by ad::StackProtect / ad_stack_protect_init
    // (safe even if it was never started — internal SSN check no-ops).
    ad_noise_swarm_stop();

    if (load_initialized() != INIT_MAGIC) return;
    ad_veh_uninstall();
    store_initialized(0u);
}

static void sentinel_log_score(const char* ctx_label, unsigned int score) {
    // File-log disabled — no on-disk score trace.
    (void)ctx_label; (void)score;
}

void sentinel_bridge_taint(unsigned char* data, unsigned int length) {
    unsigned int i;
    unsigned int score;
    unsigned __int64 state;

    if (!data || length == 0u) return;

    if (load_initialized() != INIT_MAGIC) {
        sentinel_log_score("taint:NOT_INIT", 0xA5A5A5A5u);
        for (i = 0; i < length; ++i) data[i] ^= 0xA5u;
        return;
    }

    score = load_score();
    sentinel_log_score("taint:check", score);

    // Score noise floor — config.h:AD_SCORE_NOISE_FLOOR documents that timing
    // checks, ghost thread, pool workers, and watchdog startup all produce
    // ~25-40 noise points on clean systems. Anything below 50 is considered
    // clean noise. Especially relevant for manual-mapped builds (WhipPeLoader)
    // where the framework can't find the loader EXE in PEB.Ldr — without this
    // floor, every clean cycle would taint legitimate auth tokens and the
    // server would reject them.
    if (score < 50u) return;

    state = mix64((unsigned __int64)score | ((unsigned __int64)length << 32));
    for (i = 0; i < length; ++i) {
        if ((i & 7u) == 0u) state = mix64(state);
        data[i] ^= (unsigned char)(state >> ((i & 7u) * 8u));
    }
}

void sentinel_bridge_recheck(void) {
    if (load_initialized() != INIT_MAGIC) {
        store_score(BAD_SCORE);
        sentinel_log_score("recheck:NOT_INIT", BAD_SCORE);
        return;
    }
    run_one_cycle();
    sentinel_log_score("recheck:after", load_score());
}

void sentinel_bridge_verify(void) {
    ad_result_t r = ad_run_hardened(&g_state);
    unsigned int prev;
    AD_DECRYPT_RESULT(r);
    // ad_verify_result returns 1 = tampered, 0 = clean.
    if (ad_verify_result(&r)) {
        store_score(BAD_SCORE);
        sentinel_log_score("verify:TAMPERED", BAD_SCORE);
    } else {
        prev = load_score();
        store_score(prev > r.score ? prev : r.score);
        sentinel_log_score("verify:after", load_score());
    }
}

unsigned __int64 sentinel_bridge_snapshot(void) {
    return g_score_enc ^ ((unsigned __int64)g_score_key << 1);
}

/* Decrypted score (0 if clean, >=50 if debugger detected). Used by
 * Sentinel::deriveAuthTag — the server recomputes with score=0, so any
 * non-zero score from this loader breaks the HMAC and gets rejected.
 * Distinct from snapshot() which returns a tamper-detection value. */
unsigned int sentinel_bridge_score(void) {
    return load_score();
}

unsigned int sentinel_bridge_checks_run(void) { return g_checks_run; }
unsigned int sentinel_bridge_checks_hit(void) { return g_checks_hit; }


/* Toolhelp32-based process scan — no raw syscalls, uses kernel32 exports only.
 * Fallback for systems where NtQuerySystemInformation stub scanning fails
 * (HVCI, Credential Guard, Win11 26200+ kernel mitigations).
 *
 * PROCESSENTRY32W layout (x64):
 *   +0  dwSize           (DWORD)
 *   +4  cntUsage         (DWORD)
 *   +8  th32ProcessID    (DWORD)
 *   +12 th32DefaultHeapID(ULONG_PTR = 8 bytes on x64)
 *   +20 th32ModuleID     (DWORD)
 *   +24 cntThreads       (DWORD)
 *   +28 th32ParentProcessID (DWORD)
 *   +32 pcPriClassBase   (LONG)
 *   +36 dwFlags          (DWORD)
 *   +40 szExeFile        (WCHAR[MAX_PATH] = 520 bytes)
 *   total = 560 bytes
 */
static int sentinel_th32_scan(void) {
    typedef void* (__stdcall *FN_CT)(unsigned int, unsigned int);
    typedef int   (__stdcall *FN_PF)(void*, void*);
    typedef int   (__stdcall *FN_PN)(void*, void*);
    typedef int   (__stdcall *FN_CH)(void*);

    FN_CT pCT = (FN_CT)ad_resolve_api(AD_HASH_KERNEL32, AD_HASH("CreateToolhelp32Snapshot"));
    FN_PF pPF = (FN_PF)ad_resolve_api(AD_HASH_KERNEL32, AD_HASH("Process32FirstW"));
    FN_PN pPN = (FN_PN)ad_resolve_api(AD_HASH_KERNEL32, AD_HASH("Process32NextW"));
    FN_CH pCH = (FN_CH)ad_resolve_api(AD_HASH_KERNEL32, AD_HASH("CloseHandle"));
    if (!pCT || !pPF || !pPN || !pCH) return 0;

    void* snap = pCT(0x2u, 0u); /* TH32CS_SNAPPROCESS */
    if (!snap || snap == (void*)(u64)~(u64)0u) return 0;

    /* RE tool name needles (wide chars). */
    static const u16 n_x64  [] = {'x','6','4','d','b','g'};
    static const u16 n_x32  [] = {'x','3','2','d','b','g'};
    static const u16 n_ce   [] = {'c','h','e','a','t','e','n','g','i','n','e'};
    static const u16 n_olly [] = {'o','l','l','y','d','b','g'};
    static const u16 n_fid  [] = {'f','i','d','d','l','e','r'};
    static const u16 n_ghid [] = {'g','h','i','d','r','a'};
    static const u16 n_wdbg [] = {'w','i','n','d','b','g'};
    static const u16 n_cut  [] = {'c','u','t','t','e','r'};
    static const u16 n_ch   [] = {'c','h','a','r','l','e','s'};

    u8 pe[560]; *(u32*)pe = 560u;
    u32 our_pid = (u32)(u64)__readgsqword(0x40);
    int found = 0;
    const char* label = "UNKNOWN_TH32";
    unsigned int hit_mask = 0u;

    if (pPF(snap, pe)) {
        do {
            u32 pid = *(u32*)(pe + 8);
            if (pid == our_pid || pid == 0u || pid == 4u) continue;

            const u16* nm = (const u16*)(pe + 40);
            u32 nc = 0;
            while (nc < 260u && nm[nc]) nc++;
            if (!nc) continue;

            if (ad_ws_image_is_wireshark_family(nm, nc)) {
                label = "WIRESHARK_TH32"; hit_mask = 0x10u; found = 1; break;
            }
            if (ad_id_image_is_ida_family(nm, nc)) {
                label = "IDA_TH32"; hit_mask = 0x08u; found = 1; break;
            }
            if (ad_ws_wcontains_ci(nm,nc,n_x64, 6u) ||
                ad_ws_wcontains_ci(nm,nc,n_x32, 6u)) {
                label = "X64DBG_TH32"; hit_mask = 0x01u; found = 1; break;
            }
            if (ad_ws_wcontains_ci(nm,nc,n_ce,  11u)) {
                label = "CE_TH32"; hit_mask = 0x02u; found = 1; break;
            }
            if (ad_ws_wcontains_ci(nm,nc,n_olly, 7u)) {
                label = "OLLY_TH32"; hit_mask = 0x40u; found = 1; break;
            }
            if (ad_ws_wcontains_ci(nm,nc,n_fid,  7u)) {
                label = "FIDDLER_TH32"; hit_mask = 0x04u; found = 1; break;
            }
            if (ad_ws_wcontains_ci(nm,nc,n_ghid, 6u)) {
                label = "GHIDRA_TH32"; hit_mask = 0x08u; found = 1; break;
            }
            if (ad_ws_wcontains_ci(nm,nc,n_wdbg, 6u)) {
                label = "WINDBG_TH32"; hit_mask = 0x80u; found = 1; break;
            }
            if (ad_ws_wcontains_ci(nm,nc,n_cut,  6u)) {
                label = "CUTTER_TH32"; hit_mask = 0x20u; found = 1; break;
            }
            if (ad_ws_wcontains_ci(nm,nc,n_ch,   7u)) {
                label = "CHARLES_TH32"; hit_mask = 0x200u; found = 1; break;
            }
        } while (pPN(snap, pe));
    }
    pCH(snap);

    if (found) { g_redetect_mask = hit_mask; }
    return found;
}

/* VMP-specific: check if ScyllaHide has been injected into our process.
 * ScyllaHide's DLL injection mode drops a helper DLL to patch VMP anti-debug
 * calls in-place; these names appear in our own module list when active.
 * Uses ad_resolve_api to avoid a direct GetModuleHandleA import visible to reversers. */
static int check_scyllahide_self(void) {
    typedef void* (__stdcall *FN_GMH)(const char*);
    FN_GMH pGMH = (FN_GMH)ad_resolve_api(AD_HASH_KERNEL32, AD_HASH("GetModuleHandleA"));
    if (!pGMH) return 0;

    static const char* const kNames[] = {
        "ScyllaHide.dll",
        "HideDebugger.dll",
        "scyllahide.dll",
        "hidedebugger.dll",
        NULL
    };
    int i;
    for (i = 0; kNames[i]; i++) {
        if (pGMH(kNames[i])) { g_redetect_mask = 0x400u; return 1; }
    }
    return 0;
}

/* VMP-specific: check if hardware breakpoints are set on the current thread.
 * Reversers use DR0-DR3 to set breakpoints at VM_BEGIN/VM_END to trace VMP
 * handlers without single-stepping. Checks the current thread only (fast, no
 * snapshot). ScyllaHide fakes GetThreadContext to return zeroed DRs once
 * attached — this check is most reliable in the pre-attach auth phase.
 *
 * CONTEXT (AMD64) layout (no <windows.h> needed):
 *   +0x030  ContextFlags   (DWORD)  — CONTEXT_DEBUG_REGISTERS = 0x00100010
 *   +0x048  Dr0  +0x050 Dr1  +0x058 Dr2  +0x060 Dr3
 *   +0x068  Dr6  +0x070 Dr7
 *   Total size: 0x4D0 bytes, must be 16-byte aligned.
 * GetCurrentThread() pseudo-handle = (void*)(intptr_t)(-2). */
static int check_hardware_bp_self(void) {
    typedef int (__stdcall *FN_GTC)(void*, void*);
    FN_GTC pGTC = (FN_GTC)ad_resolve_api(AD_HASH_KERNEL32, AD_HASH("GetThreadContext"));
    if (!pGTC) return 0;

    __declspec(align(16)) unsigned char ctx[0x4D0];
    int k;
    for (k = 0; k < 0x80; k++) ctx[k] = 0;        /* zero up to Dr7+8 */
    *(unsigned int*)(ctx + 0x30) = 0x00100010u;    /* CONTEXT_DEBUG_REGISTERS */

    void* hSelf = (void*)(intptr_t)(-2);           /* GetCurrentThread() */
    if (!pGTC(hSelf, ctx)) return 0;

    u64 dr0 = *(u64*)(ctx + 0x48);
    u64 dr1 = *(u64*)(ctx + 0x50);
    u64 dr2 = *(u64*)(ctx + 0x58);
    u64 dr3 = *(u64*)(ctx + 0x60);
    u64 dr7 = *(u64*)(ctx + 0x70);

    /* DR7 bits 0,2,4,6 = local enable for DR0-DR3 */
    if ((dr0 || dr1 || dr2 || dr3) && (dr7 & 0xFFu)) {
        g_redetect_mask = 0x800u;
        return 1;
    }
    return 0;
}

/* x64dbg artifact detection via file and named-pipe checks.
 *
 * 1. .dd64 database — x64dbg creates <target_path>.dd64 when it opens a binary.
 *    If we find it next to our exe, this specific loader was debugged with x64dbg.
 *
 * 2. Named pipe enumeration — x64dbg bridge (x64bridge.dll) creates a named pipe
 *    for GUI↔engine IPC; the name always contains "x64dbg". Enumerating \\.\pipe\*
 *    with FindFirstFileW/FindNextFileW works on NPFS and catches any version.
 *
 * Both use ad_resolve_api to avoid visible kernel32 imports. */
static int check_x64dbg_artifacts(void) {
    typedef void* (__stdcall *FN_GMF)(void*, char*, unsigned int);
    typedef void* (__stdcall *FN_CFA)(const char*, unsigned int, unsigned int,
                                      void*, unsigned int, unsigned int, void*);
    typedef int   (__stdcall *FN_CH)(void*);
    typedef void* (__stdcall *FN_FFF)(const u16*, void*);
    typedef int   (__stdcall *FN_FNF)(void*, void*);
    typedef int   (__stdcall *FN_FC)(void*);

    FN_GMF pGMF = (FN_GMF)ad_resolve_api(AD_HASH_KERNEL32, AD_HASH("GetModuleFileNameA"));
    FN_CFA pCFA = (FN_CFA)ad_resolve_api(AD_HASH_KERNEL32, AD_HASH("CreateFileA"));
    FN_CH  pCH  = (FN_CH) ad_resolve_api(AD_HASH_KERNEL32, AD_HASH("CloseHandle"));

    /* 1. Check for .dd64 next to our executable */
    if (pGMF && pCFA && pCH) {
        char exePath[520] = {0};
        if (pGMF(NULL, exePath, 512u)) {
            int len = 0;
            while (exePath[len]) len++;
            if (len > 0 && len < 512) {
                exePath[len+0] = '.'; exePath[len+1] = 'd';
                exePath[len+2] = 'd'; exePath[len+3] = '6';
                exePath[len+4] = '4'; exePath[len+5] = '\0';
                void* hFile = pCFA(exePath, 0x80000000u /*GENERIC_READ*/,
                                   0x07u /*SHARE_ALL*/, NULL,
                                   3u /*OPEN_EXISTING*/, 0u, NULL);
                /* (void*)(~(u64)0u) = 0xFFFFFFFFFFFFFFFF = INVALID_HANDLE_VALUE on x64.
                 * (u64)(u32)~0u would give 0x00000000FFFFFFFF (zero-extended) — wrong. */
                if (hFile && hFile != (void*)(~(u64)0u)) {
                    pCH(hFile);
                    g_redetect_mask = 0x1000u;
                    return 1;
                }
            }
        }
    }

    /* 2. Enumerate \\.\pipe\* for any pipe whose name contains "x64dbg".
     * WIN32_FIND_DATAW manual layout (x64, no windows.h):
     *   +0   dwFileAttributes (4 bytes)
     *   +4   ftCreationTime   (8 bytes)
     *   +12  ftLastAccessTime (8 bytes)
     *   +20  ftLastWriteTime  (8 bytes)
     *   +28  nFileSizeHigh    (4 bytes)
     *   +32  nFileSizeLow     (4 bytes)
     *   +36  dwReserved0      (4 bytes)
     *   +40  dwReserved1      (4 bytes)
     *   +44  cFileName        (WCHAR[260] = 520 bytes)
     *   +564 cAlternateFileName (WCHAR[14] = 28 bytes)  total: 592 bytes */
    FN_FFF pFFF = (FN_FFF)ad_resolve_api(AD_HASH_KERNEL32, AD_HASH("FindFirstFileW"));
    FN_FNF pFNF = (FN_FNF)ad_resolve_api(AD_HASH_KERNEL32, AD_HASH("FindNextFileW"));
    FN_FC  pFC  = (FN_FC) ad_resolve_api(AD_HASH_KERNEL32, AD_HASH("FindClose"));

    if (pFFF && pFNF && pFC) {
        static const u16 kPipePath[] = {
            '\\','\\','.','\\','p','i','p','e','\\','*', 0
        };
        unsigned char fd[592];
        *(unsigned int*)fd = 592u; /* dwSize = sizeof(WIN32_FIND_DATAW) */
        void* hFind = pFFF(kPipePath, fd);
        void* invH  = (void*)(~(u64)0u); /* 0xFFFFFFFFFFFFFFFF = INVALID_HANDLE_VALUE */
        if (hFind && hFind != invH) {
            int found = 0;
            do {
                const u16* name = (const u16*)(fd + 44);
                int i;
                for (i = 0; name[i] && !found; i++) {
                    u16 c = name[i];
                    if ((c == 'x' || c == 'X') &&
                        name[i+1] == '6' && name[i+2] == '4' &&
                        (name[i+3] == 'd' || name[i+3] == 'D') &&
                        (name[i+4] == 'b' || name[i+4] == 'B') &&
                        (name[i+5] == 'g' || name[i+5] == 'G'))
                        found = 1;
                }
            } while (!found && pFNF(hFind, fd));
            pFC(hFind);
            if (found) { g_redetect_mask = 0x2000u; return 1; }
        }
    }

    return 0;
}

/* Fresh one-shot scan for RE/analysis tools — does NOT use the cached score.
 * Returns 1 if Wireshark, IDA, x64dbg, Cheat Engine, ScyllaHide, hardware BPs,
 * or any other tool is detected; 0 if clean.
 * Used by ReverseDetector to trigger an immediate shutdown before auth. */
int sentinel_bridge_re_detect(void) {
    unsigned int m;

    /* VMP-specific checks first (fastest, no process snapshot needed) */
    if (check_scyllahide_self()) return 1;   /* ScyllaHide DLL in our process */
    if (check_hardware_bp_self()) return 1;  /* HWBPs on current thread */

    /* x64dbg file/pipe artifacts (fast, no process snapshot) */
    if (check_x64dbg_artifacts()) return 1;

    /* Toolhelp32 process name scan */
    if (sentinel_th32_scan()) return 1;

    /* NtQSI-based scans */
    m = ad_wireshark_detect();
    if (m) { g_redetect_mask = 0x010u; return 1; }

    m = (unsigned int)ad_ida_detect();
    if (m) { g_redetect_mask = 0x008u; return 1; }

#ifndef WHIP_BYPASS_MODE
    /* ad_re_detect() scans process list + modules for RE tools (Process Hacker,
     * Frida, etc.). En bypass (Electron), des outils légitimes sur la machine
     * dev déclenchent des faux positifs — désactivé uniquement en bypass. */
    m = (unsigned int)ad_re_detect();
    if (m) { g_redetect_mask = m; return 1; }
#endif

    return 0;
}

unsigned int sentinel_bridge_redetect_mask(void) { return g_redetect_mask; }

/* Build a bitmask of individual checks that fired in the last run_one_cycle().
 * Bit layout mirrors ReverseDetectedHandler.FLAG_* on the server side so the
 * server's describeFlags() renders human-readable names in the log/webhook.
 *   bit  0 = PEB.BeingDebugged    bit  1 = NtGlobalFlag
 *   bit  2 = HeapFlags            bit  3 = DebugPort
 *   bit  4 = DebugFlags           bit  5 = HWBP
 *   bit  6 = RDTSC_TIMING         bit  7 = SYSCALL_TIMING
 *   bit  8 = NtClose              bit  9 = RDTSC_DOUBLE
 *   bit 10 = NTDLL_HOOKED         bit 11 = PAGE_RWX
 *   bit 31 = DISPATCHER_PATCHED (score was forced to BAD_SCORE)            */
unsigned int sentinel_bridge_get_hit_flags(void) {
    unsigned int bits = 0u;
    if (!ad_dbg_layers.enabled) return 0u;
    if (ad_dbg_layers.f_peb_debug)    bits |= (1u << 0);
    if (ad_dbg_layers.f_ntgflag)      bits |= (1u << 1);
    if (ad_dbg_layers.f_heap)         bits |= (1u << 2);
    if (ad_dbg_layers.f_dbg_port)     bits |= (1u << 3);
    if (ad_dbg_layers.f_dbg_flags)    bits |= (1u << 4);
    if (ad_dbg_layers.f_hwbp)         bits |= (1u << 5);
    if (ad_dbg_layers.f_timing)       bits |= (1u << 6);
    if (ad_dbg_layers.f_syscall)      bits |= (1u << 7);
    if (ad_dbg_layers.f_ntclose)      bits |= (1u << 8);
    if (ad_dbg_layers.f_rdtsc_dbl)    bits |= (1u << 9);
    if (ad_dbg_layers.f_ntdll_hooked) bits |= (1u << 10);
    if (ad_dbg_layers.f_page_rwx)     bits |= (1u << 11);
    if (load_score() == BAD_SCORE)    bits |= (1u << 31);
    return bits;
}

/* Serialise the layer-by-layer score breakdown captured by the last
 * run_one_cycle() into a compact key=value string for the REVERSE_DETECTED
 * report field. The server logs this verbatim so admins can tell exactly
 * which layer pushed the score over the threshold. */
void sentinel_bridge_get_layer_report(char* buf, unsigned int buflen) {
    if (!buf || buflen < 4u) return;
    if (!ad_dbg_layers.enabled) {
        buf[0] = '?'; buf[1] = '\0';
        return;
    }
    snprintf(buf, (size_t)buflen,
        "corr=%u deep=%u cross=%u patch=%u exotic=%u adv=%u extra=%u poison=%u "
        "hits=%u/12 peb=%u ntgf=%u heap=%u port=%u flg=%u hwbp=%u "
        "tim=%u sys=%u ntcl=%u rdtsc2=%u hook=%u rwx=%u",
        ad_dbg_layers.correlation,  ad_dbg_layers.deep,
        ad_dbg_layers.cross,        ad_dbg_layers.patch,
        ad_dbg_layers.exotic,       ad_dbg_layers.advanced,
        ad_dbg_layers.extra,        ad_dbg_layers.self_poison_final,
        ad_dbg_layers.raw_hits,
        ad_dbg_layers.f_peb_debug,  ad_dbg_layers.f_ntgflag,
        ad_dbg_layers.f_heap,       ad_dbg_layers.f_dbg_port,
        ad_dbg_layers.f_dbg_flags,  ad_dbg_layers.f_hwbp,
        ad_dbg_layers.f_timing,     ad_dbg_layers.f_syscall,
        ad_dbg_layers.f_ntclose,    ad_dbg_layers.f_rdtsc_dbl,
        ad_dbg_layers.f_ntdll_hooked, ad_dbg_layers.f_page_rwx);
}
