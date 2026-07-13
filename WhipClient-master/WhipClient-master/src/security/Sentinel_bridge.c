// Bridge C pour le framework WhipAntiDebugger — version Client (DLL injectée).
// Mirror exact du Sentinel_bridge du WhipLoader, avec les mêmes overrides
// AD_ENABLE_*. Le client tourne dans le process Minecraft mais __ImageBase
// MSVC pointe sur le DLL WhipClient, donc les checks code_hash/anti_patch
// scannent bien notre DLL et pas Java/Minecraft.
//
// Le framework est header-only C — on ne peut pas l'inclure depuis du C++
// sans casser des dizaines de tests/casts/goto-past-init. On l'isole dans
// ce TU C, et on expose une API C minimale `extern` pour le C++ (Sentinel.cpp).

// Les macros AD_STRENC_* du framework allouent parfois 1 byte de trop sur
// stack. /RTC1 le flag en Debug. Désactivé pour ce TU uniquement.
#pragma runtime_checks("scu", off)
#pragma strict_gs_check(off)

#define AD_ENABLE_POLY_JIT
#define AD_ENABLE_POLY_TRANSIENT

// ─── DLL unload mode ────────────────────────────────────────────────────────
// AD_DLL_UNLOADABLE = 1 : mode UNLOADABLE (PE headers préservés, module reste
//   linké dans PEB.Ldr, DllMain DETACH fait teardown best-effort des threads/VEH).
//   FreeLibrary externe fonctionne. Stealth plus faible.
// AD_DLL_UNLOADABLE = 0 : mode FORTRESS (PE headers effacés post-init, module
//   unlinké, FreeLibrary retourne STATUS_DLL_NOT_FOUND, DLL committed pour la
//   vie du process). Stealth fort mais NON-DÉCHARGEABLE.
//
// Standalone (sans loader) : on a besoin de pouvoir unload proprement après
//   user shutdown → mode A.
// Avec loader : le loader gère la lifetime du process, on veut le maximum de
//   stealth → mode B.
#ifdef LOADER_IPC
#define AD_DLL_UNLOADABLE 0   // FORTRESS — pas d'unload, max stealth
#else
#define AD_DLL_UNLOADABLE 1   // UNLOADABLE — clean shutdown standalone
#endif

// ─── False-positive suppression for the WhipClient runtime ──────────────────
// Same overrides as the WhipLoader — Minecraft is a Java process loaded with
// JVM agents, hooks, and overlay libraries (Discord overlay, OBS, GameBar)
// that legitimately do "suspicious" things. Each disable below has a
// concrete trigger. See WhipLoader/src/security/Sentinel_bridge.c for the
// detailed empirical history (Win11 26200 dbgui_patch FP, anti_emulation
// flakiness, etc.).
#define AD_ENABLE_HOOK_DETECT       0
#define AD_ENABLE_NTDLL_PAGE_CHECK  0
#define AD_ENABLE_DBGUI_PATCH       0
#define AD_ENABLE_ETW_HOOK          0
#define AD_ENABLE_DEBUGGER_DLLS     1
#define AD_ENABLE_SUSPICIOUS_MODULES 0
#define AD_ENABLE_HANDLE_SCAN       0
#define AD_ENABLE_PROCESS_SCAN      0
#define AD_ENABLE_PROCESS_SIG_SCAN  0
#define AD_ENABLE_REMOTE_DEBUG      1
#define AD_ENABLE_WINDOW_SCAN       0
#define AD_ENABLE_UEF_CHECK         0
#define AD_ENABLE_PARENT_PROCESS    0
#define AD_ENABLE_ANTI_EMULATION    0

#include "antidebug/core/syscall_bridge.h"
#include "antidebug/dispatcher/dispatcher.h"
// thread_noise.h pour ad_noise_swarm_stop (kill les 6 threads cachés au shutdown)
#include "antidebug/stack/thread_noise.h"
// attach_detector — live watchdog thread, fires within ~100ms when a kernel-
// authoritative debug indicator (DebugPort, DebugObjectHandle, BeingDebugged,
// flipped DebugFlags) flips. 0-FP inside javaw/Lunar.
#include "antidebug/checks/runtime/attach_detector.h"
// anti_breakin — for ad_anti_breakin_install_with_target (custom trampoline
// target so we can notify the server before exiting).
#include "antidebug/checks/runtime/anti_breakin.h"

// MSVC-supplied symbol that resolves to the actual loaded base of THIS
// module — the WhipClient DLL. Survives manual mapping by WhipLoader and
// any subsequent rebase. NULL would fall back to PEB.ImageBase which, when
// running inside Minecraft, points at javaw.exe — wrong target.
extern char __ImageBase;

#include <intrin.h>
#include <stdint.h>
#include <stdio.h>
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

// ────────────────────────────────────────────────────────────────────────────
// Detection report capture — populated by log_detections when the cycle
// produces a score that crosses the alarm threshold. Single-slot buffer:
// new reports overwrite the previous one (the reverse-forwarder thread
// drains it within seconds, so loss only happens if multiple alarming
// cycles fire faster than the network round-trip — acceptable, the report
// content is similar across consecutive triggers).
//
// AD_REPORT_THRESHOLD mirrors the score floor used in sentinel_bridge_taint
// (50 = noise floor) but bumped to 80 so we don't spam Discord with
// borderline-noise cycles. If you want every taint-corrupting cycle to
// produce a webhook, drop this to 50.
// ────────────────────────────────────────────────────────────────────────────
#define AD_REPORT_THRESHOLD 80u
#define AD_REPORT_TEXT_CAP  4096

// Layer flag bits — must match ReverseDetectedHandler.FLAG_* on the server.
#define ADF_PEB_DEBUG          (1u << 0)
#define ADF_NTGFLAG            (1u << 1)
#define ADF_HEAP               (1u << 2)
#define ADF_DBG_PORT           (1u << 3)
#define ADF_DBG_FLAGS          (1u << 4)
#define ADF_HWBP               (1u << 5)
#define ADF_TIMING             (1u << 6)
#define ADF_SYSCALL            (1u << 7)
#define ADF_NTCLOSE            (1u << 8)
#define ADF_RDTSC_DBL          (1u << 9)
#define ADF_NTDLL_HOOKED       (1u << 10)
#define ADF_PAGE_RWX           (1u << 11)
#define ADF_TLS                (1u << 12)
#define ADF_FAKE_HWBP          (1u << 13)
#define ADF_ANTI_ATTACH        (1u << 14)
#define ADF_FRIDA              (1u << 15)
#define ADF_VEH_DECOY          (1u << 16)
#define ADF_ETW_HOOK           (1u << 17)
#define ADF_DISPATCHER_PATCHED (1u << 31)

static volatile unsigned int g_pending_report   = 0;
static char                   g_report_text[AD_REPORT_TEXT_CAP];
static volatile unsigned int  g_report_score    = 0;
static volatile unsigned int  g_report_checks_run = 0;
static volatile unsigned int  g_report_checks_hit = 0;
static volatile unsigned int  g_report_check_mask = 0;
static volatile unsigned int  g_report_flags    = 0;

// Live attach detector — separate background thread polling 4 indicators
// every 25-100ms. `g_attach_reported` is a one-shot latch so a sustained
// debugger session doesn't queue a new identical report on every cycle.
static ad_attach_ctx_t        g_attach_ctx;
static volatile unsigned int  g_attach_reported = 0;
static volatile unsigned int  g_attach_started  = 0;

// kernel32 imports for notify_reverse_and_exit (kernel-injected breakin
// thread doesn't have CRT context, so we resolve through dllimport).
__declspec(dllimport) void  __stdcall Sleep(unsigned long ms);
__declspec(dllimport) void  __stdcall RtlExitUserProcess(unsigned long st);

// Trampoline target for ad_anti_breakin_install_with_target. The kernel
// injects a thread at our patched DbgUiRemoteBreakin → trampoline jumps
// here with ecx=1. We:
//   1. Force-latch the watchdog detection (so consume_report pops a report)
//   2. Sleep ~1500ms — gives the C++ forwarder time to drain & ship the
//      REVERSE_DETECTED packet to the VPS
//   3. Then exit with status 1 like the original behaviour
//
// The kernel-injected breakin thread runs in parallel to the forwarder,
// so the Sleep doesn't block the network send.
void __stdcall notify_reverse_and_exit(unsigned long status) {
    (void)status;

    // Force the watchdog latch — even if its own poll didn't see the
    // indicators yet, an attach DID happen (we wouldn't be here otherwise).
    g_attach_ctx.detected |= AD_ATTACH_REASON_PEB_BD
                           | AD_ATTACH_REASON_DBG_PORT
                           | AD_ATTACH_REASON_DBG_OBJECT;

    // Give the C++ forwarder time to: poll (≤400ms) → consume_report →
    // sendReverseDetected (network RTT ~30-100ms). 1500ms is generous.
    Sleep(1500u);

    RtlExitUserProcess(1u);
}

// Pack the layer/extra detection booleans into a single u32. Same names
// the server-side handler decodes back into a human-readable list.
static unsigned int pack_detection_flags(int dispatcher_patched) {
    unsigned int f = 0u;
    if (dispatcher_patched) f |= ADF_DISPATCHER_PATCHED;
    if (ad_dbg_layers.enabled) {
        if (ad_dbg_layers.f_peb_debug)    f |= ADF_PEB_DEBUG;
        if (ad_dbg_layers.f_ntgflag)      f |= ADF_NTGFLAG;
        if (ad_dbg_layers.f_heap)         f |= ADF_HEAP;
        if (ad_dbg_layers.f_dbg_port)     f |= ADF_DBG_PORT;
        if (ad_dbg_layers.f_dbg_flags)    f |= ADF_DBG_FLAGS;
        if (ad_dbg_layers.f_hwbp)         f |= ADF_HWBP;
        if (ad_dbg_layers.f_timing)       f |= ADF_TIMING;
        if (ad_dbg_layers.f_syscall)      f |= ADF_SYSCALL;
        if (ad_dbg_layers.f_ntclose)      f |= ADF_NTCLOSE;
        if (ad_dbg_layers.f_rdtsc_dbl)    f |= ADF_RDTSC_DBL;
        if (ad_dbg_layers.f_ntdll_hooked) f |= ADF_NTDLL_HOOKED;
        if (ad_dbg_layers.f_page_rwx)     f |= ADF_PAGE_RWX;
    }
    if (ad_dbg_extras.tls)         f |= ADF_TLS;
    if (ad_dbg_extras.fake_hwbp)   f |= ADF_FAKE_HWBP;
    if (ad_dbg_extras.anti_attach) f |= ADF_ANTI_ATTACH;
    if (ad_dbg_extras.frida)       f |= ADF_FRIDA;
    if (ad_dbg_extras.veh)         f |= ADF_VEH_DECOY;
    if (ad_dbg_extras.etw)         f |= ADF_ETW_HOOK;
    return f;
}

// Build the human-readable report text into our in-memory slot so the C++
// forwarder can ship it to the VPS for Discord. Truncates safely if the buffer fills up.
static void capture_report_text(const ad_result_t* r, int patched) {
    char* out = g_report_text;
    unsigned int cap = AD_REPORT_TEXT_CAP;
    int n;
    unsigned int used = 0;

    #define APPEND(...) do { \
        if (used >= cap) break; \
        n = _snprintf_s(out + used, (cap - used), _TRUNCATE, __VA_ARGS__); \
        if (n < 0) { used = cap - 1; break; } \
        used += (unsigned int)n; \
    } while (0)

    out[0] = '\0';
    if (patched) APPEND("ad_verify_result FAILED - dispatcher patched, score forced to BAD_SCORE\n");
    APPEND("total_score : %u (0x%08X)\n", r->score, r->score);
    APPEND("checks_run  : %u\n", r->checks_run);
    APPEND("checks_hit  : %u\n", r->checks_hit);
    APPEND("check_mask  : 0x%08X\n", r->check_mask);

    if (ad_dbg_layers.enabled) {
        APPEND("--- Layer scores ---\n");
        APPEND("  correlation : %u\n", ad_dbg_layers.correlation);
        APPEND("  deep        : %u\n", ad_dbg_layers.deep);
        APPEND("  cross       : %u\n", ad_dbg_layers.cross);
        APPEND("  patch       : %u\n", ad_dbg_layers.patch);
        APPEND("  exotic      : %u\n", ad_dbg_layers.exotic);
        APPEND("  advanced    : %u\n", ad_dbg_layers.advanced);
        APPEND("  extra       : %u\n", ad_dbg_layers.extra);
        APPEND("  self_poison : %u\n", ad_dbg_layers.self_poison_final);
        APPEND("  raw_hits    : %u\n", ad_dbg_layers.raw_hits);
        APPEND("--- Flags ---\n");
        APPEND("  PEB.BeingDebugged : %s\n", ad_dbg_layers.f_peb_debug    ? "DETECTED" : "clean");
        APPEND("  NtGlobalFlag      : %s\n", ad_dbg_layers.f_ntgflag      ? "DETECTED" : "clean");
        APPEND("  Heap flags        : %s\n", ad_dbg_layers.f_heap         ? "DETECTED" : "clean");
        APPEND("  DebugPort         : %s\n", ad_dbg_layers.f_dbg_port     ? "DETECTED" : "clean");
        APPEND("  DebugFlags        : %s\n", ad_dbg_layers.f_dbg_flags    ? "DETECTED" : "clean");
        APPEND("  Hardware bp       : %s\n", ad_dbg_layers.f_hwbp         ? "DETECTED" : "clean");
        APPEND("  RDTSC timing      : %s\n", ad_dbg_layers.f_timing       ? "DETECTED" : "clean");
        APPEND("  Syscall timing    : %s\n", ad_dbg_layers.f_syscall      ? "DETECTED" : "clean");
        APPEND("  NtClose trap      : %s\n", ad_dbg_layers.f_ntclose      ? "DETECTED" : "clean");
        APPEND("  RDTSC double      : %s\n", ad_dbg_layers.f_rdtsc_dbl    ? "DETECTED" : "clean");
        APPEND("  ntdll hooked      : %s\n", ad_dbg_layers.f_ntdll_hooked ? "DETECTED" : "clean");
        APPEND("  Page RWX          : %s\n", ad_dbg_layers.f_page_rwx     ? "DETECTED" : "clean");
    }
    APPEND("--- Extras ---\n");
    APPEND("  tls=%u fake_hwbp=%u anti_attach=%u frida=%u\n",
           ad_dbg_extras.tls, ad_dbg_extras.fake_hwbp,
           ad_dbg_extras.anti_attach, ad_dbg_extras.frida);
    APPEND("  veh=%u dbgui=%u handle=%u dlls=%u procs=%u etw=%u\n",
           ad_dbg_extras.veh, ad_dbg_extras.dbgui_patch,
           ad_dbg_extras.handle_scan, ad_dbg_extras.dlls,
           ad_dbg_extras.process_scan, ad_dbg_extras.etw);
    APPEND("  trap_ss=%u trap_ctx=%u page_guard=%u remote=%u window=%u\n",
           ad_dbg_extras.trap_flag_ss, ad_dbg_extras.trap_flag_ctx,
           ad_dbg_extras.page_guard_sentinel, ad_dbg_extras.f_remote,
           ad_dbg_extras.f_window);
    APPEND("  ods=%u ifeo=%u job=%u uef=%u dbg_filter=%u mem_bp=%u\n",
           ad_dbg_extras.f_ods, ad_dbg_extras.f_ifeo,
           ad_dbg_extras.f_job, ad_dbg_extras.f_uef,
           ad_dbg_extras.f_dbg_filter, ad_dbg_extras.f_mem_bp);
    APPEND("  ntdll_page=%u behavior=%u delta=%u tsc_drift=%u wireshark=%u\n",
           ad_dbg_extras.f_ntdll_page, ad_dbg_extras.f_behavior,
           ad_dbg_extras.f_delta, ad_dbg_extras.tsc_drift,
           ad_dbg_extras.wireshark);
    APPEND("  emu=%u vm_full=%u\n", ad_dbg_emu_score, ad_dbg_vmfull_score);

    #undef APPEND
}

static void log_detections(const ad_result_t* r, int patched) {
    if (patched || r->score >= AD_REPORT_THRESHOLD) {
        capture_report_text(r, patched);
        g_report_score      = r->score;
        g_report_checks_run = r->checks_run;
        g_report_checks_hit = r->checks_hit;
        g_report_check_mask = r->check_mask;
        g_report_flags      = pack_detection_flags(patched);
        g_pending_report    = 1u;
    }
}

// Run un cycle complet de checks et stocke le score.
// noinline pour que VMP puisse virtualiser tout le body.
static __declspec(noinline) void run_one_cycle(void) {
    ad_dbg_layers.enabled = 1;
    // Enable the per-check breakdown structs so log_detections can show which
    // sub-check inside each layer contributed to the score (e.g. which of the
    // advanced layer's 16 sub-checks added the false-positive 10 points).
    ad_dbg_deep.enabled  = 1;
    ad_dbg_patch.enabled = 1;
    ad_result_t r = ad_run_hardened(&g_state);
    AD_DECRYPT_RESULT(r);

    // Verify le dispatcher n'a pas été patché pour retourner zero.
    // ad_verify_dispatcher_alive returns 1 = tampered, 0 = clean.
    if (ad_verify_result(&r)) {
        log_detections(&r, 1);
        store_score(BAD_SCORE);
        return;
    }

    log_detections(&r, 0);
    store_score(r.score);
}

// ────────────────────────────────────────────────────────────────────────────
// API C exposée au C++
// ────────────────────────────────────────────────────────────────────────────
void sentinel_bridge_init(void) {
    ad_init(&g_state, (void*)&__ImageBase, 0u);
    ad_anti_attach_set_no_inherit();
    ad_veh_install();

    if (ad_attach_detector_start(&g_attach_ctx, 1u)) {
        g_attach_started = 1u;
    }

    ad_anti_breakin_install_with_target((void*)&notify_reverse_and_exit);
    store_initialized(INIT_MAGIC);
    run_one_cycle();
}

// Cleanup à appeler AVANT FreeLibrary/DLL unload. Désinstalle :
//   1. Les 4 VEH installés par ad_veh_install — sinon dangling pointers à la
//      prochaine exception après unload.
//   2. Les 6 noise threads lancés par StackProtect via ad_noise_swarm_start —
//      ils pointent vers ad_noise_thread_entry IN our DLL ; sans stop, ils
//      tournent encore quand FreeLibrary unmappe la DLL → crash garanti.
void sentinel_bridge_cleanup(void) {
    // ad_noise_swarm_stop est sûr à appeler même si swarm_start n'a pas été
    // exécuté (le no-op via SSN_FAILED). On l'appelle inconditionnellement.
    ad_noise_swarm_stop();

    // Stop the attach watchdog thread — flag-only, the thread polls the flag
    // on its next jittered wake (≤100ms).
    if (g_attach_started) ad_attach_detector_stop(&g_attach_ctx);

    if (load_initialized() != INIT_MAGIC) return;
    ad_veh_uninstall();
    store_initialized(0u);
}

void sentinel_bridge_taint(unsigned char* data, unsigned int length) {
    unsigned int i;
    unsigned int score;
    unsigned __int64 state;

    if (!data || length == 0u) return;

    if (load_initialized() != INIT_MAGIC) {
        return;
    }

    score = load_score();

    // Score noise floor — config.h:AD_SCORE_NOISE_FLOOR documents that
    // timing checks, ghost thread, pool workers, and watchdog startup all
    // produce ~25-40 noise points on clean systems. Anything below 50 is
    // considered clean. Especially important for manual-mapped DLLs in javaw:
    // HotSpot walks every thread's stack on safepoints, generates RDTSC/timing
    // noise, and some checks react to the DLL's absence from PEB.Ldr. Without
    // this floor, perfectly clean cycles taint legitimate IPC tokens → server
    // rejects → client loops.
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
        return;
    }
    run_one_cycle();
}

void sentinel_bridge_verify(void) {
    ad_result_t r = ad_run_hardened(&g_state);
    unsigned int prev;
    AD_DECRYPT_RESULT(r);
    if (ad_verify_result(&r)) {
        store_score(BAD_SCORE);
    } else {
        prev = load_score();
        store_score(prev > r.score ? prev : r.score);
    }
}

unsigned __int64 sentinel_bridge_snapshot(void) {
    return g_score_enc ^ ((unsigned __int64)g_score_key << 1);
}

// Live attach poll — drains the watchdog's latched reason mask and, on the
// FIRST detection, captures a synthetic report into the same single-slot
// buffer the regular cycle uses, so consume_report ships it to the VPS.
//
// out_reason: optional, receives the OR-ed reason mask (bits documented in
//             attach_detector.h: PEB_BD / DBG_PORT / DBG_OBJECT / FLAGS_FLIP).
//
// Returns 1 if a brand-new attach was just observed (caller may also drain
// consume_report immediately), 0 if no attach OR already reported once.
int sentinel_bridge_attach_poll(unsigned int* out_reason) {
    unsigned int reason = ad_attach_was_detected(&g_attach_ctx);
    if (out_reason) *out_reason = reason;
    if (!reason) return 0;
    if (g_attach_reported) return 0;

    // First-detection latch — capture synthetic report into the slot.
    char* out = g_report_text;
    unsigned int cap = AD_REPORT_TEXT_CAP;
    int n;
    unsigned int used = 0;
    out[0] = '\0';

    n = _snprintf_s(out, cap, _TRUNCATE,
        "INSTANT ATTACH DETECTED (live watchdog)\n"
        "reason_mask : 0x%X\n"
        "  PEB.BeingDebugged       : %s\n"
        "  ProcessDebugPort != 0   : %s\n"
        "  ProcessDebugObjectHandle: %s\n"
        "  ProcessDebugFlags flip  : %s\n"
        "watchdog_cycles : %llu\n",
        reason,
        (reason & AD_ATTACH_REASON_PEB_BD)     ? "DETECTED" : "clean",
        (reason & AD_ATTACH_REASON_DBG_PORT)   ? "DETECTED" : "clean",
        (reason & AD_ATTACH_REASON_DBG_OBJECT) ? "DETECTED" : "clean",
        (reason & AD_ATTACH_REASON_FLAGS_FLIP) ? "DETECTED" : "clean",
        (unsigned long long)g_attach_ctx.cycles);
    if (n > 0) used = (unsigned int)n;
    (void)used;

    g_report_score      = 250u;             // Above AD_REPORT_THRESHOLD
    g_report_checks_run = 4u;
    g_report_checks_hit = (reason & 1u) + ((reason >> 1) & 1u) +
                          ((reason >> 2) & 1u) + ((reason >> 3) & 1u);
    g_report_check_mask = reason;
    // Map watchdog reason bits onto existing layer flag bits.
    {
        unsigned int f = 0u;
        if (reason & AD_ATTACH_REASON_PEB_BD)     f |= ADF_PEB_DEBUG;
        if (reason & AD_ATTACH_REASON_DBG_PORT)   f |= ADF_DBG_PORT;
        if (reason & AD_ATTACH_REASON_DBG_OBJECT) f |= ADF_DBG_PORT;  // closest layer flag
        if (reason & AD_ATTACH_REASON_FLAGS_FLIP) f |= ADF_DBG_FLAGS | ADF_ANTI_ATTACH;
        g_report_flags = f;
    }
    g_pending_report = 1u;
    g_attach_reported = 1u;
    return 1;
}

// Drain the pending detection report, if any. Returns 1 and copies the
// slot into the caller's buffers; returns 0 if nothing is pending.
// Single-consumer semantics — the security forwarder thread is the only
// caller. No mutex: writes from the recheck thread happen at cycle end
// (~3-8s apart) and a torn read just produces a slightly stale report,
// which is fine for an alerting channel.
int sentinel_bridge_consume_report(char* outText, unsigned int outCap,
                                   unsigned int* score, unsigned int* checksRun,
                                   unsigned int* checksHit, unsigned int* checkMask,
                                   unsigned int* flags) {
    if (!g_pending_report) return 0;
    if (outText && outCap > 0u) {
        unsigned int i;
        unsigned int max = outCap - 1u;
        if (max > AD_REPORT_TEXT_CAP - 1u) max = AD_REPORT_TEXT_CAP - 1u;
        for (i = 0; i < max && g_report_text[i] != '\0'; ++i) outText[i] = g_report_text[i];
        outText[i] = '\0';
    }
    if (score)     *score     = g_report_score;
    if (checksRun) *checksRun = g_report_checks_run;
    if (checksHit) *checksHit = g_report_checks_hit;
    if (checkMask) *checkMask = g_report_check_mask;
    if (flags)     *flags     = g_report_flags;
    g_pending_report = 0u;
    return 1;
}
