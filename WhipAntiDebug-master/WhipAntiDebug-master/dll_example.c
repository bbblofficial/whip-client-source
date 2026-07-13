// ===== file: dll_example.c =====
//
// DLL injection template for WhipAntiDebugger.
//
// This DLL can be injected into a target process via:
//   - Manual mapping (recommended)
//   - LoadLibrary injection
//   - Thread hijacking
//
// Key differences from main_example.c (EXE):
//
//   1. LOADER LOCK: DllMain runs under the loader lock — no heavy work.
//      All initialization happens in a spawned thread.
//
//   2. IMAGE BASE: PEB.ImageBaseAddress points to the HOST EXE, not our DLL.
//      We pass hinstDLL (our module base) to ad_init() for correct code
//      integrity hashing.
//
//   3. NO CRT: Injected DLLs should avoid CRT to minimize footprint.
//      We use direct syscalls for everything.
//
//   4. STEALTH: The init thread is hidden from debugger via
//      NtSetInformationThread(ThreadHideFromDebugger).
//
//   5. PE SECTIONS: Code integrity checks hash OUR .text section, not
//      the host process's. We compute the scan region from our PE header.
//

#include "antidebug/core/syscall_bridge.h"
#include "antidebug/core/vmp_markers.h"
#include "antidebug/dispatcher/dispatcher.h"
#include "antidebug/core/mem_encrypt.h"
#include "antidebug/core/latent_tamper.h"
#include "antidebug/core/latent_tamper2.h"
#include "antidebug/core/watchdog.h"
#include "antidebug/core/poly_syscall.h"
#include "antidebug/core/hyperion_blob.h"
#include "antidebug/checks/runtime/anti_breakin.h"
#include "antidebug/checks/runtime/attach_detector.h"
#include "antidebug/checks/runtime/halos_gate_desync.h"
#include "antidebug/checks/runtime/heavens_gate.h"
#include "antidebug/checks/runtime/raise_hard_error.h"
#include "antidebug/checks/runtime/etw_ti_detect.h"
#include "antidebug/checks/runtime/kernel_callback_indirect.h"
#include "antidebug/checks/runtime/private_exec_scan.h"
#include "antidebug/checks/runtime/fake_hwbp.h"
#include "antidebug/checks/runtime/page_guard_trap.h"
#include "antidebug/checks/exceptions/veh_encrypted_cfg.h"
#include "antidebug/checks/integrity/anti_tamper.h"
#include "antidebug/checks/integrity/critical_scan.h"
#include "antidebug/checks/timing/total_elapsed.h"
#include "antidebug/checks/timing/tsc_qpc_drift.h"
#include "antidebug/checks/advanced/syscall_verify.h"
#include "antidebug/checks/advanced/anti_scyllahide.h"
#include "antidebug/checks/advanced/anti_titanhide.h"
#include "antidebug/checks/advanced/deep_scyllahide.h"
#include "antidebug/checks/advanced/decoy_honeypot.h"
#include "antidebug/checks/vm/hwid_fingerprint.h"
#include "antidebug/checks/debug/al_khaser_classics.h"
#include "antidebug/checks/debug/kd_extra.h"
#include "antidebug/checks/deep_checks.h"
#include "antidebug/stack/stealth_exec.h"
#include "antidebug/stack/thread_noise.h"
#include "antidebug/stack/gadget_chain.h"

// New hardening modules
#include "antidebug/core/stealth_wipe.h"
#include "antidebug/core/text_encrypt.h"
#include "antidebug/core/heartbeat.h"
#include "antidebug/core/score_vault.h"
#include "antidebug/checks/debug/remote_debug.h"

// Integrity guards against single-point-of-failure hooks
#include "antidebug/core/syscall_guard.h"
#include "antidebug/core/api_guard.h"

// ---------------------------------------------------------------------------
// DLL-specific globals
// ---------------------------------------------------------------------------
static volatile void*  g_dll_base          = 0;   // Our hinstDLL
static volatile u32    g_dll_text_sz       = 0;   // Our .text section size
static volatile b32    g_initialized       = 0;
static volatile b32    g_should_exit       = 0;
static volatile void*  g_init_thread_handle = 0;  // For clean shutdown in DETACH
static ad_state_t      g_state;

// Score XOR key — initialized from RDTSC at init.
// Caller must: real_score = ad_dll_get_score() ^ ad_dll_get_score_key()
static volatile u32    g_score_xor_key = 0;

#if AD_ENABLE_TEXT_ARMOR
static ad_text_armor_t g_text_armor;
#endif
#if AD_ENABLE_HEARTBEAT
static ad_heartbeat_t  g_heartbeat;
#endif

// Supplemental-layer state — mirrors the EXE's main_example.c globals so
// `ad_dll_run_supplemental` matches the EXE's `ad_run_supplemental`.
static volatile u32         g_init_module_count = 0;
static ad_tamper_baseline_t g_tamper_bl;
static ad_attach_ctx_t      g_attach_ctx;
static volatile u32         g_supplemental_score = 0;

ANTIDEBUG_INLINE void ad_dll_snapshot_modules(void) {
    u32 mc = 0u;
    __try {
        u8* peb = (u8*)__readgsqword(0x60);
        u8* ldr = *(u8**)(peb + 0x18);
        u8* list_head = ldr + 0x10;
        u8* entry = *(u8**)list_head;
        while (entry != list_head && mc < 200u) {
            mc++;
            entry = *(u8**)entry;
        }
    } __except(1) { mc = 0u; }
    g_init_module_count = mc;
}

// ---------------------------------------------------------------------------
// Supplemental layer — mirrors main_example.c::ad_run_supplemental.
// All checks wrapped in __try/__except: a crash inside one means hostile
// environment, so we credit the weight anyway.
// ---------------------------------------------------------------------------
static u32 ad_dll_run_supplemental(void) {
    u32 score = 0u;

#if AD_ENABLE_VM_HYPERVISOR
    __try { if (ad_vm_cpuid_hypervisor_bit()) score += 2u; } __except(1) { score += 2u; }
#endif
#if AD_ENABLE_VM_RDTSC
    __try { if (ad_vm_rdtsc_overhead())       score += 2u; } __except(1) { score += 2u; }
#endif
#if AD_ENABLE_LOOP_TIMING
    __try { if (ad_loop_timing())             score += 2u; } __except(1) { score += 2u; }
#endif
    __try { if (ad_debug_object_handle())     score += 2u; } __except(1) { score += 2u; }
#if AD_ENABLE_KERNEL_DEBUGGER
    __try { if (ad_kernel_debugger())         score += 3u; } __except(1) { score += 3u; }
#endif
#if AD_ENABLE_QPC_TIMING
    __try { if (ad_qpc_timing())              score += 2u; } __except(1) { score += 2u; }
#endif
#if AD_ENABLE_DEBUG_OBJECT_REMOVE
    __try { if (ad_remove_debug_object())     score += 4u; } __except(1) { score += 4u; }
#endif
#if AD_ENABLE_GUARD_PAGE_TRAP
    __try { if (ad_guard_page_trap())         score += 3u; } __except(1) { score += 3u; }
#endif
#if AD_ENABLE_DR_CANARY
    __try { if (ad_dr_canary())               score += 3u; } __except(1) { score += 3u; }
#endif
#if AD_ENABLE_INSTRUMENTATION_CB
    __try { if (ad_instrumentation_callback_check()) score += 4u; } __except(1) { score += 4u; }
#endif
#if AD_ENABLE_SEH_CHECK
    __try { if (ad_seh_breakpoint())          score += 2u; } __except(1) { score += 2u; }
#endif

    __try { if (ad_anti_breakin_verify())     score += 6u; } __except(1) { score += 6u; }

    // Live attach detector — instant trip on any kernel-side debugger attach.
    // Each reason bit is 0-FP in Java/JVM and similar noisy hosts.
    __try {
        u32 atr = ad_attach_was_detected(&g_attach_ctx);
        if (atr) score += 12u;
    } __except(1) { score += 12u; }
    __try { if (ad_halos_gate_desync())       score += 7u; } __except(1) { score += 7u; }
    __try { score += ad_halos_gate_multi_count() * 4u; } __except(1) { score += 16u; }
    __try { if (ad_heavens_gate_check())      score += 5u; } __except(1) { score += 5u; }
    __try { if (ad_raise_hard_error_probe())  score += 6u; } __except(1) { score += 6u; }
    __try { if (ad_etw_ti_check())            score += 5u; } __except(1) { score += 5u; }
    __try { if (ad_kernel_callback_indirect()) score += 4u; } __except(1) { score += 4u; }

    // PRIVATE+EXEC: surplus only — Win10/11 has 30-70 legitimate regions.
    __try {
        u32 raw = ad_private_exec_scan();
        u32 surplus = (raw > AD_PRIV_EXEC_BASELINE) ? (raw - AD_PRIV_EXEC_BASELINE) : 0u;
        score += surplus * 3u;
    } __except(1) { /* assume clean */ }

    __try { if (ad_hyperion_check())          score += 9u; } __except(1) { score += 9u; }
    __try { if (ad_veh_cfg_verify())          score += 8u; } __except(1) { score += 8u; }
    __try { score += ad_veh_cfg_run(); }      __except(1) { score += 4u; }

#if AD_ENABLE_SYSCALL_VERIFY
    __try { score += ad_sv_master(); }        __except(1) {}
#endif

#if AD_ENABLE_ANTI_SCYLLAHIDE
    __try { score += ad_scyllahide_extended(); }  __except(1) {}
    __try { score += ad_deep_scyllahide_master(); } __except(1) {}
#endif

    // Anti-tamper master (Cheat Engine + foreign VM_WRITE + code integrity)
    __try { score += ad_anti_tamper_master(&g_tamper_bl); } __except(1) {}

    // Anti-DLL-injection: module-count delta vs init baseline.
    // Threshold relaxed for DLL context — host processes routinely load
    // additional modules over time (Defender, shell extensions, COM
    // servers). Use +8 instead of +2 to keep the FP rate near zero.
    __try {
        u32 current_modules = 0u;
        u8* peb = (u8*)__readgsqword(0x60);
        u8* ldr = *(u8**)(peb + 0x18);
        u8* list_head = ldr + 0x10;
        u8* entry = *(u8**)list_head;
        while (entry != list_head && current_modules < 200u) {
            current_modules++;
            entry = *(u8**)entry;
        }
        if (g_init_module_count != 0u && current_modules > g_init_module_count + 8u)
            score += 10u;
    } __except(1) { /* DLL ctx — don't poison on PEB walk fault */ }

    // KUSER_SHARED_DATA kernel-debugger flags (unhookable)
    __try {
        volatile u8* kusd = (volatile u8*)0x7FFE0000ULL;
        volatile u8 kd_enabled = *(volatile u8*)(kusd + 0x02D4);
        if (kd_enabled) score += 10u;
        volatile u8 kd_not_present = *(volatile u8*)(kusd + 0x02D5);
        if (!kd_not_present) score += 8u;
    } __except(1) { score += 10u; }

#if AD_ENABLE_HWID_FINGERPRINT
    __try { score += ad_hwid_fingerprint_master(); } __except(1) {}
#endif

    __try { score += ad_al_khaser_classics_master(); } __except(1) {}
    __try { score += ad_kd_extra_master(); }            __except(1) {}

    return score;
}

// ---------------------------------------------------------------------------
// Compute our .text section size from our own PE headers.
// This is critical — ad_init() needs to hash OUR code, not the host EXE.
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE u32 ad_dll_get_text_size(void* dll_base) {
    u8* base = (u8*)dll_base;

    // DOS header → PE offset
    u32 e_lfanew = *(u32*)(base + 0x3C);
    u8* pe       = base + e_lfanew;

    // COFF header
    u16 num_sections    = *(u16*)(pe + 6);
    u16 opt_header_size = *(u16*)(pe + 20);

    // Section headers start after optional header
    u8* sections = pe + 24 + opt_header_size;

    // Walk sections, find .text
    for (u16 i = 0; i < num_sections; i++) {
        u8* sec = sections + i * 40;
        // Section name is first 8 bytes
        if (sec[0] == '.' && sec[1] == 't' && sec[2] == 'e' &&
            sec[3] == 'x' && sec[4] == 't') {
            u32 vsize = *(u32*)(sec + 8);   // VirtualSize
            return vsize;
        }
    }

    // Fallback: use default
    return 0x2000u;
}

// AD_STRENC_NtCreateThreadEx is provided by scheduler_sync.h via dispatcher.h

// "NtResumeThread" (14 chars) — not in the framework's string_encrypt.h
#ifndef AD_STRENC_NtResumeThread
#define AD_STRENC_NtResumeThread(buf)                                         \
    do {                                                                      \
        const u8 _k = AD_STR_KEY(0xCC);                                      \
        char buf##_e[15];                                                     \
        AD_ENC(buf##_e,  0, 'N', _k); AD_ENC(buf##_e,  1, 't', _k);        \
        AD_ENC(buf##_e,  2, 'R', _k); AD_ENC(buf##_e,  3, 'e', _k);        \
        AD_ENC(buf##_e,  4, 's', _k); AD_ENC(buf##_e,  5, 'u', _k);        \
        AD_ENC(buf##_e,  6, 'm', _k); AD_ENC(buf##_e,  7, 'e', _k);        \
        AD_ENC(buf##_e,  8, 'T', _k); AD_ENC(buf##_e,  9, 'h', _k);        \
        AD_ENC(buf##_e, 10, 'r', _k); AD_ENC(buf##_e, 11, 'e', _k);        \
        AD_ENC(buf##_e, 12, 'a', _k); AD_ENC(buf##_e, 13, 'd', _k);        \
        AD_DECODE_BUF(buf##_e, 14, _k);                                      \
        for (unsigned _ci = 0; _ci < 15; _ci++) (buf)[_ci] = buf##_e[_ci];   \
    } while (0)
#endif

// "NtTerminateThread" (17 chars) — needed for clean shutdown in DllMain DETACH
#ifndef AD_STRENC_NtTerminateThread
#define AD_STRENC_NtTerminateThread(buf)                                      \
    do {                                                                      \
        const u8 _k = AD_STR_KEY(0xCC);                                      \
        char buf##_e[18];                                                     \
        AD_ENC(buf##_e,  0, 'N', _k); AD_ENC(buf##_e,  1, 't', _k);        \
        AD_ENC(buf##_e,  2, 'T', _k); AD_ENC(buf##_e,  3, 'e', _k);        \
        AD_ENC(buf##_e,  4, 'r', _k); AD_ENC(buf##_e,  5, 'm', _k);        \
        AD_ENC(buf##_e,  6, 'i', _k); AD_ENC(buf##_e,  7, 'n', _k);        \
        AD_ENC(buf##_e,  8, 'a', _k); AD_ENC(buf##_e,  9, 't', _k);        \
        AD_ENC(buf##_e, 10, 'e', _k); AD_ENC(buf##_e, 11, 'T', _k);        \
        AD_ENC(buf##_e, 12, 'h', _k); AD_ENC(buf##_e, 13, 'r', _k);        \
        AD_ENC(buf##_e, 14, 'e', _k); AD_ENC(buf##_e, 15, 'a', _k);        \
        AD_ENC(buf##_e, 16, 'd', _k);                                        \
        AD_DECODE_BUF(buf##_e, 17, _k);                                      \
        for (unsigned _ci = 0; _ci < 18; _ci++) (buf)[_ci] = buf##_e[_ci];   \
    } while (0)
#endif

// ---------------------------------------------------------------------------
// Thread resurrection: respawn the watchdog if heartbeat says it's dead.
//
// Uses NtCreateThreadEx + NtSetInformationThread(HideFromDebugger) +
// NtResumeThread, same pattern as the init thread spawner. The new
// watchdog inherits the same entry point and is hidden from debugger.
// ---------------------------------------------------------------------------
#ifdef _MSC_VER
static NOINLINE void ad_dll_respawn_watchdog(void) {
    static u16 s_create = AD_SSN_UNRESOLVED;
    static u16 s_seti   = AD_SSN_UNRESOLVED;
    static u16 s_resume = AD_SSN_UNRESOLVED;

    AD_RESOLVE_SSN_ENC(s_create, NtCreateThreadEx, 17);
    AD_RESOLVE_SSN_ENC(s_seti,   NtSetInformationThread, 23);
    AD_RESOLVE_SSN_ENC(s_resume, NtResumeThread, 15);

    if (s_create == AD_SSN_FAILED || s_resume == AD_SSN_FAILED) return;

    // Reset watchdog globals so the new thread starts clean
    g_watchdog_kill = 0;
    g_watchdog_penalty = 0;
    AD_BARRIER();

    ad_handle_t handle = 0;
    ad_ntstatus_t st = (ad_ntstatus_t)(s64)SyscallStub(s_create,
        &handle,
        (void*)(u64)0x001FFFFFul,   // THREAD_ALL_ACCESS
        (void*)0,                    // ObjectAttributes
        (void*)(u64)AD_CURRENT_PROCESS,
        (void*)ad_watchdog_entry,    // Same entry point
        (void*)0,                    // Argument
        (void*)(u64)0x00000004ul,    // CREATE_SUSPENDED
        (void*)0, (void*)0, (void*)0, (void*)0
    );

    if (!AD_NT_SUCCESS(st) || !handle) return;

    // Hide from debugger
    if (s_seti != AD_SSN_FAILED) {
        AD_SYSCALL4(s_seti, handle, (u64)17, (u64)0, (u64)0);
    }

    // Resume
    u32 prev = 0;
    AD_SYSCALL2(s_resume, handle, &prev);
}
#endif

// ---------------------------------------------------------------------------
// Check loop — placed in .armor section so it survives .text encryption.
// Everything that calls into .text must happen between unlock and lock.
// ---------------------------------------------------------------------------
#pragma code_seg(".armor")
static NOINLINE void ad_dll_check_loop(u16 ssn_delay) {
    u32 loop_iter = 0;
    while (!g_should_exit) {
        if (g_initialized) {
            // Unlock .text for check execution
#if AD_ENABLE_TEXT_ARMOR
            ad_text_armor_unlock(&g_text_armor);
#endif

            ad_result_t result;
            AD_ZERO_BUF(&result, sizeof(result));

            __try {
                result = ad_run_hardened(&g_state);
                AD_DECRYPT_RESULT(result);
            }
            __except (1) {
                result.score      = 0xFFFFFFFFu;
                result.checks_hit = (u32)AD_CHECK_COUNT;
                result.checks_run = (u32)AD_CHECK_COUNT;
            }

            // Remote debugger check
#if AD_ENABLE_REMOTE_DEBUG
            __try {
                if (ad_remote_debug_check()) result.score += 8u;
            } __except(1) { result.score += 8u; }
#endif

            // SyscallStub prologue integrity (detects inline hook / INT3)
            __try {
                if (ad_syscall_guard_verify()) result.score += 15u;
            } __except(1) { result.score += 15u; }

            // API resolver cross-validation (InMemoryOrder vs InLoadOrder)
            // Spot-check ntdll resolution to detect PEB list tampering
            __try {
                if (ad_api_cross_validate(
                        AD_HASH_NTDLL, AD_HASH("NtQueryInformationProcess")))
                    result.score += 15u;
            } __except(1) { result.score += 15u; }

            // Heartbeat pump — detect if watchdog was suspended
#if AD_ENABLE_HEARTBEAT
            ad_heartbeat_pump_a(&g_heartbeat);
            if (ad_heartbeat_stalled_b(&g_heartbeat))
                result.score += 10u;  // watchdog thread was suspended
#endif

            // Snapshot the hardened-only score *before* the supplemental
            // layer is added. Latent-tamper arming is gated on this snapshot
            // so the per-check baseline noise from the 60+ supplemental
            // checks (small weights even on clean hosts) doesn't trip the
            // self-destruct on every iteration.
            u32 hardened_only = result.score;

            // Supplemental layer — VM, kernel-debugger, halo/heaven, ETW-TI,
            // ScyllaHide ext, anti-tamper, kd_extra, al_khaser, hwid, etc.
            // Mirrors the EXE's `ad_run_supplemental` so DLL injection has
            // the same coverage as the EXE.
            u32 sup = 0u;
            __try { sup = ad_dll_run_supplemental(); } __except(1) { sup = 16u; }
            g_supplemental_score = sup;
            result.score += sup;

            // Regenerate poly gadgets every 3rd iteration to defeat persistent hooks
#if AD_ENABLE_POLY_SYSCALL
            if ((loop_iter % 3u) == 2u)
                ad_poly_regenerate();
#endif

            // Arm latent tampers if suspicious (both independent sentinels).
            // Gate on hardened-only — the supplemental layer's baseline noise
            // on clean hosts would otherwise trip self-destruct every loop.
            ad_latent_arm_if(hardened_only >= 2u);
            ad_latent2_arm_if(hardened_only >= 2u);
            u32 wd_pen = ad_watchdog_read_penalty();
            if (wd_pen > 0) {
                ad_latent_arm_if(1);
                ad_latent2_arm_if(1);
            }

            // Thread resurrection: if watchdog (thread B) is dead, respawn it
#if AD_ENABLE_HEARTBEAT
            if (ad_heartbeat_should_respawn_b(&g_heartbeat)) {
#ifdef _MSC_VER
                ad_dll_respawn_watchdog();
#endif
                // Reset heartbeat stall counters so we don't re-spawn
                // every iteration — give the new thread time to pump
                g_heartbeat.stall_count_b = 0;
                g_heartbeat.last_seen_b   = g_heartbeat.beat_b;
                AD_BARRIER();
            }
#endif

            // Re-lock .text
#if AD_ENABLE_TEXT_ARMOR
            ad_text_armor_lock(&g_text_armor);
#endif
        }

        // Sleep 3-7 seconds via direct syscall (randomized, SSN pre-resolved)
        if (ssn_delay != AD_SSN_FAILED) {
            u64 tsc = __rdtsc();
            u32 delay_ms = 3000u + (u32)(tsc % 4000u);
            // NtDelayExecution uses 100ns units, negative = relative
            s64 delay_100ns = -(s64)delay_ms * 10000LL;
            AD_SYSCALL2(ssn_delay, (void*)0, &delay_100ns);
        }

        loop_iter++;
    }
}
#pragma code_seg()

// ---------------------------------------------------------------------------
// Init thread — runs OUTSIDE loader lock.
// All heavy initialization happens here.
// ---------------------------------------------------------------------------
static unsigned long __stdcall ad_dll_init_thread(void* param) {
    (void)param;

    void* dll_base = (void*)g_dll_base;
    u32   text_sz  = g_dll_text_sz;

    // Phase 1: Syscall bridge
    whip_bridge_init();

    // Phase 1a: Snapshot SyscallStub prologue for tamper detection
    ad_syscall_guard_init();

    // Phase 1b: Polymorphic syscall gadgets
#if AD_ENABLE_POLY_SYSCALL
    ad_poly_init();
#endif

    // Phase 1c: Generate score XOR key from RDTSC
    g_score_xor_key = (u32)(__rdtsc() ^ 0xA5A5A5A5u);
    if (g_score_xor_key == 0u) g_score_xor_key = 0x1337BEEFu;  // never zero

    // Phase 2: Hide this thread from debugger
    {
        static u16 s_ssn_sit = AD_SSN_UNRESOLVED;
        AD_RESOLVE_SSN_ENC(s_ssn_sit, NtSetInformationThread, 23);
        if (s_ssn_sit != AD_SSN_FAILED) {
            // ThreadHideFromDebugger = 17
            AD_SYSCALL4(s_ssn_sit, AD_CURRENT_THREAD,
                        (void*)(u64)17, (void*)0, (void*)0);
        }
    }

    // Phase 3: Core anti-debug init with OUR DLL's base and .text size
    ad_init(&g_state, dll_base, text_sz);

    // Phase 3b: Set NoDebugInherit (ProcessDebugFlags = 0)
    ad_anti_attach_set_no_inherit();

    // Phase 3c: Init text armor (prepare for .text encryption)
#if AD_ENABLE_TEXT_ARMOR
    ad_text_armor_init(&g_text_armor, dll_base);
#endif

    // Phase 3d: Init heartbeat
#if AD_ENABLE_HEARTBEAT
    ad_heartbeat_init(&g_heartbeat);
#endif

    // Phase 4: Latent tamper sentinels (two independent sentinels)
    ad_latent_init();
    ad_latent2_init();

    // Phase 5: Watchdog background thread
    ad_watchdog_start();

    // Phase 6: VEH exception handler
    ad_veh_install();

    // Phase 7: Anti-breakin (DbgUiRemoteBreakin trampoline)
    ad_anti_breakin_install();

    // Phase 7-bis: Live attach detector — background thread polling
    // PEB.BeingDebugged + DebugPort + DebugObjectHandle + flipped DebugFlags
    // every 25-100ms. ad_attach_was_detected(&g_attach_ctx) returns instantly.
    // check_flags_flip=1 because Phase 3b already set NoDebugInherit.
    __try { (void)ad_attach_detector_start(&g_attach_ctx, 1u); } __except(1) {}

    // Phase 7a: Snapshot module count for the supplemental DLL-injection check.
    ad_dll_snapshot_modules();

    // Phase 7b: Full install block — same set the EXE arms in
    // `ad_do_install_block`. Each item __try-guarded so one failure
    // doesn't abort the rest.
    __try { (void)ad_fake_hwbp_install(); }   __except(1) {}
    __try { (void)ad_decoy_install(); }       __except(1) {}
    __try {
        ad_page_guard_init(&g_ad_page_guard);
        ad_page_guard_arm(&g_ad_page_guard);
    } __except(1) {}
    __try { (void)ad_veh_cfg_install(); }     __except(1) {}
    __try { ad_tsc_qpc_calibrate(&g_tsc_qpc_ctx); } __except(1) {}
#if AD_ENABLE_THREAD_NOISE
    __try { (void)ad_noise_swarm_start(); }   __except(1) {}
#endif

    // Phase 7c: Anti-tamper baseline — CRC32 critical functions AFTER hooks
    // are installed. Any further patching (by a reverser) fails the CRC.
    AD_ZERO_BUF(&g_tamper_bl, sizeof(g_tamper_bl));
    __try {
        ad_tamper_baseline_init(&g_tamper_bl,
            (const void*)&ad_dll_run_supplemental,
            (const void*)&ad_dll_init_thread);
    } __except(1) {}

    g_initialized = 1;
    AD_BARRIER();

    // Phase 9: Post-init stealth — erase PE headers + unlink from PEB
#if AD_ENABLE_PE_HEADER_ERASE
    ad_erase_pe_headers(dll_base);
#endif
#if AD_ENABLE_MODULE_UNLINK
    ad_unlink_module(dll_base);
#endif

    // Phase 10: Resolve sleep SSN before locking .text
    u16 cached_ssn_delay = AD_SSN_UNRESOLVED;
    AD_RESOLVE_SSN_ENC(cached_ssn_delay, NtDelayExecution, 17);

    // Phase 11: Lock .text (encrypt at rest)
#if AD_ENABLE_TEXT_ARMOR
    ad_text_armor_lock(&g_text_armor);
#endif

    // Phase 12: Main anti-debug loop (in .armor section)
    ad_dll_check_loop(cached_ssn_delay);

    // Cleanup
#if AD_ENABLE_POLY_SYSCALL
    ad_poly_destroy();
#endif
    ad_watchdog_stop();
    return 0;
}

// ---------------------------------------------------------------------------
// Spawn init thread via direct syscall — no CreateThread, no API hooks
// ---------------------------------------------------------------------------
static void ad_dll_spawn_init_thread(void) {
    whip_bridge_init();

    static u16 s_ssn_create = AD_SSN_UNRESOLVED;
    AD_RESOLVE_SSN_ENC(s_ssn_create, NtCreateThreadEx, 17);
    if (s_ssn_create == AD_SSN_FAILED) return;

    ad_handle_t thread_handle = 0;
    // NtCreateThreadEx(
    //   &handle, ACCESS_MASK, NULL, process, start, param,
    //   flags, 0, 0, 0, NULL)
    SyscallStub(s_ssn_create,
        &thread_handle,                         // ThreadHandle out
        (void*)0x1FFFFFULL,                     // THREAD_ALL_ACCESS
        (void*)0,                               // ObjectAttributes
        AD_CURRENT_PROCESS,                     // ProcessHandle
        (void*)&ad_dll_init_thread,             // StartRoutine
        (void*)0,                               // Argument
        (void*)(u64)0x00000004u,                // CREATE_SUSPENDED
        (void*)0, (void*)0, (void*)0,           // ZeroBits, StackSize, MaxStackSize
        (void*)0                                // AttributeList
    );

    if (thread_handle) {
        // Hide thread from debugger before resuming
        static u16 s_ssn_sit = AD_SSN_UNRESOLVED;
        AD_RESOLVE_SSN_ENC(s_ssn_sit, NtSetInformationThread, 23);
        if (s_ssn_sit != AD_SSN_FAILED) {
            AD_SYSCALL4(s_ssn_sit, thread_handle,
                        (void*)(u64)17, (void*)0, (void*)0);
        }

        // Resume
        static u16 s_ssn_resume = AD_SSN_UNRESOLVED;
        AD_RESOLVE_SSN_ENC(s_ssn_resume, NtResumeThread, 15);
        if (s_ssn_resume != AD_SSN_FAILED) {
            AD_SYSCALL2(s_ssn_resume, thread_handle, (void*)0);
        }

        // Keep handle around for DllMain DETACH so we can terminate the
        // init thread before the loader unmaps us. Don't close it here.
        g_init_thread_handle = thread_handle;
    }
}

// ---------------------------------------------------------------------------
// DllMain — minimal, no loader lock violations
// Not exported: the loader invokes us via the PE AddressOfEntryPoint, not
// via the export table.
// ---------------------------------------------------------------------------
int __stdcall DllMain(void* hinstDLL, u32 fdwReason, void* lpvReserved) {
    (void)lpvReserved;

    switch (fdwReason) {
    case 1:  // DLL_PROCESS_ATTACH
        // Save our module base — needed for code integrity hashing
        g_dll_base    = hinstDLL;
        g_dll_text_sz = ad_dll_get_text_size(hinstDLL);

        // Spawn init thread — all heavy work happens there
        ad_dll_spawn_init_thread();
        break;

    case 0:  // DLL_PROCESS_DETACH
        g_should_exit = 1;
        AD_BARRIER();
#if AD_DLL_UNLOADABLE
        // UNLOADABLE mode: full teardown so an external FreeLibrary leaves
        // no thread executing in our (about-to-be-unmapped) memory.
        //
        // lpvReserved == NULL → genuine FreeLibrary call → do the cleanup.
        // lpvReserved != NULL → process is terminating; kernel reclaims
        //                      everything; skip cleanup to avoid loader-lock
        //                      pitfalls.
        if (lpvReserved == 0) {
            __try {
                // 1. Force-terminate the init thread. It may be sleeping
                //    inside check_loop's NtDelayExecution (up to 7s) — we
                //    can't wait that long inside DllMain, and we can't
                //    rely on it polling g_should_exit fast enough.
                //    NtTerminateThread on a thread parked in
                //    NtDelayExecution is benign (no kernel locks held).
                if (g_init_thread_handle) {
                    static u16 s_term = AD_SSN_UNRESOLVED;
                    AD_RESOLVE_SSN_ENC(s_term, NtTerminateThread, 18);
                    if (s_term != AD_SSN_FAILED) {
                        AD_SYSCALL2(s_term, (void*)g_init_thread_handle, (void*)0);
                    }
                }

                // 2. Stop helper threads that live in our .text.
#if AD_ENABLE_THREAD_NOISE
                ad_noise_swarm_stop();
#endif
                ad_watchdog_stop();

                // 3. Remove VEH handlers — their callbacks point into our
                //    code and would crash the process if dispatched after
                //    the unmap.
                ad_veh_uninstall();

                // 4. Close the init-thread handle (we kept it open so we
                //    could terminate the thread above).
                if (g_init_thread_handle) {
                    static u16 s_close = AD_SSN_UNRESOLVED;
                    AD_RESOLVE_SSN_ENC(s_close, NtClose, 8);
                    if (s_close != AD_SSN_FAILED) {
                        AD_SYSCALL1(s_close, (void*)g_init_thread_handle);
                    }
                    g_init_thread_handle = 0;
                }
            } __except(1) {}
        }
#endif
        break;
    }
    return 1;  // TRUE
}

// No exported API — the framework operates autonomously after DllMain
// spawns the init thread. The DLL has no public surface.
