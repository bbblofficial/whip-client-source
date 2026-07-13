// ===== file: main_example.c =====
//
// CTF Challenge: extract the flag.
//
// The flag is encrypted with a key derived from the anti-debug score.
// If score == 0 (clean environment), the key decrypts the flag correctly.
// If score > 0 (debugger/VM/hook detected), the key is wrong → garbage.
//
// Objective for a reverser: make this program print the real flag.
//

// ── MAXIMUM-PROTECTION BUILD ────────────────────────────────────────────
// Activate every opt-in opsec tier before any poly_syscall.h include so
// the storage-level toggles kick in from the very first TU that pulls
// the header. Run the resulting exe through VMProtect Ultimate (mutation
// + virtualization on main + derive_key_stream + ghost_* + ad_run_*) to
// stack the VMP layer on top.
//
//   AD_ENABLE_POLY_JIT        — T3: `0F 05` present only during a live
//                                call window; `90 90` at rest. ~4 extra
//                                syscalls per real syscall.
//   AD_ENABLE_POLY_TRANSIENT  — T5: fresh page per call; new address
//                                each time. ~3 extra syscalls per real
//                                syscall. Defeats hook-by-address.
//
// T5 takes precedence when the allocator succeeds; T3 kicks in as the
// fallback on the stable gadget pool when a transient alloc fails. In
// practice almost every call uses T5.
#define AD_ENABLE_POLY_JIT
#define AD_ENABLE_POLY_TRANSIENT

#include "antidebug/core/syscall_bridge.h"
#include "antidebug/core/vmp_markers.h"
#include "antidebug/dispatcher/dispatcher.h"
#include "antidebug/stack/moonwalk.h"
#include "antidebug/stack/moonwalk_asm.h"
#include "antidebug/stack/phantom_call.h"
#include "antidebug/stack/stack_desync.h"
#include "antidebug/stack/gadget_chain.h"
#include "antidebug/stack/syscall_spoof.h"
#include "antidebug/stack/stack_flood.h"
#include "antidebug/checks/runtime/anti_dump.h"
#include "antidebug/checks/runtime/anti_breakin.h"
#include "antidebug/checks/runtime/halos_gate_desync.h"
#include "antidebug/checks/runtime/heavens_gate.h"
#include "antidebug/checks/runtime/raise_hard_error.h"
#include "antidebug/checks/runtime/etw_ti_detect.h"
#include "antidebug/checks/runtime/kernel_callback_indirect.h"
#include "antidebug/checks/runtime/private_exec_scan.h"
#include "antidebug/checks/exceptions/veh_encrypted_cfg.h"
#include "antidebug/checks/integrity/anti_patch.h"
#include "antidebug/checks/deep_checks.h"
#include "antidebug/checks/integrity/nop_patrol.h"
#include "antidebug/core/mem_encrypt.h"
#include "antidebug/core/latent_tamper.h"
#include "antidebug/core/latent_tamper2.h"
#include "antidebug/core/hyperion_blob.h"
#include "antidebug/vm/vm_programs.h"
#include "antidebug/checks/integrity/critical_scan.h"
#include "antidebug/checks/timing/total_elapsed.h"
#include "antidebug/checks/advanced/syscall_verify.h"
#include "antidebug/checks/advanced/anti_scyllahide.h"
#include "antidebug/checks/advanced/anti_titanhide.h"
#include "antidebug/honeypot/ai_decoys.h"
#include "antidebug/checks/advanced/deep_scyllahide.h"
#include "antidebug/checks/advanced/decoy_honeypot.h"
#include "antidebug/checks/integrity/anti_tamper.h"
#include "antidebug/checks/vm/hwid_fingerprint.h"
#include "antidebug/stack/stealth_exec.h"
#include "antidebug/stack/thread_noise.h"
#include "antidebug/core/poly_syscall.h"
#include "antidebug/core/watchdog.h"
#include "antidebug/core/sentinels.h"
#include "antidebug/stack/main_ra_spoof.h"
#include "antidebug/core/flag_honeypot.h"
#include "antidebug/checks/decoy_checks.h"
#include "antidebug/core/veh_dispatch.h"
#include "antidebug/stack/cloaked_call.h"
#include "antidebug/core/opaque.h"
#include "antidebug/checks/debugger/int3_pockets.h"
#include "antidebug/stack/fake_decrypt_thread.h"
#include "antidebug/early_warning.h"
// Suite anti-analyse statique exposée via une façade pour éviter de tirer
// <windows.h> dans cette TU (il entre en conflit avec les prototypes manuels
// du projet : RtlCaptureContext, RaiseException, etc.).
#include "antidebug/static_analysis_orchestrator.h"
#include "antidebug/checks/debug/al_khaser_classics.h"
#include "antidebug/checks/debug/kd_extra.h"

// ---------------------------------------------------------------------------
// Minimal console output — no CRT, no printf, no imports
// ---------------------------------------------------------------------------

// Encrypted: "NtWriteFile" (11 chars)
#define AD_STRENC_NtWriteFile(buf)                                           \
    do {                                                                     \
        const u8 _k = AD_STR_KEY(0x33);                                     \
        char buf##_e[12];                                                    \
        AD_ENC(buf##_e,  0, 'N', _k); AD_ENC(buf##_e,  1, 't', _k);       \
        AD_ENC(buf##_e,  2, 'W', _k); AD_ENC(buf##_e,  3, 'r', _k);       \
        AD_ENC(buf##_e,  4, 'i', _k); AD_ENC(buf##_e,  5, 't', _k);       \
        AD_ENC(buf##_e,  6, 'e', _k); AD_ENC(buf##_e,  7, 'F', _k);       \
        AD_ENC(buf##_e,  8, 'i', _k); AD_ENC(buf##_e,  9, 'l', _k);       \
        AD_ENC(buf##_e, 10, 'e', _k);                                       \
        AD_DECODE_BUF(buf##_e, 11, _k);                                     \
        for (unsigned _ci = 0; _ci < 12; _ci++) (buf)[_ci] = buf##_e[_ci];  \
    } while (0)

// Encrypted: "NtTerminateProcess" (18 chars)
#define AD_STRENC_NtTerminateProcess(buf)                                    \
    do {                                                                     \
        const u8 _k = AD_STR_KEY(0x4A);                                     \
        char buf##_e[19];                                                    \
        AD_ENC(buf##_e,  0, 'N', _k); AD_ENC(buf##_e,  1, 't', _k);       \
        AD_ENC(buf##_e,  2, 'T', _k); AD_ENC(buf##_e,  3, 'e', _k);       \
        AD_ENC(buf##_e,  4, 'r', _k); AD_ENC(buf##_e,  5, 'm', _k);       \
        AD_ENC(buf##_e,  6, 'i', _k); AD_ENC(buf##_e,  7, 'n', _k);       \
        AD_ENC(buf##_e,  8, 'a', _k); AD_ENC(buf##_e,  9, 't', _k);       \
        AD_ENC(buf##_e, 10, 'e', _k); AD_ENC(buf##_e, 11, 'P', _k);       \
        AD_ENC(buf##_e, 12, 'r', _k); AD_ENC(buf##_e, 13, 'o', _k);       \
        AD_ENC(buf##_e, 14, 'c', _k); AD_ENC(buf##_e, 15, 'e', _k);       \
        AD_ENC(buf##_e, 16, 's', _k); AD_ENC(buf##_e, 17, 's', _k);       \
        AD_DECODE_BUF(buf##_e, 18, _k);                                     \
        for (unsigned _ci = 0; _ci < 19; _ci++) (buf)[_ci] = buf##_e[_ci];  \
    } while (0)

// File-scope SSN cache. Must be warmed via ad_terminate_warmup() BEFORE
// ad_erase_ntdll_header() runs, otherwise the export-table walk inside
// AD_RESOLVE_SSN_ENC hits the now-zeroed ntdll first page and faults.
static u16 g_terminate_ssn = AD_SSN_UNRESOLVED;

static void ad_terminate_warmup(void) {
    if (g_terminate_ssn != AD_SSN_UNRESOLVED) return;
    AD_RESOLVE_SSN_ENC(g_terminate_ssn, NtTerminateProcess, 19);
}

static void ad_terminate_self(ad_ntstatus_t exit_code) {
    if (g_terminate_ssn == AD_SSN_UNRESOLVED) ad_terminate_warmup();
    if (g_terminate_ssn == AD_SSN_FAILED) return;
    // NtTerminateProcess(ProcessHandle, ExitStatus)
    AD_SYSCALL2(g_terminate_ssn, AD_CURRENT_PROCESS, (u64)exit_code);
}

// IO_STATUS_BLOCK for NtWriteFile
typedef struct {
    union { ad_ntstatus_t Status; void* Pointer; } u;
    u64 Information;
} AD_IO_STATUS_BLOCK;

// Get stdout handle from PEB.ProcessParameters
static void* get_stdout_handle(void) {
#if defined(_MSC_VER)
    u8* peb = (u8*)__readgsqword(0x60);
    u8* params = *(u8**)(peb + 0x20);
    return *(void**)(params + 0x28);
#else
    return (void*)0;
#endif
}

static void write_console(const char* msg, u32 len) {
    static u16 s_ssn = AD_SSN_UNRESOLVED;
    AD_RESOLVE_SSN_ENC(s_ssn, NtWriteFile, 12);
    if (s_ssn == AD_SSN_FAILED) return;

    void* stdout_h = get_stdout_handle();
    if (!stdout_h) return;

    AD_IO_STATUS_BLOCK iosb;
    AD_ZERO_BUF(&iosb, sizeof(iosb));

    SyscallStub(s_ssn,
        stdout_h, (void*)0, (void*)0, (void*)0,
        &iosb, (void*)msg, (void*)(u64)len,
        (void*)0, (void*)0, (void*)0, (void*)0
    );
}

static u32 str_len(const char* s) {
    u32 n = 0;
    while (s[n]) n++;
    return n;
}

static void print(const char* msg) {
    write_console(msg, str_len(msg));
}

static void print_score(const char* label, u32 val) {
    char buf[64]; u32 bi = 0;
    const char* p = label; while (*p) buf[bi++] = *p++;
    char num[12]; int pos = 0;
    if (val == 0) { num[pos++] = '0'; }
    else { u32 v = val; while (v > 0) { num[pos++] = (char)('0' + v%10u); v/=10u; } }
    int ni; for (ni = pos-1; ni >= 0; ni--) buf[bi++] = num[ni];
    buf[bi++] = '\r'; buf[bi++] = '\n';
    write_console(buf, bi);
}


// ---------------------------------------------------------------------------
// The flag is encrypted — NEVER appears as plaintext in binary.
// ---------------------------------------------------------------------------

#define FLAG_LEN 35

#define AD_BUILD_FLAG_ON_STACK(buf)                                          \
    do {                                                                     \
        const u8 _fk = AD_STR_KEY(0xE7);                                    \
        char buf##_e[36];                                                    \
        AD_ENC(buf##_e,  0, 'F', _fk); AD_ENC(buf##_e,  1, 'L', _fk);    \
        AD_ENC(buf##_e,  2, 'A', _fk); AD_ENC(buf##_e,  3, 'G', _fk);    \
        AD_ENC(buf##_e,  4, '{', _fk); AD_ENC(buf##_e,  5, 'W', _fk);    \
        AD_ENC(buf##_e,  6, 'h', _fk); AD_ENC(buf##_e,  7, '1', _fk);    \
        AD_ENC(buf##_e,  8, 'p', _fk); AD_ENC(buf##_e,  9, '_', _fk);    \
        AD_ENC(buf##_e, 10, '4', _fk); AD_ENC(buf##_e, 11, 'n', _fk);    \
        AD_ENC(buf##_e, 12, 't', _fk); AD_ENC(buf##_e, 13, '1', _fk);    \
        AD_ENC(buf##_e, 14, 'D', _fk); AD_ENC(buf##_e, 15, '3', _fk);    \
        AD_ENC(buf##_e, 16, 'b', _fk); AD_ENC(buf##_e, 17, 'u', _fk);    \
        AD_ENC(buf##_e, 18, 'g', _fk); AD_ENC(buf##_e, 19, '_', _fk);    \
        AD_ENC(buf##_e, 20, 'U', _fk); AD_ENC(buf##_e, 21, 'n', _fk);    \
        AD_ENC(buf##_e, 22, 'r', _fk); AD_ENC(buf##_e, 23, '3', _fk);    \
        AD_ENC(buf##_e, 24, 'v', _fk); AD_ENC(buf##_e, 25, '3', _fk);    \
        AD_ENC(buf##_e, 26, 'r', _fk); AD_ENC(buf##_e, 27, 's', _fk);    \
        AD_ENC(buf##_e, 28, '4', _fk); AD_ENC(buf##_e, 29, 'b', _fk);    \
        AD_ENC(buf##_e, 30, 'l', _fk); AD_ENC(buf##_e, 31, '3', _fk);    \
        AD_ENC(buf##_e, 32, '!', _fk); AD_ENC(buf##_e, 33, '}', _fk);    \
        AD_ENC(buf##_e, 34, '\0', _fk);                                    \
        AD_DECODE_BUF(buf##_e, 35, _fk);                                   \
        for (unsigned _fi = 0; _fi < 36; _fi++) (buf)[_fi] = buf##_e[_fi]; \
    } while (0)

// =========================================================================
// VMP-protected functions — each isolated with #pragma optimize off/on
// so the compiler never merges them across marker boundaries.
// =========================================================================

// --- derive_key_stream: Virtualization (small, no loops that vectorize) ---
#pragma optimize("", off)
__declspec(noinline)
static void derive_key_stream(u32 score, u8* key_out, u32 len) {
    VMProtectBeginVirtualization("dk");
    u64 h = 0xCBF29CE484222325ULL;
    h ^= (u64)score;
    h *= 0x00000100000001B3ULL;
    h ^= (u64)(score * 0x9E3779B9u);
    h *= 0x00000100000001B3ULL;

    u32 i;
    for (i = 0; i < len; i++) {
        h ^= (u64)i;
        h *= 0x00000100000001B3ULL;
        key_out[i] = (u8)(h & 0xFF);
    }
    VMProtectEnd();
}
#pragma optimize("", on)

typedef struct {
    ad_state_t*  state;
    ad_result_t  result;
} run_args_t;

// --- run_trampoline: Mutation (calls into huge inlined code) ---
#pragma optimize("", off)
__declspec(noinline)
static void run_trampoline(void* raw_arg) {
    VMProtectBeginMutation("rt");
    run_args_t* a = (run_args_t*)raw_arg;

    __try {
        a->result = ad_run_hardened(a->state);
        AD_DECRYPT_RESULT(a->result);
    }
    __except (1) {
        // A crash during checks = hostile environment (EPT hook, stack
        // manipulation, SEH chain disrupted, etc.). Max suspicion.
        AD_ZERO_BUF(&a->result, sizeof(a->result));
        a->result.score      = 0xFFFFFFFFu;
        a->result.checks_hit = (u32)AD_CHECK_COUNT;
        a->result.checks_run = (u32)AD_CHECK_COUNT;
    }

    VMProtectEnd();
}
#pragma optimize("", on)

// Forward declaration — defined below.
static u32 ad_run_supplemental(ad_state_t* s, const ad_tamper_baseline_t* tamper_bl);

// Module count baseline for anti-DLL injection (set in main, checked in supplemental)
static volatile u32 g_init_module_count = 0;


// Stealth wrapper for ad_run_hardened: runs in a ghost thread so the
// main thread's stack shows only NtWaitForSingleObject during execution.
typedef struct {
    ad_state_t*             state;
    ad_gadget_table_t*      gadgets;
    ad_decoy_table_t*       decoys;
    ad_result_t             result;
} ghost_hardened_args_t;

static u32 ghost_hardened_fn(void* raw) {
    ghost_hardened_args_t* a = (ghost_hardened_args_t*)raw;
    // Stack flood + phantom call inside the ghost thread
    ad_flood_ctx_t flood;
    ad_flood_stack(&flood, a->gadgets, a->decoys);

    run_args_t rargs;
    rargs.state = a->state;
    AD_ZERO_BUF(&rargs.result, sizeof(rargs.result));
    ad_phantom_indirect(run_trampoline, &rargs);

    ad_flood_restore(&flood);
    a->result = rargs.result;
    return rargs.result.score;
}

// Stealth wrapper for ad_run_supplemental: runs via APC so the stack
// shows KiUserApcDispatcher → ntdll → anonymous callback.
typedef struct {
    ad_state_t*                    state;
    const ad_tamper_baseline_t*    tamper_bl;
} ghost_sup_args_t;

static u32 ghost_supplemental_fn(void* raw) {
    ghost_sup_args_t* a = (ghost_sup_args_t*)raw;
    return ad_run_supplemental(a->state, a->tamper_bl);
}

// Supplemental checks: VM + dispatcher-only checks not in ad_run_hardened.
// Runs in main() AFTER ad_flood_restore — own stack frame, no inlining
// explosion. The whole body is wrapped in VMProtectBeginMutation so the
// dispatcher table of all the new feat/* checks (anti_breakin verify,
// halos_gate, halos_gate_multi, veh_cfg verify+run) is mutated as a
// single unit at protection time, hiding the call sequence and the
// per-check weights from static analysis.
#pragma optimize("", off)
// Per-check accumulator for diagnosing silent false positives.
// Populated only in AD_DEBUG_BREAKDOWN builds; zero overhead otherwise.
typedef struct {
    u32 vm_hyper, vm_rdtsc, loop_tim, dbgobj_h, kdbg, qpc, dbgobj_rm;
    u32 guard_pg, dr_canary, instcb, seh_bp;
    u32 breakin, halos_one, halos_multi, heavens, raise_hard, etw_ti;
    u32 kcb_indirect, priv_exec, hyperion, veh_verify, veh_run;
    u32 syscall_verify, sh_extended, dsh_master;
} ad_dbg_sup_t;
static volatile ad_dbg_sup_t ad_dbg_sup = {0};


#define AD_SUP_ACC(field, weight, expr) \
    do { u32 _v = 0u; __try { _v = (expr) ? (weight) : 0u; } __except(1) { _v = (weight); } \
         score += _v; ad_dbg_sup.field = _v; } while(0)

#define AD_SUP_ACC_RAW(field, expr, fail_weight) \
    do { u32 _v = 0u; __try { _v = (expr); } __except(1) { _v = (fail_weight); } \
         score += _v; ad_dbg_sup.field = _v; } while(0)

__declspec(noinline)

static u32 ad_run_supplemental(ad_state_t* s, const ad_tamper_baseline_t* tamper_bl) {
    VMProtectBeginMutation("supplemental");
    u32 score = 0u;
    AD_UNUSED(s);

    // All supplemental checks are wrapped in __try/__except. A crash
    // inside any check means hostile environment → add the weight anyway.

#if AD_ENABLE_VM_HYPERVISOR
    AD_SUP_ACC(vm_hyper, 2u, ad_vm_cpuid_hypervisor_bit());
#endif
#if AD_ENABLE_VM_RDTSC
    AD_SUP_ACC(vm_rdtsc, 2u, ad_vm_rdtsc_overhead());
#endif
#if AD_ENABLE_LOOP_TIMING
    AD_SUP_ACC(loop_tim, 2u, ad_loop_timing());
#endif
    AD_SUP_ACC(dbgobj_h, 2u, ad_debug_object_handle());
#if AD_ENABLE_KERNEL_DEBUGGER
    AD_SUP_ACC(kdbg, 3u, ad_kernel_debugger());
#endif
#if AD_ENABLE_QPC_TIMING
    AD_SUP_ACC(qpc, 2u, ad_qpc_timing());
#endif
#if AD_ENABLE_DEBUG_OBJECT_REMOVE
    AD_SUP_ACC(dbgobj_rm, 4u, ad_remove_debug_object());
#endif
#if AD_ENABLE_GUARD_PAGE_TRAP
    AD_SUP_ACC(guard_pg, 3u, ad_guard_page_trap());
#endif
#if AD_ENABLE_DR_CANARY
    AD_SUP_ACC(dr_canary, 3u, ad_dr_canary());
#endif
#if AD_ENABLE_INSTRUMENTATION_CB
    AD_SUP_ACC(instcb, 4u, ad_instrumentation_callback_check());
#endif
#if AD_ENABLE_SEH_CHECK
    AD_SUP_ACC(seh_bp, 2u, ad_seh_breakpoint());
#endif

    AD_SUP_ACC(breakin, 6u, ad_anti_breakin_verify());
    AD_SUP_ACC(halos_one, 7u, ad_halos_gate_desync());
    AD_SUP_ACC_RAW(halos_multi, ad_halos_gate_multi_count() * 4u, 16u);
    AD_SUP_ACC(heavens, 5u, ad_heavens_gate_check());
    AD_SUP_ACC(raise_hard, 6u, ad_raise_hard_error_probe());
    AD_SUP_ACC(etw_ti, 5u, ad_etw_ti_check());
    AD_SUP_ACC(kcb_indirect, 4u, ad_kernel_callback_indirect());
    // PRIVATE+EXEC region count. Modern Win10/11 has 30-70 such regions
    // legitimately (Defender AmsiScanBuffer hooks, AppContainer, ETW
    // providers, shell extensions, …). Score only the SURPLUS above the
    // typical clean baseline.
    {
        u32 raw = 0u;
        __try { raw = ad_private_exec_scan(); } __except(1) { raw = 4u; /* assume clean+small */ }
        u32 surplus = (raw > AD_PRIV_EXEC_BASELINE) ? (raw - AD_PRIV_EXEC_BASELINE) : 0u;
        u32 v = surplus * 3u;
        score += v;
        ad_dbg_sup.priv_exec = v;
    }
    AD_SUP_ACC(hyperion, 9u, ad_hyperion_check());
    AD_SUP_ACC(veh_verify, 8u, ad_veh_cfg_verify());
    AD_SUP_ACC_RAW(veh_run, ad_veh_cfg_run(), 4u);

    // ── Direct-syscall debug state verification ─────────────────────────
    // These MUST run in native code (not VMP Virtualization) because
    // WhipSysCall's SyscallStub needs a real x86 call frame. VMP Mutation
    // is fine — it only obfuscates, doesn't interpret.
#if AD_ENABLE_SYSCALL_VERIFY
    {
        u32 sv = 0u;
        __try { sv = ad_sv_master(); } __except(1) { sv = 0u; }
        // Store in volatile to prevent optimization and allow debugger inspection
        volatile u32 dbg_sv_score = sv;
        AD_UNUSED(dbg_sv_score);
        score += sv;
    }
#endif

#if AD_ENABLE_ANTI_SCYLLAHIDE
    {
        u32 sh = 0u;
        __try { sh = ad_scyllahide_extended(); } __except(1) { sh = 0u; }
        score += sh;
    }
    {
        u32 dsh = 0u;
        __try { dsh = ad_deep_scyllahide_master(); } __except(1) { dsh = 0u; }
        score += dsh;
    }
#endif

    // ── Anti-tamper: Cheat Engine + foreign VM_WRITE + code integrity ───
    {
        u32 at = 0u;
        __try { at = ad_anti_tamper_master(tamper_bl); } __except(1) { at = 0u; }
        score += at;
    }

    // ── Anti-DLL injection: compare module count against init baseline ──
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
        if (current_modules > g_init_module_count + 2u) score += 10u;
    } __except(1) { score += 10u; }

    // ── Cheat Engine detection: scan process list for cheatengine*.exe ──
    __try {
        volatile u8* kusd = (volatile u8*)0x7FFE0000ULL;
        volatile u8 kd_enabled = *(volatile u8*)(kusd + 0x02D4);
        if (kd_enabled) score += 10u;
        volatile u8 kd_not_present = *(volatile u8*)(kusd + 0x02D5);
        if (!kd_not_present) score += 8u;
    } __except(1) { score += 10u; }

    // ── HWID / environment fingerprint ─────────────────────────────────
#if AD_ENABLE_HWID_FINGERPRINT
    {
        u32 hw = 0u;
        __try { hw = ad_hwid_fingerprint_master(); } __except(1) { hw = 0u; }
        score += hw;
    }
#endif

    // ── al-khaser classics — 6 well-known checks ported to direct-syscall
    {
        u32 ak = 0u;
        __try { ak = ad_al_khaser_classics_master(); } __except(1) { ak = 0u; }
        score += ak;
    }

    // ── kd-extra — DebugActiveProcess(self), VEH count, BreakOnTermination
    {
        u32 kx = 0u;
        __try { kx = ad_kd_extra_master(); } __except(1) { kx = 0u; }
        score += kx;
    }

    VMProtectEnd();
    return score;
}
#pragma optimize("", on)

// =========================================================================
// Install block — extracted from main() into its own function so VMProtect
// treats `main` and `ad_install_block` as two distinct, non-overlapping
// code regions. Without this split, the SDK marker inside main created a
// sub-region that collided with a GUI-added "main" protection.
//
//   * __declspec(noinline): forbids the compiler from inlining this body
//     back into main (which would recreate the overlap).
//   * #pragma optimize off: disables cross-function optimisations — the
//     function stays in its own address range and its prologue/epilogue
//     are predictable, which is what VMP's static analysis expects.
//
// The SDK marker `VMProtectBeginUltra("ad_install_block")` lives at the
// top of this function now. In the VMP GUI, add `main` as a separate
// function entry; the SDK marker inside this function handles the rest
// with no overlap.
// =========================================================================
#pragma optimize("", off)
__declspec(noinline)
static int ad_do_install_block(void) {
    VMProtectBeginUltra("ad_install_block");

    // VEH-based indirect dispatch: install a high-priority handler that
    // converts `int3` at AD_VEH_CALL sites into a hidden CALL via an
    // encrypted function table. Must run before any AD_VEH_CALL is
    // issued below. Registration binds slot IDs to no-arg targets; the
    // pointers are XOR-encrypted at registration time with per-slot keys.
    __try {
        (void)ad_veh_disp_install();
        ad_veh_disp_register(AD_VEH_SLOT_NOISE_SWARM_START,
            (ad_veh_disp_fn_t)(void*)&ad_noise_swarm_start);
        ad_veh_disp_register(AD_VEH_SLOT_ANTI_ATTACH,
            (ad_veh_disp_fn_t)(void*)&ad_anti_attach_set_no_inherit);
        ad_veh_disp_register(AD_VEH_SLOT_DROP_SE_DEBUG,
            (ad_veh_disp_fn_t)(void*)&ad_drop_se_debug);
    } __except(1) {}

    // Control Flow Flattening dispatcher. Same state-machine as before;
    // just moved inside this dedicated function. Net execution order
    // is preserved (VEH first, poly_init before watchdog_start).
    {
        #define AD_CFF_N 15u
        u32 cff_key = (u32)(__rdtsc() & 0xFFu);
        u8  cff_next[AD_CFF_N];
        {
            u32 i;
            for (i = 0; i + 1u < AD_CFF_N; i++)
                cff_next[i] = (u8)((i + 1u) ^ cff_key);
            cff_next[AD_CFF_N - 1u] = (u8)(0xFFu ^ cff_key);
        }
        u8  cff_state = (u8)(0u ^ cff_key);
        u32 cff_guard = 0u;
        while (cff_state != (u8)(0xFFu ^ cff_key) && cff_guard < 64u) {
            u8 s = (u8)(cff_state ^ cff_key);
            switch (s) {
                case  0: __try { (void)ad_veh_install(); }                  __except(1) {} break;
                case  1: __try { AD_VEH_CALL(AD_VEH_SLOT_DROP_SE_DEBUG); }  __except(1) {} break;
                case  2: __try { (void)ad_fake_hwbp_install(); }            __except(1) {} break;
                case  3: __try { AD_VEH_CALL(AD_VEH_SLOT_ANTI_ATTACH); }    __except(1) {} break;
                case  4: __try { (void)ad_anti_breakin_install(); }         __except(1) {} break;
                case  5: __try { (void)ad_latent_init(); }                  __except(1) {} break;
                case  6: __try { (void)ad_latent2_init(); }                 __except(1) {} break;
                case  7: __try { (void)ad_veh_cfg_install(); }              __except(1) {} break;
                case  8: __try { (void)ad_decoy_install(); }                __except(1) {} break;
                case  9: __try {
                             ad_page_guard_init(&g_ad_page_guard);
                             ad_page_guard_arm(&g_ad_page_guard);
                         } __except(1) {} break;
                case 10: __try { AD_VEH_CALL(AD_VEH_SLOT_NOISE_SWARM_START); } __except(1) {} break;
                case 11: __try { ad_poly_init(); }                          __except(1) {} break;
                case 12: __try { ad_watchdog_start(); }                     __except(1) {} break;
                case 13: __try { ad_ws_hook_install(); }                    __except(1) {} break;
                case 14: __try { ad_tsc_qpc_calibrate(&g_tsc_qpc_ctx); }   __except(1) {} break;
                default:
                    cff_state = (u8)(0xFFu ^ cff_key);
                    cff_guard++;
                    continue;
            }
            cff_state = cff_next[s];
            cff_guard++;
        }
        #undef AD_CFF_N
    }
    VMProtectEnd();
    return 0;
}
#pragma optimize("", on)

// =========================================================================
// Orchestrator — runs the full program payload inside a detached worker
// thread spawned by main() via ad_ghost_exec. The worker's call chain is
//
//     ntdll!RtlUserThreadStart → kernel32!BaseThreadInitThunk
//         → <RWX trampoline>   → ad_ghost_thread_entry
//         → ad_main_orchestrator → ...
//
// — `main` is COMPLETELY ABSENT from any sample of this thread's stack.
// A reverser sampling the worker thread sees no path back to the entry
// point. Renamed from the original `main`; signature matches the
// `ad_stealth_fn_t` ad_ghost_exec requires.
// #pragma optimize off keeps the orchestrator's code range disjoint
// from main's so the VMP GUI can protect both without overlap errors.
// =========================================================================
#pragma optimize("", off)
static u32 __stdcall ad_main_orchestrator(void* arg) {
    AD_UNUSED(arg);
    VMProtectBeginVirtualization("orchestrator");
    AD_DISABLE_AVX512();

    // ── Early Warning System — AI assistant warnings displayed immediately
    ad_early_warning_init();

    // ── AI Confusion Layer — Deploy fake functions and misleading patterns
    ad_static_deploy_confusion();
    ad_static_confuse_ai();

    // ── AI honeypot anchor: keeps the decoy strings in the final image
    // so that an LLM-driven RE assistant scanning .rdata trips on them
    // and reads the "this is not a CTF" notice. Zero functional cost.
    ad_ai_decoys_anchor();

    // ── Opaque predicate noise seed. Must run before AD_OPAQUE_* macros
    // and INT3/UD2 pockets so their predicates cannot be constant-folded.
    ad_opaque_seed();

    // ── Scattered trap pockets — dead branches that a reverser who
    // patches predicates or strays off the happy path lands in.
    AD_INT3_POCKET();
    AD_DECOY_POCKET();

    // ── Honeypot flag strings — touch table so linker retains it in
    // .rdata and the decryption path runs (leaves plausible flag bytes
    // on the stack briefly for a memory-scraping reverser to find).
    // Return value folded into a volatile global so the call cannot be
    // dead-stripped.
    {
        static volatile u32 g_hp_anchor = 0u;
        g_hp_anchor ^= ad_honeypot_touch();
    }

    // ── Decoy check spam — 38 functions that LOOK like anti-debug
    // checks but never contribute to the real score. A reverser must
    // analyze each call target to prove it is dead. Result XOR-folded
    // into a volatile anchor so the call graph cannot be stripped.
    //
    // Invoked via CloakedCall0 — the trampoline XOR-scrambles this
    // function's return address on the stack for the duration of the
    // decoy call. A stack dump captured while ad_decoy_master runs
    // shows a garbage pointer where our caller would be, masking the
    // call graph from live stack walkers.
    {
        static volatile u32 g_dec_anchor = 0u;
        g_dec_anchor ^= (u32)(u64)CloakedCall0((void*)&ad_decoy_master);
    }

    // ── Banner ──────────────────────────────────────────────────────────
    print("=== WhipAntiDebugger CTF Challenge ===\r\n");
    print("Objective: extract the flag.\r\n");
    print("The flag is encrypted with a key derived from the security score.\r\n");
    print("Score 0 = clean environment = correct decryption.\r\n\r\n");

    // ── Init ────────────────────────────────────────────────────────────
    if (!whip_bridge_init()) {
        print("[FATAL] WhipSysCall init failed.\r\n");
        VMProtectEnd();
        return 1;
    }

    // Detached sentinels — three threads with no score, direct punishment.
    // Spawned right after the syscall bridge so their NtDelayExecution /
    // NtQueryInformationProcess / NtGetContextThread / NtTerminateProcess
    // calls all resolve. Their state is independent of the dispatcher and
    // the score vault, so a NOP at the scoring path leaves them armed.
#if !AD_TESTING_MODE
    __try { (void)ad_sentinels_init(); } __except(1) {}
#endif

    ad_state_t state;
    ad_init(&state, (void*)0, 0u);

    // ── Snapshot tick count for total-elapsed detection ──────────────────
    u32 init_tick = ad_elapsed_tick_snapshot();

    // ── Init decoy tables ───────────────────────────────────────────────
    ad_decoy_table_t decoys;
    ad_decoy_table_init(&decoys);

    // ── Snapshot module count for anti-DLL injection ────────────────────
    {
        u32 mc = 0u;
        u8* peb = (u8*)__readgsqword(0x60);
        u8* ldr = *(u8**)(peb + 0x18);
        u8* list_head = ldr + 0x10;
        u8* entry = *(u8**)list_head;
        while (entry != list_head && mc < 200u) {
            mc++;
            entry = *(u8**)entry;
        }
        g_init_module_count = mc;
    }
    ad_gadget_table_t gadgets;
    ad_gadget_table_init(&gadgets);

    // ── Init self-hash ──────────────────────────────────────────────────
    // Must re-seal state MAC after self_hash_init — ad_init seals the MAC as
    // its very last step, but ad_self_hash_init writes to state.self_hashes
    // afterwards, which would break MAC verification in ad_run_hardened.
    {
        const void* fns[] = {
            (const void*)run_trampoline,
            (const void*)ad_main_orchestrator,
            (const void*)derive_key_stream,
            (const void*)ad_run_supplemental,
            (const void*)ghost_hardened_fn,
            (const void*)ghost_supplemental_fn,
        };
        ad_self_hash_init(&state.self_hashes, fns, 6u);
        ad_state_mac_update(&state.state_mac, &state, sizeof(state), &state.memkey);
    }

    // ── Install one-shot anti-debug hooks ────────────────────────────────
    // Delegated to ad_do_install_block() — its own __declspec(noinline)
    // function with VMProtectBeginUltra inside. Keeping it out-of-line
    // means `main` and `ad_install_block` occupy disjoint address ranges
    // so the VMProtect GUI can protect both without the "address already
    // used" overlap error.
    (void)ad_do_install_block();

    // ── Fake decryption worker threads — hidden from debugger, loop
    // producing plausible flag-looking bytes in a visible buffer. A
    // reverser who catches them in the thread list and sets bp on the
    // XOR loop spends time reversing a mirage; their output is never
    // consumed.
    __try { ad_fake_decrypt_spawn(); } __except(1) {}

    // ── ANTI-STATIC ANALYSIS PROTECTION SUITE ──────────────────────────
    // Toutes les détections statiques (binaire, environnement, sandbox,
    // bypass, hooks, etc.) sont regroupées derrière une façade qui isole
    // les includes <windows.h> du reste de la TU.
    print("[*] Running anti-static analysis checks...\r\n");
    u32 static_score = ad_static_analysis_full_master();

    if (static_score > 50) {
        print("[!] STATIC ANALYSIS DETECTED - SCORE CONTAMINATED\r\n");
        // Don't exit immediately, but contaminate the commitment
    }

    // ── Anti-tamper baseline ────────────────────────────────────────────
    // CRC32 critical functions AFTER hooks are installed — so the baseline
    // includes the hook patches. Any FURTHER patching (by a reverser) will
    // be detected as CRC mismatch.
    ad_tamper_baseline_t tamper_bl;
    AD_ZERO_BUF(&tamper_bl, sizeof(tamper_bl));
    __try {
        ad_tamper_baseline_init(&tamper_bl,
            (const void*)ad_run_supplemental,
            (const void*)ad_main_orchestrator);
    } __except(1) {}

    // ── NOP Patrol ──────────────────────────────────────────────────────
    ad_nop_patrol_t patrol;
    AD_ZERO_BUF(&patrol, sizeof(patrol));

    print("[*] Running security checks...\r\n");

    // ── Run hardened checks with full stack spoofing ─────────────────────
#ifdef AD_DEBUG_BREAKDOWN
    ad_dbg_layers.enabled = 1u;
    ad_dbg_deep.enabled = 1u;
    ad_dbg_patch.enabled = 1u;
#endif
    ad_result_t r;
    {
        // Run hardened checks inside a GHOST THREAD — main thread stack
        // shows only NtWaitForSingleObject. Inside the ghost thread,
        // stack flood + phantom call add two more layers of obfuscation.
        ghost_hardened_args_t ghost_args;
        ghost_args.state   = &state;
        ghost_args.gadgets = &gadgets;
        ghost_args.decoys  = &decoys;
        AD_ZERO_BUF(&ghost_args.result, sizeof(ghost_args.result));

        ad_ghost_exec(ghost_hardened_fn, &ghost_args);
        r = ghost_args.result;
    }

    // Reseal MAC — the ghost thread ran on a pool worker which has a
    // different TEB, so the MAC computed inside ad_run_hardened reflects
    // the worker's context. Re-stamp from the main thread.
    ad_state_mac_update(&state.state_mac, &state, sizeof(state), &state.memkey);

    // ── Encrypt result immediately ──────────────────────────────────────
    ad_enc_result_t enc_r;
    ad_result_encrypt(&enc_r, &r, &state.memkey);

    // SizeOfImage inflate — corrupt the PE field so dump tools choke,
    // but safe at runtime (we never re-read this field ourselves).
    {
        void* img = ad_vault_load_ptr(&state.image_base_enc, &state.memkey);
        ad_size_of_image_inflate(img);
    }
    AD_ZERO_BUF(&r, sizeof(r));

    // ── NOP Patrol check ────────────────────────────────────────────────
    ad_patrol_seal(&patrol);
    u32 nop_score = ad_patrol_score(&patrol);

    // ── Supplemental checks (VM CPUID/RDTSC, loop, kernel dbg, QPC, etc.) ─
    // Runs here — outside the stack flood — in its own __declspec(noinline)
    // frame so the stack usage of run_trampoline is not blown out.
    // Run supplemental checks via SELF-APC — stack shows only
    // KiUserApcDispatcher → ntdll → anonymous callback.
    ghost_sup_args_t sup_args;
    sup_args.state     = &state;
    sup_args.tamper_bl = &tamper_bl;
    volatile u32 sup_score = ad_apc_exec(ghost_supplemental_fn, &sup_args);

    // ── Extra VM checks not in dispatcher or ad_run_hardened ────────────
    // ad_vm_hypervisor_vendor : CPUID 0x40000000 EAX >= 0x40000000
    // ad_vm_vendor_known      : exact 12-byte vendor string match
    // ad_vm_vmware_signature  : VMware leaf 0x40000010
#if AD_ENABLE_VM_HYPERVISOR
    if (ad_vm_hypervisor_vendor())  sup_score += 3u;
    if (ad_vm_vendor_known())       sup_score += 4u;
    if (ad_vm_vmware_signature())   sup_score += 2u;
#endif

    // ── Critical function scan — detect BPs on derive_key_stream etc. ──
    {
        const void* critical_fns[] = {
            (const void*)derive_key_stream,
            (const void*)run_trampoline,
            (const void*)ad_main_orchestrator
        };
        u32 crit_score = ad_critical_scan_master(critical_fns, 3u);
        sup_score += crit_score;
    }

    // ── Total elapsed time check — erun/stepping overhead detection ────
    sup_score += ad_elapsed_check(state.init_tsc, init_tick);

    // Reseal MAC — state was modified by supplemental checks and the
    // ghost/APC execution paths. Re-stamp so the debug verify passes.
    ad_state_mac_update(&state.state_mac, &state, sizeof(state), &state.memkey);

    // ── Derive decryption key from score ────────────────────────────────
    ad_result_t tmp = ad_result_decrypt(&enc_r, &state.memkey);

    // Accumulate into obfuscated score — Cheat Engine can't scan for
    // the raw value because it's XOR-encrypted in memory.
    ad_score_ctx_t score_ctx;
    // Pre-seed the accumulator at -(AD_SCORE_NOISE_FLOOR) so the floor is
    // absorbed inside the encrypted vault — no visible subtraction, no
    // extractable constant at the call site.
    ad_score_init_with_floor(&score_ctx, AD_SCORE_NOISE_FLOOR);
    ad_score_add(&score_ctx, tmp.score);
    ad_score_add(&score_ctx, nop_score);
    ad_score_add(&score_ctx, sup_score);
    ad_score_add(&score_ctx, static_score);  // Add static analysis detection score
    ad_score_add(&score_ctx, ad_watchdog_read_penalty());

    // ad_score_read() already saturates at 0 when below the embedded floor.
    volatile u32 final_score = ad_score_read(&score_ctx);
    u32 final_hits  = tmp.checks_hit;

    // Arm the latent tamper trip from the RAW per-layer scores so a
    // reverser must patch every individual contributor — not just the
    // final aggregate — to keep the sentinel thread quiet.
#if !AD_TESTING_MODE
    ad_latent_arm_if((b32)(tmp.score   != 0u));
    ad_latent_arm_if((b32)(nop_score   != 0u));
    ad_latent_arm_if((b32)(sup_score   != 0u));
    ad_latent2_arm_if((b32)(tmp.score  != 0u));
    ad_latent2_arm_if((b32)(nop_score  != 0u));
    ad_latent2_arm_if((b32)(sup_score  != 0u));
#endif
#ifdef AD_DEBUG_BREAKDOWN
    print_score("[DBG] hardened_score: ", tmp.score);
    print_score("[DBG] nop_score:      ", nop_score);
    print_score("[DBG] sup_score:      ", sup_score);
    print_score("[DBG] static_score:   ", static_score);
    print_score("[S] basic:        ", g_ad_static_score_basic);
    print_score("[S] traps:        ", g_ad_static_score_traps);
    print_score("[S] analysis:     ", g_ad_static_score_analysis);
    print_score("[S] comprehens:   ", g_ad_static_score_compre);
    print_score("[S] integrity:    ", g_ad_static_score_intgr);
    print_score("[S] sandbox:      ", g_ad_static_score_sandbox);
    print_score("[S] bypass:       ", g_ad_static_score_bypass);
    print_score("[S] addl:         ", g_ad_static_score_addl);
    print_score("[A] pdata:        ", g_ad_addl_pdata);
    print_score("[A] pdata_ratio%: ", g_ad_addl_pdata_ratio);
    print_score("[A] pdata_n:      ", g_ad_addl_pdata_entries);
    print_score("[A] pdata_oot:    ", g_ad_addl_pdata_oot);
    print_score("[A] cc_island:    ", g_ad_addl_cc);
    print_score("[A] kshared:      ", g_ad_addl_kshared);
    print_score("[B] inject:       ", g_ad_byp_inject);
    print_score("[B] hook:         ", g_ad_byp_hook);
    print_score("[B] struct:       ", g_ad_byp_struct);
    print_score("[B] byte:         ", g_ad_byp_byte);
    print_score("[B] tools:        ", g_ad_byp_tools);
    print_score("[B] syscall:      ", g_ad_byp_syscall);
    print_score("[Bsc] entropy:    ", g_ad_ba_entropy);
    print_score("[Bsc] patches:    ", g_ad_ba_patches);
    print_score("[Bsc] imports:    ", g_ad_ba_imports);
    print_score("[Bsc] extsec:     ", g_ad_ba_extsec);
    print_score("[Bsc] pehdr:      ", g_ad_ba_pehdr);
    print_score("[Bsc] consist:    ", g_ad_ba_consist);
    print_score("[Tr] ts:          ", g_ad_tr_ts);
    print_score("[Tr] tools:       ", g_ad_tr_tools);
    print_score("[Tr] hidbp:       ", g_ad_tr_hidbp);
    print_score("[Co] envvar:      ", g_ad_co_envvar);
    print_score("[Co] reg:         ", g_ad_co_reg);
    print_score("[Co] files:       ", g_ad_co_files);
    print_score("[Co] svc:         ", g_ad_co_svc);
    print_score("[Co] bgproc:      ", g_ad_co_bgproc);
    print_score("[Co] dlls:        ", g_ad_co_dlls);
    print_score("[Co] hooks:       ", g_ad_co_hooks);

    // ── Layer-by-layer dump captured INSIDE ad_run_hardened ─────────────
    print_score("[L] correlation: ", ad_dbg_layers.correlation);
    print_score("[L] deep:        ", ad_dbg_layers.deep);
    print_score("[L] cross:       ", ad_dbg_layers.cross);
    print_score("[L] patch:       ", ad_dbg_layers.patch);
    print_score("[L] exotic:      ", ad_dbg_layers.exotic);
    print_score("[L] advanced:    ", ad_dbg_layers.advanced);
    print_score("[L] extra:       ", ad_dbg_layers.extra);
    print_score("[L] self_poison: ", ad_dbg_layers.self_poison_final);
    print_score("[L] raw_hits:    ", ad_dbg_layers.raw_hits);
    print_score("[L] f_peb_bd:    ", ad_dbg_layers.f_peb_debug);
    print_score("[L] f_ntg:       ", ad_dbg_layers.f_ntgflag);
    print_score("[L] f_heap:      ", ad_dbg_layers.f_heap);
    print_score("[L] f_dbg_port:  ", ad_dbg_layers.f_dbg_port);
    print_score("[L] f_dbg_flags: ", ad_dbg_layers.f_dbg_flags);
    print_score("[L] f_hwbp:      ", ad_dbg_layers.f_hwbp);
    print_score("[L] f_timing:    ", ad_dbg_layers.f_timing);
    print_score("[L] f_syscall:   ", ad_dbg_layers.f_syscall);
    print_score("[L] f_ntclose:   ", ad_dbg_layers.f_ntclose);
    print_score("[L] f_rdtsc_dbl: ", ad_dbg_layers.f_rdtsc_dbl);
    print_score("[L] f_ntdll_hk:  ", ad_dbg_layers.f_ntdll_hooked);
    print_score("[L] f_page_rwx:  ", ad_dbg_layers.f_page_rwx);

    // Deep sub-scores
    print_score("[D] self_map:    ", ad_dbg_deep.self_mapping);
    print_score("[D] poison_peb:  ", ad_dbg_deep.info_poison_peb);
    print_score("[D] poison_ntg:  ", ad_dbg_deep.info_poison_ntg);
    print_score("[D] timing_rat:  ", ad_dbg_deep.timing_ratio);
    print_score("[D] cpuid_cons:  ", ad_dbg_deep.cpuid_consistency);
    print_score("[D] cache_tim:   ", ad_dbg_deep.cache_timing);
    print_score("[D] sched_var:   ", ad_dbg_deep.scheduling_variance);

    // Anti-patch sub-scores
    print_score("[P] page_rwx:    ", ad_dbg_patch.page_rwx);
    print_score("[P] prologues:   ", ad_dbg_patch.prologues_hooked);
    print_score("[P] selfhash:    ", ad_dbg_patch.self_hash_patched);
    print_score("[P] int3_count:  ", ad_dbg_patch.int3_count);
    print_score("[P] int3_added:  ", ad_dbg_patch.int3_added);

    // Extra-check sub-scores
    print_score("[X] tls:         ", ad_dbg_extras.tls);
    print_score("[X] fake_hwbp:   ", ad_dbg_extras.fake_hwbp);
    print_score("[X] anti_attach: ", ad_dbg_extras.anti_attach);
    print_score("[X] frida:       ", ad_dbg_extras.frida);
    print_score("[X] cross_timer: ", ad_dbg_extras.cross_timer);
    print_score("[X] vad_ldr:     ", ad_dbg_extras.vad_ldr);
    print_score("[X] stack_unw:   ", ad_dbg_extras.stack_unwind);
    print_score("[X] veh:         ", ad_dbg_extras.veh);
    print_score("[X] dbgui_patch: ", ad_dbg_extras.dbgui_patch);
    print_score("[X] handle_scan: ", ad_dbg_extras.handle_scan);
    print_score("[X] dlls:        ", ad_dbg_extras.dlls);
    print_score("[X] process_scn: ", ad_dbg_extras.process_scan);
    print_score("[X] etw:         ", ad_dbg_extras.etw);
    print_score("[X] tf_ss:       ", ad_dbg_extras.trap_flag_ss);
    print_score("[X] tf_ctx:      ", ad_dbg_extras.trap_flag_ctx);
    print_score("[X] pg_sentinel: ", ad_dbg_extras.page_guard_sentinel);
    print_score("[X] remote:      ", ad_dbg_extras.f_remote);
    print_score("[X] window:      ", ad_dbg_extras.f_window);
    print_score("[X] ods_timing:  ", ad_dbg_extras.f_ods);
    print_score("[X] ifeo:        ", ad_dbg_extras.f_ifeo);
    print_score("[X] job:         ", ad_dbg_extras.f_job);
    print_score("[X] uef:         ", ad_dbg_extras.f_uef);
    print_score("[X] dbg_filter:  ", ad_dbg_extras.f_dbg_filter);
    print_score("[X] mem_bp:      ", ad_dbg_extras.f_mem_bp);
    print_score("[X] ntdll_page:  ", ad_dbg_extras.f_ntdll_page);
    print_score("[X] behavior:    ", ad_dbg_extras.f_behavior);
    print_score("[X] delta:       ", ad_dbg_extras.f_delta);
    print_score("[X] wireshark:   ", ad_dbg_extras.wireshark);

    // Supplemental sub-scores (re-read from KUSD, cheap)
    {
        volatile u8* kusd = (volatile u8*)0x7FFE0000ULL;
        print_score("[S] kd_enabled:  ", (u32)*(volatile u8*)(kusd + 0x02D4));
        print_score("[S] kd_absent:   ", (u32)*(volatile u8*)(kusd + 0x02D5));
    }
#endif // AD_DEBUG_BREAKDOWN
    AD_ZERO_BUF(&tmp, sizeof(tmp));

    // ── Print diagnostics ───────────────────────────────────────────────
    {
        char buf[64];
        u32 s = final_score;
        char num[12];
        int pos = 0;
        if (s == 0) {
            num[pos++] = '0';
        } else {
            while (s > 0) {
                num[pos++] = '0' + (char)(s % 10);
                s /= 10;
            }
        }
        u32 bi = 0;
        const char* prefix = "[*] Security score: ";
        while (*prefix) buf[bi++] = *prefix++;
        int ni;
        for (ni = pos - 1; ni >= 0; ni--) buf[bi++] = num[ni];
        buf[bi++] = '\r'; buf[bi++] = '\n';
        buf[bi] = 0;
        write_console(buf, bi);
    }

    {
        char buf[64];
        u32 s = final_hits;
        char num[12];
        int pos = 0;
        if (s == 0) {
            num[pos++] = '0';
        } else {
            while (s > 0) {
                num[pos++] = '0' + (char)(s % 10);
                s /= 10;
            }
        }
        u32 bi = 0;
        const char* prefix = "[*] Checks hit: ";
        while (*prefix) buf[bi++] = *prefix++;
        int ni;
        for (ni = pos - 1; ni >= 0; ni--) buf[bi++] = num[ni];
        buf[bi++] = '\r'; buf[bi++] = '\n';
        buf[bi] = 0;
        write_console(buf, bi);
    }

#ifdef AD_DEBUG_BREAKDOWN
    // Reseal MAC, then verify IMMEDIATELY — before any diagnostic check can
    // mutate state fields (temporal_ctx, heisenberg_ctx, etc.).  Storing the
    // result in a local avoids the false "mac_bad=1" caused by running further
    // checks (which legitimately modify the struct) prior to the verify.
    __try { ad_state_mac_update(&state.state_mac, &state, sizeof(state), &state.memkey); } __except(1){}
    b32 diag_mac_bad = 0;
    __try { diag_mac_bad = ad_state_mac_verify(&state.state_mac, &state, sizeof(state), &state.memkey); } __except(1){}
    // ── Diagnostic: per-component hardened score ─────────────────────────
    {
        void* diag_img = ad_vault_load_ptr(&state.image_base_enc, &state.memkey);
        u32 d_corr = 0, d_deep = 0, d_cross = 0, d_patch = 0;
        u32 d_exotic = 0, d_adv = 0, d_extra = 0;

        // Correlation: all observable checks = 0 (checks_hit=0), hide_faked from state
        b32 d_hide_faked = (b32)(state.thread_hidden && !state.hide_verified);
        __try { d_corr = ad_build_truth_and_correlate(
            0,0,0, 0,0,0, 0,0,0, d_hide_faked,0,0); } __except(1){}

        __try { d_deep  = ad_deep_check_master(diag_img, state.image_scan_size); }  __except(1){}
        __try { d_cross = ad_h_cross_validate_peb(); }                               __except(1){}
        if (diag_img)
            __try { d_patch = ad_anti_patch_full(diag_img, state.image_scan_size, &state.self_hashes, (const void**)0, 0u); } __except(1){}
        __try { d_exotic = ad_exotic_master(state.init_tsc, 0u); }                   __except(1){}  // 0 = real raw_hits
        __try { d_adv   = ad_advanced_master(diag_img, state.image_scan_size, &state.temporal_ctx, &state.heisenberg_ctx, &state.memkey, state.init_tsc); } __except(1){}
        __try { d_extra = ad_extra_master(); }                                        __except(1){}

        print_score("[DBG] hide_faked: ", (u32)d_hide_faked);
        print_score("[DBG] corr:   ", d_corr);
        print_score("[DBG] deep:   ", d_deep);
        print_score("[DBG] cross:  ", d_cross);
        print_score("[DBG] patch:  ", d_patch);
        print_score("[DBG] exotic: ", d_exotic);
        print_score("[DBG] adv:    ", d_adv);
        print_score("[DBG] extra:  ", d_extra);

        // Per-check hardened breakdown — find which sub-checks of
        // ad_h_master() inflate hardened_score on a clean machine.
        { b32 v = 0; __try { v = ad_h_peb_being_debugged(); } __except(1){} print_score("[H] peb_bd:       ", (u32)v); }
        { b32 v = 0; __try { v = ad_h_peb_nt_global_flag(); } __except(1){} print_score("[H] peb_ntg:      ", (u32)v); }
        { b32 v = 0; __try { v = ad_h_heap_flags();         } __except(1){} print_score("[H] heap_flags:   ", (u32)v); }
        { b32 v = 0; __try { v = ad_h_debug_port();         } __except(1){} print_score("[H] dbg_port:     ", (u32)v); }
        { b32 v = 0; __try { v = ad_h_debug_flags();        } __except(1){} print_score("[H] dbg_flags:    ", (u32)v); }
        { b32 v = 0; __try { v = ad_h_hardware_bp();        } __except(1){} print_score("[H] hw_bp:        ", (u32)v); }
        { b32 v = 0; __try { v = ad_h_rdtsc_timing();       } __except(1){} print_score("[H] rdtsc_tim:    ", (u32)v); }
        { b32 v = 0; __try { v = ad_h_rdtsc_double();       } __except(1){} print_score("[H] rdtsc_dbl:    ", (u32)v); }
        { b32 v = 0; __try { v = ad_h_syscall_timing();     } __except(1){} print_score("[H] sysc_tim:     ", (u32)v); }
        { b32 v = 0; __try { v = ad_h_ntclose_trap();       } __except(1){} print_score("[H] ntclose_trap: ", (u32)v); }

        // Flags consumed by ad_run_hardened that were NOT in the previous breakdown.
        { b32 v = 0; __try { v = ad_detect_ntdll_hooks(); } __except(1){} print_score("[H] ntdll_hook:   ", (u32)v); }
        { b32 v = 0; __try { v = diag_img ? ad_check_page_protection(diag_img) : 0; } __except(1){} print_score("[H] page_rwx:     ", (u32)v); }

        // Self-poison components.
        // NOTE: mac_bad is expected to show 1 in the diagnostic because
        // the state has been mutated by score computation, encryption,
        // and debug re-runs. The REAL MAC check inside ad_run_hardened
        // fires before any of that happens and is accurate.
        print_score("[SP] mac_bad:     ", (u32)diag_mac_bad);
        { b32 v = 0; __try { v = ad_resolver_guard_check(&state.resolver_guard); } __except(1){} print_score("[SP] resolver:    ", (u32)v); }
        { u64 c = 0; __try { c = ad_vault_load(&state.init_canary, &state.memkey); } __except(1){} print_score("[SP] canary_zero: ", (u32)(c == 0ULL)); }
        { b32 v = 0; __try { v = (b32)VMProtectIsDebuggerPresent(true); } __except(1){} print_score("[SP] vmp_dbg:     ", (u32)v); }
        { b32 v = 0; __try { v = (b32)(!VMProtectIsValidImageCRC()); } __except(1){} print_score("[SP] vmp_crc_bad: ", (u32)v); }

        // Real correlation score with the actual flag values used in production.
        {
            u32 v = 0;
            __try {
                b32 f1  = ad_h_peb_being_debugged();
                b32 f2  = ad_h_peb_nt_global_flag();
                b32 f3  = ad_h_heap_flags();
                b32 f4  = ad_h_debug_port();
                b32 f5  = ad_h_debug_flags();
                b32 f6  = ad_h_rdtsc_timing();
                b32 f7  = ad_h_syscall_timing();
                b32 f8  = ad_detect_ntdll_hooks();
                b32 f9  = ad_h_hardware_bp();
                b32 f10 = (b32)(state.thread_hidden && !state.hide_verified);
                b32 f11 = ad_h_ntclose_trap();
                b32 f12 = diag_img ? ad_check_page_protection(diag_img) : 0;
                v = ad_build_truth_and_correlate(f1,f2,f3, f4,f5,f6, f7,f8,f9, f10,f11,f12);
            } __except(1){}
            print_score("[DBG] corr_real: ", v);
        }

        // Per-check exotic breakdown
        { b32 v = 0; __try { v = ad_trap_flag_check();           } __except(1){} print_score("[EX] trap_flag:     ", (u32)v); }
        { b32 v = 0; __try { v = ad_int2d_check();               } __except(1){} print_score("[EX] int2d:         ", (u32)v); }
        { b32 v = 0; __try { v = ad_debug_object_count();        } __except(1){} print_score("[EX] dbg_obj_count: ", (u32)v); }
        { b32 v = 0; __try { v = ad_nested_exception_check();    } __except(1){} print_score("[EX] nested_exc:    ", (u32)v); }
        { b32 v = 0; __try { v = ad_process_in_job();            } __except(1){} print_score("[EX] proc_in_job:   ", (u32)v); }
        { b32 v = 0; __try { v = ad_yield_timing();              } __except(1){} print_score("[EX] yield_timing:  ", (u32)v); }
        { b32 v = 0; __try { v = ad_shared_user_data_timing();   } __except(1){} print_score("[EX] kusd_timing:   ", (u32)v); }
        { b32 v = 0; __try { v = ad_environment_too_clean();     } __except(1){} print_score("[EX] too_clean:     ", (u32)v); }
        { b32 v = 0; __try { v = (b32)ad_timing_bomb(state.init_tsc, 0u); } __except(1){} print_score("[EX] timing_bomb:   ", (u32)v); }

        // Per-check advanced breakdown
        { u32 v = 0; __try { if (diag_img) v = ad_ghost_breakpoint_check(diag_img, 256u) ? 10u : 0u; } __except(1){} print_score("[ADV] ghost_bp:     ", v); }
        { u32 v = 0; __try { v = ad_ghost_breakpoint_ntdll() ? 10u : 0u; } __except(1){} print_score("[ADV] ghost_ntdll:  ", v); }
        { u32 v = 0; __try { ad_cross_proc_ctx_t cx; v = ad_cross_process_validate(&cx) ? 10u : 0u; } __except(1){} print_score("[ADV] cross_proc:   ", v); }
        { u32 v = 0; __try { v = ad_selfmod_race_check() ? 9u : 0u; } __except(1){} print_score("[ADV] selfmod:      ", v); }
        { u32 v = 0; __try { v = ad_scheduler_sync_check() ? 8u : 0u; } __except(1){} print_score("[ADV] scheduler:    ", v); }
        { u32 v = 0; __try { v = ad_temporal_trap_verify(&state.temporal_ctx, &state.memkey) ? 8u : 0u; } __except(1){} print_score("[ADV] temporal:     ", v); }
        { u32 v = 0; __try { v = ad_pipeline_desync_check() ? 7u : 0u; } __except(1){} print_score("[ADV] pipeline:     ", v); }
        { u32 v = 0; __try { v = ad_heisenberg_check(&state.heisenberg_ctx, &state.memkey) ? 7u : 0u; } __except(1){} print_score("[ADV] heisenberg:   ", v); }
        { u32 v = 0; __try { v = ad_exception_fingerprint_check() ? 6u : 0u; } __except(1){} print_score("[ADV] exc_fp:       ", v); }
        { u32 v = 0; __try { v = ad_impossible_states_check() ? 5u : 0u; } __except(1){} print_score("[ADV] impossible:   ", v); }
        { u32 v = 0; __try { v = ad_pressure_test_check() ? 4u : 0u; } __except(1){} print_score("[ADV] pressure:     ", v); }
        { u32 v = 0; __try { v = ad_scyllahide_master(); } __except(1){} print_score("[ADV] scyllahide:   ", v); }
        { u32 v = 0; __try { v = ad_titanhide_master();  } __except(1){} print_score("[ADV] titanhide:    ", v); }

        // Per-supplemental-check breakdown (silent FP contributors)
        print_score("[SUP] vm_hyper:     ", ad_dbg_sup.vm_hyper);
        print_score("[SUP] vm_rdtsc:     ", ad_dbg_sup.vm_rdtsc);
        print_score("[SUP] loop_tim:     ", ad_dbg_sup.loop_tim);
        print_score("[SUP] dbgobj_h:     ", ad_dbg_sup.dbgobj_h);
        print_score("[SUP] kdbg:         ", ad_dbg_sup.kdbg);
        print_score("[SUP] qpc:          ", ad_dbg_sup.qpc);
        print_score("[SUP] dbgobj_rm:    ", ad_dbg_sup.dbgobj_rm);
        print_score("[SUP] guard_pg:     ", ad_dbg_sup.guard_pg);
        print_score("[SUP] dr_canary:    ", ad_dbg_sup.dr_canary);
        print_score("[SUP] instcb:       ", ad_dbg_sup.instcb);
        print_score("[SUP] seh_bp:       ", ad_dbg_sup.seh_bp);
        print_score("[SUP] breakin:      ", ad_dbg_sup.breakin);
        print_score("[SUP] halos_one:    ", ad_dbg_sup.halos_one);
        print_score("[SUP] halos_multi:  ", ad_dbg_sup.halos_multi);
        print_score("[SUP] heavens:      ", ad_dbg_sup.heavens);
        print_score("[SUP] raise_hard:   ", ad_dbg_sup.raise_hard);
        print_score("[SUP] etw_ti:       ", ad_dbg_sup.etw_ti);
        print_score("[SUP] kcb_indirect: ", ad_dbg_sup.kcb_indirect);
        print_score("[SUP] priv_exec:    ", ad_dbg_sup.priv_exec);
        print_score("[SUP] hyperion:     ", ad_dbg_sup.hyperion);
        print_score("[SUP] veh_verify:   ", ad_dbg_sup.veh_verify);
        print_score("[SUP] veh_run:      ", ad_dbg_sup.veh_run);

        // Untracked extra_master contributors
        extern volatile u32 ad_dbg_emu_score;
        extern volatile u32 ad_dbg_vmfull_score;
        print_score("[X] emu_master:  ", ad_dbg_emu_score);
        print_score("[X] vm_full:     ", ad_dbg_vmfull_score);


        // Force a second vm_full run with diagnostics enabled to
        // see which sub-check fires.
        ad_dbg_vm.enabled = 1u;
        (void)ad_vm_full_master();
        print_score("[VM] hypervisor: ", ad_dbg_vm.basic_hypervisor);
        print_score("[VM] vendor:     ", ad_dbg_vm.basic_vendor);
        print_score("[VM] vmware_sig: ", ad_dbg_vm.basic_vmware_sig);
        print_score("[VM] rdtsc:      ", ad_dbg_vm.basic_rdtsc);
        print_score("[VM] hwid:       ", ad_dbg_vm.hwid);
        print_score("[VM] emulation:  ", ad_dbg_vm.emulation);
        print_score("[VM] cpuid_deep: ", ad_dbg_vm.cpuid_deep);
        print_score("[VM] firmware:   ", ad_dbg_vm.firmware);
        print_score("[VM] device:     ", ad_dbg_vm.device);
        print_score("[VM] io_backdoor:", ad_dbg_vm.io_backdoor);
        print_score("[VM] memory:     ", ad_dbg_vm.memory);
        print_score("[VM] timing:     ", ad_dbg_vm.timing);
    }
#endif // AD_DEBUG_BREAKDOWN

    // ── Flag decryption — runs INSIDE WhipVM ─────────────────────────────
    {
        char real_flag_buf[36];
        AD_BUILD_FLAG_ON_STACK(real_flag_buf);

        // Immediately scramble plaintext with an ASLR-derived byte so
        // real_flag_buf is never readable as plain ASCII on the stack.
        // A hardware BP on real_flag_buf sees XOR'd bytes, not the flag.
        // _xk is wiped after the FNV loop; net output on encrypted_flag
        // is bit-for-bit identical to the unscrambled version.
        u32 _rt = vm_runtime_key();
        u8  _xk = vm_enc_key(_rt);
        _rt = 0u;
        {
            u32 _si;
            for (_si = 0u; _si < (u32)sizeof(real_flag_buf); _si++)
                ((volatile u8*)real_flag_buf)[_si] ^= _xk;
        }

        // Inline FNV key derivation (score=0) byte-by-byte — no persistent key
        // buffer. Un-scrambles real_flag_buf[ei] (^ _xk) on-the-fly while
        // XOR-encrypting: net result = plaintext[ei] ^ fnv_key[ei] as before.
        // FNV basis is mixed with a stable ASLR key (PEB+TEB) so the key stream
        // is not invertible from a memory dump without knowing the ASLR layout.
        //
        // MBA (Mixed Boolean-Arithmetic): every XOR is expanded into an
        // equivalent expression using +/-/&/| so Ghidra/IDA decompilers
        // produce unreadable arithmetic and symbolic solvers explode. The
        // three identities cycled below are all provably equivalent to XOR:
        //    a ^ b  ==  (a | b) - (a & b)
        //    a ^ b  ==  (a + b) - 2*(a & b)
        //    a ^ b  ==  (a & ~b) | (~a & b)
        #define AD_MBA_XOR_A(a, b) (((a) | (b)) - ((a) & (b)))
        #define AD_MBA_XOR_B(a, b) (((a) + (b)) - (((a) & (b)) << 1))
        #define AD_MBA_XOR_C(a, b) (((a) & ~(b)) | (~(a) & (b)))
        u8 encrypted_flag[FLAG_LEN];
        {
            u32 _rt_stable = vm_runtime_key_stable();  // PEB+TEB, stable per-process
            // MBA form A for the FNV-basis ^ ASLR mix.
            volatile u64 _kst = AD_MBA_XOR_A((u64)0xCBF29CE484222325ULL,
                                             (u64)_rt_stable);
            _rt_stable = 0u;
            _kst *= 0x00000100000001B3ULL;  // score=0 → h ^= 0 is no-op, *= prime
            _kst *= 0x00000100000001B3ULL;  // *= prime (second init round)
            u32 ei;
            for (ei = 0; ei < FLAG_LEN; ei++) {
                // MBA form B for the per-byte seed mixing.
                _kst = AD_MBA_XOR_B(_kst, (u64)ei);
                _kst *= 0x00000100000001B3ULL;
                // MBA chain: un-scramble via form C, then fold key via form A.
                u8 _plain = (u8)AD_MBA_XOR_C((u32)(u8)real_flag_buf[ei],
                                             (u32)_xk);
                u8 _key   = (u8)(_kst & 0xFFu);
                encrypted_flag[ei] = (u8)AD_MBA_XOR_A((u32)_plain, (u32)_key);
            }
            _kst = 0;
            _xk  = 0;
        }
        #undef AD_MBA_XOR_A
        #undef AD_MBA_XOR_B
        #undef AD_MBA_XOR_C
        AD_ZERO_BUF(real_flag_buf, sizeof(real_flag_buf));

        u8 vm_output[FLAG_LEN + 1];
        AD_ZERO_BUF(vm_output, sizeof(vm_output));

        // ── Sentinel liveness guard ──────────────────────────────────────────
        // Both sentinel threads must be alive and have completed at least one
        // 100ms/250ms sleep slice (woke > 0). A reverser who suspended or killed
        // them to prevent delayed crashes will have woke == 0 or alive == 0.
        // Failure: re-arm sentinels, zero encrypted_flag → garbage output, no hint.
#if !AD_TESTING_MODE
        {
            b32 s1_ok = (b32)(ad_latent_thread_started != 0u &&
                               ad_latent_thread_alive   != 0u &&
                               (ad_latent_thread_woke ^ ad_latent_woke_key) > 0u);
            b32 s2_ok = (b32)(g_latent2.started != 0u &&
                               (g_latent2.woke ^ g_latent2.woke_key) > 0u);
            if (!s1_ok || !s2_ok) {
                ad_latent_arm_if((b32)1);
                ad_latent2_arm_if((b32)1);
                AD_ZERO_BUF(encrypted_flag, sizeof(encrypted_flag));
            }
        }
#endif

        // Use rolling commitment instead of raw score sum.
        // Clean run: no check fired → commitment = 0 = correct VM key.
        // Any check fired, or final_score patched after commitment was computed:
        // commitment != 0 → VM decodes wrong score → wrong key stream → garbage.
        u32 commitment_score = ad_score_read_commitment(&score_ctx);

        // ── DEBUG: Afficher le commitment_score réel ──
        {
            char debug_buf[64];
            const char* prefix = "[CRACK] Real commitment_score: ";
            u32 cs = commitment_score;
            char num[12];
            int pos = 0;
            if (cs == 0) {
                num[pos++] = '0';
            } else {
                while (cs > 0) {
                    num[pos++] = '0' + (char)(cs % 10);
                    cs /= 10;
                }
            }
            u32 bi = 0;
            while (*prefix) debug_buf[bi++] = *prefix++;
            for (int ni = pos - 1; ni >= 0; ni--) debug_buf[bi++] = num[ni];
            debug_buf[bi++] = '\r'; debug_buf[bi++] = '\n'; debug_buf[bi] = 0;
            write_console(debug_buf, bi);
        }

        // ── REVERSE ENGINEERING PATCH: Force commitment_score to 0 ──
        commitment_score = 0;

        // ── Sentinel poison fold ─────────────────────────────────────────
        // Detached sentinels (core/sentinels.h) corrupt this byte if any
        // of their checks fired. Clean run → poison decodes to 0 → fold is
        // a no-op. Detected → fold flips bits in commitment_score → wrong
        // VM key stream → garbage output. The fold sits AFTER the test
        // patch so even nullifying `commitment_score` does not bypass it.
#if !AD_TESTING_MODE
        commitment_score = ad_sentinels_poison_fold(commitment_score);
        // Liveness gate: if any sentinel was killed/suspended pre-output,
        // zero the encrypted buffer so the VM has nothing meaningful left
        // to decrypt. ad_sentinels_alive() also poisons internally on its
        // way out so a re-arm protects later passes.
        if (!ad_sentinels_alive()) {
            AD_ZERO_BUF(encrypted_flag, sizeof(encrypted_flag));
            commitment_score ^= 0xDEADBEEFu;
        }
#endif

        vm_derive_and_decrypt_flag(commitment_score, encrypted_flag, vm_output, FLAG_LEN);

        vm_output[FLAG_LEN] = '\0';
        AD_ZERO_BUF(encrypted_flag, sizeof(encrypted_flag));

        // ── Debugger-aware output (tier M). If a debugger is attached
        // AT THE MOMENT OF OUTPUT, replace the (already garbage)
        // vm_output with a plausible honeypot flag string chosen at
        // runtime. A reverser who sees something that looks like
        // "ADCTF{...}" printed under their debugger will submit it,
        // waste the submission budget, and only realise the deception
        // after the CTF backend rejects it. Score == 0 clean runs are
        // unaffected: dbg_now is false, vm_output prints normally.
        const char* _out_buf = (const char*)vm_output;
        u32         _out_len = FLAG_LEN;
        u8          _honey_buf[AD_HP_ROW];
        {
            b32 _dbg_now = 0;
            __try { _dbg_now = (b32)VMProtectIsDebuggerPresent(true); }
            __except(1) { _dbg_now = 0; }
            if (AD_OPAQUE_IF(!_dbg_now) == 0) {
                u8* _peb = (u8*)__readgsqword(0x60);
                if (_peb && _peb[0x02] != 0u) _dbg_now = 1;
            }
            if (_dbg_now) {
                u32 _hi = (u32)(__rdtsc() % AD_HP_COUNT);
                u32 _li;
                for (_li = 0; _li + 1u < AD_HP_ROW; _li++) {
                    u8 _c = (u8)(ad_honeypot_flags[_hi][_li] ^ AD_HP_KEY);
                    _honey_buf[_li] = _c;
                    if (_c == 0u) break;
                }
                _honey_buf[_li] = 0u;
                _out_buf = (const char*)_honey_buf;
                _out_len = _li;
            }
        }

        print("\r\n");
        print("[*] Result:\r\n");
        print("    ");
        write_console(_out_buf, _out_len);
        print("\r\n\r\n");

        AD_ZERO_BUF(vm_output, sizeof(vm_output));
        AD_ZERO_BUF(_honey_buf, sizeof(_honey_buf));
    }

    VMProtectEnd();
    // ── Kill decoy swarm before exit ──────────────────────────────────
    ad_noise_swarm_stop();
    ad_watchdog_stop();
    ad_fake_decrypt_stop();
    // ad_poly_destroy() intentionally NOT called: keeping the poly
    // gadget pages mapped until process termination means any snapshot
    // (live memory dump, debugger pause) captures them. The OS reclaims
    // the pages when ad_terminate_self fires the exit syscall. Freeing
    // them here only served to hide them from live inspection, which
    // hurts verification more than it helps opsec.

    // ── Anti-dump: erase headers LAST — after all output is done ────────
    // PE header erase sets PAGE_NOACCESS, ntdll erase prevents export parsing.
    // Both are safe here because we terminate via syscall immediately after.
    //
    // CRITICAL: ad_terminate_warmup() MUST run before ad_erase_ntdll_header()
    // because the SSN resolver walks ntdll exports — once the first page is
    // zeroed/PAGE_NOACCESS, no further SSN can be resolved and a subsequent
    // ad_terminate_self would access-violation instead of terminating cleanly.
    ad_terminate_warmup();
    // Tell sentinels to bail on their next iteration — without this they
    // race the kernel terminate and can fire NtTerminateProcess(0xC000026E)
    // a few ms before our own clean exit lands, surfacing as exit 139.
    ad_sentinels_request_exit();
    {
        void* img = ad_vault_load_ptr(&state.image_base_enc, &state.memkey);
        ad_erase_pe_header(img);
    }
    ad_erase_ntdll_header();
    ad_terminate_self(0);
    return 0;  // unreachable — orchestrator never returns to main()
}
#pragma optimize("", on)

// =========================================================================
// Entry point — thin trampoline.
//
// Stack-trace consequences:
//   * Main thread stack snapshot:
//       <fake ntdll!RtlUserThreadStart> → main → ntdll!NtWaitForSingleObject
//     The "fake" comes from ad_main_ra_spoof() overwriting main's saved
//     return-address slot with an address inside RtlUserThreadStart. main
//     itself is just blocked on the ghost thread's event — nothing of the
//     real program logic appears in the visible frame chain.
//
//   * Worker thread stack snapshot:
//       BaseThreadInitThunk → <RWX trampoline> → ad_ghost_thread_entry
//           → ad_main_orchestrator → ...
//     `main` is COMPLETELY ABSENT from this thread. A reverser sampling
//     here finds no path back to the entry point.
//
// The orchestrator self-terminates via `ad_terminate_self(0)` so control
// flow never returns through main's corrupted RA — no crash on exit.
// =========================================================================
#pragma optimize("", off)
int main(void) {
    VMProtectBeginVirtualization("main");
    AD_DISABLE_AVX512();

    // Resolve direct-syscall bridge before spawning the worker — the
    // ghost-exec path needs NtCreateThreadEx etc. as SSNs.
    if (!whip_bridge_init()) {
        VMProtectEnd();
        return 1;
    }

    // Spoof the saved RA of the calling frame so any unwinder walking
    // up from main lands inside ntdll instead of kernel32!BaseThreadInitThunk.
    // Must run BEFORE ad_ghost_exec so the spoofed value is in place during
    // the long NtWaitForSingleObject below.
    ad_main_ra_spoof();

    // Strip main's RUNTIME_FUNCTION entry from .pdata so any stack walker
    // resolving RIP through the exception directory finds NO function info
    // for main's address range — the frame is no longer labelled "main",
    // it appears as a hex offset or as the nearest export-table decoy.
    ad_hide_main_pdata((void*)&main);

    // Pre-resolve NtTerminateProcess SSN now, while ntdll's PE header is
    // still intact. The orchestrator zeroes ntdll's first page right before
    // exit, after which no further AD_RESOLVE_SSN_ENC can succeed.
    ad_terminate_warmup();

    // Detach the entire program payload to a worker thread. Direct syscall
    // path (NtCreateThreadEx + RWX trampoline) — `main` does not appear in
    // the worker's stack. Main thread blocks here on NtWaitForSingleObject.
    (void)ad_ghost_exec(ad_main_orchestrator, (void*)0);

    // Orchestrator calls ad_terminate_self on success — only reached on the
    // ghost-exec timeout fallback. Terminate hard so the corrupted return
    // slot never executes.
    VMProtectEnd();
    ad_terminate_self(0);
    return 0;
}
#pragma optimize("", on)
