// ===== file: antidebug/dispatcher/dispatcher.h =====
//
// Non-linear anti-debug dispatcher.
//
// Design goals:
//   - Randomised execution order each run (XORSHIFT64 PRNG seeded by RDTSC)
//   - Per-check probabilistic skipping (confuses timing-based bypass analysis)
//   - No centralized "if (debugger) exit()" — caller decides action
//   - Suspicion accumulated as a composite score, not a flag
//   - Fully inline, zero IAT footprint from this file alone
//
#ifndef ANTIDEBUG_DISPATCHER_H
#define ANTIDEBUG_DISPATCHER_H

#include "../core/types.h"
#include "../core/macros.h"
#include "../core/config.h"
#include "../core/syscall_bridge.h"
#include "../core/mem_encrypt.h"
#include "../core/value_guard.h"
#include "../core/self_protect.h"
#include "../core/api_hash.h"      // ad_resolve_api / ad_hash_str — used by extended correlation feed

// Pull in every check module
#include "../checks/debug/peb.h"
#include "../checks/debug/debug_port.h"
#include "../checks/debug/flags.h"
#include "../checks/timing/rdtsc.h"
#include "../checks/timing/loops.h"
#include "../checks/breakpoints/int3_scan.h"
#include "../checks/breakpoints/hardware.h"
#include "../checks/exceptions/seh.h"
#include "../checks/threads/hide_thread.h"
#include "../checks/vm/vm_detect.h"
#include "../checks/integrity/code_hash.h"
#include "../checks/debug/system_info.h"
#include "../checks/debug/handle_trace.h"
#include "../checks/debug/debug_object_remove.h"
#include "../checks/debug/parent_process.h"     // al-khaser: parent process check
#include "../checks/debug/se_debug.h"           // al-khaser: SeDebugPrivilege token check
#include "../checks/timing/qpc_timing.h"
#include "../checks/runtime/hook_detect.h"
#include "../checks/runtime/guard_pages.h"
#include "../checks/runtime/thread_monitor.h"
#include "../checks/runtime/instrumentation.h"
#include "../checks/runtime/write_watch.h"      // al-khaser: WriteWatch DBI detection
#include "../checks/integrity/anti_patch.h"
#include "../checks/hardened.h"
#include "../checks/correlation.h"
#include "../checks/deep_checks.h"
#include "../checks/exotic.h"
#include "../checks/advanced/advanced_master.h"
#include "../checks/extra_master.h"
#include "../core/vmp_markers.h"

// ---------------------------------------------------------------------------
// XORSHIFT64 PRNG
// Period: 2^64 - 1. Passes BigCrush. No stdlib dependency.
// ---------------------------------------------------------------------------
typedef struct {
    u64 state;
} ad_prng_t;

ANTIDEBUG_INLINE u64 ad_prng_next(ad_prng_t* rng) {
    u64 x = rng->state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    rng->state = x;
    return x;
}

// Seed from RDTSC + compile-time constant for per-run uniqueness
ANTIDEBUG_INLINE void ad_prng_init(ad_prng_t* rng) {
#if defined(_MSC_VER)
    u64 tsc = __rdtsc();
#else
    u64 tsc = 0;
#endif
    // Derive PRNG seed at runtime — never appears as a single immediate
    u64 seed_derived = ad_derive64(
        0xC0FFEE13DEADB33FULL ^ 0x93A7F1E2D4C8B056ULL,
        0x93A7F1E2D4C8B056ULL
    );
    rng->state = seed_derived ^ tsc;
    // Fallback also derived
    if (rng->state == 0ULL) {
        rng->state = ad_derive64(
            0xDEADC0FFEE1337ABULL ^ 0x4B7E9A2CF1D36580ULL,
            0x4B7E9A2CF1D36580ULL
        );
    }
    // Warm up
    ad_prng_next(rng);
    ad_prng_next(rng);
}

// Returns 1 if this check should be probabilistically skipped
ANTIDEBUG_INLINE b32 ad_prng_should_skip(ad_prng_t* rng) {
    u64 r = ad_prng_next(rng);
    return (b32)((r & 0xFULL) < (u64)AD_SKIP_PROBABILITY);
}

// ---------------------------------------------------------------------------
// Fisher-Yates shuffle on a u8 index array
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE void ad_shuffle_u8(u8* arr, u32 n, ad_prng_t* rng) {
    u32 i;
    for (i = n - 1u; i > 0u; i--) {
        u32 j = (u32)(ad_prng_next(rng) % (u64)(i + 1u));
        u8 tmp  = arr[i];
        arr[i]  = arr[j];
        arr[j]  = tmp;
    }
}

// ---------------------------------------------------------------------------
// Check-ID enumeration
// Changing these values (or the ordering in ad_run) is one way to
// differentiate builds without changing the logic.
// ---------------------------------------------------------------------------
typedef enum {
    AD_CHECK_PEB_DEBUGGED    = 0,
    AD_CHECK_PEB_NTGLOBALFLAG= 1,
    AD_CHECK_HEAP_FLAGS      = 2,
    AD_CHECK_DEBUG_PORT      = 3,
    AD_CHECK_DEBUG_FLAGS     = 4,
    AD_CHECK_DEBUG_OBJ       = 5,
    AD_CHECK_HW_BP           = 6,
    AD_CHECK_RDTSC_STEP      = 7,
    AD_CHECK_RDTSC_DOUBLE    = 8,
    AD_CHECK_LOOP_TIME       = 9,
    AD_CHECK_SEH_BP          = 10,
    AD_CHECK_VM_CPUID        = 11,
    AD_CHECK_VM_RDTSC        = 12,
    AD_CHECK_CODE_INTEGRITY  = 13,
    AD_CHECK_KERNEL_DBG      = 14,
    AD_CHECK_CLOSE_HANDLE    = 15,
    AD_CHECK_QPC_TIMING      = 16,
    AD_CHECK_DBG_OBJ_REMOVE  = 17,
    AD_CHECK_HOOK_DETECT     = 18,
    AD_CHECK_GUARD_PAGE      = 19,
    AD_CHECK_DR_CANARY       = 20,
    AD_CHECK_SUSPECT_MODULES = 21,
    AD_CHECK_INSTR_CALLBACK  = 22,
    AD_CHECK_ANTI_PATCH      = 23,

    // Advanced checks (new)
    AD_CHECK_GHOST_BP        = 24,
    AD_CHECK_PIPELINE_DESYNC = 25,
    AD_CHECK_SCHED_SYNC      = 26,
    AD_CHECK_EXCEPTION_FP    = 27,
    AD_CHECK_IMPOSSIBLE_CPU  = 28,
    AD_CHECK_SELFMOD_RACE    = 29,
    AD_CHECK_PRESSURE_TEST   = 30,
    AD_CHECK_TEMPORAL_TRAP   = 31,

    AD_CHECK_COUNT           = 32   // was 24, now 32 (fits u32 bitmask)
} ad_check_id_t;

// ---------------------------------------------------------------------------
// Dispatcher state — caller owns, opaque to end-user
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// Init canary: a cryptographic proof that ad_init ran to completion
// without being patched. Computed from RDTSC + memkey + a magic constant.
// Verified at every ad_run(). If someone NOPs ad_init or patches it to
// skip checks, the canary won't match and all checks report suspicious.
// ---------------------------------------------------------------------------
// Canary magic — derived at runtime, never as a single immediate
#define AD_CANARY_MAGIC_ENC  0x7A3F1D9E5BC804A2ULL
#define AD_CANARY_MAGIC_MASK 0xE5D2A3B71F9C6830ULL

typedef struct {
    ad_prng_t            prng;
    ad_memkey_t          memkey;           // runtime memory encryption key
    ad_vault_t           code_hash_enc;   // encrypted code hash baseline
    ad_vault_t           image_base_enc;  // encrypted image base pointer
    ad_vault_t           init_canary;     // encrypted canary — proves init was real
    ad_vault_t           state_mac;       // MAC of this struct — detects external edits
    ad_self_hash_table_t self_hashes;     // continuous CRC32 self-integrity
    ad_resolver_guard_t  resolver_guard;  // CRC of WhipSysCall bridge functions
    u32                  image_scan_size;
    u64                  init_tsc;
    b32                  thread_hidden;
    b32                  hide_verified;
    b32                  initialized;

    // Advanced anti-debug state (new)
    ad_temporal_ctx_t    temporal_ctx;     // temporal trap T0 state
    ad_heisenberg_ctx_t  heisenberg_ctx;   // observation-dependent state
} ad_state_t;

// ad_result_t is defined in core/types.h so mem_encrypt.h can use it

// ---------------------------------------------------------------------------
// ad_init — must be called once before ad_run
//
// image_base: base of the region to hash for integrity (pass NULL to
//             auto-detect from PEB; does NOT work for manual-mapped modules).
// scan_size:  number of bytes to hash (0 → use AD_CODE_HASH_REGION_SIZE).
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE void ad_init(ad_state_t* s, void* image_base, u32 scan_size) {
    AD_ZERO_BUF(s, sizeof(*s));

    // ── Phase 1: Memory encryption key ──────────────────────────────────
    ad_memkey_init(&s->memkey);
    ad_prng_init(&s->prng);

#if defined(_MSC_VER)
    s->init_tsc = __rdtsc();
#endif

    // ── Phase 2: Early PEB tripwire ─────────────────────────────────────
    // Check PEB.BeingDebugged BEFORE anything else. If a reverser is
    // stepping through init, this fires immediately. The result is folded
    // into the init canary — patching it corrupts the canary silently.
    u8 early_peb = 0;
#if AD_ENABLE_PEB_BEING_DEBUGGED
    early_peb = (u8)ad_peb_being_debugged();
#endif

    // ── Phase 3: Image base + code hash ─────────────────────────────────
    void* base = image_base ? image_base : ad_image_base_from_peb();
    s->image_scan_size = scan_size ? scan_size : (u32)AD_CODE_HASH_REGION_SIZE;
    ad_vault_store_ptr(&s->image_base_enc, base, &s->memkey);

    if (base) {
        u64 hash = ad_code_hash_capture(base, s->image_scan_size);
        ad_vault_store(&s->code_hash_enc, hash, &s->memkey);
    }

    // ── Phase 4: Hide thread + VERIFY it actually worked ────────────────
#if AD_ENABLE_HIDE_THREAD
    s->thread_hidden = ad_hide_thread();

    // ScyllaHide/TitanHide bypass: they return STATUS_SUCCESS but don't
    // actually hide the thread. Query it back to verify.
    if (s->thread_hidden) {
        s->hide_verified = (b32)(!ad_verify_thread_hidden());
        // ad_verify_thread_hidden returns 1 if NOT hidden (bypass detected)
        // So hide_verified=1 means verified OK, 0 means bypass or can't verify
    }
#endif

    // ── Phase 5: Second PEB check ───────────────────────────────────────
    // A reverser who patches BeingDebugged before Phase 2 might not have
    // done so yet here (race window). We XOR with Phase 2 result.
    u8 late_peb = 0;
#if AD_ENABLE_PEB_NT_GLOBAL_FLAG
    late_peb = (u8)ad_peb_nt_global_flag();
#endif

    // ── Phase 6: Compute init canary ────────────────────────────────────
    // Canary = f(memkey, RDTSC, PEB results, PRNG state, magic)
    // If ANY phase was patched/skipped, this value will be wrong.
    // ad_run() verifies it silently — no branch, no comparison the
    // reverser can easily find and patch.
    {
        u64 canary = ad_derive64(AD_CANARY_MAGIC_ENC, AD_CANARY_MAGIC_MASK);
        canary ^= ad_memkey_get(&s->memkey);
        canary ^= s->init_tsc;
        canary ^= ((u64)early_peb << 40) | ((u64)late_peb << 48);
        canary ^= s->prng.state;
        // Rotate to mix bits
        canary = (canary << 31) | (canary >> 33);
        canary *= 0x9E3779B97F4A7C15ULL;  // golden ratio hash
        ad_vault_store(&s->init_canary, canary, &s->memkey);
    }

    // ── Phase 7: Resolver guard — CRC of WhipSysCall bridge ─────────────
    ad_resolver_guard_init(&s->resolver_guard);

    // ── Phase 8: Anti-attach — occupy debug port ────────────────────────
    ad_anti_attach();  // if fails -> debugger already attached (detected elsewhere)

    // ── Phase 8b: Remote debug baseline snapshot ───────────────────────
    // Capture all localhost high-port TCP listeners NOW so we can detect
    // new debug servers (Frida, IDA remote, etc.) launched after init.
#if AD_ENABLE_REMOTE_DEBUG
    ad_remote_debug_snapshot_init();
#endif

    // ── Phase 9: Advanced anti-debug state init ─────────────────────────
#if AD_ENABLE_TEMPORAL_TRAPS
    ad_temporal_trap_plant(&s->temporal_ctx, &s->memkey);
#endif
#if AD_ENABLE_HEISENBERG
    ad_heisenberg_init(&s->heisenberg_ctx, &s->memkey);
#endif

    s->initialized = 1;

    // ── Phase 10: Seal the state with a MAC ─────────────────────────────
    // This MUST be the last thing in init — any write after this breaks MAC
    ad_state_mac_update(&s->state_mac, s, sizeof(*s), &s->memkey);
}

// ---------------------------------------------------------------------------
// ad_run — execute all enabled checks in randomised order
//
// Each call shuffles the execution order and may skip individual checks.
// Never call exit() or TerminateProcess() here — the CALLER decides the
// response based on the returned ad_result_t.
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE ad_result_t ad_run(ad_state_t* s) {
    ad_result_t r;
    AD_ZERO_BUF(&r, sizeof(r));

    // ── State MAC verification ──────────────────────────────────────────
    // If someone wrote to ad_state_t externally (Cheat Engine, x64dbg),
    // the MAC won't match → poison. Branchless accumulation.
    u32 mac_poison = 0;
    {
        b32 mac_bad = ad_state_mac_verify(
            &s->state_mac, s, sizeof(*s), &s->memkey);
        mac_poison = mac_bad ? 0x8000u : 0u;
    }

    // ── Resolver guard ──────────────────────────────────────────────────
    // Verify WhipSysCall bridge hasn't been hooked
    {
        b32 resolver_hooked = ad_resolver_guard_check(&s->resolver_guard);
        mac_poison += resolver_hooked ? 0x4000u : 0u;
    }

    // ── Flow chain init ─────────────────────────────────────────────────
    ad_flow_chain_t flow;
    ad_flow_chain_init(&flow, s->init_tsc ^ ad_memkey_get(&s->memkey));

    // ── Canary verification ─────────────────────────────────────────────
    // Recompute what the canary SHOULD be if init ran cleanly.
    // If someone NOPed init or patched PEB checks, this will mismatch.
    // On mismatch: silently poison the score — no branch to patch.
    u64 stored_canary = ad_vault_load(&s->init_canary, &s->memkey);
    // We can't recompute exactly (early_peb/late_peb were ephemeral),
    // but we CAN verify the canary is nonzero and structurally valid.
    // A zeroed/corrupted state → canary = 0 or = raw key (detectable).
    u32 canary_poison = 0;
    {
        // If init was skipped entirely, memkey is zero → canary decrypts to
        // garbage or zero. If init was patched, canary won't have the magic
        // bits. We check for structural validity:
        u64 canary_check = stored_canary ^ ad_derive64(AD_CANARY_MAGIC_ENC, AD_CANARY_MAGIC_MASK);
        // A valid canary has high entropy. A bypassed one is 0 or low-entropy.
        // Count zero bytes — a real canary should have at most 1 zero byte.
        u32 zero_bytes = 0;
        u32 cb;
        for (cb = 0; cb < 8u; cb++) {
            if (((canary_check >> (cb * 8u)) & 0xFFu) == 0u) zero_bytes++;
        }
        // 3+ zero bytes = likely corrupted/bypassed
        if (zero_bytes >= 3u || stored_canary == 0ULL) {
            canary_poison = 0xFFFFu;
        }
    }

    // ── Hide-thread bypass check ────────────────────────────────────────
    // If we called hide_thread and it "succeeded" but verification shows
    // the thread isn't actually hidden → ScyllaHide/TitanHide bypass.
    // Inject directly into score without a branchable check.
#if AD_ENABLE_HIDE_THREAD
    {
        u32 hide_bypass = (u32)(s->thread_hidden && !s->hide_verified);
        canary_poison += hide_bypass * 0x100u;
    }
#endif

    // Decrypt values we need from the vault (live on stack only)
    void* image_base   = ad_vault_load_ptr(&s->image_base_enc, &s->memkey);
    u64   code_hash_bl = ad_vault_load(&s->code_hash_enc, &s->memkey);

    // Build and shuffle the index table
    u8 order[AD_CHECK_COUNT];
    u8 i;
    for (i = 0u; i < (u8)AD_CHECK_COUNT; i++) order[i] = i;
    ad_shuffle_u8(order, (u32)AD_CHECK_COUNT, &s->prng);

    u32 slot;
    for (slot = 0u; slot < (u32)AD_CHECK_COUNT; slot++) {
        u8  idx = order[slot];
        b32 hit = 0;

        // Probabilistic skip — confuses static timing analysis
        if (ad_prng_should_skip(&s->prng)) continue;

        // ── Dispatch ────────────────────────────────────────────────────────
        switch ((ad_check_id_t)idx) {

#if AD_ENABLE_PEB_BEING_DEBUGGED
        case AD_CHECK_PEB_DEBUGGED:
            hit = ad_peb_being_debugged();
            break;
#endif

#if AD_ENABLE_PEB_NT_GLOBAL_FLAG
        case AD_CHECK_PEB_NTGLOBALFLAG:
            hit = ad_peb_nt_global_flag();
            break;
#endif

#if AD_ENABLE_HEAP_FLAGS
        case AD_CHECK_HEAP_FLAGS:
            hit = ad_heap_flags();
            break;
#endif

#if AD_ENABLE_DEBUG_PORT
        case AD_CHECK_DEBUG_PORT:
            hit = ad_debug_port();
            break;
#endif

#if AD_ENABLE_DEBUG_FLAGS
        case AD_CHECK_DEBUG_FLAGS:
            hit = ad_debug_flags();
            break;
#endif

        case AD_CHECK_DEBUG_OBJ:
            hit = ad_debug_object_handle();
            break;

#if AD_ENABLE_HARDWARE_BP
        case AD_CHECK_HW_BP:
            hit = ad_hardware_breakpoints();
            break;
#endif

#if AD_ENABLE_RDTSC_TIMING
        case AD_CHECK_RDTSC_STEP:
            hit = ad_rdtsc_timing();
            break;
#endif

#if AD_ENABLE_RDTSC_DOUBLE
        case AD_CHECK_RDTSC_DOUBLE:
            hit = ad_rdtsc_double();
            break;
#endif

#if AD_ENABLE_LOOP_TIMING
        case AD_CHECK_LOOP_TIME:
            hit = ad_loop_timing();
            break;
#endif

#if AD_ENABLE_SEH_CHECK
        case AD_CHECK_SEH_BP:
            hit = ad_seh_breakpoint();
            break;
#endif

#if AD_ENABLE_VM_HYPERVISOR
        case AD_CHECK_VM_CPUID:
            hit = ad_vm_cpuid_hypervisor_bit();
            break;
#endif

#if AD_ENABLE_VM_RDTSC
        case AD_CHECK_VM_RDTSC:
            hit = ad_vm_rdtsc_overhead();
            break;
#endif

#if AD_ENABLE_CODE_INTEGRITY
        case AD_CHECK_CODE_INTEGRITY:
            if (image_base) {
                hit = ad_code_integrity_full(
                    image_base,
                    s->image_scan_size,
                    code_hash_bl);
            }
            break;
#endif

#if AD_ENABLE_KERNEL_DEBUGGER
        case AD_CHECK_KERNEL_DBG:
            hit = ad_kernel_debugger();
            break;
#endif

#if AD_ENABLE_CLOSE_HANDLE_TRAP
        case AD_CHECK_CLOSE_HANDLE:
            hit = ad_close_handle_trap();
            break;
#endif

#if AD_ENABLE_QPC_TIMING
        case AD_CHECK_QPC_TIMING:
            hit = ad_qpc_timing();
            break;
#endif

#if AD_ENABLE_DEBUG_OBJECT_REMOVE
        case AD_CHECK_DBG_OBJ_REMOVE:
            hit = ad_remove_debug_object();
            break;
#endif

        // ── Runtime checks (anti-hook, anti-instrument, traps) ──────────

#if AD_ENABLE_HOOK_DETECT
        case AD_CHECK_HOOK_DETECT:
            hit = ad_detect_ntdll_hooks();
            break;
#endif

#if AD_ENABLE_GUARD_PAGE_TRAP
        case AD_CHECK_GUARD_PAGE:
            hit = ad_guard_page_trap();
            break;
#endif

#if AD_ENABLE_DR_CANARY
        case AD_CHECK_DR_CANARY:
            hit = ad_dr_canary();
            break;
#endif

#if AD_ENABLE_SUSPICIOUS_MODULES
        case AD_CHECK_SUSPECT_MODULES:
            hit = ad_detect_suspicious_modules();
            break;
#endif

#if AD_ENABLE_INSTRUMENTATION_CB
        case AD_CHECK_INSTR_CALLBACK:
            hit = ad_instrumentation_callback_check();
            break;
#endif

#if AD_ENABLE_CODE_INTEGRITY
        case AD_CHECK_ANTI_PATCH:
        {
            u32 patch_score = ad_anti_patch_full(
                image_base,
                s->image_scan_size,
                &s->self_hashes,
                (const void**)0,  // critical_fns filled by caller if needed
                0u
            );
            hit = (b32)(patch_score >= ad_derive32(0x9A7Bu, 0x9A7Fu));  // >= 4
        }
            break;
#endif

        // ── Advanced checks (new) ────────────────────────────────────────

#if AD_ENABLE_GHOST_BREAKPOINTS
        case AD_CHECK_GHOST_BP:
            if (image_base) hit = ad_ghost_breakpoint_check(image_base, AD_GHOST_BP_SCAN_SIZE);
            break;
#endif

#if AD_ENABLE_PIPELINE_DESYNC
        case AD_CHECK_PIPELINE_DESYNC:
            hit = ad_pipeline_desync_check();
            break;
#endif

#if AD_ENABLE_SCHEDULER_SYNC
        case AD_CHECK_SCHED_SYNC:
            hit = ad_scheduler_sync_check();
            break;
#endif

#if AD_ENABLE_EXCEPTION_FINGERPRINT
        case AD_CHECK_EXCEPTION_FP:
            hit = ad_exception_fingerprint_check();
            break;
#endif

#if AD_ENABLE_IMPOSSIBLE_STATES
        case AD_CHECK_IMPOSSIBLE_CPU:
            hit = ad_impossible_states_check();
            break;
#endif

#if AD_ENABLE_SELFMOD_RACE
        case AD_CHECK_SELFMOD_RACE:
            hit = ad_selfmod_race_check();
            break;
#endif

#if AD_ENABLE_PRESSURE_TEST
        case AD_CHECK_PRESSURE_TEST:
            hit = ad_pressure_test_check();
            break;
#endif

#if AD_ENABLE_TEMPORAL_TRAPS
        case AD_CHECK_TEMPORAL_TRAP:
            hit = ad_temporal_trap_verify(&s->temporal_ctx, &s->memkey);
            break;
#endif

        default:
            continue;
        }

        r.checks_run++;

        // ── Flow chain: each executed check transforms the chain ────────
        // Both sides (chain + expected) get the same transform.
        // If someone NOPs a check, only 'expected' advances → mismatch.
        ad_flow_chain_step(&flow, (u32)idx, hit);
        ad_flow_chain_expect(&flow, (u32)idx, hit);

        if (hit) {
            r.checks_hit++;

            // Accumulate score with PRNG noise to prevent trivial pattern matching
            u64 noise = ad_prng_next(&s->prng);
            r.score  += (u32)(noise >> 48) + (1u << (idx & 0x1Fu));
            r.check_mask |= (1u << (idx & 0x1Fu));
        }
    }

    // ── Flow chain verification ────────────────────────────────────────
    // If a check was NOPed, flow.chain != flow.expected
    u32 flow_poison = ad_flow_chain_verify(&flow) ? 0x2000u : 0u;

    // ── Inject ALL poison layers into score (branchless) ────────────────
    // canary_poison: init tampered
    // mac_poison:    state externally modified / resolver hooked
    // flow_poison:   check function NOPed
    // All are ADDs — no conditional branches to patch.
    u32 total_poison = canary_poison + mac_poison + flow_poison;
    r.score      += total_poison;
    r.checks_hit += (total_poison != 0u) ? (u32)AD_CHECK_COUNT : 0u;

    // ── Re-seal state MAC ───────────────────────────────────────────────
    // Update MAC after our legitimate modifications to PRNG state
    ad_state_mac_update(&s->state_mac, s, sizeof(*s), &s->memkey);

    // Wipe decrypted values from stack
    AD_BARRIER();
    image_base = (void*)0;
    code_hash_bl = 0;
    stored_canary = 0;
    canary_poison = 0;
    mac_poison = 0;
    flow_poison = 0;
    total_poison = 0;
    AD_BARRIER();

    return r;
}

// ---------------------------------------------------------------------------
// Query helpers — call these on the returned ad_result_t
// ---------------------------------------------------------------------------

// Returns 1 if the environment is suspicious (threshold or more checks fired)
// Threshold derived at runtime — not a visible immediate in disassembly
ANTIDEBUG_INLINE b32 ad_is_suspicious(const ad_result_t* r) {
    // AD_SUSPICION_THRESHOLD = 2, encoded as 0x5C3D ^ 0x5C3F = 0x0002
    u32 thresh = ad_derive32(0x5C3Du, 0x5C3Fu);
    return ad_opaque_gt_u32(r->checks_hit + 1u, thresh);
    // +1 because opaque_gt is strict >, and we want >=
}

// Returns 1 if a specific check fired (use ad_check_id_t values)
ANTIDEBUG_INLINE b32 ad_check_fired(const ad_result_t* r, ad_check_id_t id) {
    return (b32)((r->check_mask >> (u32)id) & 1u);
}

// Returns a normalized confidence value in [0, 100]
ANTIDEBUG_INLINE u32 ad_confidence_pct(const ad_result_t* r) {
    if (r->checks_run == 0u) return 0u;
    return (r->checks_hit * 100u) / r->checks_run;
}

// ---------------------------------------------------------------------------
// HARDENED MODE — single call that runs ALL hardened checks + self-protect
//
// This is the recommended entry point for production use. It:
//   1. Verifies state MAC + resolver guard + flow chain
//   2. Runs all hardened checks (triple-read, cross-validate, statistical)
//   3. Runs all runtime checks (hooks, guard pages, modules, instruments)
//   4. Applies anti-patch (CRC32, prologue, page protect, INT3 density)
//   5. Injects all poison layers
//   6. Re-seals the state
//
// Returns a fully populated ad_result_t. Score > 0 = suspicious.
// The higher the score, the more layers detected something.
// ---------------------------------------------------------------------------
// Debug capture for layer-by-layer scoring inside ad_run_hardened.
// Set ad_dbg_layers.enabled = 1 before calling ad_run_hardened to populate.
typedef struct {
    u32 enabled;
    u32 self_poison_initial;
    u32 correlation;
    u32 deep;
    u32 cross;
    u32 patch;
    u32 exotic;
    u32 advanced;
    u32 extra;
    u32 self_poison_final;
    u32 raw_hits;
    u32 f_peb_debug, f_ntgflag, f_heap, f_dbg_port, f_dbg_flags, f_hwbp;
    u32 f_timing, f_syscall, f_ntclose, f_rdtsc_dbl, f_ntdll_hooked, f_page_rwx;
} ad_dbg_layers_t;
static volatile ad_dbg_layers_t ad_dbg_layers = {0};

ANTIDEBUG_INLINE ad_result_t ad_run_hardened(ad_state_t* s) {
    ad_result_t r;
    AD_ZERO_BUF(&r, sizeof(r));

    // ── Layer 0: Self-protection ────────────────────────────────────────
    u32 self_poison = 0;
    {
        b32 mac_bad = ad_state_mac_verify(&s->state_mac, s, sizeof(*s), &s->memkey);
        self_poison += mac_bad ? 0x8000u : 0u;
    }
    {
        b32 resolver_bad = ad_resolver_guard_check(&s->resolver_guard);
        self_poison += resolver_bad ? 0x4000u : 0u;
    }
    {
        u64 canary = ad_vault_load(&s->init_canary, &s->memkey);
        if (canary == 0ULL) self_poison += 0xFFFFu;
    }

    // ── Layer 1: Hardened observable checks ──────────────────────────────
    // Each check returns a boolean fact that feeds the correlation engine
    b32 f_peb_debug     = ad_h_peb_being_debugged();
    b32 f_ntgflag_debug = ad_h_peb_nt_global_flag();
    b32 f_heap_debug    = ad_h_heap_flags();
    b32 f_debug_port    = ad_h_debug_port();
    b32 f_debug_flags   = ad_h_debug_flags();
    b32 f_hwbp          = ad_h_hardware_bp();
    b32 f_timing_slow   = ad_h_rdtsc_timing();
    b32 f_syscall_slow  = ad_h_syscall_timing();
#if AD_ENABLE_CLOSE_HANDLE_TRAP
    b32 f_ntclose_trap  = ad_h_ntclose_trap();
#else
    b32 f_ntclose_trap  = 0;
#endif
    b32 f_rdtsc_double  = ad_h_rdtsc_double();

    // Runtime checks
    b32 f_ntdll_hooked  = ad_detect_ntdll_hooks();
    b32 f_exception_eaten = (b32)(f_ntclose_trap);  // NtClose trap = exception eaten
    b32 f_hide_faked    = (b32)(s->thread_hidden && !s->hide_verified);

    // Page protection
    void* img = ad_vault_load_ptr(&s->image_base_enc, &s->memkey);
    b32 f_page_rwx = img ? ad_check_page_protection(img) : 0;

    // ── Extended correlation inputs (added 2026-04-27) ──────────────────
    //
    // Three additional independent facts that resist common stealth shims
    // (ScyllaHide-class plugins hook ntdll user-mode entries; none of these
    // are reachable through ntdll exports):
    //
    //   1. KUSER_SHARED_DATA.KdDebuggerEnabled / KdDebuggerNotPresent —
    //      kernel-only fixed-address page (0x7FFE0000), read-only from
    //      user mode. A plugin can't fake values here.
    //   2. ntdll!DbgBreakPoint first-byte audit — its prologue is
    //      `cc c3` (int3; ret). A debugger / hook plugin patches it to
    //      land its breakpoint somewhere else.
    //   3. (tools_present is fed in as 0 here — it's already covered by
    //      the static_score path which sums into raw score. Adding it
    //      to correlation would double-count the dev-box-with-tools-open
    //      case and surprise users. Re-enable if the static path is
    //      reworked.)
    b32 f_kd_present = 0;
    b32 f_dbgbreak_patched = 0;
#if defined(_MSC_VER) && AD_ENABLE_KD_PRESENT
    {
        volatile const u8* kusd = (volatile const u8*)0x7FFE0000ULL;
        u8 kd_en  = kusd[0x2D4];
        u8 kd_np  = kusd[0x2D5];
        // Either flag set wrong = kernel debugger present
        if (kd_en != 0u || kd_np == 0u) f_kd_present = 1;
    }
#endif
#if defined(_MSC_VER) && AD_ENABLE_DBGBREAK_AUDIT
    {
        // Resolve ntdll!DbgBreakPoint and check its first byte. We don't
        // patch this symbol ourselves (only DbgUiRemoteBreakin), so any
        // value other than 0xCC is a third-party hook.
        //
        // Cache the resolved address. `ad_run_hardened` is called many
        // times per orchestrator pass and re-walking PEB.LdrData /
        // ntdll exports each time is (a) wasteful and (b) racy against
        // the LDR rundown that happens during late shutdown — every
        // ~200 runs that race surfaced as a no-result crash because
        // ad_resolve_api ran outside any SEH frame.
        //
        // The full block is wrapped in __try so even pathological PEB
        // states (LDR list partially unlinked, ntdll header zeroed by
        // ad_erase_ntdll_header on a peer thread) silently degrade to
        // "untouched" instead of AV'ing the orchestrator.
        static volatile void* s_cached_dbgbreak = (void*)0;
        static volatile u32   s_cached_hash     = 0u;
        __try {
            if (s_cached_hash == 0u) s_cached_hash = ad_hash_str("DbgBreakPoint");
            void* fn = (void*)s_cached_dbgbreak;
            if (!fn) {
                fn = ad_resolve_api(AD_HASH_NTDLL, s_cached_hash);
                s_cached_dbgbreak = fn;
            }
            if (fn) {
                u8 b0 = *(volatile const u8*)fn;
                if (b0 != 0xCCu) f_dbgbreak_patched = 1;
            }
        } __except(1) { /* unreadable / racy LDR = treat as untouched */ }
    }
#endif

    // ── Layer 2: Correlation engine — EXPONENTIAL scoring ───────────────
    u32 correlation_score = ad_build_truth_and_correlate_ex(
        f_peb_debug, f_ntgflag_debug, f_heap_debug,
        f_debug_port, f_debug_flags, f_timing_slow,
        f_syscall_slow, f_ntdll_hooked, f_hwbp,
        f_hide_faked, f_exception_eaten, f_page_rwx,
        f_kd_present, /*tools_present=*/0, f_dbgbreak_patched
    );

    // ── Layer 3: Deep reality checks ────────────────────────────────────
#if AD_ENABLE_PEB_BEING_DEBUGGED
    u32 deep_score = ad_deep_check_master(img, s->image_scan_size);
#else
    u32 deep_score = 0;
#endif

    // ── Layer 4: PEB cross-validation (dedicated) ───────────────────────
    u32 cross_score = ad_h_cross_validate_peb();

    // ── Layer 5: Anti-patch ─────────────────────────────────────────────
    u32 patch_score = 0;
    if (img) {
        patch_score = ad_anti_patch_full(
            img, s->image_scan_size, &s->self_hashes,
            (const void**)0, 0u
        );
    }

    // ── Aggregate — count raw hits ──────────────────────────────────────
    u32 raw_hits = 0;
    raw_hits += (u32)f_peb_debug + (u32)f_ntgflag_debug + (u32)f_heap_debug;
    raw_hits += (u32)f_debug_port + (u32)f_debug_flags + (u32)f_hwbp;
    raw_hits += (u32)f_timing_slow + (u32)f_syscall_slow + (u32)f_ntclose_trap;
    raw_hits += (u32)f_rdtsc_double + (u32)f_ntdll_hooked + (u32)f_page_rwx;

    // ── Layer 6: Exotic checks (needs raw_hits for timing bomb) ─────────
#if AD_ENABLE_SEH_CHECK
    u32 exotic_score = ad_exotic_master(s->init_tsc, raw_hits);
#else
    u32 exotic_score = 0;
#endif

    // ── Layer 7: Advanced checks ────────────────────────────────────────
    u32 advanced_score = ad_advanced_master(
        img, s->image_scan_size,
        &s->temporal_ctx, &s->heisenberg_ctx,
        &s->memkey, s->init_tsc
    );

    // ── Layer 7b: Extra checks (handle scan, DLL scan, ETW, TF…) ────────
    u32 extra_score = ad_extra_master();

    // ── Layer 8: VMProtect built-in detection ───────────────────────────
    {
        b32 vmp_debug = (b32)VMProtectIsDebuggerPresent(true);
        b32 vmp_crc_bad = (b32)(!VMProtectIsValidImageCRC());
        self_poison += vmp_debug   ? 0x6000u : 0u;
        self_poison += vmp_crc_bad ? 0x3000u : 0u;
    }

    // ── Build result ────────────────────────────────────────────────────
    r.checks_run = 12u;
    r.checks_hit = raw_hits;
    r.score      = correlation_score   // exponential if contradictions
                 + deep_score          // shadow exec, poisoning, cache, variance
                 + cross_score         // PEB cross-validation
                 + patch_score         // CRC32, prologues, page, INT3
                 + exotic_score        // trap flag, INT2D, yield, KUSD, timing bomb
                 + advanced_score      // ghost BP, pipeline, scheduler, heisenberg, etc.
                 + extra_score         // dbgui patch, handle scan, DLL scan, ETW, TF
                 + self_poison;        // state MAC, resolver, canary, VMP

    if (ad_dbg_layers.enabled) {
        ad_dbg_layers.correlation = correlation_score;
        ad_dbg_layers.deep        = deep_score;
        ad_dbg_layers.cross       = cross_score;
        ad_dbg_layers.patch       = patch_score;
        ad_dbg_layers.exotic      = exotic_score;
        ad_dbg_layers.advanced    = advanced_score;
        ad_dbg_layers.extra       = extra_score;
        ad_dbg_layers.self_poison_final = self_poison;
        ad_dbg_layers.raw_hits    = raw_hits;
        ad_dbg_layers.f_peb_debug = (u32)f_peb_debug;
        ad_dbg_layers.f_ntgflag   = (u32)f_ntgflag_debug;
        ad_dbg_layers.f_heap      = (u32)f_heap_debug;
        ad_dbg_layers.f_dbg_port  = (u32)f_debug_port;
        ad_dbg_layers.f_dbg_flags = (u32)f_debug_flags;
        ad_dbg_layers.f_hwbp      = (u32)f_hwbp;
        ad_dbg_layers.f_timing    = (u32)f_timing_slow;
        ad_dbg_layers.f_syscall   = (u32)f_syscall_slow;
        ad_dbg_layers.f_ntclose   = (u32)f_ntclose_trap;
        ad_dbg_layers.f_rdtsc_dbl = (u32)f_rdtsc_double;
        ad_dbg_layers.f_ntdll_hooked = (u32)f_ntdll_hooked;
        ad_dbg_layers.f_page_rwx  = (u32)f_page_rwx;
    }

    // ── Re-seal state ───────────────────────────────────────────────────
    ad_state_mac_update(&s->state_mac, s, sizeof(*s), &s->memkey);

    // ── ATTACK 3 FIX: Return address integrity check ───────────────────
    // If an attacker sets a BP on our RET and patches EAX (score), the
    // return address will point into the debugger's trampoline or into
    // code outside any legitimately loaded module. Poison the score
    // if the return address is hijacked.
    //
    // Walk PEB.Ldr.InLoadOrderModuleList (DLL-safe) to verify that
    // _ReturnAddress() falls inside a known loaded module.
#if defined(_MSC_VER) && AD_ENABLE_RETADDR_CHECK
    {
        void* ret_addr = _ReturnAddress();
        u8* ra = (u8*)ret_addr;
        b32 ra_in_module = 0;

        // First: is the return address inside OUR OWN image? In manual-map
        // scenarios (WhipMmap, BlackBone, etc.) the DLL is intentionally
        // absent from PEB.Ldr, so the loader-list walk below would never
        // find us — yielding a guaranteed false positive on every cycle
        // and saturating the score to 0xFFFFFFFF. Compare against the
        // image base + size we already snapshotted at ad_init() time.
        {
            void* our_base = ad_vault_load_ptr(&s->image_base_enc, &s->memkey);
            if (our_base) {
                u8* base = (u8*)our_base;
                // Read SizeOfImage from our own PE headers (offset
                // OptionalHeader.SizeOfImage = e_lfanew + 0x18 + 0x38).
                __try {
                    u32 e_lfanew = *(u32*)(base + 0x3C);
                    u32 size_of_image = *(u32*)(base + e_lfanew + 0x18 + 0x38);
                    if (size_of_image > 0u && ra >= base && ra < base + size_of_image) {
                        ra_in_module = 1;
                    }
                } __except(1) { /* unreadable headers (manual-map post-erase) */ }
            }
        }

        if (!ra_in_module) {
            u8* peb = (u8*)__readgsqword(0x60);
            u8* ldr = *(u8**)(peb + 0x18);         // PEB.Ldr
            if (ldr) {
                u8* list_head = ldr + 0x10;         // InLoadOrderModuleList
                u8* entry = *(u8**)list_head;
                u32 walk = 0u;
                while (entry != list_head && walk < 200u) {
                    void* mod_base = *(void**)(entry + 0x30);  // DllBase
                    u32   mod_size = *(u32*)(entry + 0x40);     // SizeOfImage
                    if (mod_base && mod_size) {
                        u8* mod_start = (u8*)mod_base;
                        u8* mod_end   = mod_start + mod_size;
                        if (ra >= mod_start && ra < mod_end) {
                            ra_in_module = 1;
                            break;
                        }
                    }
                    entry = *(u8**)entry;
                    walk++;
                }
            }
        }

        // Return address outside all loaded modules AND outside our own image
        // = debugger trampoline, hook detour, or JIT code cache. Poison
        // score irrecoverably.
        if (!ra_in_module) {
            r.score = 0xFFFFFFFFu;
        }
    }
#endif // _MSC_VER && AD_ENABLE_RETADDR_CHECK

    // ── Score transit encryption ────────────────────────────────────────
    // XOR the score with a per-call key so it's never plaintext in RAX.
    // A reverser who patches "mov [score], 0" after the call gets
    // 0 ^ key = key (wrong), not zero.
    {
#if defined(_MSC_VER)
        u32 transit_key = (u32)(__rdtsc() ^ (u64)(uintptr_t)&r);
#else
        u32 transit_key = 0xBAADF00Du;
#endif
        if (transit_key == 0u) transit_key = 0xDEAD0001u;
        r.score ^= transit_key;
        r.check_mask ^= transit_key;  // also protect check_mask
        r._transit_key = transit_key;  // caller uses this to decrypt
    }

    return r;
}

// Decrypt score after ad_run_hardened returns
#define AD_DECRYPT_RESULT(r) do { \
    (r).score      ^= (r)._transit_key; \
    (r).check_mask ^= (r)._transit_key; \
} while(0)

// ---------------------------------------------------------------------------
// Verify dispatcher output wasn't patched to return zeros
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE b32 ad_verify_result(const ad_result_t* r) {
    return ad_verify_dispatcher_alive(r, 5u);
}

#endif // ANTIDEBUG_DISPATCHER_H
