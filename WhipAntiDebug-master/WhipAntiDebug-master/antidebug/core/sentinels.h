// ===== file: antidebug/core/sentinels.h =====
//
// Detached Sentinels — autonomous anti-debug surveillance threads with
// no score contribution and direct punishment vectors.
//
// PURPOSE
// -------
// The dispatcher / score_vault / latent_tamper pipeline is the "loud"
// path: every check feeds points into an aggregate that gates the flag
// derivation. A reverser who maps the scoring path can NOP-patch at the
// accumulation point and bypass the whole layer with a single edit.
//
// The sentinels close that gap with a **fully detached** sub-system:
//
//   * Three independent threads, each with its own role and personality.
//   * No reference to ad_state_t, score_ctx, latent_*, guardian_*.
//     Static analysis cannot relate them to the scoring graph; dynamic
//     analysis cannot suspend "the score thread" because there is none.
//   * No call site adds the sentinels' opinion to a number. They run
//     their own checks, make their own decision, and **directly punish**.
//
// PUNISHMENT VECTORS
// ------------------
//   1. POISON  — a single XOR-encoded global byte that main folds into
//                the flag commitment right before vm_derive_and_decrypt.
//                Clean run → 0 → commitment passes through unchanged.
//                Detected → non-zero → key stream diverges → garbage flag.
//   2. KILL    — direct-syscall NtTerminateProcess on severe signals
//                (hardware breakpoints, ntdll hook patches, suspended
//                peer thread). Random delay 1–6s after detection so the
//                cause is uncorrelatable with the effect.
//   3. WILD    — delayed dereference of a wild function pointer in a
//                thread the reverser never spawned. Same flavour as
//                latent_tamper but rip-derived from a different magic
//                so it cannot be filtered by RIP value.
//
// CROSS-WATCH
// -----------
// Each sentinel publishes a heartbeat. Each sentinel ALSO reads its peer's
// heartbeat. If a peer stalls (suspended / killed) the watcher arms its
// own punishment vectors. Killing one thread to silence its checks turns
// the other two into executioners.
//
// API
// ---
//   ad_sentinels_init()         — spawn all three threads (call once)
//   ad_sentinels_poison_fold(x) — XOR poison into a u32 (used by main)
//   ad_sentinels_alive()        — main-thread liveness check (returns 0
//                                 if any sentinel is dead → also poisons)
//
#ifndef ANTIDEBUG_SENTINELS_H
#define ANTIDEBUG_SENTINELS_H

#include "types.h"
#include "macros.h"
#include "api_hash.h"
#include "syscall_bridge.h"
#include "string_encrypt.h"
#include "strenc_extra.h"
#include "../checks/debug/kd_deep.h"

#ifdef _MSC_VER

// ---------------------------------------------------------------------------
// Local string-encrypt macros for syscall names not yet defined in
// string_encrypt.h. Each is guarded so it does not clash with a definition
// already pulled in via latent_tamper.h or main_example.c.
// ---------------------------------------------------------------------------
#ifndef AD_STRENC_NtDelayExecution
#define AD_STRENC_NtDelayExecution(buf)                                      \
    do {                                                                     \
        const u8 _k = AD_STR_KEY(0x71);                                     \
        char buf##_e[17];                                                    \
        AD_ENC(buf##_e,  0, 'N', _k); AD_ENC(buf##_e,  1, 't', _k);       \
        AD_ENC(buf##_e,  2, 'D', _k); AD_ENC(buf##_e,  3, 'e', _k);       \
        AD_ENC(buf##_e,  4, 'l', _k); AD_ENC(buf##_e,  5, 'a', _k);       \
        AD_ENC(buf##_e,  6, 'y', _k); AD_ENC(buf##_e,  7, 'E', _k);       \
        AD_ENC(buf##_e,  8, 'x', _k); AD_ENC(buf##_e,  9, 'e', _k);       \
        AD_ENC(buf##_e, 10, 'c', _k); AD_ENC(buf##_e, 11, 'u', _k);       \
        AD_ENC(buf##_e, 12, 't', _k); AD_ENC(buf##_e, 13, 'i', _k);       \
        AD_ENC(buf##_e, 14, 'o', _k); AD_ENC(buf##_e, 15, 'n', _k);       \
        AD_DECODE_BUF(buf##_e, 16, _k);                                     \
        for (unsigned _ci = 0; _ci < 17; _ci++) (buf)[_ci] = buf##_e[_ci];  \
    } while (0)
#endif

#ifndef AD_STRENC_NtTerminateProcess
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
#endif

// ---------------------------------------------------------------------------
// Tunables
// ---------------------------------------------------------------------------
#ifndef AD_SENT_A_PERIOD_MIN_MS
#define AD_SENT_A_PERIOD_MIN_MS   800u    // PEB watcher
#endif
#ifndef AD_SENT_A_PERIOD_MAX_MS
#define AD_SENT_A_PERIOD_MAX_MS   2200u
#endif
#ifndef AD_SENT_B_PERIOD_MIN_MS
#define AD_SENT_B_PERIOD_MIN_MS   1200u   // hardware/syscall executioner
#endif
#ifndef AD_SENT_B_PERIOD_MAX_MS
#define AD_SENT_B_PERIOD_MAX_MS   3500u
#endif
#ifndef AD_SENT_C_PERIOD_MIN_MS
#define AD_SENT_C_PERIOD_MIN_MS   2000u   // hook auditor
#endif
#ifndef AD_SENT_C_PERIOD_MAX_MS
#define AD_SENT_C_PERIOD_MAX_MS   4500u
#endif
#ifndef AD_SENT_D_PERIOD_MIN_MS
#define AD_SENT_D_PERIOD_MIN_MS   3000u   // kernel debugger watcher
#endif
#ifndef AD_SENT_D_PERIOD_MAX_MS
#define AD_SENT_D_PERIOD_MAX_MS   6000u
#endif

// Punishment delay window: detection → action. Random per detection so the
// reverser cannot bisect the trigger by timing.
#ifndef AD_SENT_KILL_DELAY_MIN_MS
#define AD_SENT_KILL_DELAY_MIN_MS 1000u
#endif
#ifndef AD_SENT_KILL_DELAY_MAX_MS
#define AD_SENT_KILL_DELAY_MAX_MS 6000u
#endif

// Cross-watch: a peer heartbeat that hasn't moved in this many ms is dead.
#ifndef AD_SENT_PEER_TIMEOUT_MS
// Must exceed the slowest peer's max period plus its kill-delay slack.
// Sentinel D can sleep up to 6s, then a kill gates 1–6s more before a
// peer would see the heartbeat resume; below 13s we false-positive on a
// peer that is merely sleeping. 15s leaves headroom for OS scheduling
// jitter on heavily loaded hosts.
#define AD_SENT_PEER_TIMEOUT_MS   15000u
#endif

// Decoded poison magic. Stored XOR'd with ad_sent_xor_key().
#define AD_SENT_POISON_MAGIC      0x5234A78Cu

// ---------------------------------------------------------------------------
// Detached state — single TU storage guard
// ---------------------------------------------------------------------------
#ifndef AD_SENT_STORAGE_DEFINED
#define AD_SENT_STORAGE_DEFINED

// Per-sentinel heartbeat + last-seen-tick. All XOR-encoded so a memory
// scanner cannot dump them and a WPM cannot zero them without producing a
// non-zero decoded value (which the watcher reads as "tampered" and
// punishes immediately).
volatile u64 ad_sent_a_beat = 0;
volatile u64 ad_sent_b_beat = 0;
volatile u64 ad_sent_c_beat = 0;
volatile u64 ad_sent_d_beat = 0;
volatile u32 ad_sent_a_alive = 0;
volatile u32 ad_sent_b_alive = 0;
volatile u32 ad_sent_c_alive = 0;
volatile u32 ad_sent_d_alive = 0;
volatile u32 ad_sent_started = 0;

// Set to 1 by ad_sentinels_request_exit() right before the orchestrator
// calls NtTerminateProcess. Each sentinel loop checks this flag at the
// top of every iteration and returns immediately, suppressing any further
// poison/kill work. Without this signal the kernel terminate races with a
// sentinel waking up — the sentinel can fire NtTerminateProcess(0xC000026E)
// before the orchestrator's clean exit lands, producing a spurious exit
// code 139 even though no detection ever occurred.
volatile u32 ad_sent_exit_requested = 0;

// Poison output — spread across FOUR independent slots, each XOR-encoded
// with a different per-process key derivation. To clean the poison via
// kernel write-process-memory, an attacker has to identify and zero all
// four slots in the same window between detection and the next sentinel
// poll (~3 s minimum); zeroing only some of them leaves residual XOR
// factors in the fold output. Each sentinel poll re-arms all four if any
// detection signal fires, so the WPM/re-arm race favors us.
volatile u32 ad_sent_poison_enc1 = 0;
volatile u32 ad_sent_poison_enc2 = 0;
volatile u32 ad_sent_poison_enc3 = 0;
volatile u32 ad_sent_poison_enc4 = 0;

#endif // AD_SENT_STORAGE_DEFINED

// ---------------------------------------------------------------------------
// Per-process XOR key — same trick as latent_tamper. PEB pointer is unique
// per run, shared across threads, unobtainable from a static dump.
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE u64 ad_sent_xor_key(void) {
    u64 peb = (u64)__readgsqword(0x60);
    return peb ^ 0xC9B4F70E11D52A83ULL;
}

ANTIDEBUG_INLINE u32 ad_sent_xor_key32(void) {
    u64 k = ad_sent_xor_key();
    return (u32)(k ^ (k >> 32));
}

// Per-slot key derivation. Each of the four poison slots uses a different
// XOR mask so a kd that learns one slot's key cannot reuse it on the others.
ANTIDEBUG_INLINE u32 ad_sent_xor_key32_v(u32 variant) {
    u64 k = ad_sent_xor_key();
    u32 base = (u32)(k ^ (k >> 32));
    // Each variant gets a unique twist via Knuth's golden-ratio constant.
    return base ^ (variant * 0x9E3779B9u) ^ (u32)(variant ^ (variant << 13));
}

// ---------------------------------------------------------------------------
// Tiny xorshift PRNG — RDTSC-seeded per call site, not shared across threads
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE u64 ad_sent_xs(u64* s) {
    u64 x = *s;
    x ^= x << 13; x ^= x >> 7; x ^= x << 17;
    *s = x;
    return x;
}

ANTIDEBUG_INLINE u32 ad_sent_rand_range(u64* s, u32 lo, u32 hi) {
    u32 span = hi - lo;
    return lo + (u32)(ad_sent_xs(s) % (u64)span);
}

// ---------------------------------------------------------------------------
// Direct-syscall delay (mirrors latent_tamper.h's pattern; redefined here
// so the sentinel module is self-contained and not coupled to latent_*).
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE void ad_sent_delay_ms(u32 ms) {
    static u16 s_ssn = AD_SSN_UNRESOLVED;
    AD_RESOLVE_SSN_ENC(s_ssn, NtDelayExecution, 17);
    if (s_ssn == AD_SSN_FAILED) return;
    s64 interval = -((s64)ms * 10000LL);
    (void)AD_SYSCALL2(s_ssn, (u64)0, &interval);
}

// Read KUSER_SHARED_DATA.InterruptTime — wall-clock 100ns ticks, monotonic
// regardless of thread suspension. Used to detect SuspendThread on a peer.
ANTIDEBUG_INLINE u64 ad_sent_interrupt_time(void) {
    volatile const u8* kusd = (volatile const u8*)0x7FFE0000ULL;
    for (;;) {
        u32 high1 = *(volatile const u32*)(kusd + 0x08 + 4);
        u32 low   = *(volatile const u32*)(kusd + 0x08 + 0);
        u32 high2 = *(volatile const u32*)(kusd + 0x08 + 4);
        if (high1 == high2) return ((u64)high1 << 32) | (u64)low;
    }
}

// ---------------------------------------------------------------------------
// Heartbeat helpers — each sentinel publishes (counter ^ key << 32 | wall_ms)
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE u64 ad_sent_pack_beat(u32 counter) {
    u64 wall = ad_sent_interrupt_time() / 10000u;  // ms
    u64 raw  = ((u64)counter << 32) | (wall & 0xFFFFFFFFu);
    return raw ^ ad_sent_xor_key();
}

ANTIDEBUG_INLINE u32 ad_sent_unpack_counter(u64 enc) {
    u64 raw = enc ^ ad_sent_xor_key();
    return (u32)(raw >> 32);
}

ANTIDEBUG_INLINE u32 ad_sent_unpack_wall(u64 enc) {
    u64 raw = enc ^ ad_sent_xor_key();
    return (u32)(raw & 0xFFFFFFFFu);
}

// ---------------------------------------------------------------------------
// Punishment primitives
// ---------------------------------------------------------------------------

// Vector 1: poison — fold a non-zero magic into FOUR encoded globals,
// each with a different XOR key and a different magic constant. To clean
// the poison via WPM the attacker has to (a) locate all four slots in
// .data, and (b) zero each one to its specific resting value (0 ^ key_v),
// before the next sentinel poll re-arms them.
ANTIDEBUG_INLINE void ad_sent_punish_poison(void) {
    u64 jit;
#if defined(_MSC_VER)
    jit = __rdtsc();
#else
    jit = 0xDEADBEEF;
#endif
    u32 magic = AD_SENT_POISON_MAGIC ^ (u32)(jit | 1u);

    u32 c1 = ad_sent_poison_enc1 ^ ad_sent_xor_key32_v(1);
    u32 c2 = ad_sent_poison_enc2 ^ ad_sent_xor_key32_v(2);
    u32 c3 = ad_sent_poison_enc3 ^ ad_sent_xor_key32_v(3);
    u32 c4 = ad_sent_poison_enc4 ^ ad_sent_xor_key32_v(4);

    c1 ^= magic;
    c2 ^= magic ^ 0xA5A5A5A5u;
    c3 ^= magic ^ 0x5A5A5A5Au;
    c4 ^= magic ^ 0xCAFEBABEu;

    ad_sent_poison_enc1 = c1 ^ ad_sent_xor_key32_v(1);
    ad_sent_poison_enc2 = c2 ^ ad_sent_xor_key32_v(2);
    ad_sent_poison_enc3 = c3 ^ ad_sent_xor_key32_v(3);
    ad_sent_poison_enc4 = c4 ^ ad_sent_xor_key32_v(4);
}

// Helper — produces a randomised low-32-bit mix for the wild pointer so the
// resulting RIP is not filterable. Defined ahead of punish_kill (forward
// reference would not compile under -Wimplicit-function-declaration).
ANTIDEBUG_INLINE u64 ad_sent_jit_mix(u64* s) {
    return (ad_sent_xs(s) & 0xFFFFFFFFu);
}

// Vector 2: terminate — direct syscall, no kernel32 path. Random pre-delay
// so the cause→effect window is wide. If NtTerminateProcess does not
// resolve or returns, fall through to a wild dereference so punishment
// never silently no-ops.
ANTIDEBUG_INLINE void ad_sent_punish_kill(u64* prng) {
    u32 ms = ad_sent_rand_range(prng,
                                AD_SENT_KILL_DELAY_MIN_MS,
                                AD_SENT_KILL_DELAY_MAX_MS);
    ad_sent_delay_ms(ms);

    static u16 s_ssn = AD_SSN_UNRESOLVED;
    AD_RESOLVE_SSN_ENC(s_ssn, NtTerminateProcess, 19);
    if (s_ssn != AD_SSN_FAILED) {
        (void)AD_SYSCALL2(s_ssn, AD_CURRENT_PROCESS, (u64)0xC000026Eu /* INVALID_TASK */);
    }

    // Wild-pointer fallback. Reached only if NtTerminateProcess didn't
    // resolve or failed to terminate (extremely unlikely on success).
    u64 wild_addr = 0xA17C00DE00000000ULL ^ ad_sent_jit_mix(prng);
    typedef void (*fn_void_t)(void);
    fn_void_t f = (fn_void_t)(uintptr_t)wild_addr;
    f();
}

// ---------------------------------------------------------------------------
// Detection primitives — each sentinel uses a subset
// ---------------------------------------------------------------------------

// Sentinel A: PEB.BeingDebugged + NtGlobalFlag + DebugPort syscall.
// All three together cover the loudest debug signals; any one firing is
// definitive. NO timing checks here (would FP under heavy CPU load).
ANTIDEBUG_INLINE b32 ad_sent_a_detect(void) {
    // PEB direct read — gs:[0x60] → +0x02 BeingDebugged, +0xBC NtGlobalFlag
    u8* peb = (u8*)__readgsqword(0x60);
    if (peb == (u8*)0) return 0;
    if (peb[0x02] != 0u) return 1;
    u32 ngf = *(volatile u32*)(peb + 0xBC);
    if ((ngf & 0x70u) == 0x70u) return 1;  // FLG_HEAP_*

    // DebugPort via NtQueryInformationProcess(ProcessDebugPort)
    static u16 s_ssn = AD_SSN_UNRESOLVED;
    AD_RESOLVE_SSN_ENC(s_ssn, NtQueryInformationProcess, 26);
    if (s_ssn == AD_SSN_FAILED) return 0;
    u64 port = 0;
    u32 rl = 0;
    ad_ntstatus_t st = AD_SYSCALL5(s_ssn,
                                   AD_CURRENT_PROCESS,
                                   (u64)AD_PROCESS_DEBUG_PORT,
                                   &port,
                                   (u64)sizeof(port),
                                   &rl);
    if (AD_NT_SUCCESS(st) && port != 0) return 1;

    return 0;
}

// Sentinel B: GetThreadContext on self → DR0..3 / DR7 set = HWBP attached.
// Uses NtGetContextThread direct syscall on AD_CURRENT_THREAD. A debugger
// can't filter this without intercepting the syscall itself.
ANTIDEBUG_INLINE b32 ad_sent_b_detect(void) {
    static u16 s_ssn = AD_SSN_UNRESOLVED;
    AD_RESOLVE_SSN_ENC(s_ssn, NtGetContextThread, 19);
    if (s_ssn == AD_SSN_FAILED) return 0;

    AD_CONTEXT ctx;
    AD_ZERO_BUF(&ctx, sizeof(ctx));
    ctx.ContextFlags = AD_CONTEXT_DEBUG_REGISTERS;
    ad_ntstatus_t st = AD_SYSCALL2(s_ssn, AD_CURRENT_THREAD, &ctx);
    if (!AD_NT_SUCCESS(st)) return 0;

    if (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3) return 1;
    // DR7 lower bits: L0/G0/L1/G1/L2/G2/L3/G3 enabled = HWBP active even
    // if DRn was hidden by ScyllaHide between get_ctx and read.
    if ((ctx.Dr7 & 0xFFu) != 0u) return 1;
    return 0;
}

// Sentinel C: ntdll trampoline byte audit. Checks the first instruction
// of two known anti-attach targets; if a 0xE9 (jmp) or 0xCC (int3) sits
// where the original prologue should be, a hook is installed.
ANTIDEBUG_INLINE b32 ad_sent_c_detect(void) {
    void* dbg_break = ad_resolve_api(AD_HASH_NTDLL, ad_hash_str("DbgBreakPoint"));
    void* dbg_ui    = ad_resolve_api(AD_HASH_NTDLL, ad_hash_str("DbgUiRemoteBreakin"));

    if (dbg_break) {
        u8 b0 = *(volatile const u8*)dbg_break;
        // Original DbgBreakPoint = `cc c3` (int3; ret). A hook overwrites
        // the int3 with `e9 ...` (5-byte jmp) or `48 b8 ...` (mov rax,imm64).
        // 0xCC is the legitimate baseline — anything else = hook.
        if (b0 != 0xCCu) return 1;
    }

    if (dbg_ui) {
        // DbgUiRemoteBreakin can be in one of two valid states:
        //
        // 1. Untouched Windows prologue — first byte is REX.W (0x48 / 0x4C)
        //    or REX (0x40). This is the state if `ad_anti_breakin_install`
        //    wasn't installed (or failed) on this run.
        //
        // 2. Patched by US (`ad_anti_breakin_install`) with a 17-byte stub:
        //
        //      offset 0..4 :  B9 01 00 00 00          mov ecx, 1
        //      offset 5..6 :  48 B8                   REX.W; mov rax, imm64
        //      offset 7..14:  <RtlExitUserProcess>    (process-specific)
        //      offset 15..16: FF E0                   jmp rax
        //
        //    Bytes 7..14 vary per process (ASLR), but 0,1..4,5,6,15,16 are
        //    deterministic. Verifying every deterministic byte catches an
        //    external debugger hook landing ON TOP of our stub (a hot-patch
        //    that replaces our `B9 01 00 00 00` prefix with a `E9 ...` jmp,
        //    for example).
        //
        // Anything else = a foreign hook → fire.
        volatile const u8* p = (volatile const u8*)dbg_ui;
        u8 b0 = p[0];
        if (b0 == 0x48u || b0 == 0x4Cu || b0 == 0x40u) {
            return 0;  // unpatched original — fine
        }
        if (b0 == 0xB9u
         && p[1]  == 0x01u && p[2]  == 0x00u
         && p[3]  == 0x00u && p[4]  == 0x00u
         && p[5]  == 0x48u && p[6]  == 0xB8u
         && p[15] == 0xFFu && p[16] == 0xE0u) {
            return 0;  // exactly our installed stub — fine
        }
        return 1;  // neither state — external hook detected
    }
    return 0;
}

// Sentinel D: KERNEL DEBUGGER watcher. Three independent signals — any one
// firing means kd is attached or freezing the system.
//
//   1. KUSER_SHARED_DATA.KdDebuggerEnabled (offset 0x2D4) — kernel sets this
//      to 1 when a kd is connected. Always 0 on a clean machine.
//
//   2. KUSER_SHARED_DATA.KdDebuggerNotPresent (offset 0x2D5) — inverse flag,
//      0 means kd is attached. Always 1 on a clean machine.
//
//   3. RDTSC vs InterruptTime drift — when kd halts the target machine at a
//      breakpoint, the entire OS freezes: InterruptTime stops advancing,
//      Sleep() returns instantly when the system thaws, but the CPU's
//      Time-Stamp Counter keeps going relative to wall time only when the
//      VM/host is also frozen. We sample both before a Sleep, then again
//      after; if InterruptTime barely moved while RDTSC advanced enormously
//      (or vice versa), we caught a freeze.
//
// On detection → poison only (kd reads the same memory as the program; the
// flag derivation is corrupted via the sentinel poison fold in main, not
// via direct termination).
ANTIDEBUG_INLINE b32 ad_sent_d_detect(void) {
    volatile const u8* kusd = (volatile const u8*)0x7FFE0000ULL;

    // Direct flags
    u8 kd_enabled     = *(volatile const u8*)(kusd + 0x02D4);
    u8 kd_not_present = *(volatile const u8*)(kusd + 0x02D5);
    if (kd_enabled != 0u)        return 1;
    if (kd_not_present == 0u)    return 1;

    // Deep-syscall checks — direct kernel queries that a kd cannot
    // transparently mask without rewriting the WhipSysCall stub itself.
    // SystemKernelDebuggerInformation, ProcessDebugObjectHandle, and
    // NtSystemDebugControl behaviour. See antidebug/checks/debug/kd_deep.h.
    if (ad_kd_deep_master() != 0u) return 1;

    // Time-skip detection: take an InterruptTime + RDTSC sample, sleep
    // briefly, sample again. On clean hardware InterruptTime advances by
    // approximately the requested sleep ms × 10000 (100ns ticks); RDTSC
    // advances by some multiple of that based on TSC freq. If kd halts
    // mid-sleep, InterruptTime barely moves while RDTSC continues
    // (or both freeze and resume — the ratio is wildly off).
#ifdef _MSC_VER
    u64 it_before = ad_sent_interrupt_time();
    u64 tsc_before = __rdtsc();
    ad_sent_delay_ms(80u);
    u64 it_after = ad_sent_interrupt_time();
    u64 tsc_after = __rdtsc();

    u64 it_delta_ms = (it_after - it_before) / 10000u;   // 100ns → ms
    u64 tsc_delta   = tsc_after - tsc_before;

    // Expected: it_delta_ms ≈ 80, tsc_delta ≈ 80 × tsc_freq_per_ms.
    // We don't know tsc_freq exactly, but we can reject extreme ratios.
    //
    //   - If it_delta_ms > 5000 (we slept WAY longer than asked) → freeze.
    //   - If tsc_delta is huge (> 10× expected) but it_delta_ms is normal
    //     → kd VM with paused TSC, less common but possible.
    if (it_delta_ms > 5000ULL) return 1;
    // Sanity: TSC must move at all during 80ms — if it's frozen we caught
    // the inverse case (TSC paused, InterruptTime advanced).
    if (tsc_delta < 1000ULL) return 1;
#endif
    return 0;
}

// ---------------------------------------------------------------------------
// Cross-watch: is a peer's heartbeat stalled?
// Returns 1 if the peer beat slot has not advanced in > AD_SENT_PEER_TIMEOUT_MS.
// `prev_counter_inout` holds the last counter we observed; updated in place.
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE b32 ad_sent_peer_stalled(volatile u64* peer_beat,
                                           u32* prev_counter_inout) {
    u64 enc = *peer_beat;
    if (enc == 0) {
        // Peer not yet started its first beat — give it grace
        return 0;
    }
    u32 cur_counter = ad_sent_unpack_counter(enc);
    if (cur_counter != *prev_counter_inout) {
        *prev_counter_inout = cur_counter;
        return 0;
    }
    // Counter stuck — check wall-clock age of the last beat
    u32 beat_wall = ad_sent_unpack_wall(enc);
    u32 now_wall  = (u32)(ad_sent_interrupt_time() / 10000u);
    u32 age = now_wall - beat_wall;
    return (b32)(age > AD_SENT_PEER_TIMEOUT_MS);
}

// ---------------------------------------------------------------------------
// Sentinel A — PEB watcher. Periodic, light. On detection: poison + kill.
// ---------------------------------------------------------------------------
static unsigned long __stdcall ad_sentinel_a_thread(void* arg) {
    AD_UNUSED(arg);
    ad_sent_a_alive = 1;
    // Publish a primer beat IMMEDIATELY so ad_sentinels_alive() doesn't race
    // the first delay window. Without this, an orchestrator that finishes
    // fast (clean run, no detection delays) reaches the alive() check before
    // any sentinel has slept once → all four beats are 0 → alive() returns
    // false → punish_poison fires → commitment_score corrupts → garbage flag
    // even on a clean run.
    ad_sent_a_beat = ad_sent_pack_beat(0);

    u64 prng = __rdtsc() ^ 0xA1B2C3D4E5F60718ULL;
    u32 counter = 1;
    u32 peer_b_prev = 0;
    u32 peer_c_prev = 0;
    u32 peer_d_prev = 0;

    for (;;) {
        if (ad_sent_exit_requested) return 0;
        u32 ms = ad_sent_rand_range(&prng,
                                    AD_SENT_A_PERIOD_MIN_MS,
                                    AD_SENT_A_PERIOD_MAX_MS);
        ad_sent_delay_ms(ms);
        if (ad_sent_exit_requested) return 0;

        ad_sent_a_beat = ad_sent_pack_beat(counter++);

        b32 hit = 0;
        __try { hit = ad_sent_a_detect(); } __except(1) { hit = 1; }

        // Cross-watch: any peer stalled → treat as detection.
        if (!hit && ad_sent_peer_stalled(&ad_sent_b_beat, &peer_b_prev)) hit = 1;
        if (!hit && ad_sent_peer_stalled(&ad_sent_c_beat, &peer_c_prev)) hit = 1;
        if (!hit && ad_sent_peer_stalled(&ad_sent_d_beat, &peer_d_prev)) hit = 1;

        if (hit) {
            ad_sent_punish_poison();
            // 50/50: kill now or just poison and let main read it later.
            if ((ad_sent_xs(&prng) & 1ULL) != 0ULL) {
                ad_sent_punish_kill(&prng);
            }
        }
    }
#pragma warning(suppress: 4702)
    return 0;
}

// ---------------------------------------------------------------------------
// Sentinel B — hardware executioner. Slightly slower cycle. Hardware BPs
// always trigger kill (no debugger sets DRn legitimately on production code).
// ---------------------------------------------------------------------------
static unsigned long __stdcall ad_sentinel_b_thread(void* arg) {
    AD_UNUSED(arg);
    ad_sent_b_alive = 1;
    ad_sent_b_beat  = ad_sent_pack_beat(0);  // primer beat — see sentinel A

    u64 prng = __rdtsc() ^ 0x7B5C2A1E8F94D603ULL;
    u32 counter = 1;
    u32 peer_a_prev = 0;
    u32 peer_c_prev = 0;
    u32 peer_d_prev = 0;

    for (;;) {
        if (ad_sent_exit_requested) return 0;
        u32 ms = ad_sent_rand_range(&prng,
                                    AD_SENT_B_PERIOD_MIN_MS,
                                    AD_SENT_B_PERIOD_MAX_MS);
        ad_sent_delay_ms(ms);
        if (ad_sent_exit_requested) return 0;

        ad_sent_b_beat = ad_sent_pack_beat(counter++);

        b32 hwbp = 0;
        __try { hwbp = ad_sent_b_detect(); } __except(1) { hwbp = 1; }

        b32 peer_dead = 0;
        if (ad_sent_peer_stalled(&ad_sent_a_beat, &peer_a_prev)) peer_dead = 1;
        if (ad_sent_peer_stalled(&ad_sent_c_beat, &peer_c_prev)) peer_dead = 1;
        if (ad_sent_peer_stalled(&ad_sent_d_beat, &peer_d_prev)) peer_dead = 1;

        if (hwbp) {
            // Hardware BPs are an unambiguous signal — go straight to kill.
            ad_sent_punish_poison();
            ad_sent_punish_kill(&prng);
        } else if (peer_dead) {
            // A suspended peer means an attacker is pausing threads
            // selectively — same severity.
            ad_sent_punish_poison();
            ad_sent_punish_kill(&prng);
        }
    }
#pragma warning(suppress: 4702)
    return 0;
}

// ---------------------------------------------------------------------------
// Sentinel C — hook auditor. Slowest cycle (hooks are static after install).
// On hook detection: poison only — termination would expose the hook check.
// ---------------------------------------------------------------------------
static unsigned long __stdcall ad_sentinel_c_thread(void* arg) {
    AD_UNUSED(arg);
    ad_sent_c_alive = 1;
    ad_sent_c_beat  = ad_sent_pack_beat(0);  // primer beat — see sentinel A

    u64 prng = __rdtsc() ^ 0x3F8E2D5A6C71B940ULL;
    u32 counter = 1;
    u32 peer_a_prev = 0;
    u32 peer_b_prev = 0;
    u32 peer_d_prev = 0;

    for (;;) {
        if (ad_sent_exit_requested) return 0;
        u32 ms = ad_sent_rand_range(&prng,
                                    AD_SENT_C_PERIOD_MIN_MS,
                                    AD_SENT_C_PERIOD_MAX_MS);
        ad_sent_delay_ms(ms);
        if (ad_sent_exit_requested) return 0;

        ad_sent_c_beat = ad_sent_pack_beat(counter++);

        b32 hooked = 0;
        __try { hooked = ad_sent_c_detect(); } __except(1) { hooked = 0; }

        b32 peer_dead = 0;
        if (ad_sent_peer_stalled(&ad_sent_a_beat, &peer_a_prev)) peer_dead = 1;
        if (ad_sent_peer_stalled(&ad_sent_b_beat, &peer_b_prev)) peer_dead = 1;
        if (ad_sent_peer_stalled(&ad_sent_d_beat, &peer_d_prev)) peer_dead = 1;

        if (hooked) {
            // Stay quiet — corrupt the flag and let the user think the
            // build is broken. Don't tip off that we noticed the hook.
            ad_sent_punish_poison();
        }
        if (peer_dead) {
            ad_sent_punish_poison();
            ad_sent_punish_kill(&prng);
        }
    }
#pragma warning(suppress: 4702)
    return 0;
}

// ---------------------------------------------------------------------------
// Sentinel D — kernel debugger watcher. Polls KUSER_SHARED_DATA flags +
// detects host-system freezes via RDTSC/InterruptTime drift. On detection:
// poison only (kd has full memory access — termination is futile, but a
// corrupted flag still defeats the goal). Slowest period because the
// detection itself sleeps 80 ms per call.
// ---------------------------------------------------------------------------
static unsigned long __stdcall ad_sentinel_d_thread(void* arg) {
    AD_UNUSED(arg);
    ad_sent_d_alive = 1;
    ad_sent_d_beat  = ad_sent_pack_beat(0);  // primer beat — see sentinel A

    u64 prng = __rdtsc() ^ 0xC4B8E27A91D3F605ULL;
    u32 counter = 1;
    u32 peer_a_prev = 0;
    u32 peer_b_prev = 0;
    u32 peer_c_prev = 0;

    for (;;) {
        if (ad_sent_exit_requested) return 0;
        u32 ms = ad_sent_rand_range(&prng,
                                    AD_SENT_D_PERIOD_MIN_MS,
                                    AD_SENT_D_PERIOD_MAX_MS);
        ad_sent_delay_ms(ms);
        if (ad_sent_exit_requested) return 0;

        ad_sent_d_beat = ad_sent_pack_beat(counter++);

        b32 kd = 0;
        __try { kd = ad_sent_d_detect(); } __except(1) { kd = 1; }

        b32 peer_dead = 0;
        if (ad_sent_peer_stalled(&ad_sent_a_beat, &peer_a_prev)) peer_dead = 1;
        if (ad_sent_peer_stalled(&ad_sent_b_beat, &peer_b_prev)) peer_dead = 1;
        if (ad_sent_peer_stalled(&ad_sent_c_beat, &peer_c_prev)) peer_dead = 1;

        if (kd) {
            // Silent — kd reads everything anyway. Just corrupt the
            // outcome by poisoning. Don't try to kill (kd would catch it).
            ad_sent_punish_poison();
        }
        if (peer_dead) {
            ad_sent_punish_poison();
            ad_sent_punish_kill(&prng);
        }
    }
#pragma warning(suppress: 4702)
    return 0;
}

// ---------------------------------------------------------------------------
// API exposed to main
// ---------------------------------------------------------------------------

// Resolve CreateThread the same way latent_tamper does — kernelbase first,
// kernel32 fallback.
typedef void* (__stdcall *ad_sent_create_thread_t)(
    void*  lpThreadAttributes,
    u64    dwStackSize,
    void*  lpStartAddress,
    void*  lpParameter,
    u32    dwCreationFlags,
    u32*   lpThreadId
);

ANTIDEBUG_INLINE void* ad_sent_resolve_create_thread(void) {
    u32 h = ad_hash_str("CreateThread");
    void* fn = ad_resolve_api(AD_HASH_KERNELBASE, h);
    if (!fn) fn = ad_resolve_api(AD_HASH_KERNEL32, h);
    return fn;
}

// Idempotent. Spawns the three sentinel threads. Returns 1 on success.
ANTIDEBUG_INLINE b32 ad_sentinels_init(void) {
    if (ad_sent_started) return 1;

    // Seed each slot so the fold reads back exactly 0 in the clean state.
    // Static init leaves encX = 0, which decodes to xor_key32_v(i); the
    // fold then layers the per-slot constants 0/A5A5/5A5A/CAFEBABE on top
    // and folds the four results — for the result to vanish, every
    // post-constant value must be identical. We pick "all zeros after
    // the constant XOR" as the canonical clean state. The keys depend on
    // PEB pointer so this MUST run at process start, not statically.
    ad_sent_poison_enc1 = 0u          ^ ad_sent_xor_key32_v(1);
    ad_sent_poison_enc2 = 0xA5A5A5A5u ^ ad_sent_xor_key32_v(2);
    ad_sent_poison_enc3 = 0x5A5A5A5Au ^ ad_sent_xor_key32_v(3);
    ad_sent_poison_enc4 = 0xCAFEBABEu ^ ad_sent_xor_key32_v(4);

    ad_sent_create_thread_t pCreate = (ad_sent_create_thread_t)
        ad_sent_resolve_create_thread();
    if (!pCreate) return 0;

    u32 tid = 0;
    void* h_a = pCreate((void*)0, 0ULL, (void*)&ad_sentinel_a_thread, (void*)0, 0u, &tid);
    void* h_b = pCreate((void*)0, 0ULL, (void*)&ad_sentinel_b_thread, (void*)0, 0u, &tid);
    void* h_c = pCreate((void*)0, 0ULL, (void*)&ad_sentinel_c_thread, (void*)0, 0u, &tid);
    void* h_d = pCreate((void*)0, 0ULL, (void*)&ad_sentinel_d_thread, (void*)0, 0u, &tid);

    if (!h_a || !h_b || !h_c || !h_d) return 0;

    // Wait for all four sentinels to publish their primer beat. Without
    // this barrier the orchestrator can race ahead, reach the
    // ad_sentinels_alive() gate before the kernel has scheduled the
    // threads, observe ad_sent_X_alive == 0 / ad_sent_X_beat == 0, and
    // poison the commitment_score even though no detection occurred.
    // 250 ms cap is plenty even on heavily loaded boxes; if a thread
    // genuinely cannot start in that window, alive() will catch it
    // legitimately later.
    {
        u32 spins = 0;
        while (spins++ < 50u) {
            if (ad_sent_a_alive && ad_sent_b_alive
             && ad_sent_c_alive && ad_sent_d_alive
             && ad_sent_a_beat  && ad_sent_b_beat
             && ad_sent_c_beat  && ad_sent_d_beat) break;
            ad_sent_delay_ms(5u);
        }
    }

    ad_sent_started = 1;
    return 1;
}

// Fold the four-slot sentinel poison into commitment_score. Clean: every
// slot decodes to 0 → returns x unchanged. Detected: any non-zero slot
// flips bits in x → wrong key downstream → garbage flag.
//
// XOR is expressed via Mixed Boolean-Arithmetic identities so a kd that
// tries to NOP-out the function body must produce code that returns x
// VERBATIM — patching to "mov eax, ecx; ret" is straightforward, but the
// MBA expansion makes the real function body chunky enough that a casual
// "stub it out with a few nops" doesn't cleanly compile away. The four
// slots also force the patcher to find ALL FOUR globals to zero them.
//
// MBA identities used (each provably equivalent to XOR):
//   a ^ b == (a | b) - (a & b)       [form A]
//   a ^ b == (a + b) - 2 * (a & b)   [form B]
//   a ^ b == (a & ~b) | (~a & b)     [form C]
ANTIDEBUG_INLINE u32 ad_sentinels_poison_fold(u32 x) {
    u32 p1 = ad_sent_poison_enc1 ^ ad_sent_xor_key32_v(1);
    u32 p2 = ad_sent_poison_enc2 ^ ad_sent_xor_key32_v(2);
    u32 p3 = ad_sent_poison_enc3 ^ ad_sent_xor_key32_v(3);
    u32 p4 = ad_sent_poison_enc4 ^ ad_sent_xor_key32_v(4);

    // Re-mix the per-slot magics applied in punish_poison() so any single
    // surviving slot still contributes a non-zero value after combining.
    p2 ^= 0xA5A5A5A5u;
    p3 ^= 0x5A5A5A5Au;
    p4 ^= 0xCAFEBABEu;

    // Combine via three different MBA forms — each chosen to defeat the
    // most obvious peephole optimizations.
    u32 m12 = (p1 | p2) - (p1 & p2);                    // form A
    u32 m34 = (p3 + p4) - (((u32)(p3 & p4)) << 1);      // form B
    u32 c   = (m12 & ~m34) | (~m12 & m34);              // form C
    return (x | c) - (x & c);                           // form A
}

// Read whether all sentinels are alive AND have produced at least one beat.
// Side-effect: if any sentinel never started, poison the global so a
// suspended-at-init attempt still corrupts the flag.
ANTIDEBUG_INLINE b32 ad_sentinels_alive(void) {
    b32 ok = (b32)(ad_sent_a_alive && ad_sent_b_alive && ad_sent_c_alive
                && ad_sent_d_alive
                && ad_sent_a_beat  && ad_sent_b_beat  && ad_sent_c_beat
                && ad_sent_d_beat);
    if (!ok) {
        ad_sent_punish_poison();
    }
    return ok;
}

// Signal all sentinels to exit on their next iteration. Must be called by
// the orchestrator immediately before NtTerminateProcess so a sentinel
// waking up mid-shutdown does not race the kernel terminate by issuing its
// own NtTerminateProcess(0xC000026E) — which would surface as exit code
// 139 and look like a crash even on a clean run.
ANTIDEBUG_INLINE void ad_sentinels_request_exit(void) {
    ad_sent_exit_requested = 1u;
}

#else  // !_MSC_VER — non-MSVC fallback (no-op stubs)

ANTIDEBUG_INLINE b32 ad_sentinels_init(void)         { return 0; }
ANTIDEBUG_INLINE u32 ad_sentinels_poison_fold(u32 x) { return x; }
ANTIDEBUG_INLINE b32 ad_sentinels_alive(void)        { return 1; }
ANTIDEBUG_INLINE void ad_sentinels_request_exit(void) { }

#endif // _MSC_VER

#endif // ANTIDEBUG_SENTINELS_H
