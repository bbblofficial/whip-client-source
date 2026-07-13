// ===== file: antidebug/core/latent_tamper.h =====
//
// Latent Tamper — silent score capture + delayed unrelated crash.
//
// Purpose
// -------
// Existing tamper_trip.h crashes IMMEDIATELY when a watched region is
// patched. That is great against simple in-place NOPs, but a careful
// reverser running our binary in a debugger will see the access-violation,
// rewind, and trace it back to the check that produced the wild pointer.
//
// Latent Tamper takes the opposite stance:
//
//   1. We never react during the check phase. The score is captured into
//      an encoded global at the moment it is computed, and the visible
//      flow continues exactly as a clean run would: the flag prints, the
//      banner says "Environment CLEAN", everything looks fine.
//
//   2. A sentinel thread spawned at init sits in a Sleep loop. After a
//      randomised delay (default 8-22 seconds) it checks the encoded
//      armed flag. If the flag is set, it dereferences a deliberately
//      corrupted function pointer, raising an EXCEPTION_ACCESS_VIOLATION
//      from inside its OWN thread, far away in time and stack from any
//      anti-debug check.
//
// What the reverser sees
// ----------------------
//   * Patches the check, runs the binary, sees the real flag, celebrates.
//   * 12 seconds later the process pops with:
//
//       Unhandled exception at 0x000000005E04AD9B
//       0xC0000005: Access violation executing location 0x000000005E04AD9B
//
//     in a thread they never spawned, with no stack frame inside the
//     binary, no symbol, and no path back to the check they patched.
//
// They will spend a long time chasing a crash bug that does not exist.
//
// API
// ---
//   ad_latent_init()         — spawn the sentinel thread once at startup
//   ad_latent_arm_if(cond)   — atomically arm the trip if cond is true
//   ad_latent_is_armed()     — read-back, mostly for diagnostics
//
// All state lives in a single u64 obfuscated by xor with a runtime-derived
// key. Static inspection sees only an opaque .bss qword.
//
#ifndef ANTIDEBUG_LATENT_TAMPER_H
#define ANTIDEBUG_LATENT_TAMPER_H

#include "types.h"
#include "macros.h"
#include "api_hash.h"
#include "syscall_bridge.h"
#include "string_encrypt.h"
#include "strenc_extra.h"

#ifndef AD_LATENT_DELAY_MIN_MS
#define AD_LATENT_DELAY_MIN_MS  2000u
#endif
#ifndef AD_LATENT_DELAY_MAX_MS
#define AD_LATENT_DELAY_MAX_MS  8000u
#endif

// Encoded armed flag. The actual armed value is AD_LATENT_ARMED_MAGIC,
// stored XOR'd with ad_latent_xor_key(). The default zero state decodes
// to "not armed".
#define AD_LATENT_ARMED_MAGIC   0x5A4D45525A41u  // ASCII "ZAREMZ"

// Storage definition guard so multiple includes do not multiply symbols.
#ifndef AD_LATENT_STORAGE_DEFINED
#define AD_LATENT_STORAGE_DEFINED
volatile u64 ad_latent_state = 0;
volatile u32 ad_latent_thread_started = 0;
volatile u32 ad_latent_thread_alive   = 0;  // set inside the sentinel body
volatile u32 ad_latent_thread_woke    = 0;  // XOR-encoded: (count ^ woke_key)
volatile u32 ad_latent_woke_key       = 0;  // RDTSC-seeded secret, set by sentinel at start
#endif

// XOR key derived from the PEB pointer (read via the GS segment).
// MUST be per-process not per-thread: encode happens on main, decode on
// the sentinel thread, so a TEB-based key would diverge between threads.
// PEB is shared across all threads in the same process and is a stable
// non-zero quantity, unknowable from a static dump.
ANTIDEBUG_INLINE u64 ad_latent_xor_key(void) {
#ifdef _MSC_VER
    u64 peb = (u64)__readgsqword(0x60);
    return (peb ^ 0xA5A5A5A5A5A5A5A5ULL);
#else
    return 0xA5A5A5A5A5A5A5A5ULL;
#endif
}

// Tiny xorshift PRNG seeded from RDTSC for the sleep duration. Doesn't
// need to be cryptographically anything — we just want some variance so
// the reverser can't time the crash from a previous run.
ANTIDEBUG_INLINE u32 ad_latent_rand_delay(void) {
#ifdef _MSC_VER
    u64 s = __rdtsc();
    s ^= s << 13; s ^= s >> 7; s ^= s << 17;
    u32 span = (AD_LATENT_DELAY_MAX_MS - AD_LATENT_DELAY_MIN_MS);
    return AD_LATENT_DELAY_MIN_MS + (u32)(s % (u64)span);
#else
    return AD_LATENT_DELAY_MIN_MS;
#endif
}

// Hashes for kernel32 + ntdll APIs we need, built char-by-char so the
// names never appear in .rdata as contiguous blobs.
ANTIDEBUG_INLINE u32 ad_latent_hash_create_thread(void) {
    char b[13];
    b[ 0]='C'; b[ 1]='r'; b[ 2]='e'; b[ 3]='a'; b[ 4]='t';
    b[ 5]='e'; b[ 6]='T'; b[ 7]='h'; b[ 8]='r'; b[ 9]='e';
    b[10]='a'; b[11]='d'; b[12]=0;
    return ad_hash_str(b);
}

// Read the kernel-shared interrupt time directly from KUSER_SHARED_DATA
// at the fixed user-mode address 0x7FFE0000. The InterruptTime field is
// a LARGE_INTEGER at +0x8 measured in 100ns ticks. This is monotonic
// wall time that the kernel updates regardless of who's holding the
// thread, so it's the perfect baseline for "did a debugger pause me?"
// detection: a SuspendThread pause does NOT stop interrupt time, but it
// DOES stop our NtDelayExecution from progressing — so the elapsed
// interrupt time after a paused sleep will far exceed the requested.
//
// 0x7FFE0000 is mapped read-only into every Win32 process. Reading it
// is a single MOV — no API call, no syscall, nothing to hook.
#define AD_KUSER_SHARED ((volatile const u8*)0x7FFE0000)

ANTIDEBUG_INLINE u64 ad_latent_interrupt_time(void) {
    // KUSER_SHARED_DATA.InterruptTime is updated atomically as a 96-bit
    // structure: { LowPart, High1Time, High2Time }. We read in the
    // LowPart/High1 order and retry if High1 changes mid-read.
    for (;;) {
        u32 high1 = *(volatile const u32*)(AD_KUSER_SHARED + 0x08 + 4);
        u32 low   = *(volatile const u32*)(AD_KUSER_SHARED + 0x08 + 0);
        u32 high2 = *(volatile const u32*)(AD_KUSER_SHARED + 0x08 + 4);
        if (high1 == high2) return ((u64)high1 << 32) | (u64)low;
    }
}

typedef void* (__stdcall *ad_fn_create_thread_t)(
    void*  lpThreadAttributes,
    u64    dwStackSize,
    void*  lpStartAddress,
    void*  lpParameter,
    u32    dwCreationFlags,
    u32*   lpThreadId
);

// CreateThread is a forwarder in kernel32.dll on Win10+ — it resolves
// to the real implementation in kernelbase.dll. ad_resolve_api rejects
// forwarder RVAs, so we have to ask kernelbase directly first and only
// fall back to kernel32 on older systems.
ANTIDEBUG_INLINE void* ad_latent_resolve(u32 func_hash) {
    void* fn = ad_resolve_api(AD_HASH_KERNELBASE, func_hash);
    if (!fn) fn = ad_resolve_api(AD_HASH_KERNEL32, func_hash);
    return fn;
}

// "NtDelayExecution" (16 chars) string-encrypt — local definition,
// guarded against the canonical macros in core/string_encrypt.h.
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

// Issue NtDelayExecution as a direct syscall via WhipSysCall. We do not
// route through ntdll!NtDelayExecution because that path can be hooked,
// inlined-paused, or replaced. Direct syscall = the kernel sees us no
// matter what user-mode shenanigans are present.
//
// DelayInterval is in 100ns units, NEGATIVE for relative.
ANTIDEBUG_INLINE void ad_latent_delay_ms(u32 ms) {
    static u16 s_ssn = AD_SSN_UNRESOLVED;
    AD_RESOLVE_SSN_ENC(s_ssn, NtDelayExecution, 17);
    if (s_ssn == AD_SSN_FAILED) return;

    s64 interval = -((s64)ms * 10000LL);  // ms -> 100ns, negative = relative
    (void)AD_SYSCALL2(s_ssn, (u64)0, &interval);
}

// Sentinel thread body. Sleeps a random duration, then checks the armed
// flag. If armed, dereferences a wild function pointer to crash hard.
//
// Note: declared static so it never gets a name in the export table or
// the import table. Address is taken locally inside ad_latent_init.
#ifdef _MSC_VER
#ifndef AD_LATENT_RA_INTRINSIC_DECLARED
#define AD_LATENT_RA_INTRINSIC_DECLARED
void* _AddressOfReturnAddress(void);
#pragma intrinsic(_AddressOfReturnAddress)
#endif
#endif

#ifndef AD_STRENC_NtTerminateThread
#define AD_STRENC_NtTerminateThread(buf)                                     \
    do {                                                                     \
        const u8 _k = AD_STR_KEY(0x6E);                                     \
        char buf##_e[18];                                                    \
        AD_ENC(buf##_e,  0, 'N', _k); AD_ENC(buf##_e,  1, 't', _k);       \
        AD_ENC(buf##_e,  2, 'T', _k); AD_ENC(buf##_e,  3, 'e', _k);       \
        AD_ENC(buf##_e,  4, 'r', _k); AD_ENC(buf##_e,  5, 'm', _k);       \
        AD_ENC(buf##_e,  6, 'i', _k); AD_ENC(buf##_e,  7, 'n', _k);       \
        AD_ENC(buf##_e,  8, 'a', _k); AD_ENC(buf##_e,  9, 't', _k);       \
        AD_ENC(buf##_e, 10, 'e', _k); AD_ENC(buf##_e, 11, 'T', _k);       \
        AD_ENC(buf##_e, 12, 'h', _k); AD_ENC(buf##_e, 13, 'r', _k);       \
        AD_ENC(buf##_e, 14, 'e', _k); AD_ENC(buf##_e, 15, 'a', _k);       \
        AD_ENC(buf##_e, 16, 'd', _k);                                       \
        AD_DECODE_BUF(buf##_e, 17, _k);                                     \
        for (unsigned _ci = 0; _ci < 18; _ci++) (buf)[_ci] = buf##_e[_ci];  \
    } while (0)
#endif

static u32 __stdcall ad_latent_sentinel_thread(void* arg) {
    AD_UNUSED(arg);

    // Forge saved RA → fake ntdll parent so any stack walker that reaches
    // this frame sees `ntdll!RtlUserThreadStart+0x21` instead of the real
    // `kernel32!BaseThreadInitThunk`. The thread either crashes via the
    // wild-pointer arm OR exits via NtTerminateThread (see end of body) —
    // ret is never executed, so the corrupted RA is harmless.
#ifdef _MSC_VER
    {
        void* fake = ad_resolve_api(AD_HASH_NTDLL,
                                     ad_hash_str("RtlUserThreadStart"));
        if (fake) {
            void** ra_slot = (void**)_AddressOfReturnAddress();
            *ra_slot = (void*)((u8*)fake + 0x21);
        }
    }
#endif

    ad_latent_thread_alive = 1;

    // Primer beat — publish a non-zero (woke ^ woke_key) IMMEDIATELY so
    // ad_sentinels_alive() / s1_ok gate doesn't race the first 250ms slice.
    // Without this, main reaches the flag-decrypt gate before the sentinel
    // returns from its first NtDelayExecution, sees (0^0)=0, decides the
    // sentinel was killed pre-start, and zeroes encrypted_flag → flag corrupt
    // on every clean run. Same fix pattern as commit 6be6f18 for ad_sent_*.
#ifdef _MSC_VER
    {
        u32 _wk = (u32)__rdtsc();
        _wk ^= _wk << 13; _wk ^= _wk >> 7; _wk ^= _wk << 17;
        ad_latent_woke_key    = _wk | 1u;
        ad_latent_thread_woke = 1u ^ ad_latent_woke_key;  // primer beat
    }
#endif

    u32 delay_ms = ad_latent_rand_delay();
    u64 t_start  = ad_latent_interrupt_time();  // monotonic kernel ticks

    // Sleep via direct syscall, in 250ms slices so we re-check the
    // armed state regularly. We deliberately do NOT use Sleep() — that
    // path is intercept-able by ntdll hooks. NtDelayExecution issued
    // via the WhipSysCall direct stub bypasses any user-mode patch.
    //
    // FAST PATH: after each slice we check the interrupt time. If the
    // real wall-clock elapsed far exceeds the requested slice, we were
    // suspended by NtSuspendThread. In that case we arm AND crash
    // immediately — no remaining delay for the reverser to exploit.
    volatile b32 fast_crash = 0;
    volatile b32 do_crash   = 0;  // local crash decision — not bypassable via WPM on the global
    u64 last_seen_state = ad_latent_state;  // track for per-slice tamper detection
    u32 elapsed_req = 0u;
    u32 _woke_count = 0u;
    while (elapsed_req < delay_ms) {
        u64 t_slice_start = ad_latent_interrupt_time();
        ad_latent_delay_ms(250u);
        elapsed_req += 250u;
        // woke_key set up-front by the primer beat above; loop just bumps
        // the counter using the same key so main never observes an
        // inconsistent (woke, key) snapshot.
        _woke_count++;
        ad_latent_thread_woke = (_woke_count + 1u) ^ ad_latent_woke_key;

        // Per-slice suspension check: 250ms requested, if wall-clock
        // shows >2s we were frozen. Crash NOW — don't give them time.
        u64 t_slice_end   = ad_latent_interrupt_time();
        u64 slice_real_ms = (t_slice_end - t_slice_start) / 10000u;
        // Threshold raised from 2 s → 5 s. The 2 s ceiling on a 250 ms slice
        // (8× requested) caught genuine SuspendThread but also clipped
        // legitimate scheduling stalls during the early-init thread storm
        // (sentinels A-D + latent2 + watchdog + noise_swarm all spinning up
        // simultaneously) → false-positive crash with no Result printed.
        // 5 s (20×) keeps real-debugger-pause detection while tolerating
        // contended boot.
        if (slice_real_ms > 5000u) {
            u64 v = AD_LATENT_ARMED_MAGIC ^ ad_latent_xor_key();
            ad_latent_state = v;
            fast_crash = 1;
            do_crash   = 1;
            break;  // skip remaining delay — crash below
        }

        // Per-slice external arm + tamper detection.
        // Window: ≤250ms instead of the full 2–8s sleep.
        {
            u64 _cur = ad_latent_state;
            // External arm fired this slice
            if (last_seen_state == 0u && _cur != 0u) {
                u64 _dec = _cur ^ ad_latent_xor_key();
                if (_dec == AD_LATENT_ARMED_MAGIC) do_crash = 1;
            }
            // Armed state zeroed this slice → WPM tampering
            if (last_seen_state != 0u && _cur == 0u) do_crash = 1;
            last_seen_state = _cur;
        }
        if (do_crash) break;
    }

    // Wall-time post-check (only when fast path didn't fire): if the
    // total elapsed interrupt time far exceeds the requested delay,
    // the thread was suspended at some point.
    if (!fast_crash) {
        u64 t_end       = ad_latent_interrupt_time();
        u64 ticks_real  = t_end - t_start;             // 100ns units
        u64 ms_real     = ticks_real / 10000u;         // ms
        if (ms_real > (u64)delay_ms * 2u + 500u) {
            // Suspended by SuspendThread, slept-and-stepped by a debugger,
            // or hard-stopped + resumed. Either way: hostile environment.
            u64 v = AD_LATENT_ARMED_MAGIC ^ ad_latent_xor_key();
            ad_latent_state = v;
            do_crash = 1;
        }
    }

    // Suspension-detected arm: do_crash is on our stack — not bypassable via
    // WPM on any global. If the sentinel itself didn't detect suspension, fall
    // through to check the global for an external arm from the main thread
    // (ad_latent_arm_if). That read still has a larger bypass window (the
    // full sentinel delay) but is the intended signal path for main-thread arms.
    if (!do_crash) {
        u64 _cur = ad_latent_state;
        // If the global was armed but is now zero → zeroed by WPM between slices
        if (last_seen_state != 0u && _cur == 0u) {
            do_crash = 1;
        } else {
            u64 dec = _cur ^ ad_latent_xor_key();
            if (dec == AD_LATENT_ARMED_MAGIC) do_crash = 1;
        }
    }
    if (!do_crash) {
        // Not armed → exit via NtTerminateThread direct syscall instead of
        // ret (which would jump to our forged saved-RA = fake ntdll address).
#ifdef _MSC_VER
        static u16 s_term = AD_SSN_UNRESOLVED;
        AD_RESOLVE_SSN_ENC(s_term, NtTerminateThread, 18);
        if (s_term != AD_SSN_FAILED) {
            (void)AD_SYSCALL2(s_term, AD_CURRENT_THREAD, (u64)0);
        }
#endif
        return 0;
    }

    // Armed. Build a wild function pointer. Mix magic with the per-process
    // PEB key so the resulting RIP is unique per run and gives no grep target.
    u64 wild = 0x5E04AD9B00000000ULL ^ ((AD_LATENT_ARMED_MAGIC ^ ad_latent_xor_key()) & 0xFFFFFFFFu);
    typedef void (*fn_void_t)(void);
    fn_void_t f = (fn_void_t)(uintptr_t)wild;
    f();   // EXCEPTION_ACCESS_VIOLATION here — far from any check.

    return 0;
}

// One-time init. Spawns the sentinel thread. Idempotent.
ANTIDEBUG_INLINE b32 ad_latent_init(void) {
#ifdef _MSC_VER
    if (ad_latent_thread_started) return 1;

    ad_fn_create_thread_t pCreate = (ad_fn_create_thread_t)
        ad_latent_resolve(ad_latent_hash_create_thread());
    if (!pCreate) return 0;

    u32 tid = 0;
    void* h = pCreate(0, 0, (void*)&ad_latent_sentinel_thread, 0, 0, &tid);
    if (!h) return 0;

    ad_latent_thread_started = 1;

    // Wait barrier — block until the sentinel reaches its primer beat.
    // Without this, main can race past the s1_ok gate before the kernel
    // has scheduled the thread, observe alive==0 / woke^key==0, and zero
    // the encrypted_flag → garbage on every clean run. Mirrors the same
    // barrier in ad_sentinels_init().
    {
        u32 spins = 0;
        while (spins++ < 50u) {
            if (ad_latent_thread_alive
             && (ad_latent_thread_woke ^ ad_latent_woke_key) > 0u) break;
            ad_latent_delay_ms(5u);
        }
    }
    return 1;
#else
    return 0;
#endif
}

// Atomically arm the trip if `cond` is non-zero. Once armed, cannot be
// unset by anything in this header — the disarm requires a private key
// that we never expose to user code paths a reverser would patch.
ANTIDEBUG_INLINE void ad_latent_arm_if(b32 cond) {
    if (!cond) return;
    u64 v = AD_LATENT_ARMED_MAGIC ^ ad_latent_xor_key();
    ad_latent_state = v;
}

// Diagnostic only — true if the sentinel will crash on next wake.
ANTIDEBUG_INLINE b32 ad_latent_is_armed(void) {
    u64 enc = ad_latent_state;
    u64 dec = enc ^ ad_latent_xor_key();
    return (b32)(dec == AD_LATENT_ARMED_MAGIC);
}

#endif // ANTIDEBUG_LATENT_TAMPER_H
