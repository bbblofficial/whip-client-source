// ===== file: antidebug/core/whip_hostile.h =====
//
// Whip Hostile — active countermeasures that make reverse engineering
// the framework progressively unbearable once tamper is confirmed.
//
// TRIGGER POLICY
// ──────────────
// All hostile behaviours are gated on `ad_gm_is_tampered(matrix)`.
// CLEAN state: zero cost, zero user-visible effect.
// TAMPERED state: progressively harder to work with.
//
// COUNTERMEASURES (all gated, composable, user-configurable)
// ──────────────────────────────────────────────────────────
//
//  A. SLOW-DOWN CASCADE (`AD_WH_ENABLE_SLOWDOWN`)
//     Every subsequent check call sleeps a random 100-3000 ms. A user
//     who patches 5 checks then runs them in a loop waits ~50 s per
//     iteration. Single-stepping becomes unbearable.
//
//  B. EXCEPTION SPAM (`AD_WH_ENABLE_EXCSPAM` + call `ad_wh_tick`)
//     Each call raises a benign custom exception (user-mode code
//     0xE0DEADC0) that our VEH swallows. x64dbg default config breaks
//     on it → user sees a popup every tick. Disabling exception break
//     in x64dbg takes per-code configuration.
//
//  C. FAKE-FINDING POISONING (`AD_WH_ENABLE_FAKE_ODS`)
//     OutputDebugStringA with plausible-looking but bogus content:
//       "[CRYPTO] decrypted key @ 0x7ff6d1a4fe20"
//       "[FLAG] flag{debug_mode_abcdef} found at heap 0x01f2a040"
//       "[BYPASS] score dispatch hook installed"
//     Addresses random, not real. Reverse engineer spends hours
//     chasing false leads.
//
//  D. MEMORY DECOY (`AD_WH_ENABLE_MEM_DECOY`)
//     Writes pattern-scanner-bait strings to random heap locations:
//       "flag{fake_flag_1234}", "password=adminadmin", "key:8392..."
//     Strings tools / pattern scanners hit thousands of decoys; real
//     secrets drown in noise.
//
//  E. DELAYED SUICIDE (`AD_WH_ENABLE_SUICIDE`)
//     Schedule process exit at tick + random(10-30 min) post-tamper.
//     Attacker iterates, thinks they've bypassed us, runs for 20 min,
//     process dies with no obvious cause. Re-patch, rerun, same.
//
// CALL SITE
// ─────────
//   // Once at init, after Guardian Matrix init:
//   ad_wh_init(&hostile, &matrix);
//   // Every check call site, before returning:
//   ad_wh_tick(&hostile);
//
#ifndef ANTIDEBUG_WHIP_HOSTILE_H
#define ANTIDEBUG_WHIP_HOSTILE_H

#include "guardian_matrix.h"

#ifdef _MSC_VER

// Feature toggles — compile-time defines.
#ifndef AD_WH_ENABLE_SLOWDOWN
#define AD_WH_ENABLE_SLOWDOWN     1
#endif
#ifndef AD_WH_ENABLE_EXCSPAM
#define AD_WH_ENABLE_EXCSPAM      1
#endif
#ifndef AD_WH_ENABLE_FAKE_ODS
#define AD_WH_ENABLE_FAKE_ODS     1
#endif
#ifndef AD_WH_ENABLE_MEM_DECOY
#define AD_WH_ENABLE_MEM_DECOY    1
#endif
#ifndef AD_WH_ENABLE_SUICIDE
#define AD_WH_ENABLE_SUICIDE      1
#endif

#ifndef AD_WH_SLOWDOWN_MIN_MS
#define AD_WH_SLOWDOWN_MIN_MS     100u
#endif
#ifndef AD_WH_SLOWDOWN_MAX_MS
#define AD_WH_SLOWDOWN_MAX_MS     3000u
#endif
#ifndef AD_WH_EXCSPAM_CODE
#define AD_WH_EXCSPAM_CODE        0xE0DEADC0u
#endif
#ifndef AD_WH_SUICIDE_MIN_MS
#define AD_WH_SUICIDE_MIN_MS      600000u   // 10 min
#endif
#ifndef AD_WH_SUICIDE_MAX_MS
#define AD_WH_SUICIDE_MAX_MS      1800000u  // 30 min
#endif

__declspec(dllimport) void  __stdcall Sleep(unsigned long ms);
__declspec(dllimport) void  __stdcall OutputDebugStringA(const char*);
__declspec(dllimport) void  __stdcall ExitProcess(unsigned long);
__declspec(dllimport) void  __stdcall RaiseException(unsigned long code,
                                                      unsigned long flags,
                                                      unsigned long n_args,
                                                      const u64* args);
__declspec(dllimport) void* __stdcall VirtualAlloc(void*, u64, unsigned long, unsigned long);
__declspec(dllimport) unsigned long __stdcall GetTickCount(void);

typedef struct {
    ad_gm_matrix_t* matrix;
    u32             initialized;
    u64             prng;
    u32             tick_count;         // # of ticks since last status
    u32             first_tamper_tick;  // GetTickCount at first observed tamper
    u32             suicide_deadline;   // when to exit (tick count)
    u32             _pad;
} ad_wh_ctx_t;

ANTIDEBUG_INLINE u64 ad_wh_xs(u64* s) {
    u64 x = *s;
    x ^= x << 13; x ^= x >> 7; x ^= x << 17;
    *s = x;
    return x;
}

ANTIDEBUG_INLINE b32 ad_wh_init(ad_wh_ctx_t* c, ad_gm_matrix_t* m) {
    if (!c || !m) return 0;
    u32 k; for (k = 0; k < (u32)sizeof(*c); k++) ((volatile u8*)c)[k] = 0;
    c->matrix = m;
    c->prng = __rdtsc() ^ 0x9E3779B97F4A7C15ULL;
    c->initialized = 1u;
    return 1;
}

// A. Slow-down — sleep random interval if tampered.
ANTIDEBUG_INLINE void ad_wh_slowdown(ad_wh_ctx_t* c) {
#if AD_WH_ENABLE_SLOWDOWN
    if (!ad_gm_is_tampered(c->matrix)) return;
    u64 r = ad_wh_xs(&c->prng);
    u32 span = AD_WH_SLOWDOWN_MAX_MS - AD_WH_SLOWDOWN_MIN_MS;
    u32 ms = AD_WH_SLOWDOWN_MIN_MS + (u32)(r % span);
    Sleep(ms);
#else
    (void)c;
#endif
}

// B. Exception spam — raise a custom exception. Our VEH must be
// registered to swallow 0xE0DEADC0. Under x64dbg with default settings,
// this pops a first-chance break.
ANTIDEBUG_INLINE void ad_wh_excspam(ad_wh_ctx_t* c) {
#if AD_WH_ENABLE_EXCSPAM
    if (!ad_gm_is_tampered(c->matrix)) return;
    __try {
        RaiseException(AD_WH_EXCSPAM_CODE, 0, 0, 0);
    } __except (1) { /* swallow */ }
#else
    (void)c;
#endif
}

// C. Fake-finding ODS — print plausible but bogus analysis output.
ANTIDEBUG_INLINE void ad_wh_fake_ods(ad_wh_ctx_t* c) {
#if AD_WH_ENABLE_FAKE_ODS
    if (!ad_gm_is_tampered(c->matrix)) return;
    static const char* lines[] = {
        "[CRYPTO] key derivation completed, result @ 0x00007ff6d1a4fe20\n",
        "[FLAG] flag{debug_mode_active_abcdef} decoded at heap 0x01f2a040\n",
        "[BYPASS] score dispatch hook installed at 0x00007ff7abc12340\n",
        "[CHECK] all anti-debug checks returned clean status = 0\n",
        "[LICENCE] valid license found, signature OK\n",
        "[SENTINEL] heartbeat tick = 0x4242, guard region intact\n",
        "[VAULT] decrypted secret @ 0x00000188c7a30000 (1024 bytes)\n",
        "[AUTH] authentication token decoded, uid=0x7f3e9c01\n",
    };
    u64 r = ad_wh_xs(&c->prng);
    u32 idx = (u32)(r % (sizeof(lines) / sizeof(lines[0])));
    OutputDebugStringA(lines[idx]);
#else
    (void)c;
#endif
}

// D. Memory decoy — write decoy strings to allocated heap locations.
// Only writes ONCE per tick (reuses a persistent decoy buffer per ctx
// to bound memory use).
ANTIDEBUG_INLINE void ad_wh_mem_decoy(ad_wh_ctx_t* c) {
#if AD_WH_ENABLE_MEM_DECOY
    if (!ad_gm_is_tampered(c->matrix)) return;

    // Static buffer allocated lazily — 4 KB of decoy patterns.
    static volatile u8* g_decoy = 0;
    if (!g_decoy) {
        g_decoy = (volatile u8*)VirtualAlloc((void*)0, 0x1000, 0x3000u, 0x04u);
        if (!g_decoy) return;
    }

    // Rotate between several plausible pattern writes.
    static const char* patterns[] = {
        "flag{fake_flag_5e8a12cd}",
        "password=admin_admin_1234",
        "secret_key:8392fdabc001ef43",
        "serial=XXXX-YYYY-ZZZZ-AAAA",
        "license_token=valid_trial_900",
        "admin_pin=9999",
    };
    u64 r = ad_wh_xs(&c->prng);
    const char* p = patterns[(u32)(r % (sizeof(patterns) / sizeof(patterns[0])))];
    u32 off = (u32)(ad_wh_xs(&c->prng) & 0xF00u);   // random 256-byte boundary

    u32 i = 0;
    while (p[i] && off + i < 0x1000u) {
        g_decoy[off + i] = (u8)p[i];
        i++;
    }
#else
    (void)c;
#endif
}

// E. Delayed suicide — set deadline when first tamper observed; when
// GetTickCount passes the deadline, exit the process.
ANTIDEBUG_INLINE void ad_wh_suicide(ad_wh_ctx_t* c) {
#if AD_WH_ENABLE_SUICIDE
    if (!ad_gm_is_tampered(c->matrix)) return;
    u32 now = GetTickCount();
    if (c->suicide_deadline == 0u) {
        u64 r = ad_wh_xs(&c->prng);
        u32 span = AD_WH_SUICIDE_MAX_MS - AD_WH_SUICIDE_MIN_MS;
        c->first_tamper_tick = now;
        c->suicide_deadline = now + AD_WH_SUICIDE_MIN_MS + (u32)(r % span);
    }
    if (now >= c->suicide_deadline) {
        ExitProcess((unsigned long)0xBADF00Du);
    }
#else
    (void)c;
#endif
}

// Master tick — call from anywhere, preferably at the end of each
// check. Zero cost when clean.
ANTIDEBUG_INLINE void ad_wh_tick(ad_wh_ctx_t* c) {
    if (!c || !c->initialized) return;
    if (!ad_gm_is_tampered(c->matrix)) { c->tick_count++; return; }

    c->tick_count++;
    ad_wh_fake_ods(c);
    ad_wh_mem_decoy(c);
    ad_wh_excspam(c);
    ad_wh_slowdown(c);
    ad_wh_suicide(c);
}

// Bypass tick — returns without any hostile action, for use inside
// internal paths that shouldn't self-poison.
ANTIDEBUG_INLINE void ad_wh_bypass_tick(ad_wh_ctx_t* c) {
    if (!c || !c->initialized) return;
    c->tick_count++;
}

#else  // !_MSC_VER
typedef struct { int _unused; } ad_wh_ctx_t;
ANTIDEBUG_INLINE b32 ad_wh_init(ad_wh_ctx_t* c, ad_gm_matrix_t* m) { (void)c; (void)m; return 0; }
ANTIDEBUG_INLINE void ad_wh_tick(ad_wh_ctx_t* c) { (void)c; }
#endif // _MSC_VER

#endif // ANTIDEBUG_WHIP_HOSTILE_H
