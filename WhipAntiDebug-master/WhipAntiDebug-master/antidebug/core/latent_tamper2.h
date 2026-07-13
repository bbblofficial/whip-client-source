// ===== file: antidebug/core/latent_tamper2.h =====
//
// Latent Tamper 2 — independent sentinel with code corruption crash.
//
// Purpose
// -------
// A second, fully independent latent tamper sentinel that operates
// alongside latent_tamper.h. Key differences:
//
//   * Different arming mechanism: ROL-encoded global (not XOR with PEB)
//   * Shorter delay range: 1-5 seconds (vs 2-8 for primary)
//   * Faster polling: 100ms slices (vs 250ms)
//   * Different crash method: corrupt our own .text section by writing
//     0x00 bytes to a random code address. The next time that function
//     runs, the process crashes with EXCEPTION_ACCESS_VIOLATION at a
//     *legitimate* code address — looks like a memory corruption bug,
//     not an anti-debug crash.
//
// What the reverser sees
// ----------------------
//   * Process crashes at a valid RIP inside the binary's .text
//   * The crash address is a real function that was executing
//   * The bytes at that address are corrupted (0x00 = ADD [RAX], AL)
//   * No wild pointer, no suspicious pattern — looks like a heap/stack
//     overflow that smashed code, or a race condition
//
// API
// ---
//   ad_latent2_init()         — spawn the sentinel thread
//   ad_latent2_arm_if(cond)   — atomically arm the trip
//
#ifndef ANTIDEBUG_LATENT_TAMPER2_H
#define ANTIDEBUG_LATENT_TAMPER2_H

#include "types.h"
#include "macros.h"
#include "api_hash.h"
#include "syscall_bridge.h"
#include "string_encrypt.h"
#include "strenc_extra.h"

#ifndef AD_LATENT2_DELAY_MIN_MS
#define AD_LATENT2_DELAY_MIN_MS  1000u
#endif
#ifndef AD_LATENT2_DELAY_MAX_MS
#define AD_LATENT2_DELAY_MAX_MS  5000u
#endif

// Armed magic — different from latent_tamper.h's value.
// Stored ROL'd by 13 bits (not XOR'd with PEB) for diversity.
#define AD_LATENT2_ARMED_MAGIC   0x44454144434F4445ULL  // ASCII "DEADCODE"

// ---------------------------------------------------------------------------
// Storage — guarded against multiple includes
// ---------------------------------------------------------------------------
#ifndef AD_LATENT2_STORAGE_DEFINED
#define AD_LATENT2_STORAGE_DEFINED
typedef struct {
    volatile u64 armed_state;
    volatile u32 started;
    volatile u32 woke;      // XOR-encoded: (count ^ woke_key) — not raw count
    volatile u32 woke_key;  // RDTSC-seeded secret set by sentinel at start
} ad_latent2_t;

static ad_latent2_t g_latent2 = { 0, 0, 0, 0 };
#endif

// ---------------------------------------------------------------------------
// ROL/ROR encoding — different from latent_tamper's XOR-with-PEB scheme
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE u64 ad_latent2_rol64(u64 v, u32 n) {
    n &= 63u;
    if (n == 0u) return v;
    return (v << n) | (v >> (64u - n));
}

ANTIDEBUG_INLINE u64 ad_latent2_ror64(u64 v, u32 n) {
    n &= 63u;
    if (n == 0u) return v;
    return (v >> n) | (v << (64u - n));
}

// Encode: ROL by 13, then XOR with RDTSC-seeded constant derived at
// init. We use a fixed per-process value: the base address of ntdll,
// which is stable across threads and non-obvious from a static dump.
ANTIDEBUG_INLINE u64 ad_latent2_encode_key(void) {
#ifdef _MSC_VER
    u64 peb = (u64)__readgsqword(0x60);
    if (!peb) return 0x7A7A7A7A7A7A7A7AULL;
    u64 ldr = *(u64*)(peb + 0x18);
    if (!ldr) return 0x7A7A7A7A7A7A7A7AULL;
    u64 first = *(u64*)(ldr + 0x10);
    if (!first) return 0x7A7A7A7A7A7A7A7AULL;
    u64 base  = *(u64*)(first + 0x30);
    return base ^ 0x7A7A7A7A7A7A7A7AULL;
#else
    return 0x7A7A7A7A7A7A7A7AULL;
#endif
}

ANTIDEBUG_INLINE u64 ad_latent2_encode(u64 val) {
    return ad_latent2_rol64(val, 13u) ^ ad_latent2_encode_key();
}

ANTIDEBUG_INLINE u64 ad_latent2_decode(u64 enc) {
    return ad_latent2_ror64(enc ^ ad_latent2_encode_key(), 13u);
}

// ---------------------------------------------------------------------------
// Random delay (1-5 seconds)
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE u32 ad_latent2_rand_delay(void) {
#ifdef _MSC_VER
    u64 s = __rdtsc();
    s ^= s << 7; s ^= s >> 13; s ^= s << 11;
    u32 span = (AD_LATENT2_DELAY_MAX_MS - AD_LATENT2_DELAY_MIN_MS);
    return AD_LATENT2_DELAY_MIN_MS + (u32)(s % (u64)span);
#else
    return AD_LATENT2_DELAY_MIN_MS;
#endif
}

// ---------------------------------------------------------------------------
// NtDelayExecution via direct syscall (100ms slices)
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE void ad_latent2_delay_ms(u32 ms) {
    static u16 s_ssn = AD_SSN_UNRESOLVED;
    AD_RESOLVE_SSN_ENC(s_ssn, NtDelayExecution, 17);
    if (s_ssn == AD_SSN_FAILED) return;

    s64 interval = -((s64)ms * 10000LL);
    (void)AD_SYSCALL2(s_ssn, (u64)0, &interval);
}

// ---------------------------------------------------------------------------
// Interrupt time read (same KUSER_SHARED_DATA technique)
// ---------------------------------------------------------------------------
#ifndef AD_KUSER_SHARED
#define AD_KUSER_SHARED ((volatile const u8*)0x7FFE0000)
#endif

ANTIDEBUG_INLINE u64 ad_latent2_interrupt_time(void) {
    for (;;) {
        u32 high1 = *(volatile const u32*)(AD_KUSER_SHARED + 0x08 + 4);
        u32 low   = *(volatile const u32*)(AD_KUSER_SHARED + 0x08 + 0);
        u32 high2 = *(volatile const u32*)(AD_KUSER_SHARED + 0x08 + 4);
        if (high1 == high2) return ((u64)high1 << 32) | (u64)low;
    }
}

// ---------------------------------------------------------------------------
// Code corruption crash: write 0x00 to a random offset in our .text
//
// We locate our own module base from the PEB, find .text, pick a
// random offset, make it RWX, write zeros, restore RX. Next time
// that code runs: crash at a legitimate address.
// ---------------------------------------------------------------------------
#ifndef AD_STRENC_NtProtectVirtualMemory
#define AD_STRENC_NtProtectVirtualMemory(buf)                                \
    do {                                                                     \
        const u8 _k = AD_STR_KEY(0xE3);                                     \
        char buf##_e[23];                                                    \
        AD_ENC(buf##_e,  0, 'N', _k); AD_ENC(buf##_e,  1, 't', _k);       \
        AD_ENC(buf##_e,  2, 'P', _k); AD_ENC(buf##_e,  3, 'r', _k);       \
        AD_ENC(buf##_e,  4, 'o', _k); AD_ENC(buf##_e,  5, 't', _k);       \
        AD_ENC(buf##_e,  6, 'e', _k); AD_ENC(buf##_e,  7, 'c', _k);       \
        AD_ENC(buf##_e,  8, 't', _k); AD_ENC(buf##_e,  9, 'V', _k);       \
        AD_ENC(buf##_e, 10, 'i', _k); AD_ENC(buf##_e, 11, 'r', _k);       \
        AD_ENC(buf##_e, 12, 't', _k); AD_ENC(buf##_e, 13, 'u', _k);       \
        AD_ENC(buf##_e, 14, 'a', _k); AD_ENC(buf##_e, 15, 'l', _k);       \
        AD_ENC(buf##_e, 16, 'M', _k); AD_ENC(buf##_e, 17, 'e', _k);       \
        AD_ENC(buf##_e, 18, 'm', _k); AD_ENC(buf##_e, 19, 'o', _k);       \
        AD_ENC(buf##_e, 20, 'r', _k); AD_ENC(buf##_e, 21, 'y', _k);       \
        AD_DECODE_BUF(buf##_e, 22, _k);                                     \
        for (unsigned _ci = 0; _ci < 23; _ci++) (buf)[_ci] = buf##_e[_ci];  \
    } while (0)
#endif

ANTIDEBUG_INLINE void ad_latent2_corrupt_code(void) {
#ifdef _MSC_VER
    u8* peb  = (u8*)__readgsqword(0x60);
    if (!peb) return;
    u8* base = *(u8**)(peb + 0x10);
    if (!base) return;

    // Walk PE to find .text
    u32 e_lfanew = *(u32*)(base + 0x3C);
    u8* pe       = base + e_lfanew;
    u16 num_sec  = *(u16*)(pe + 6);
    u16 opt_sz   = *(u16*)(pe + 20);
    u8* sections = pe + 24 + opt_sz;

    u8* text_va  = 0;
    u32 text_sz  = 0;
    for (u16 i = 0; i < num_sec; i++) {
        u8* sec = sections + i * 40;
        if (sec[0] == '.' && sec[1] == 't' && sec[2] == 'e' &&
            sec[3] == 'x' && sec[4] == 't') {
            text_sz = *(u32*)(sec + 8);    // VirtualSize
            u32 rva = *(u32*)(sec + 12);   // VirtualAddress
            text_va = base + rva;
            break;
        }
    }
    if (!text_va || text_sz < 0x200u) return;

    // Pick a random offset in the middle of .text (avoid the very start
    // which contains the entry point and PE loader stubs)
    u64 tsc = __rdtsc();
    tsc ^= tsc >> 17; tsc ^= tsc << 13; tsc ^= tsc >> 7;
    u32 offset = 0x100u + (u32)(tsc % (text_sz - 0x200u));
    u8* target = text_va + offset;

    // NtProtectVirtualMemory: change page to PAGE_EXECUTE_READWRITE (0x40)
    static u16 s_prot = AD_SSN_UNRESOLVED;
    AD_RESOLVE_SSN_ENC(s_prot, NtProtectVirtualMemory, 23);
    if (s_prot == AD_SSN_FAILED) return;

    void* region_base = (void*)target;
    u64   region_size = 16u;
    u32   old_prot    = 0;

    // Make RWX
    AD_SYSCALL5(s_prot, AD_CURRENT_PROCESS,
                &region_base, &region_size,
                (u64)0x40u, &old_prot);

    // Corrupt: write 0x00 bytes (ADD [RAX], AL — will fault on next exec
    // if RAX is not a writable address, which it usually isn't)
    volatile u8* p = (volatile u8*)target;
    p[0] = 0x00; p[1] = 0x00; p[2] = 0x00; p[3] = 0x00;
    p[4] = 0x00; p[5] = 0x00; p[6] = 0x00; p[7] = 0x00;

    // Restore original protection (make it look untouched)
    region_base = (void*)target;
    region_size = 16u;
    u32 dummy = 0;
    AD_SYSCALL5(s_prot, AD_CURRENT_PROCESS,
                &region_base, &region_size,
                (u64)old_prot, &dummy);
#endif
}

// ---------------------------------------------------------------------------
// Sentinel thread 2 — 100ms slices, fast-react, code-corruption crash
// ---------------------------------------------------------------------------
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

static u32 __stdcall ad_latent2_sentinel_thread(void* arg) {
    AD_UNUSED(arg);

    // Forge saved RA → fake ntdll parent (hides BTIT/RUTS in stack walks).
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

    u32 delay_ms = ad_latent2_rand_delay();
    u64 t_start  = ad_latent2_interrupt_time();

    // Sleep in 100ms slices — faster response than primary sentinel
    u32 elapsed_req = 0u;
    u32 _woke_count = 0u;
    volatile b32 fast_crash = 0;
    volatile b32 do_crash   = 0;  // local crash decision — not bypassable via WPM on the global
    u64 last_seen_state = g_latent2.armed_state;  // track for per-slice tamper detection
    while (elapsed_req < delay_ms) {
        u64 t_slice_start = ad_latent2_interrupt_time();
        ad_latent2_delay_ms(100u);
        elapsed_req += 100u;
        // woke_key set on FIRST real sleep — before this: woke=0, key=0
        // → (0^0)=0 → liveness guard fails if sentinel killed before first sleep.
#ifdef _MSC_VER
        if (_woke_count == 0u) {
            u32 _wk = (u32)__rdtsc();
            _wk ^= _wk >> 13; _wk ^= _wk << 7; _wk ^= _wk >> 17;
            g_latent2.woke_key = _wk | 1u;
        }
#endif
        _woke_count++;
        g_latent2.woke = _woke_count ^ g_latent2.woke_key;  // heartbeat — XOR-encoded

        // Per-slice suspension check: if 100ms sleep took >1.5s of wall
        // time, we were frozen. Arm and crash immediately.
        u64 t_slice_end   = ad_latent2_interrupt_time();
        u64 slice_real_ms = (t_slice_end - t_slice_start) / 10000u;
        // Threshold raised from 1.5 s → 3 s. 100 ms slice * 15× was too
        // tight during the init thread storm (sentinels + watchdog spinning
        // up at once) and false-fired on benign scheduler stalls.
        if (slice_real_ms > 3000u) {
            g_latent2.armed_state = ad_latent2_encode(AD_LATENT2_ARMED_MAGIC);
            fast_crash = 1;
            do_crash   = 1;
            break;
        }

        // Per-slice external arm + tamper detection.
        // Window: ≤100ms instead of the full 1–5s sleep.
        {
            u64 _cur = g_latent2.armed_state;
            // External arm fired this slice
            if (last_seen_state == 0u && _cur != 0u) {
                u64 _dec = ad_latent2_decode(_cur);
                if (_dec == AD_LATENT2_ARMED_MAGIC) do_crash = 1;
            }
            // Armed state zeroed this slice → WPM tampering
            if (last_seen_state != 0u && _cur == 0u) do_crash = 1;
            last_seen_state = _cur;
        }
        if (do_crash) break;
    }

    // Post-loop wall-time check (only if fast path didn't fire)
    if (!fast_crash) {
        u64 t_end      = ad_latent2_interrupt_time();
        u64 ms_real    = (t_end - t_start) / 10000u;
        if (ms_real > (u64)delay_ms * 2u + 300u) {
            g_latent2.armed_state = ad_latent2_encode(AD_LATENT2_ARMED_MAGIC);
            do_crash = 1;
        }
    }

    // Suspension-detected arm: do_crash is on our stack — not bypassable via
    // WPM on any global. If the sentinel itself didn't detect suspension, fall
    // through to check the global for an external arm from the main thread
    // (ad_latent2_arm_if). That read still has a larger bypass window (the
    // full sentinel delay) but is the intended signal path for main-thread arms.
    if (!do_crash) {
        u64 _cur = g_latent2.armed_state;
        // If the global was armed but is now zero → zeroed by WPM between slices
        if (last_seen_state != 0u && _cur == 0u) {
            do_crash = 1;
        } else {
            u64 dec = ad_latent2_decode(_cur);
            if (dec == AD_LATENT2_ARMED_MAGIC) do_crash = 1;
        }
    }
    if (!do_crash) {
        // Not armed → exit via NtTerminateThread direct syscall to avoid
        // executing the forged saved-RA via ret.
#ifdef _MSC_VER
        static u16 s_term2 = AD_SSN_UNRESOLVED;
        AD_RESOLVE_SSN_ENC(s_term2, NtTerminateThread, 18);
        if (s_term2 != AD_SSN_FAILED) {
            (void)AD_SYSCALL2(s_term2, AD_CURRENT_THREAD, (u64)0);
        }
#endif
        return 0;
    }

    // Armed — corrupt our own .text section
    ad_latent2_corrupt_code();

    return 0;
}

// ---------------------------------------------------------------------------
// Init — spawn sentinel thread 2. Idempotent.
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE b32 ad_latent2_init(void) {
#ifdef _MSC_VER
    if (g_latent2.started) return 1;

    // Resolve CreateThread from kernelbase/kernel32
    char ct[13];
    ct[ 0]='C'; ct[ 1]='r'; ct[ 2]='e'; ct[ 3]='a'; ct[ 4]='t';
    ct[ 5]='e'; ct[ 6]='T'; ct[ 7]='h'; ct[ 8]='r'; ct[ 9]='e';
    ct[10]='a'; ct[11]='d'; ct[12]=0;
    u32 ct_hash = ad_hash_str(ct);

    typedef void* (__stdcall *fn_create_t)(
        void*, u64, void*, void*, u32, u32*);
    fn_create_t pCreate = (fn_create_t)ad_resolve_api(AD_HASH_KERNELBASE, ct_hash);
    if (!pCreate) pCreate = (fn_create_t)ad_resolve_api(AD_HASH_KERNEL32, ct_hash);
    if (!pCreate) return 0;

    u32 tid = 0;
    void* h = pCreate(0, 0, (void*)&ad_latent2_sentinel_thread, 0, 0, &tid);
    if (!h) return 0;

    g_latent2.started = 1;
    return 1;
#else
    return 0;
#endif
}

// ---------------------------------------------------------------------------
// Arm — ROL-encode the magic into the global
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE void ad_latent2_arm_if(b32 condition) {
    if (!condition) return;
    g_latent2.armed_state = ad_latent2_encode(AD_LATENT2_ARMED_MAGIC);
}

#endif // ANTIDEBUG_LATENT_TAMPER2_H
