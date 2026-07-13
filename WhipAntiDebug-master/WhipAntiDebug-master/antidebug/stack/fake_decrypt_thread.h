// ===== file: antidebug/stack/fake_decrypt_thread.h =====
//
// Fake flag-decryption worker threads.
//
// Spawns N background threads that LOOK like they are doing the real
// flag decryption:
//   * read from a static byte table that resembles ciphertext
//   * derive an FNV-style rolling key from PEB-stable inputs
//   * write transformed bytes into a buffer that ends up looking like
//     an `ADCTF{...}`-shaped string on a memory dump
//   * do it in a loop with a short delay, so a reverser who attaches
//     later still catches them mid-compute
//
// None of their output is consumed.  The real flag is derived in main().
// A reverser who sees these threads in a thread list, sets a bp on the
// XOR loop, and single-steps through the derivation, is chasing a
// mirage — they will eventually produce something that LOOKS like a
// decrypted flag ("ADCTF{VmXhKdQ7TpB2f3wMn5e}") but it is garbage the
// real scoring system never validates.
//
// CPU cost: each thread burns ~0.1% CPU (short XOR loop + NtDelay).
// Negligible compared to the friction added for a manual reverser.
//
#ifndef ANTIDEBUG_FAKE_DECRYPT_THREAD_H
#define ANTIDEBUG_FAKE_DECRYPT_THREAD_H

#include "../core/types.h"
#include "../core/macros.h"
#include "../core/syscall_bridge.h"
#include "../core/string_encrypt.h"
#include "../core/strenc_extra.h"
#include "../core/poly_syscall.h"

#if defined(_MSC_VER)

// ---------------------------------------------------------------------------
// Fake "ciphertext" table.  Looks like encrypted flag material in .rdata.
// ---------------------------------------------------------------------------
#ifndef AD_FAKE_DECRYPT_STORAGE_DEFINED
#define AD_FAKE_DECRYPT_STORAGE_DEFINED

#define AD_FAKE_WORKERS 3u

// 64 bytes of noise-ish data.  The exact contents are irrelevant — what
// matters is that they exist in .rdata and look like ciphertext.
static const u8 ad_fake_cipher[64] = {
    0x5A, 0x9C, 0x3F, 0xE1, 0xB2, 0x74, 0xD8, 0x06,
    0xA3, 0x48, 0x12, 0xCE, 0x7B, 0x91, 0x2D, 0xF5,
    0x60, 0x8A, 0x4C, 0xB7, 0xE9, 0x03, 0x5D, 0x72,
    0x1E, 0x9F, 0xD0, 0x66, 0x48, 0x3A, 0x85, 0xC1,
    0x7D, 0x29, 0xB4, 0x56, 0xE0, 0xF8, 0x17, 0x4B,
    0x8E, 0xC3, 0x60, 0x92, 0x24, 0x5F, 0xA7, 0xD1,
    0x38, 0x6B, 0xE5, 0x4F, 0x9A, 0x02, 0xD7, 0x81,
    0xB6, 0x4D, 0x2C, 0xF0, 0x58, 0x73, 0xE4, 0x1F,
};

// Per-worker output buffer.  A reverser scraping memory for ASCII
// flag-shaped strings will find each worker's buffer at various stages
// of "decryption".
static volatile u8 ad_fake_output[AD_FAKE_WORKERS][40];

// Running rolling key per worker.  Exposed as volatile so a reverser
// setting a memory watchpoint on it sees constant mutation.
static volatile u64 ad_fake_key[AD_FAKE_WORKERS];

static volatile u32 ad_fake_kill     = 0u;
static volatile u32 ad_fake_rounds[AD_FAKE_WORKERS];
static void*        ad_fake_handles[AD_FAKE_WORKERS];

// The "flag template" bytes a worker eventually produces.  Looks like
// a CTF flag.  Content is deliberately wrong — the real flag lives in
// main() and never touches this buffer.
static const u8 ad_fake_template[] = "ADCTF{VmXhKdQ7TpB2f3wMn5e}";

#endif // AD_FAKE_DECRYPT_STORAGE_DEFINED

// ---------------------------------------------------------------------------
// Worker body.  Burns CPU doing fake decryption.  A reverser stepping
// through sees XOR + FNV rolling key + byte writes — exactly what a
// real stream cipher would look like.
// ---------------------------------------------------------------------------
static unsigned long __stdcall ad_fake_decrypt_worker(void* param) {
    u64 widx64 = (u64)param;
    u32 widx = (u32)(widx64 & 0x3u);
    if (widx >= AD_FAKE_WORKERS) widx = 0u;

    static u16 s_delay = AD_SSN_UNRESOLVED;
    AD_RESOLVE_SSN_ENC(s_delay, NtDelayExecution, 17);

    // Seed the per-worker rolling key from PEB address + worker index —
    // same shape as a real ASLR-derived key.
    u8* peb = (u8*)__readgsqword(0x60);
    u64 seed = 0xCBF29CE484222325ULL;
    if (peb) seed ^= (u64)(uintptr_t)peb;
    seed ^= (u64)widx * 0x9E3779B97F4A7C15ULL;
    ad_fake_key[widx] = seed;

    while (!ad_fake_kill) {
        u64 k = ad_fake_key[widx];

        // Looks like an FNV-1a pass over the ciphertext.
        u32 i;
        for (i = 0; i < sizeof(ad_fake_cipher); i++) {
            k ^= (u64)ad_fake_cipher[i];
            k *= 0x00000100000001B3ULL;
        }

        // Produce 26 "decrypted" bytes into our buffer using a
        // decay-XOR stream.  The output LOOKS like a flag.
        u32 tlen = (u32)(sizeof(ad_fake_template) - 1u);
        for (i = 0; i < tlen && i < 39u; i++) {
            // XOR the template byte with a key byte derived from k.
            // In a CLEAN decryption, the XOR would restore plaintext;
            // here we XOR template (already looks like a flag) with
            // zero-ish low bits of k → result keeps the flag shape but
            // with occasional corruption.  Either way, looks real to a
            // reverser.
            u8 ks = (u8)((k >> ((i & 7u) * 8u)) & 0xFFu);
            ad_fake_output[widx][i] = (u8)(ad_fake_template[i] ^ (ks & 0x1Fu));
            k = k * 0x100000001B3ULL + (u64)i;
        }
        ad_fake_output[widx][39] = 0u;

        ad_fake_key[widx] = k;
        ad_fake_rounds[widx] += 1u;

        // Short nap so CPU usage is light; a reverser attaching after
        // many rounds still catches us mid-compute.
        if (s_delay != AD_SSN_FAILED) {
            s64 wait = -1000000LL;    // 100 ms
            AD_SYSCALL2(s_delay, (u64)0, &wait);
        }
    }
    return 0;
}

// ---------------------------------------------------------------------------
// Spawn the fake workers.  Hidden from debugger via
// NtSetInformationThread(ThreadHideFromDebugger).
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE void ad_fake_decrypt_spawn(void) {
    static u16 s_create = AD_SSN_UNRESOLVED;
    static u16 s_seti   = AD_SSN_UNRESOLVED;
    static u16 s_resume = AD_SSN_UNRESOLVED;

    AD_RESOLVE_SSN_ENC(s_create, NtCreateThreadEx,       17);
    AD_RESOLVE_SSN_ENC(s_seti,   NtSetInformationThread, 23);
    AD_RESOLVE_SSN_ENC(s_resume, NtResumeThread,         15);
    if (s_create == AD_SSN_FAILED || s_resume == AD_SSN_FAILED) return;

    u32 w;
    for (w = 0; w < AD_FAKE_WORKERS; w++) {
        ad_fake_handles[w] = (void*)0;
        ad_fake_rounds[w]  = 0u;

        void* handle = (void*)0;
        ad_ntstatus_t st = (ad_ntstatus_t)(s64)ad_poly_call(s_create,
            &handle,
            (void*)(u64)0x001FFFFFul,
            (void*)0,
            (void*)(u64)AD_CURRENT_PROCESS,
            (void*)ad_fake_decrypt_worker,
            (void*)(u64)w,
            (void*)(u64)0x00000004ul,  // CREATE_SUSPENDED
            (void*)0, (void*)0, (void*)0, (void*)0
        );
        if (!AD_NT_SUCCESS(st) || !handle) continue;

        if (s_seti != AD_SSN_FAILED) {
            AD_SYSCALL4(s_seti, handle, (u64)17, (u64)0, (u64)0);
        }
        u32 prev = 0u;
        AD_SYSCALL2(s_resume, handle, &prev);
        ad_fake_handles[w] = handle;
    }
}

// ---------------------------------------------------------------------------
// Signal all workers to exit.  Called at the end of main().
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE void ad_fake_decrypt_stop(void) {
    ad_fake_kill = 1u;
    AD_BARRIER();
    static u16 s_delay = AD_SSN_UNRESOLVED;
    AD_RESOLVE_SSN_ENC(s_delay, NtDelayExecution, 17);
    if (s_delay != AD_SSN_FAILED) {
        s64 wait = -2000000LL;  // 200 ms
        AD_SYSCALL2(s_delay, (u64)0, &wait);
    }
}

#else  // !_MSC_VER
ANTIDEBUG_INLINE void ad_fake_decrypt_spawn(void) {}
ANTIDEBUG_INLINE void ad_fake_decrypt_stop(void)  {}
#endif

#endif // ANTIDEBUG_FAKE_DECRYPT_THREAD_H
