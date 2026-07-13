// ===== file: antidebug/checks/integrity/anti_tamper.h =====
//
// Anti-tamper layer — protects against:
//   1. Static binary patching (NOP/patch ad_run_supplemental before launch)
//   2. Runtime memory writes (WriteProcessMemory on score variables)
//   3. Cheat Engine / memory scanners (scan + freeze + patch)
//
// Techniques:
//   - CRC32 self-hash of critical functions at call time
//   - Score obfuscation (never stored as plaintext u32)
//   - Cheat Engine process/driver detection
//   - Foreign VM_WRITE handle detection
//   - PAGE_GUARD canary on score memory
//
#ifndef ANTIDEBUG_ANTI_TAMPER_H
#define ANTIDEBUG_ANTI_TAMPER_H

#include "../../core/types.h"
#include "../../core/macros.h"
#include "../../core/syscall_bridge.h"
#include "../../core/string_encrypt.h"
#include "anti_patch.h"

#if defined(_MSC_VER)

// =========================================================================
// 1. Obfuscated score — never stores the real score as a plain u32
// =========================================================================
//
// Cheat Engine scans for specific values (e.g. search for 0, then search
// for changed values). By XOR-encrypting the score with a runtime key,
// the value in memory is never the actual score.
//
// Usage:
//   ad_score_ctx_t ctx;
//   ad_score_init(&ctx);
//   ad_score_add(&ctx, 42);
//   u32 real = ad_score_read(&ctx);  // returns accumulated score
// =========================================================================

typedef struct {
    volatile u64 enc_val;        // score XOR'd with key
    volatile u64 key;            // runtime XOR key from RDTSC
    volatile u32 checksum;       // fold of all fields — detects WPM on any member
    volatile u64 enc_commitment; // rolling FNV commitment, XOR'd with key
    volatile u32 step_index;     // counts non-zero ad_score_add calls
} ad_score_ctx_t;

ANTIDEBUG_INLINE void ad_score_init(ad_score_ctx_t* ctx) {
    AD_LFENCE();
    u64 k = __rdtsc();
    k ^= 0xA5A5A5A5DEADBEEFULL;
    k |= 1ULL;  // ensure non-zero
    ctx->key = k;
    ctx->enc_val = k;  // score=0 → enc_val = 0 ^ key = key
    // Checksum: simple fold
    // Commitment starts at 0 (clean-run value = correct VM key = score=0).
    // enc_commitment = 0 ^ key = key.
    ctx->enc_commitment = k;
    ctx->step_index = 0u;  // must be set before checksum — checksum covers step_index
    ctx->checksum = (u32)(ctx->enc_val ^ (ctx->enc_val >> 32) ^
                          ctx->key ^ (ctx->key >> 32) ^
                          ctx->enc_commitment ^ (ctx->enc_commitment >> 32) ^
                          ctx->step_index);
}

ANTIDEBUG_INLINE void ad_score_add(ad_score_ctx_t* ctx, u32 delta) {
    u64 k = ctx->key;
    u64 cur = ctx->enc_val ^ k;  // decrypt
    cur += (u64)delta;
    ctx->enc_val = cur ^ k;       // re-encrypt
    // Roll commitment only when a check fires (delta != 0).
    // Clean run: commitment stays at 0 → correct VM decryption key.
    // Any check firing: FNV mutation → commitment unpredictably non-zero
    // → wrong VM key → garbage output. Patching final_score alone no longer helps.
    if (delta != 0u) {
        u64 c = ctx->enc_commitment ^ k;   // decrypt commitment
        c ^= (u64)delta ^ (u64)ctx->step_index;
        c *= 0x00000100000001B3ULL;         // FNV-1a prime
        ctx->enc_commitment = c ^ k;        // re-encrypt
        ctx->step_index++;
    }
    // Recompute checksum AFTER all fields are updated — covers enc_commitment
    // and step_index so WPM reset (enc_commitment = key) is detected.
    ctx->checksum = (u32)(ctx->enc_val ^ (ctx->enc_val >> 32) ^
                          ctx->key ^ (ctx->key >> 32) ^
                          ctx->enc_commitment ^ (ctx->enc_commitment >> 32) ^
                          ctx->step_index);
}

ANTIDEBUG_INLINE u32 ad_score_read(ad_score_ctx_t* ctx) {
    // Verify checksum — detects WriteProcessMemory tampering on any field
    u32 expected = (u32)(ctx->enc_val ^ (ctx->enc_val >> 32) ^
                         ctx->key ^ (ctx->key >> 32) ^
                         ctx->enc_commitment ^ (ctx->enc_commitment >> 32) ^
                         ctx->step_index);
    if (expected != ctx->checksum) {
        return 0xFFFFFFFFu;  // tampered → max score
    }
    u64 raw = ctx->enc_val ^ ctx->key;
    // Saturate: if the high bit is set the accumulator underflowed (score is
    // still below the pre-seeded noise floor) — return 0 rather than wrapping.
    if (raw >> 63) return 0u;
    return (u32)raw;
}

// Initialise the score accumulator with a pre-seeded negative offset equal to
// the noise floor.  Subsequent ad_score_add() calls accumulate normally; the
// first `floor` points cancel the offset so ad_score_read() returns 0 until
// the real score exceeds the floor — with NO visible subtraction at the call
// site and NO constant in the binary that reveals the floor value.
// The commitment is NOT affected: it rolls only when a real check fires (delta
// != 0 in ad_score_add), exactly as with ad_score_init().
ANTIDEBUG_INLINE void ad_score_init_with_floor(ad_score_ctx_t* ctx, u32 floor) {
    ad_score_init(ctx);
    u64 k = ctx->key;
    u64 cur = ctx->enc_val ^ k;  // decrypt: currently 0
    cur -= (u64)floor;           // pre-subtract: wraps to 0xFFFF...(-floor)
    ctx->enc_val = cur ^ k;      // re-encrypt
    ctx->checksum = (u32)(ctx->enc_val ^ (ctx->enc_val >> 32) ^
                          ctx->key ^ (ctx->key >> 32) ^
                          ctx->enc_commitment ^ (ctx->enc_commitment >> 32) ^
                          ctx->step_index);
}

// Returns the rolling FNV commitment.
// Clean run (no checks fired): returns 0 = correct VM decryption key.
// Any check fired: returns a non-zero mutated value → VM produces garbage output.
// Also validates the checksum — if enc_commitment was WPM'd without fixing
// the checksum, returns 0xFFFFFFFF (wrong VM key) instead of the forged 0.
ANTIDEBUG_INLINE u32 ad_score_read_commitment(const ad_score_ctx_t* ctx) {
    u32 expected = (u32)(ctx->enc_val ^ (ctx->enc_val >> 32) ^
                         ctx->key ^ (ctx->key >> 32) ^
                         ctx->enc_commitment ^ (ctx->enc_commitment >> 32) ^
                         ctx->step_index);
    if (expected != ctx->checksum) {
        return 0xFFFFFFFFu;  // tampered — wrong VM key → garbage output
    }
    return (u32)(ctx->enc_commitment ^ ctx->key);
}

// =========================================================================
// 2. Cheat Engine detection
// =========================================================================
//
// Scan running processes for known CE executables and drivers.
// Uses NtQuerySystemInformation(SystemProcessInformation) via direct
// syscall to avoid hooks.
// =========================================================================

// CE process names (wide chars, lowercase for case-insensitive compare)
// "cheatengine" = 11 chars
ANTIDEBUG_INLINE b32 ad_detect_cheat_engine(void) {
    static u16 s_ssn_qsi = AD_SSN_UNRESOLVED;
    AD_RESOLVE_SSN_ENC(s_ssn_qsi, NtQuerySystemInformation, 25);
    if (s_ssn_qsi == AD_SSN_FAILED) return 0;

    enum { BUF_SIZE = 65536 };
    static u8 s_buf[BUF_SIZE];
    AD_ZERO_BUF(s_buf, sizeof(s_buf));
    u32 needed = 0u;

    ad_ntstatus_t st = AD_SYSCALL4(s_ssn_qsi,
        (u64)5u,  // SystemProcessInformation
        s_buf, (u64)BUF_SIZE, &needed);
    if (!AD_NT_SUCCESS(st)) return 0;

    u8* entry = s_buf;
    u32 guard = 0u;

    while (entry && guard < 512u) {
        guard++;
        u32 next_offset = *(u32*)entry;

        // ImageName UNICODE_STRING at offset +0x38 (Length, MaxLen, Buffer)
        u16 name_len = *(u16*)(entry + 0x38);
        u16* name_buf = *(u16**)(entry + 0x40);

        if (name_buf && name_len >= 20u) {  // "cheatengine" = 11 wchars = 22 bytes min
            u32 chars = name_len / 2u;
            u32 ci;
            for (ci = 0u; ci + 4u <= chars; ci++) {
                u16 c0 = name_buf[ci]   | 0x20u;
                u16 c1 = name_buf[ci+1u] | 0x20u;
                u16 c2 = name_buf[ci+2u] | 0x20u;
                u16 c3 = name_buf[ci+3u] | 0x20u;
                u16 c4 = name_buf[ci+4u] | 0x20u;

                // "cheat"
                if (c0 == 'c' && c1 == 'h' && c2 == 'e' && c3 == 'a' && c4 == 't') {
                    AD_ZERO_BUF(s_buf, sizeof(s_buf));
                    return 1;
                }
            }
        }

        if (next_offset == 0u) break;
        entry += next_offset;
    }

    AD_ZERO_BUF(s_buf, sizeof(s_buf));
    return 0;
}

// =========================================================================
// 3. Foreign VM_WRITE handle detection
// =========================================================================
//
// Cheat Engine opens our process with PROCESS_VM_WRITE (0x0020) to
// patch memory. Detect handles from foreign PIDs that have write access.
// Uses direct syscall to bypass ScyllaHide's handle filtering.
// =========================================================================
ANTIDEBUG_INLINE b32 ad_detect_foreign_write_handles(void) {
    static u16 s_ssn_qsi = AD_SSN_UNRESOLVED;
    AD_RESOLVE_SSN_ENC(s_ssn_qsi, NtQuerySystemInformation, 25);
    if (s_ssn_qsi == AD_SSN_FAILED) return 0;

    static u16 s_ssn_qip = AD_SSN_UNRESOLVED;
    AD_RESOLVE_SSN_ENC(s_ssn_qip, NtQueryInformationProcess, 26);
    if (s_ssn_qip == AD_SSN_FAILED) return 0;

    // Get our PID
    AD_PROCESS_BASIC_INFO pbi;
    AD_ZERO_BUF(&pbi, sizeof(pbi));
    u32 ret_len = 0u;
    AD_SYSCALL5(s_ssn_qip, AD_CURRENT_PROCESS, (u64)0, &pbi,
                (u64)sizeof(pbi), &ret_len);
    u64 our_pid = (u64)(u64)pbi.UniqueProcessId;
    if (our_pid == 0ULL) return 0;

    // Query SystemExtendedHandleInformation (class 64)
    enum { HANDLE_BUF = 262144 };
    static u8 s_hbuf[HANDLE_BUF];
    AD_ZERO_BUF(s_hbuf, sizeof(s_hbuf));
    u32 needed = 0u;

    ad_ntstatus_t st = AD_SYSCALL4(s_ssn_qsi,
        (u64)64u,  // SystemExtendedHandleInformation
        s_hbuf, (u64)HANDLE_BUF, &needed);
    if (!AD_NT_SUCCESS(st)) {
        AD_ZERO_BUF(s_hbuf, sizeof(s_hbuf));
        return 0;
    }

    u64 num_handles = *(u64*)s_hbuf;
    u8* entries = s_hbuf + 16;  // skip header

    u32 write_handles = 0u;
    u64 hi;
    u64 max_entries = num_handles;
    if (max_entries > 8000ULL) max_entries = 8000ULL;

    for (hi = 0ULL; hi < max_entries; hi++) {
        u8* e = entries + (hi * 40u);
        if (e + 40u > s_hbuf + HANDLE_BUF) break;

        u64 handle_pid = *(u64*)(e + 8);
        u32 access = *(u32*)(e + 0x18);
        u16 type_idx = *(u16*)(e + 0x1E);

        // Process object type is typically index 7, but varies.
        // Check for PROCESS_VM_WRITE (0x0020) or PROCESS_VM_OPERATION (0x0008)
        // from a foreign PID (not us, not System, not csrss)
        if (handle_pid != our_pid && handle_pid > 4ULL) {
            if ((access & 0x0020u) && (access & 0x0008u)) {
                // Foreign PID has VM_WRITE + VM_OPERATION — can patch us
                write_handles++;
            }
        }
    }

    AD_ZERO_BUF(s_hbuf, sizeof(s_hbuf));

    // Baseline: legitimate processes (csrss, conhost) may have some handles
    // CE: opens with PROCESS_ALL_ACCESS which includes VM_WRITE
    // Baseline: csrss/conhost/svchost may hold a few VM_WRITE handles
    // CE: opens with PROCESS_ALL_ACCESS → many VM_WRITE handles
    return (b32)(write_handles > 15u);
}

// =========================================================================
// 4. Runtime code integrity — verify ad_run_supplemental isn't NOPed
// =========================================================================
//
// Static patchers NOP out entire functions or replace them with
// "xor eax, eax; ret" (31 C0 C3). We CRC32 the first 256 bytes
// of critical functions at init, then re-check before using the score.
//
// Uses ad_hw_crc32 from anti_patch.h (SSE4.2 hardware CRC32).
// =========================================================================

typedef struct {
    u32 crc_supplemental;
    u32 crc_main;
    const void* fn_supplemental;
    const void* fn_main;
} ad_tamper_baseline_t;

ANTIDEBUG_INLINE void ad_tamper_baseline_init(
    ad_tamper_baseline_t* bl,
    const void* fn_supplemental,
    const void* fn_main)
{
    bl->fn_supplemental = fn_supplemental;
    bl->fn_main = fn_main;
    bl->crc_supplemental = fn_supplemental ?
        ad_hw_crc32((const u8*)fn_supplemental, 256u) : 0u;
    bl->crc_main = fn_main ?
        ad_hw_crc32((const u8*)fn_main, 256u) : 0u;
}

ANTIDEBUG_INLINE u32 ad_tamper_baseline_check(const ad_tamper_baseline_t* bl) {
    u32 score = 0u;

    if (bl->fn_supplemental) {
        u32 crc_now = ad_hw_crc32((const u8*)bl->fn_supplemental, 256u);
        if (crc_now != bl->crc_supplemental) score += 20u;
    }
    if (bl->fn_main) {
        u32 crc_now = ad_hw_crc32((const u8*)bl->fn_main, 256u);
        if (crc_now != bl->crc_main) score += 20u;
    }

    return score;
}

// =========================================================================
// 5. Anti-freeze — detect Cheat Engine "freeze" feature
// =========================================================================
//
// CE can "freeze" a memory value by continuously writing to it.
// We detect this by writing a canary value, waiting briefly, then
// re-reading. If the value changed without our intervention → frozen.
// =========================================================================
ANTIDEBUG_INLINE b32 ad_detect_value_freeze(volatile u32* target) {
    if (!target) return 0;

    // Save original
    u32 original = *target;

    // Write canary
    u32 canary = (u32)(__rdtsc() & 0xFFFFFFFFULL) | 1u;
    *target = canary;

    // Brief delay — let CE's freeze thread overwrite
    volatile u32 dummy = 0u;
    u32 i;
    for (i = 0u; i < 1000u; i++) dummy += i;
    AD_UNUSED(dummy);

    // Re-read
    u32 current = *target;

    // Restore original
    *target = original;

    // If value changed from our canary → something is writing to this addr
    if (current != canary) return 1;

    return 0;
}

// =========================================================================
// ANTI-TAMPER MASTER
// =========================================================================
ANTIDEBUG_INLINE u32 ad_anti_tamper_master(const ad_tamper_baseline_t* bl) {
    u32 score = 0u;

    // Code integrity — detect static binary patches
    { u32 v = 0; __try { v = ad_tamper_baseline_check(bl); } __except(1){} score += v; }

    // Cheat Engine process detection
    { b32 v = 0; __try { v = ad_detect_cheat_engine(); } __except(1){} if (v) score += 15u; }

    // Foreign VM_WRITE handles (CE, debuggers, injectors)
    { b32 v = 0; __try { v = ad_detect_foreign_write_handles(); } __except(1){} if (v) score += 12u; }

    return score;
}

#else  // Non-MSVC

// The non-MSVC stubs silently returned score=0 for every check, meaning
// ad_score_read() always returned 0 → final_score = 0 → flag always shown
// regardless of environment. This is a critical security hole.
// WhipAntiDebugger requires MSVC (_MSC_VER) to compile correctly.
#error "WhipAntiDebugger requires MSVC: non-MSVC ad_score_read() stub returns 0 unconditionally, making the flag trivially accessible in any environment. Build with cl.exe."

#endif // _MSC_VER

#endif // ANTIDEBUG_ANTI_TAMPER_H
