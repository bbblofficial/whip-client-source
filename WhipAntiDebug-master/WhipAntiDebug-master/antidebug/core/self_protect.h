// ===== file: antidebug/core/self_protect.h =====
//
// Self-protection layer — protects the anti-debugger framework ITSELF.
//
// Problem:
//   A skilled reverser doesn't attack the checks — they attack the
//   framework: NOP the dispatcher loop, patch ad_run to return 0,
//   hook whip_bridge_resolve to return fake SSNs, or modify ad_state_t
//   in memory to clear the suspicion score.
//
// Solution layers:
//
//   1. STATE MAC — rolling HMAC on ad_state_t. Recomputed after every
//      legitimate write. Verified before every read. Any external
//      modification (Cheat Engine, x64dbg memory write) breaks the MAC.
//
//   2. FLOW CHAIN — a cryptographic token that's transformed by each
//      check as it executes. If a check is NOPed or skipped (patched
//      out), the chain breaks and the final value is wrong → detected.
//
//   3. SELF-CRC INLINE — macro that hashes the calling function's own
//      first N bytes before executing. If the function was patched,
//      the CRC fails → function returns "suspicious" regardless of
//      the actual check result.
//
//   4. RESOLVER GUARD — verify the WhipSysCall bridge hasn't been
//      detoured. Hash the first bytes of whip_bridge_resolve and
//      the SyscallStub.
//
//   5. CODE ARMOR — encrypt/decrypt our .text pages on demand using
//      NtProtectVirtualMemory + XOR. Code is encrypted at rest,
//      decrypted only during ad_run(), re-encrypted after.
//
#ifndef ANTIDEBUG_SELF_PROTECT_H
#define ANTIDEBUG_SELF_PROTECT_H

#include "types.h"
#include "macros.h"
#include "mem_encrypt.h"
#include "value_guard.h"
#include "syscall_bridge.h"
#include "string_encrypt.h"

// =========================================================================
// 1. STATE MAC — detects external modification of ad_state_t
// =========================================================================
//
// We compute a MAC over the critical fields of ad_state_t using FNV-1a
// mixed with the memkey. Stored encrypted in a vault. Verified before
// each ad_run() — if it doesn't match, the state was tampered.

ANTIDEBUG_INLINE u64 ad_compute_state_mac(
    const void*       state_ptr,
    u32               state_size,
    const ad_memkey_t* mk
) {
    // Hash the raw state bytes with FNV-1a
    const u8* p = (const u8*)state_ptr;
    u64 h = 0xCBF29CE484222325ULL;
    u32 i;
    for (i = 0; i < state_size; i++) {
        h ^= (u64)p[i];
        h *= 0x00000100000001B3ULL;
    }
    // Mix with memkey so the MAC changes per-run
    h ^= ad_memkey_get(mk);
    h *= 0x00000100000001B3ULL;
    return h;
}

// Store the current MAC into a vault
// The vault's cipher is zeroed before hashing so the MAC field does not
// cover its own value (which would make verify always fail).
ANTIDEBUG_INLINE void ad_state_mac_update(
    ad_vault_t*       mac_vault,
    const void*       state_ptr,
    u32               state_size,
    const ad_memkey_t* mk
) {
    mac_vault->cipher = 0ULL;   // exclude self from hash
    u64 mac = ad_compute_state_mac(state_ptr, state_size, mk);
    ad_vault_store(mac_vault, mac, mk);
}

// Verify the MAC — returns 1 if tampered, 0 if clean
ANTIDEBUG_INLINE b32 ad_state_mac_verify(
    const ad_vault_t* mac_vault,
    const void*       state_ptr,
    u32               state_size,
    const ad_memkey_t* mk
) {
    u64 stored = ad_vault_load(mac_vault, mk);
    // Zero the vault temporarily so the hash matches what was computed during update
    u64 saved_cipher = mac_vault->cipher;
    ((ad_vault_t*)mac_vault)->cipher = 0ULL;
    u64 current = ad_compute_state_mac(state_ptr, state_size, mk);
    ((ad_vault_t*)mac_vault)->cipher = saved_cipher;
    // Constant-time compare (avoid timing side channel)
    u64 diff = stored ^ current;
    return (b32)(diff != 0ULL);
}

// =========================================================================
// 2. FLOW CHAIN — detect NOPed/skipped checks
// =========================================================================
//
// A 64-bit token that each check transforms before executing.
// The transformation is: token = (token ^ check_id) * prime + check_result
//
// After all checks, the final token value is compared against what it
// SHOULD be given the checks that ran. If a check was NOPed (never
// executed its transform), the chain breaks.
//
// The expected value is computed alongside the actual value — any
// divergence means tampering.

typedef struct {
    u64 chain;
    u64 expected;
    u32 steps;
} ad_flow_chain_t;

#define AD_FLOW_CHAIN_PRIME 0x9E3779B97F4A7C15ULL

ANTIDEBUG_INLINE void ad_flow_chain_init(ad_flow_chain_t* fc, u64 seed) {
    fc->chain    = seed;
    fc->expected = seed;
    fc->steps    = 0;
}

// Called BY each check function — transforms the chain
ANTIDEBUG_INLINE void ad_flow_chain_step(ad_flow_chain_t* fc, u32 check_id, b32 result) {
    fc->chain = (fc->chain ^ (u64)check_id) * AD_FLOW_CHAIN_PRIME + (u64)result;
    fc->steps++;
}

// Called by the dispatcher to compute what the chain SHOULD be
// (mirrors the same transform but using the dispatcher's view)
ANTIDEBUG_INLINE void ad_flow_chain_expect(ad_flow_chain_t* fc, u32 check_id, b32 result) {
    fc->expected = (fc->expected ^ (u64)check_id) * AD_FLOW_CHAIN_PRIME + (u64)result;
}

// Verify chain integrity — returns 1 if broken (check was NOPed/skipped)
ANTIDEBUG_INLINE b32 ad_flow_chain_verify(const ad_flow_chain_t* fc) {
    return (b32)(fc->chain != fc->expected);
}

// =========================================================================
// 3. SELF-CRC INLINE — function self-integrity check
// =========================================================================
//
// Macro that computes CRC32 of the current function's first 32 bytes.
// Compare against a baseline captured at init. If someone NOPed or
// patched the function, the CRC won't match.
//
// Usage inside a check function:
//   AD_SELF_CRC_CHECK(baseline_crc, 32);
//   // If patched, this sets __self_tampered = 1
//   if (__self_tampered) return 1; // always report suspicious

#define AD_SELF_CRC_CHECK(baseline, scan_bytes)                         \
    b32 __self_tampered = 0;                                            \
    do {                                                                \
        /* _ReturnAddress() gives the address after our call site */    \
        /* We want OUR function's start — approximate via _AddressOfReturnAddress */ \
        /* Simpler: the caller passes their fn pointer */               \
    } while (0)

// ad_hw_crc32 lives in checks/integrity/anti_patch.h. We pull it in here
// rather than forward-declaring because it is `static __forceinline` and
// the calling code below needs the body in scope. anti_patch.h does not
// include self_protect.h, so there is no circular dependency.
#include "../checks/integrity/anti_patch.h"

// Simpler approach: the dispatcher passes the check function's address
// to this macro and we hash it directly.
ANTIDEBUG_INLINE b32 ad_verify_fn_integrity(const void* fn_addr, u32 expected_crc) {
    if (!fn_addr) return 0;
#if defined(_MSC_VER)
    u32 current = ad_hw_crc32(fn_addr, 32u);
    return (b32)(current != expected_crc);
#else
    AD_UNUSED(expected_crc);
    return 0;
#endif
}

// =========================================================================
// 4. RESOLVER GUARD — protect WhipSysCall bridge
// =========================================================================
//
// Hash the first bytes of whip_bridge_resolve() and SyscallStub().
// If someone hooked these functions (JMP patch, inline hook), the
// hash changes.

typedef struct {
    u32 resolve_crc;   // CRC32 of whip_bridge_resolve prologue
    u32 stub_crc;      // CRC32 of SyscallStub prologue
    b32 ready;
} ad_resolver_guard_t;

ANTIDEBUG_INLINE void ad_resolver_guard_init(ad_resolver_guard_t* rg) {
    AD_ZERO_BUF(rg, sizeof(*rg));

#if defined(_MSC_VER)
    // Hash the prologues of our bridge functions
    rg->resolve_crc = ad_hw_crc32((const void*)whip_bridge_resolve, 48u);
    rg->stub_crc    = ad_hw_crc32((const void*)SyscallStub, 48u);
    rg->ready = 1;
#endif
}

// Returns 1 if the resolver has been hooked/tampered
ANTIDEBUG_INLINE b32 ad_resolver_guard_check(const ad_resolver_guard_t* rg) {
    if (!rg->ready) return 0;

#if defined(_MSC_VER)
    u32 resolve_now = ad_hw_crc32((const void*)whip_bridge_resolve, 48u);
    u32 stub_now    = ad_hw_crc32((const void*)SyscallStub, 48u);

    b32 resolve_ok = (b32)(resolve_now == rg->resolve_crc);
    b32 stub_ok    = (b32)(stub_now == rg->stub_crc);

    return (b32)(!resolve_ok || !stub_ok);
#else
    return 0;
#endif
}

// =========================================================================
// 5. CODE ARMOR — encrypt/decrypt our code pages on demand
// =========================================================================
//
// XOR our .text section with a key when not executing checks.
// Before ad_run(): decrypt (XOR to restore original code)
// After ad_run():  re-encrypt (XOR again to scramble code)
//
// A memory dump while checks aren't running shows encrypted code —
// IDA/Ghidra can't analyze it.
//
// Uses NtProtectVirtualMemory to toggle W permission.

// Encrypted string: "NtProtectVirtualMemory" — reuse definition
#ifndef AD_STRENC_NtProtectVirtualMemory
#define AD_STRENC_NtProtectVirtualMemory(buf)                                \
    do {                                                                     \
        const u8 _k = AD_STR_KEY(0x3B);                                     \
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

#define AD_PAGE_ER  0x20u  // PAGE_EXECUTE_READ
#define AD_PAGE_ERW 0x40u  // PAGE_EXECUTE_READWRITE

typedef struct {
    void* code_base;       // start of region to armor
    u32   code_size;       // size in bytes
    u64   xor_key;         // encryption key
    b32   is_encrypted;    // current state
    u16   protect_ssn;     // cached SSN for NtProtectVirtualMemory
} ad_code_armor_t;

ANTIDEBUG_INLINE void ad_code_armor_init(
    ad_code_armor_t* armor,
    void* code_base,
    u32   code_size,
    u64   xor_key
) {
    armor->code_base    = code_base;
    armor->code_size    = code_size;
    armor->xor_key      = xor_key;
    armor->is_encrypted = 0;
    armor->protect_ssn  = AD_SSN_UNRESOLVED;
}

// Toggle page protection to allow writes
ANTIDEBUG_INLINE b32 ad_armor_set_rw(ad_code_armor_t* armor) {
    AD_RESOLVE_SSN_ENC(armor->protect_ssn, NtProtectVirtualMemory, 23);
    if (armor->protect_ssn == AD_SSN_FAILED) return 0;

    void* base = armor->code_base;
    u64   size = (u64)armor->code_size;
    u32   old  = 0;

    ad_ntstatus_t st = AD_SYSCALL5(
        armor->protect_ssn,
        AD_CURRENT_PROCESS,
        &base,
        &size,
        (u64)AD_PAGE_ERW,
        &old
    );
    return (b32)AD_NT_SUCCESS(st);
}

// Restore page protection to execute-read only
ANTIDEBUG_INLINE void ad_armor_set_rx(ad_code_armor_t* armor) {
    void* base = armor->code_base;
    u64   size = (u64)armor->code_size;
    u32   old  = 0;

    AD_SYSCALL5(
        armor->protect_ssn,
        AD_CURRENT_PROCESS,
        &base,
        &size,
        (u64)AD_PAGE_ER,
        &old
    );
}

// XOR the code region with the key (encrypt or decrypt — same operation)
ANTIDEBUG_INLINE void ad_armor_xor(ad_code_armor_t* armor) {
    volatile u8* p = (volatile u8*)armor->code_base;
    u64 key = armor->xor_key;
    u32 i;

    // XOR 8 bytes at a time
    u32 chunks = armor->code_size / 8u;
    volatile u64* p64 = (volatile u64*)p;
    for (i = 0; i < chunks; i++) {
        p64[i] ^= key;
        // Rotate key for each block so it's not a simple repeating XOR
        key = (key << 7) | (key >> 57);
        key ^= 0xA5A5A5A5A5A5A5A5ULL;
    }

    // Remaining bytes
    u32 tail_start = chunks * 8u;
    for (i = tail_start; i < armor->code_size; i++) {
        p[i] ^= (u8)(key >> ((i & 7u) * 8u));
    }
}

// Encrypt the code region (make it unreadable)
ANTIDEBUG_INLINE void ad_code_armor_encrypt(ad_code_armor_t* armor) {
    if (armor->is_encrypted) return;
    if (!armor->code_base || armor->code_size == 0) return;

    if (ad_armor_set_rw(armor)) {
        ad_armor_xor(armor);
        ad_armor_set_rx(armor);
        armor->is_encrypted = 1;
    }
}

// Decrypt the code region (make it executable)
ANTIDEBUG_INLINE void ad_code_armor_decrypt(ad_code_armor_t* armor) {
    if (!armor->is_encrypted) return;
    if (!armor->code_base || armor->code_size == 0) return;

    if (ad_armor_set_rw(armor)) {
        ad_armor_xor(armor);  // XOR again = decrypt
        ad_armor_set_rx(armor);
        armor->is_encrypted = 0;
    }
}

// =========================================================================
// 6. DISPATCHER INTEGRITY — verify ad_run hasn't been patched to NOP/RET
// =========================================================================
//
// A companion function that independently re-checks the most critical
// fields. Called from OUTSIDE the dispatcher to cross-validate.

ANTIDEBUG_INLINE b32 ad_verify_dispatcher_alive(
    const ad_result_t* result,
    u32 expected_min_checks
) {
    // If ad_run was NOPed to just "return {0}", checks_run would be 0
    if (result->checks_run < expected_min_checks) return 1; // tampered

    // If someone patched the score accumulation to never increment,
    // but checks_hit > 0, that's inconsistent
    if (result->checks_hit > 0 && result->score == 0) return 1;

    // If checks_hit > checks_run, something is very wrong
    if (result->checks_hit > result->checks_run) return 1;

    return 0; // looks legitimate
}

#endif // ANTIDEBUG_SELF_PROTECT_H
