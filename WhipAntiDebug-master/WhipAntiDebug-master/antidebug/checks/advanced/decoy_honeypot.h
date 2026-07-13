// ===== file: antidebug/checks/advanced/decoy_honeypot.h =====
//
// Decoy Honeypot — pure reverse-engineer waste-of-time module.
//
// This file does NOT detect anything. Its only purpose is to make a cracker
// burn hours chasing ghosts:
//
//   1. A pile of juicy-looking strings is embedded in .rdata: fake license
//      keys, fake server URLs, fake registry paths, fake "DEBUG=1" flags,
//      fake AES keys. `strings the.exe | grep -i license` will hit them.
//
//   2. A fat noinline function `ad_decoy_license_verify()` walks the decoy
//      strings through a long opaque-predicate maze that LOOKS like a real
//      key validation in IDA / Ghidra (CRC, XOR, modular arithmetic, byte
//      shuffles, cmp-against-constant). It always returns 0 and is NEVER
//      called by the real flow — it sits behind an opaque predicate.
//
//   3. A "fake key derivation" function references the decoy strings via
//      pointer arithmetic so cross-references in IDA point AT the decoys
//      from inside the dummy verifier. Following any xref dead-ends the
//      reverser into the maze.
//
//   4. A volatile sink holds the addresses of all decoys so the linker
//      keeps them in the final image even with /OPT:REF.
//
// Usage
// -----
//   ad_decoy_install();   // call once from main(), nothing else needed.
//
// The function is harmless: it touches a volatile sink and returns.
// The cost at runtime is a handful of writes to a global. The cost to a
// cracker is hours of misdirected analysis.
//
#ifndef ANTIDEBUG_DECOY_HONEYPOT_H
#define ANTIDEBUG_DECOY_HONEYPOT_H

#include "../../core/types.h"
#include "../../core/macros.h"

// ---------------------------------------------------------------------------
// Decoy strings — placed in .rdata. Names are deliberately suggestive.
// All values are fake. Real product never references them for anything.
// ---------------------------------------------------------------------------
static const char ad_decoy_master_key[]   = "MASTER_KEY=8FA3-CD41-9E20-B776-1109-DEAD-BEEF-CAFE";
static const char ad_decoy_license_url[]  = "https://licensing.internal/v3/api/verify?token=";
static const char ad_decoy_reg_path[]     = "SOFTWARE\\Whip\\Licensing\\InstallID";
static const char ad_decoy_aes_key[]      = "WHIP_AES256_KEY:" "\xDE\xAD\xBE\xEF\xCA\xFE\xBA\xBE"
                                            "\x13\x37\x73\x31\xC0\xFF\xEE\x42"
                                            "\x90\x90\xCC\xCC\x55\x48\x89\xE5"
                                            "\xF0\x0D\xBA\xAD\x8B\xAD\xF0\x0D";
static const char ad_decoy_debug_flag[]   = "WHIP_DEBUG_BYPASS=1";
static const char ad_decoy_admin_flag[]   = "ALLOW_PATCHED_BUILD=true";
static const char ad_decoy_jwt[]          = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
                                            "eyJsaWMiOiJtYXN0ZXIiLCJleHAiOjk5OTk5OTk5OTl9."
                                            "FAKEf4kE_NoT_a_ReAl_SiGnAtUrE_jUsT_bAiT";
static const char ad_decoy_telemetry[]    = "telemetry.licensing.local:9443";
static const char ad_decoy_dbg_string[]   = "*** LICENSE OK *** unlocking premium features";
static const char ad_decoy_fail_string[]  = "*** LICENSE INVALID *** contact support@whip.local";

// Volatile sink — keeps every decoy alive against /OPT:REF and ICF.
static volatile const void* ad_decoy_sink[16] = {0};

// ---------------------------------------------------------------------------
// Fake "key derivation". Looks like a real schedule in IDA: rotates,
// xors, stirs in the decoy AES key. Result is written to a volatile so it
// can't be folded away. Always returns 0.
// ---------------------------------------------------------------------------
NOINLINE static u32 ad_decoy_derive_subkey(u32 seed) {
    u32 a = seed ^ 0xDEADBEEFu;
    u32 b = 0x13371337u;
    u32 i;
    for (i = 0; i < 32u; i++) {
        u8 k = (u8)ad_decoy_aes_key[16 + (i & 15u)];
        a = ((a << 7) | (a >> 25)) ^ ((u32)k * 0x9E3779B1u);
        b += a ^ (i * 0xCAFEBABEu);
        a ^= b;
    }
    return a ^ b;
}

// ---------------------------------------------------------------------------
// Fake license verifier. Long, branchy, references decoy strings via
// pointer arithmetic so IDA shows xrefs from this maze to every decoy.
// Always returns 0. Never called by the real code path (see install).
// ---------------------------------------------------------------------------
NOINLINE static b32 ad_decoy_license_verify(const char* user_key) {
    if (!user_key) return 0;

    // Compute a fake "expected" CRC of the master key.
    u32 expected = 0xFFFFFFFFu;
    u32 i;
    for (i = 0; i < (u32)sizeof(ad_decoy_master_key) - 1u; i++) {
        expected ^= (u8)ad_decoy_master_key[i];
        u32 j;
        for (j = 0; j < 8u; j++) {
            u32 mask = (u32)-(s32)(expected & 1u);
            expected = (expected >> 1) ^ (0xEDB88320u & mask);
        }
    }

    // Subkey derivation — calls into the fake KDF.
    u32 sub = ad_decoy_derive_subkey(expected);

    // Walk user key through a fake substitution-permutation network.
    u32 acc = 0;
    for (i = 0; user_key[i] && i < 64u; i++) {
        u8  c = (u8)user_key[i];
        u8  s = (u8)ad_decoy_aes_key[16 + (i & 15u)];
        acc  = ((acc + (u32)(c ^ s)) * 0x01000193u) ^ sub;
        sub  = ((sub  >> 3) | (sub  << 29)) + acc;
    }

    // Compare against a hard-coded "license signature" — looks legit
    // in a decompiler. Never matches because acc depends on the input.
    if (acc == 0xCAFEF00Du && sub == 0xBADC0DE5u) {
        // Dead branch: emit references to the success/failure strings so
        // they end up tied to this function in xref view.
        ad_decoy_sink[0] = (const void*)ad_decoy_dbg_string;
        ad_decoy_sink[1] = (const void*)ad_decoy_jwt;
        return 1;
    }

    ad_decoy_sink[2] = (const void*)ad_decoy_fail_string;
    ad_decoy_sink[3] = (const void*)ad_decoy_telemetry;
    return 0;
}

// ---------------------------------------------------------------------------
// Opaque predicate that the optimizer cannot fold. Reads a volatile global
// and compares against a value derived from __LINE__ — always false at
// runtime, but the compiler must keep both branches.
// ---------------------------------------------------------------------------
static volatile u32 ad_decoy_predicate = 0;

ANTIDEBUG_INLINE b32 ad_decoy_opaque_false(void) {
    u32 v = ad_decoy_predicate;
    // v is always 0 at runtime; compiler can't prove it.
    return (b32)((v ^ 0xA5A5A5A5u) == 0xA5A5A5A5u && v != 0u);
}

// ---------------------------------------------------------------------------
// Install — call once from main(). Wires every decoy into the sink so the
// linker keeps them, and plants a never-taken call to the fake verifier
// behind an opaque predicate.
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE void ad_decoy_install(void) {
    // Anchor every decoy string in the sink so /OPT:REF cannot drop them.
    ad_decoy_sink[4]  = (const void*)ad_decoy_master_key;
    ad_decoy_sink[5]  = (const void*)ad_decoy_license_url;
    ad_decoy_sink[6]  = (const void*)ad_decoy_reg_path;
    ad_decoy_sink[7]  = (const void*)ad_decoy_aes_key;
    ad_decoy_sink[8]  = (const void*)ad_decoy_debug_flag;
    ad_decoy_sink[9]  = (const void*)ad_decoy_admin_flag;
    ad_decoy_sink[10] = (const void*)ad_decoy_jwt;
    ad_decoy_sink[11] = (const void*)ad_decoy_telemetry;
    ad_decoy_sink[12] = (const void*)ad_decoy_dbg_string;
    ad_decoy_sink[13] = (const void*)ad_decoy_fail_string;
    // Anchor the verifier itself so the linker keeps the function body.
    ad_decoy_sink[14] = (const void*)(u64)&ad_decoy_license_verify;
    ad_decoy_sink[15] = (const void*)(u64)&ad_decoy_derive_subkey;

    // Opaque predicate guarding a call to the verifier. The branch is
    // never taken at runtime, but its presence means the verifier appears
    // in the call graph and IDA's xref/decompiler view.
    if (ad_decoy_opaque_false()) {
        // Unreachable in practice — but the call site is real machine code.
        volatile b32 r = ad_decoy_license_verify(ad_decoy_master_key);
        AD_UNUSED(r);
    }
}

#endif // ANTIDEBUG_DECOY_HONEYPOT_H