// ===== file: antidebug/core/string_encrypt.h =====
//
// Compile-time string obfuscation for anti-debug framework.
//
// Problem:
//   Strings like "NtQueryInformationProcess" appear in plaintext in the
//   .rdata section of the compiled binary. Any reverse engineer running
//   `strings` or checking Cutter/IDA will immediately see them.
//
// Solution:
//   1. XOR each character at compile time with a key derived from __LINE__
//   2. Decrypt on the stack at runtime (never in .rdata)
//   3. Zero the stack buffer after use (anti-dump)
//
// All macros are designed for C (not C++) — no constexpr, no templates.
//
// Usage:
//   AD_STACK_STR(buf, "NtQueryInformationProcess");
//   // buf now contains the decrypted string on the stack
//   whip_bridge_resolve(buf);
//   AD_WIPE_STR(buf);
//
#ifndef ANTIDEBUG_STRING_ENCRYPT_H
#define ANTIDEBUG_STRING_ENCRYPT_H

#include "macros.h"

// ---------------------------------------------------------------------------
// XOR key derivation — uses __LINE__ and a compile-time seed so each
// call site gets a different key. The key is a single byte.
// ---------------------------------------------------------------------------
#define AD_STR_KEY(seed) ((u8)(((seed) ^ 0x5A ^ (__LINE__ * 131 + 17)) & 0xFF))

// ---------------------------------------------------------------------------
// Stack-string builder macros
//
// These build a string character-by-character on the stack. The characters
// are XOR'd with a per-site key in the source, but the compiler resolves
// all constant expressions at compile time. The resulting machine code is
// a series of MOV BYTE [rsp+N], imm8 instructions — no .rdata reference.
//
// MSVC with /O2 will fold the XOR constants, so the actual bytes written
// are the plaintext characters, BUT they are never stored as a contiguous
// string literal in the binary. They appear as immediate operands in
// individual MOV instructions, spread across the function body.
//
// For stronger obfuscation, we split into encode+decode: each byte is
// stored XOR'd, then a runtime loop decodes. This prevents the optimizer
// from folding them back to plaintext.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Encoding variant 1: XOR (original) — decode with XOR
// ---------------------------------------------------------------------------
#define AD_ENC(a, i, c, k) ((a)[(i)] = (char)((u8)(c) ^ (k)))

#define AD_DECODE_BUF(a, len, k)                        \
    do {                                                \
        volatile u8 _dk = (k);                          \
        for (unsigned _di = 0; _di < (len); _di++)      \
            (a)[_di] = (char)((u8)(a)[_di] ^ _dk);     \
        (a)[(len)] = '\0';                              \
    } while (0)

// ---------------------------------------------------------------------------
// Encoding variant 2: ADD — each byte stored as (char + key), decoded by SUB
// An IDA script that handles XOR won't decode ADD-encoded strings.
// ---------------------------------------------------------------------------
#define AD_ENC_ADD(a, i, c, k) ((a)[(i)] = (char)((u8)(c) + (k)))

#define AD_DECODE_BUF_ADD(a, len, k)                    \
    do {                                                \
        volatile u8 _dk = (k);                          \
        for (unsigned _di = 0; _di < (len); _di++)      \
            (a)[_di] = (char)((u8)(a)[_di] - _dk);     \
        (a)[(len)] = '\0';                              \
    } while (0)

// ---------------------------------------------------------------------------
// Encoding variant 3: ROT — each byte stored as ((char + key) ^ index),
// decoded by (byte ^ index) - key. Two-operation decode defeats simple
// single-op pattern matching.
// ---------------------------------------------------------------------------
#define AD_ENC_ROT(a, i, c, k) ((a)[(i)] = (char)(((u8)(c) + (k)) ^ (u8)(i)))

#define AD_DECODE_BUF_ROT(a, len, k)                    \
    do {                                                \
        volatile u8 _dk = (k);                          \
        for (unsigned _di = 0; _di < (len); _di++)      \
            (a)[_di] = (char)(((u8)(a)[_di] ^ (u8)_di) - _dk); \
        (a)[(len)] = '\0';                              \
    } while (0)

// Wipe a stack string after use
#define AD_WIPE_STR(buf, size)                          \
    do {                                                \
        volatile char* _wp = (volatile char*)(buf);     \
        for (unsigned _wi = 0; _wi < (size); _wi++)     \
            _wp[_wi] = 0;                               \
    } while (0)

// ---------------------------------------------------------------------------
// Per-function-name macros: "NtQueryInformationProcess" (25 chars)
// ---------------------------------------------------------------------------
#define AD_STRENC_NtQueryInformationProcess(buf)                             \
    do {                                                                     \
        const u8 _k = AD_STR_KEY(0xA3);                                     \
        char buf##_e[26];                                                    \
        AD_ENC(buf##_e,  0, 'N', _k); AD_ENC(buf##_e,  1, 't', _k);       \
        AD_ENC(buf##_e,  2, 'Q', _k); AD_ENC(buf##_e,  3, 'u', _k);       \
        AD_ENC(buf##_e,  4, 'e', _k); AD_ENC(buf##_e,  5, 'r', _k);       \
        AD_ENC(buf##_e,  6, 'y', _k); AD_ENC(buf##_e,  7, 'I', _k);       \
        AD_ENC(buf##_e,  8, 'n', _k); AD_ENC(buf##_e,  9, 'f', _k);       \
        AD_ENC(buf##_e, 10, 'o', _k); AD_ENC(buf##_e, 11, 'r', _k);       \
        AD_ENC(buf##_e, 12, 'm', _k); AD_ENC(buf##_e, 13, 'a', _k);       \
        AD_ENC(buf##_e, 14, 't', _k); AD_ENC(buf##_e, 15, 'i', _k);       \
        AD_ENC(buf##_e, 16, 'o', _k); AD_ENC(buf##_e, 17, 'n', _k);       \
        AD_ENC(buf##_e, 18, 'P', _k); AD_ENC(buf##_e, 19, 'r', _k);       \
        AD_ENC(buf##_e, 20, 'o', _k); AD_ENC(buf##_e, 21, 'c', _k);       \
        AD_ENC(buf##_e, 22, 'e', _k); AD_ENC(buf##_e, 23, 's', _k);       \
        AD_ENC(buf##_e, 24, 's', _k);                                       \
        AD_DECODE_BUF(buf##_e, 25, _k);                                     \
        for (unsigned _ci = 0; _ci < 26; _ci++) (buf)[_ci] = buf##_e[_ci];  \
    } while (0)

// ---------------------------------------------------------------------------
// "NtGetContextThread" (18 chars)
// ---------------------------------------------------------------------------
#define AD_STRENC_NtGetContextThread(buf)                                    \
    do {                                                                     \
        const u8 _k = AD_STR_KEY(0xB7);                                     \
        char buf##_e[19];                                                    \
        AD_ENC(buf##_e,  0, 'N', _k); AD_ENC(buf##_e,  1, 't', _k);       \
        AD_ENC(buf##_e,  2, 'G', _k); AD_ENC(buf##_e,  3, 'e', _k);       \
        AD_ENC(buf##_e,  4, 't', _k); AD_ENC(buf##_e,  5, 'C', _k);       \
        AD_ENC(buf##_e,  6, 'o', _k); AD_ENC(buf##_e,  7, 'n', _k);       \
        AD_ENC(buf##_e,  8, 't', _k); AD_ENC(buf##_e,  9, 'e', _k);       \
        AD_ENC(buf##_e, 10, 'x', _k); AD_ENC(buf##_e, 11, 't', _k);       \
        AD_ENC(buf##_e, 12, 'T', _k); AD_ENC(buf##_e, 13, 'h', _k);       \
        AD_ENC(buf##_e, 14, 'r', _k); AD_ENC(buf##_e, 15, 'e', _k);       \
        AD_ENC(buf##_e, 16, 'a', _k); AD_ENC(buf##_e, 17, 'd', _k);       \
        AD_DECODE_BUF(buf##_e, 18, _k);                                     \
        for (unsigned _ci = 0; _ci < 19; _ci++) (buf)[_ci] = buf##_e[_ci];  \
    } while (0)

// ---------------------------------------------------------------------------
// "NtSetInformationThread" (22 chars)
// ---------------------------------------------------------------------------
#define AD_STRENC_NtSetInformationThread(buf)                                \
    do {                                                                     \
        const u8 _k = AD_STR_KEY(0xC1);                                     \
        char buf##_e[23];                                                    \
        AD_ENC(buf##_e,  0, 'N', _k); AD_ENC(buf##_e,  1, 't', _k);       \
        AD_ENC(buf##_e,  2, 'S', _k); AD_ENC(buf##_e,  3, 'e', _k);       \
        AD_ENC(buf##_e,  4, 't', _k); AD_ENC(buf##_e,  5, 'I', _k);       \
        AD_ENC(buf##_e,  6, 'n', _k); AD_ENC(buf##_e,  7, 'f', _k);       \
        AD_ENC(buf##_e,  8, 'o', _k); AD_ENC(buf##_e,  9, 'r', _k);       \
        AD_ENC(buf##_e, 10, 'm', _k); AD_ENC(buf##_e, 11, 'a', _k);       \
        AD_ENC(buf##_e, 12, 't', _k); AD_ENC(buf##_e, 13, 'i', _k);       \
        AD_ENC(buf##_e, 14, 'o', _k); AD_ENC(buf##_e, 15, 'n', _k);       \
        AD_ENC(buf##_e, 16, 'T', _k); AD_ENC(buf##_e, 17, 'h', _k);       \
        AD_ENC(buf##_e, 18, 'r', _k); AD_ENC(buf##_e, 19, 'e', _k);       \
        AD_ENC(buf##_e, 20, 'a', _k); AD_ENC(buf##_e, 21, 'd', _k);       \
        AD_DECODE_BUF(buf##_e, 22, _k);                                     \
        for (unsigned _ci = 0; _ci < 23; _ci++) (buf)[_ci] = buf##_e[_ci];  \
    } while (0)

// ---------------------------------------------------------------------------
// "NtClose" (7 chars)
// ---------------------------------------------------------------------------
#define AD_STRENC_NtClose(buf)                                               \
    do {                                                                     \
        const u8 _k = AD_STR_KEY(0xD5);                                     \
        char buf##_e[8];                                                     \
        AD_ENC(buf##_e, 0, 'N', _k); AD_ENC(buf##_e, 1, 't', _k);         \
        AD_ENC(buf##_e, 2, 'C', _k); AD_ENC(buf##_e, 3, 'l', _k);         \
        AD_ENC(buf##_e, 4, 'o', _k); AD_ENC(buf##_e, 5, 's', _k);         \
        AD_ENC(buf##_e, 6, 'e', _k);                                        \
        AD_DECODE_BUF(buf##_e, 7, _k);                                      \
        for (unsigned _ci = 0; _ci < 8; _ci++) (buf)[_ci] = buf##_e[_ci];   \
    } while (0)

// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// "NtOpenProcess" (13 chars)
// ---------------------------------------------------------------------------
#define AD_STRENC_NtOpenProcess(buf)                                         \
    do {                                                                     \
        const u8 _k = AD_STR_KEY(0xC7);                                     \
        char buf##_e[14];                                                    \
        AD_ENC(buf##_e,  0, 'N', _k); AD_ENC(buf##_e,  1, 't', _k);       \
        AD_ENC(buf##_e,  2, 'O', _k); AD_ENC(buf##_e,  3, 'p', _k);       \
        AD_ENC(buf##_e,  4, 'e', _k); AD_ENC(buf##_e,  5, 'n', _k);       \
        AD_ENC(buf##_e,  6, 'P', _k); AD_ENC(buf##_e,  7, 'r', _k);       \
        AD_ENC(buf##_e,  8, 'o', _k); AD_ENC(buf##_e,  9, 'c', _k);       \
        AD_ENC(buf##_e, 10, 'e', _k); AD_ENC(buf##_e, 11, 's', _k);       \
        AD_ENC(buf##_e, 12, 's', _k);                                       \
        AD_DECODE_BUF(buf##_e, 13, _k);                                     \
        for (unsigned _ci = 0; _ci < 14; _ci++) (buf)[_ci] = buf##_e[_ci]; \
    } while (0)

// ---------------------------------------------------------------------------
// "NtQuerySystemInformation" (24 chars)
// ---------------------------------------------------------------------------
#define AD_STRENC_NtQuerySystemInformation(buf)                              \
    do {                                                                     \
        const u8 _k = AD_STR_KEY(0xD8);                                     \
        char buf##_e[25];                                                    \
        AD_ENC(buf##_e,  0, 'N', _k); AD_ENC(buf##_e,  1, 't', _k);       \
        AD_ENC(buf##_e,  2, 'Q', _k); AD_ENC(buf##_e,  3, 'u', _k);       \
        AD_ENC(buf##_e,  4, 'e', _k); AD_ENC(buf##_e,  5, 'r', _k);       \
        AD_ENC(buf##_e,  6, 'y', _k); AD_ENC(buf##_e,  7, 'S', _k);       \
        AD_ENC(buf##_e,  8, 'y', _k); AD_ENC(buf##_e,  9, 's', _k);       \
        AD_ENC(buf##_e, 10, 't', _k); AD_ENC(buf##_e, 11, 'e', _k);       \
        AD_ENC(buf##_e, 12, 'm', _k); AD_ENC(buf##_e, 13, 'I', _k);       \
        AD_ENC(buf##_e, 14, 'n', _k); AD_ENC(buf##_e, 15, 'f', _k);       \
        AD_ENC(buf##_e, 16, 'o', _k); AD_ENC(buf##_e, 17, 'r', _k);       \
        AD_ENC(buf##_e, 18, 'm', _k); AD_ENC(buf##_e, 19, 'a', _k);       \
        AD_ENC(buf##_e, 20, 't', _k); AD_ENC(buf##_e, 21, 'i', _k);       \
        AD_ENC(buf##_e, 22, 'o', _k); AD_ENC(buf##_e, 23, 'n', _k);       \
        AD_DECODE_BUF(buf##_e, 24, _k);                                     \
        for (unsigned _ci = 0; _ci < 25; _ci++) (buf)[_ci] = buf##_e[_ci]; \
    } while (0)

// ---------------------------------------------------------------------------
// "NtAllocateVirtualMemory" (23 chars)
// ---------------------------------------------------------------------------
#define AD_STRENC_NtAllocateVirtualMemory(buf)                               \
    do {                                                                     \
        const u8 _k = AD_STR_KEY(0xE2);                                     \
        char buf##_e[24];                                                    \
        AD_ENC(buf##_e,  0, 'N', _k); AD_ENC(buf##_e,  1, 't', _k);       \
        AD_ENC(buf##_e,  2, 'A', _k); AD_ENC(buf##_e,  3, 'l', _k);       \
        AD_ENC(buf##_e,  4, 'l', _k); AD_ENC(buf##_e,  5, 'o', _k);       \
        AD_ENC(buf##_e,  6, 'c', _k); AD_ENC(buf##_e,  7, 'a', _k);       \
        AD_ENC(buf##_e,  8, 't', _k); AD_ENC(buf##_e,  9, 'e', _k);       \
        AD_ENC(buf##_e, 10, 'V', _k); AD_ENC(buf##_e, 11, 'i', _k);       \
        AD_ENC(buf##_e, 12, 'r', _k); AD_ENC(buf##_e, 13, 't', _k);       \
        AD_ENC(buf##_e, 14, 'u', _k); AD_ENC(buf##_e, 15, 'a', _k);       \
        AD_ENC(buf##_e, 16, 'l', _k); AD_ENC(buf##_e, 17, 'M', _k);       \
        AD_ENC(buf##_e, 18, 'e', _k); AD_ENC(buf##_e, 19, 'm', _k);       \
        AD_ENC(buf##_e, 20, 'o', _k); AD_ENC(buf##_e, 21, 'r', _k);       \
        AD_ENC(buf##_e, 22, 'y', _k);                                       \
        AD_DECODE_BUF(buf##_e, 23, _k);                                     \
        for (unsigned _ci = 0; _ci < 24; _ci++) (buf)[_ci] = buf##_e[_ci]; \
    } while (0)

// ---------------------------------------------------------------------------
// "NtFreeVirtualMemory" (19 chars)
// ---------------------------------------------------------------------------
#define AD_STRENC_NtFreeVirtualMemory(buf)                                   \
    do {                                                                     \
        const u8 _k = AD_STR_KEY(0xF3);                                     \
        char buf##_e[20];                                                    \
        AD_ENC(buf##_e,  0, 'N', _k); AD_ENC(buf##_e,  1, 't', _k);       \
        AD_ENC(buf##_e,  2, 'F', _k); AD_ENC(buf##_e,  3, 'r', _k);       \
        AD_ENC(buf##_e,  4, 'e', _k); AD_ENC(buf##_e,  5, 'e', _k);       \
        AD_ENC(buf##_e,  6, 'V', _k); AD_ENC(buf##_e,  7, 'i', _k);       \
        AD_ENC(buf##_e,  8, 'r', _k); AD_ENC(buf##_e,  9, 't', _k);       \
        AD_ENC(buf##_e, 10, 'u', _k); AD_ENC(buf##_e, 11, 'a', _k);       \
        AD_ENC(buf##_e, 12, 'l', _k); AD_ENC(buf##_e, 13, 'M', _k);       \
        AD_ENC(buf##_e, 14, 'e', _k); AD_ENC(buf##_e, 15, 'm', _k);       \
        AD_ENC(buf##_e, 16, 'o', _k); AD_ENC(buf##_e, 17, 'r', _k);       \
        AD_ENC(buf##_e, 18, 'y', _k);                                       \
        AD_DECODE_BUF(buf##_e, 19, _k);                                     \
        for (unsigned _ci = 0; _ci < 20; _ci++) (buf)[_ci] = buf##_e[_ci]; \
    } while (0)

// ---------------------------------------------------------------------------
// "NtSetContextThread" (18 chars)
// ---------------------------------------------------------------------------
#define AD_STRENC_NtSetContextThread(buf)                                    \
    do {                                                                     \
        const u8 _k = AD_STR_KEY(0xA7);                                     \
        char buf##_e[19];                                                    \
        AD_ENC(buf##_e,  0, 'N', _k); AD_ENC(buf##_e,  1, 't', _k);       \
        AD_ENC(buf##_e,  2, 'S', _k); AD_ENC(buf##_e,  3, 'e', _k);       \
        AD_ENC(buf##_e,  4, 't', _k); AD_ENC(buf##_e,  5, 'C', _k);       \
        AD_ENC(buf##_e,  6, 'o', _k); AD_ENC(buf##_e,  7, 'n', _k);       \
        AD_ENC(buf##_e,  8, 't', _k); AD_ENC(buf##_e,  9, 'e', _k);       \
        AD_ENC(buf##_e, 10, 'x', _k); AD_ENC(buf##_e, 11, 't', _k);       \
        AD_ENC(buf##_e, 12, 'T', _k); AD_ENC(buf##_e, 13, 'h', _k);       \
        AD_ENC(buf##_e, 14, 'r', _k); AD_ENC(buf##_e, 15, 'e', _k);       \
        AD_ENC(buf##_e, 16, 'a', _k); AD_ENC(buf##_e, 17, 'd', _k);       \
        AD_DECODE_BUF(buf##_e, 18, _k);                                     \
        for (unsigned _ci = 0; _ci < 19; _ci++) (buf)[_ci] = buf##_e[_ci]; \
    } while (0)

// ---------------------------------------------------------------------------
// "NtReadVirtualMemory" (19 chars)
// ---------------------------------------------------------------------------
#define AD_STRENC_NtReadVirtualMemory(buf)                                   \
    do {                                                                     \
        const u8 _k = AD_STR_KEY(0xB4);                                     \
        char buf##_e[20];                                                    \
        AD_ENC(buf##_e,  0, 'N', _k); AD_ENC(buf##_e,  1, 't', _k);       \
        AD_ENC(buf##_e,  2, 'R', _k); AD_ENC(buf##_e,  3, 'e', _k);       \
        AD_ENC(buf##_e,  4, 'a', _k); AD_ENC(buf##_e,  5, 'd', _k);       \
        AD_ENC(buf##_e,  6, 'V', _k); AD_ENC(buf##_e,  7, 'i', _k);       \
        AD_ENC(buf##_e,  8, 'r', _k); AD_ENC(buf##_e,  9, 't', _k);       \
        AD_ENC(buf##_e, 10, 'u', _k); AD_ENC(buf##_e, 11, 'a', _k);       \
        AD_ENC(buf##_e, 12, 'l', _k); AD_ENC(buf##_e, 13, 'M', _k);       \
        AD_ENC(buf##_e, 14, 'e', _k); AD_ENC(buf##_e, 15, 'm', _k);       \
        AD_ENC(buf##_e, 16, 'o', _k); AD_ENC(buf##_e, 17, 'r', _k);       \
        AD_ENC(buf##_e, 18, 'y', _k);                                       \
        AD_DECODE_BUF(buf##_e, 19, _k);                                     \
        for (unsigned _ci = 0; _ci < 20; _ci++) (buf)[_ci] = buf##_e[_ci]; \
    } while (0)

// ---------------------------------------------------------------------------
// Convenience: resolve SSN with encrypted string + auto-wipe
//
// Replaces:
//   AD_RESOLVE_SSN(s_ssn, "NtQueryInformationProcess");
// With:
//   AD_RESOLVE_SSN_ENC(s_ssn, NtQueryInformationProcess, 26);
// ---------------------------------------------------------------------------
#define AD_RESOLVE_SSN_ENC(var, name_macro, buf_size)     \
    do {                                                  \
        if ((var) == AD_SSN_UNRESOLVED) {                 \
            char _name_buf[buf_size];                     \
            AD_STRENC_##name_macro(_name_buf);            \
            (var) = whip_bridge_resolve(_name_buf);       \
            AD_WIPE_STR(_name_buf, buf_size);             \
        }                                                 \
    } while (0)

#endif // ANTIDEBUG_STRING_ENCRYPT_H