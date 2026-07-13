// ===== file: antidebug/checks/debug/se_debug.h =====
//
// SeDebugPrivilege detection — inspired by al-khaser SeDebugPrivilege.cpp.
//
// Technique:
//   SeDebugPrivilege (LUID = {0x14, 0}, decimal 20) allows a process to
//   open any other process, including system-protected ones like csrss.exe.
//   A normal application NEVER has SeDebugPrivilege enabled in its token.
//
//   Scenarios where we'd see SeDebugPrivilege:
//     - Anti-anti-debug tool elevated our token (ScyllaHide, etc.)
//     - Injected code inherited privileges from a high-privilege parent
//     - Malformed sandbox with overly permissive token setup
//
//   Flow:
//     1. NtOpenProcessToken(CurrentProcess, TOKEN_QUERY) → token handle
//     2. NtQueryInformationToken(token, TokenPrivileges=3) → privilege array
//     3. Walk array — look for LUID {0x14, 0} with SE_PRIVILEGE_ENABLED
//     4. Close token handle
//
//   Returns 1 if SeDebugPrivilege is present AND enabled in our own token.
//   Returns 0 otherwise (expected for any normal process).
//
#ifndef ANTIDEBUG_SE_DEBUG_H
#define ANTIDEBUG_SE_DEBUG_H

#include "../../core/types.h"
#include "../../core/macros.h"
#include "../../core/syscall_bridge.h"
#include "../../core/string_encrypt.h"

// ---------------------------------------------------------------------------
// Privilege structures — no winnt.h required
// ---------------------------------------------------------------------------
typedef struct {
    u32 LowPart;
    s32 HighPart;
} AD_LUID;

typedef struct {
    AD_LUID Luid;
    u32     Attributes;
} AD_LUID_AND_ATTRIBUTES;

typedef struct {
    u32                    PrivilegeCount;
    AD_LUID_AND_ATTRIBUTES Privileges[1];   // variable-length, indexing past [0] is safe
} AD_TOKEN_PRIVILEGES_HDR;

#define AD_TOKEN_QUERY           0x0008UL
#define AD_TOKEN_PRIVILEGES_CLS  3UL          // TokenPrivileges
#define AD_SE_PRIVILEGE_ENABLED  0x00000002UL
#define AD_SE_DEBUG_LUID_LOW     0x00000014UL  // LUID.LowPart for SeDebugPrivilege

// ---------------------------------------------------------------------------
// Encrypted: "NtOpenProcessToken" (18 chars → buf_size 19)
// ---------------------------------------------------------------------------
#ifndef AD_STRENC_NtOpenProcessToken_DEFINED
#define AD_STRENC_NtOpenProcessToken_DEFINED
#define AD_STRENC_NtOpenProcessToken(buf)                                      \
    do {                                                                       \
        const u8 _k = AD_STR_KEY(0x73);                                       \
        char buf##_e[19];                                                      \
        AD_ENC(buf##_e,  0, 'N', _k); AD_ENC(buf##_e,  1, 't', _k);         \
        AD_ENC(buf##_e,  2, 'O', _k); AD_ENC(buf##_e,  3, 'p', _k);         \
        AD_ENC(buf##_e,  4, 'e', _k); AD_ENC(buf##_e,  5, 'n', _k);         \
        AD_ENC(buf##_e,  6, 'P', _k); AD_ENC(buf##_e,  7, 'r', _k);         \
        AD_ENC(buf##_e,  8, 'o', _k); AD_ENC(buf##_e,  9, 'c', _k);         \
        AD_ENC(buf##_e, 10, 'e', _k); AD_ENC(buf##_e, 11, 's', _k);         \
        AD_ENC(buf##_e, 12, 's', _k); AD_ENC(buf##_e, 13, 'T', _k);         \
        AD_ENC(buf##_e, 14, 'o', _k); AD_ENC(buf##_e, 15, 'k', _k);         \
        AD_ENC(buf##_e, 16, 'e', _k); AD_ENC(buf##_e, 17, 'n', _k);         \
        AD_DECODE_BUF(buf##_e, 18, _k);                                       \
        for (unsigned _ci = 0; _ci < 19; _ci++) (buf)[_ci] = buf##_e[_ci];   \
    } while (0)
#endif

// ---------------------------------------------------------------------------
// Encrypted: "NtQueryInformationToken" (23 chars → buf_size 24)
// ---------------------------------------------------------------------------
#ifndef AD_STRENC_NtQueryInformationToken_DEFINED
#define AD_STRENC_NtQueryInformationToken_DEFINED
#define AD_STRENC_NtQueryInformationToken(buf)                                 \
    do {                                                                       \
        const u8 _k = AD_STR_KEY(0xE2);                                       \
        char buf##_e[24];                                                      \
        AD_ENC(buf##_e,  0, 'N', _k); AD_ENC(buf##_e,  1, 't', _k);         \
        AD_ENC(buf##_e,  2, 'Q', _k); AD_ENC(buf##_e,  3, 'u', _k);         \
        AD_ENC(buf##_e,  4, 'e', _k); AD_ENC(buf##_e,  5, 'r', _k);         \
        AD_ENC(buf##_e,  6, 'y', _k); AD_ENC(buf##_e,  7, 'I', _k);         \
        AD_ENC(buf##_e,  8, 'n', _k); AD_ENC(buf##_e,  9, 'f', _k);         \
        AD_ENC(buf##_e, 10, 'o', _k); AD_ENC(buf##_e, 11, 'r', _k);         \
        AD_ENC(buf##_e, 12, 'm', _k); AD_ENC(buf##_e, 13, 'a', _k);         \
        AD_ENC(buf##_e, 14, 't', _k); AD_ENC(buf##_e, 15, 'i', _k);         \
        AD_ENC(buf##_e, 16, 'o', _k); AD_ENC(buf##_e, 17, 'n', _k);         \
        AD_ENC(buf##_e, 18, 'T', _k); AD_ENC(buf##_e, 19, 'o', _k);         \
        AD_ENC(buf##_e, 20, 'k', _k); AD_ENC(buf##_e, 21, 'e', _k);         \
        AD_ENC(buf##_e, 22, 'n', _k);                                         \
        AD_DECODE_BUF(buf##_e, 23, _k);                                       \
        for (unsigned _ci = 0; _ci < 24; _ci++) (buf)[_ci] = buf##_e[_ci];   \
    } while (0)
#endif

#if defined(_MSC_VER)

// ---------------------------------------------------------------------------
// Check: SeDebugPrivilege enabled in our own process token.
//
// A process with SeDebugPrivilege enabled can open CSRSS, LSASS, and all
// other protected processes — a capability that normal applications never
// have. Its presence in our token is a strong signal of tampering.
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE b32 ad_se_debug_privilege(void) {
    static u16 s_ssn_tok   = AD_SSN_UNRESOLVED;
    static u16 s_ssn_qit   = AD_SSN_UNRESOLVED;
    static u16 s_ssn_close = AD_SSN_UNRESOLVED;

    AD_RESOLVE_SSN_ENC(s_ssn_tok,   NtOpenProcessToken,      19);
    AD_RESOLVE_SSN_ENC(s_ssn_qit,   NtQueryInformationToken, 24);
    AD_RESOLVE_SSN_ENC(s_ssn_close, NtClose,                  8);

    if (s_ssn_tok == AD_SSN_FAILED || s_ssn_qit == AD_SSN_FAILED) return 0;

    // Open our own process token with TOKEN_QUERY
    ad_handle_t tok = (ad_handle_t)0;
    ad_ntstatus_t st = AD_SYSCALL3(
        s_ssn_tok,
        AD_CURRENT_PROCESS,
        (u64)AD_TOKEN_QUERY,
        &tok
    );
    if (!AD_NT_SUCCESS(st) || !tok) return 0;

    // Query TokenPrivileges — each entry is LUID (8) + Attributes (4) = 12 bytes.
    // A typical process has 20-40 privileges.  800 bytes = 4-byte header + 66 entries.
    u8 priv_buf[800];
    AD_ZERO_BUF(priv_buf, sizeof(priv_buf));
    u32 ret_len = 0u;

    st = AD_SYSCALL5(
        s_ssn_qit,
        tok,
        (u64)AD_TOKEN_PRIVILEGES_CLS,
        priv_buf,
        (u64)sizeof(priv_buf),
        &ret_len
    );

    if (s_ssn_close != AD_SSN_FAILED)
        AD_SYSCALL1(s_ssn_close, (u64)tok);

    if (!AD_NT_SUCCESS(st)) return 0;

    // Walk the returned privilege array
    AD_TOKEN_PRIVILEGES_HDR* tp = (AD_TOKEN_PRIVILEGES_HDR*)priv_buf;
    u32 count = tp->PrivilegeCount;
    if (count > 64u) count = 64u;   // sanity cap

    b32 found = 0;
    u32 i;
    for (i = 0u; i < count; i++) {
        const AD_LUID_AND_ATTRIBUTES* la = &tp->Privileges[i];
        if (la->Luid.LowPart  == AD_SE_DEBUG_LUID_LOW &&
            la->Luid.HighPart == 0 &&
            (la->Attributes & AD_SE_PRIVILEGE_ENABLED) != 0u) {
            found = 1;
            break;
        }
    }

    AD_ZERO_BUF(priv_buf, sizeof(priv_buf));
    return found;
}

#else  // Non-MSVC stub
ANTIDEBUG_INLINE b32 ad_se_debug_privilege(void) { return 0; }
#endif // _MSC_VER

#endif // ANTIDEBUG_SE_DEBUG_H