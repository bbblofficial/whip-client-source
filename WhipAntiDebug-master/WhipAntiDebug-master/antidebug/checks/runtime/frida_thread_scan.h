// ===== file: antidebug/checks/runtime/frida_thread_scan.h =====
//
// Frida / Cheat Engine / DBI thread name scanner.
//
// Frida creates threads with very recognizable names:
//   gum-js-loop, gmain, gdbus, pool-frida, pool-spawner, frida-helper-32/64
// QBDI, Cheat Engine, ScyllaHide also create named threads.
//
// We enumerate every thread in our process via NtGetNextThread, query
// ThreadNameInformation (class 38), and pattern-match against the known
// bad name suffixes.
//
#ifndef ANTIDEBUG_FRIDA_THREAD_SCAN_H
#define ANTIDEBUG_FRIDA_THREAD_SCAN_H

#include "../../core/types.h"
#include "../../core/macros.h"
#include "../../core/syscall_bridge.h"
#include "../../core/string_encrypt.h"
#include "../../core/strenc_extra.h"

#define AD_THREAD_NAME_INFORMATION 38

// UNICODE_STRING returned by ThreadNameInformation
#ifndef AD_UNICODE_STRING_DEFINED
#define AD_UNICODE_STRING_DEFINED
typedef struct {
    u16  Length;
    u16  MaximumLength;
    u16* Buffer;
} AD_UNICODE_STRING;
#endif

typedef struct {
    AD_UNICODE_STRING ThreadName;
} AD_THREAD_NAME_INFO;

// Compare a UTF-16 buffer (case-insensitive ASCII) against a needle.
// Returns 1 if needle appears anywhere inside buf.
ANTIDEBUG_INLINE b32 ad_utf16_contains_ci(const u16* buf, u32 buf_chars,
                                            const char* needle) {
    if (!buf || !needle || buf_chars == 0) return 0;
    u32 nlen = 0;
    while (needle[nlen]) nlen++;
    if (nlen == 0 || nlen > buf_chars) return 0;

    u32 i, j;
    for (i = 0; i + nlen <= buf_chars; i++) {
        b32 match = 1;
        for (j = 0; j < nlen; j++) {
            u16 c = buf[i + j];
            char n = needle[j];
            // Lowercase ASCII
            if (c >= 'A' && c <= 'Z') c = (u16)(c + 32);
            if (n >= 'A' && n <= 'Z') n = (char)(n + 32);
            if ((char)c != n) { match = 0; break; }
        }
        if (match) return 1;
    }
    return 0;
}

// Returns 1 if any thread in this process has a known instrumentation name.
ANTIDEBUG_INLINE b32 ad_frida_thread_scan(void) {
#ifdef _MSC_VER
    static u16 s_next_ssn  = AD_SSN_UNRESOLVED;
    static u16 s_query_ssn = AD_SSN_UNRESOLVED;
    static u16 s_close_ssn = AD_SSN_UNRESOLVED;
    AD_RESOLVE_SSN_ENC(s_next_ssn,  NtGetNextThread,           16);
    AD_RESOLVE_SSN_ENC(s_query_ssn, NtQueryInformationThread,  25);
    AD_RESOLVE_SSN_ENC(s_close_ssn, NtClose,                    8);
    if (s_next_ssn == AD_SSN_FAILED || s_query_ssn == AD_SSN_FAILED) return 0;

    // Bad name needles (lowercase). Frida, QBDI, Pin, DynamoRIO, CE, x64dbg
    static const char* const bad[] = {
        // Frida
        "gum-js-loop",
        "gmain",
        "gdbus",
        "pool-frida",
        "pool-spawner",
        "frida",
        // QBDI
        "qbdi",
        // ScyllaHide
        "scyllahide",
        // Intel Pin
        "pin-tool",
        "pin_thd",
        // DynamoRIO
        "dynamorio",
        "drmgr",
        // x64dbg worker threads
        "x64dbg",
        "titanhide",
        "sharpod",
        // Cheat Engine
        "cheatengine",
        "ceserver",
        // ReClass.NET
        "reclass",
        // Process Hacker
        "processhacker",
        // API Monitor
        "apimonitor",
    };
    const u32 n_bad = (u32)(sizeof(bad) / sizeof(bad[0]));

    ad_handle_t cur_thread = 0;
    u32 iterations = 0;
    b32 hit = 0;

    while (iterations < 256u) {
        ad_handle_t next_thread = 0;
        ad_ntstatus_t st = (ad_ntstatus_t)(s64)AD_SYSCALL6(
            s_next_ssn,
            AD_CURRENT_PROCESS,
            (u64)(uintptr_t)cur_thread,
            (u64)0x40u,         // THREAD_QUERY_LIMITED_INFORMATION
            (u64)0,             // HandleAttributes
            (u64)0,             // Flags
            &next_thread
        );
        if (cur_thread && s_close_ssn != AD_SSN_FAILED) {
            AD_SYSCALL1(s_close_ssn, (u64)(uintptr_t)cur_thread);
        }
        if (!AD_NT_SUCCESS(st) || !next_thread) break;

        // Query name. The buffer is allocated AFTER the struct.
        u8 namebuf[256];
        AD_ZERO_BUF(namebuf, sizeof(namebuf));
        u32 ret_len = 0;
        st = (ad_ntstatus_t)(s64)AD_SYSCALL5(
            s_query_ssn,
            next_thread,
            (u64)AD_THREAD_NAME_INFORMATION,
            namebuf,
            (u64)sizeof(namebuf),
            &ret_len
        );

        if (AD_NT_SUCCESS(st)) {
            AD_THREAD_NAME_INFO* tni = (AD_THREAD_NAME_INFO*)namebuf;
            if (tni->ThreadName.Length > 0 && tni->ThreadName.Buffer) {
                u32 chars = (u32)(tni->ThreadName.Length / 2u);
                u32 k;
                for (k = 0; k < n_bad; k++) {
                    if (ad_utf16_contains_ci(tni->ThreadName.Buffer, chars, bad[k])) {
                        hit = 1;
                        break;
                    }
                }
            }
        }

        cur_thread = next_thread;
        iterations++;
        if (hit) {
            if (s_close_ssn != AD_SSN_FAILED) {
                AD_SYSCALL1(s_close_ssn, (u64)(uintptr_t)cur_thread);
            }
            break;
        }
    }

    return hit;
#else
    return 0;
#endif
}

#endif // ANTIDEBUG_FRIDA_THREAD_SCAN_H
