// ===== file: antidebug/core/strenc_extra.h =====
//
// Extra encrypted syscall name macros for Tier-S/A/B checks.
// Mirrors the pattern from antidebug/checks/debug/se_debug.h.
//
#ifndef ANTIDEBUG_STRENC_EXTRA_H
#define ANTIDEBUG_STRENC_EXTRA_H

#include "string_encrypt.h"

// ---------------------------------------------------------------------------
// "NtSetInformationProcess" — 23 chars → buf_size 24
// ---------------------------------------------------------------------------
#ifndef AD_STRENC_NtSetInformationProcess_DEFINED
#define AD_STRENC_NtSetInformationProcess_DEFINED
#define AD_STRENC_NtSetInformationProcess(buf)                                  \
    do {                                                                         \
        const u8 _k = AD_STR_KEY(0x41);                                         \
        char buf##_e[24];                                                        \
        AD_ENC(buf##_e,  0, 'N', _k); AD_ENC(buf##_e,  1, 't', _k);             \
        AD_ENC(buf##_e,  2, 'S', _k); AD_ENC(buf##_e,  3, 'e', _k);             \
        AD_ENC(buf##_e,  4, 't', _k); AD_ENC(buf##_e,  5, 'I', _k);             \
        AD_ENC(buf##_e,  6, 'n', _k); AD_ENC(buf##_e,  7, 'f', _k);             \
        AD_ENC(buf##_e,  8, 'o', _k); AD_ENC(buf##_e,  9, 'r', _k);             \
        AD_ENC(buf##_e, 10, 'm', _k); AD_ENC(buf##_e, 11, 'a', _k);             \
        AD_ENC(buf##_e, 12, 't', _k); AD_ENC(buf##_e, 13, 'i', _k);             \
        AD_ENC(buf##_e, 14, 'o', _k); AD_ENC(buf##_e, 15, 'n', _k);             \
        AD_ENC(buf##_e, 16, 'P', _k); AD_ENC(buf##_e, 17, 'r', _k);             \
        AD_ENC(buf##_e, 18, 'o', _k); AD_ENC(buf##_e, 19, 'c', _k);             \
        AD_ENC(buf##_e, 20, 'e', _k); AD_ENC(buf##_e, 21, 's', _k);             \
        AD_ENC(buf##_e, 22, 's', _k);                                            \
        AD_DECODE_BUF(buf##_e, 23, _k);                                          \
        for (unsigned _ci = 0; _ci < 24; _ci++) (buf)[_ci] = buf##_e[_ci];      \
    } while (0)
#endif

// ---------------------------------------------------------------------------
// "NtAdjustPrivilegesToken" — 23 chars → buf_size 24
// ---------------------------------------------------------------------------
#ifndef AD_STRENC_NtAdjustPrivilegesToken_DEFINED
#define AD_STRENC_NtAdjustPrivilegesToken_DEFINED
#define AD_STRENC_NtAdjustPrivilegesToken(buf)                                  \
    do {                                                                         \
        const u8 _k = AD_STR_KEY(0x55);                                         \
        char buf##_e[24];                                                        \
        AD_ENC(buf##_e,  0, 'N', _k); AD_ENC(buf##_e,  1, 't', _k);             \
        AD_ENC(buf##_e,  2, 'A', _k); AD_ENC(buf##_e,  3, 'd', _k);             \
        AD_ENC(buf##_e,  4, 'j', _k); AD_ENC(buf##_e,  5, 'u', _k);             \
        AD_ENC(buf##_e,  6, 's', _k); AD_ENC(buf##_e,  7, 't', _k);             \
        AD_ENC(buf##_e,  8, 'P', _k); AD_ENC(buf##_e,  9, 'r', _k);             \
        AD_ENC(buf##_e, 10, 'i', _k); AD_ENC(buf##_e, 11, 'v', _k);             \
        AD_ENC(buf##_e, 12, 'i', _k); AD_ENC(buf##_e, 13, 'l', _k);             \
        AD_ENC(buf##_e, 14, 'e', _k); AD_ENC(buf##_e, 15, 'g', _k);             \
        AD_ENC(buf##_e, 16, 'e', _k); AD_ENC(buf##_e, 17, 's', _k);             \
        AD_ENC(buf##_e, 18, 'T', _k); AD_ENC(buf##_e, 19, 'o', _k);             \
        AD_ENC(buf##_e, 20, 'k', _k); AD_ENC(buf##_e, 21, 'e', _k);             \
        AD_ENC(buf##_e, 22, 'n', _k);                                            \
        AD_DECODE_BUF(buf##_e, 23, _k);                                          \
        for (unsigned _ci = 0; _ci < 24; _ci++) (buf)[_ci] = buf##_e[_ci];      \
    } while (0)
#endif

// ---------------------------------------------------------------------------
// "NtGetNextThread" — 15 chars → buf_size 16
// ---------------------------------------------------------------------------
#ifndef AD_STRENC_NtGetNextThread_DEFINED
#define AD_STRENC_NtGetNextThread_DEFINED
#define AD_STRENC_NtGetNextThread(buf)                                          \
    do {                                                                         \
        const u8 _k = AD_STR_KEY(0x91);                                         \
        char buf##_e[16];                                                        \
        AD_ENC(buf##_e,  0, 'N', _k); AD_ENC(buf##_e,  1, 't', _k);             \
        AD_ENC(buf##_e,  2, 'G', _k); AD_ENC(buf##_e,  3, 'e', _k);             \
        AD_ENC(buf##_e,  4, 't', _k); AD_ENC(buf##_e,  5, 'N', _k);             \
        AD_ENC(buf##_e,  6, 'e', _k); AD_ENC(buf##_e,  7, 'x', _k);             \
        AD_ENC(buf##_e,  8, 't', _k); AD_ENC(buf##_e,  9, 'T', _k);             \
        AD_ENC(buf##_e, 10, 'h', _k); AD_ENC(buf##_e, 11, 'r', _k);             \
        AD_ENC(buf##_e, 12, 'e', _k); AD_ENC(buf##_e, 13, 'a', _k);             \
        AD_ENC(buf##_e, 14, 'd', _k);                                            \
        AD_DECODE_BUF(buf##_e, 15, _k);                                          \
        for (unsigned _ci = 0; _ci < 16; _ci++) (buf)[_ci] = buf##_e[_ci];      \
    } while (0)
#endif

// ---------------------------------------------------------------------------
// "NtDelayExecution" — 16 chars → buf_size 17  (ADD encoding)
// ---------------------------------------------------------------------------
#ifndef AD_STRENC_NtDelayExecution_DEFINED
#define AD_STRENC_NtDelayExecution_DEFINED
#define AD_STRENC_NtDelayExecution(buf)                                         \
    do {                                                                         \
        const u8 _k = AD_STR_KEY(0xC3);                                         \
        char buf##_e[17];                                                        \
        AD_ENC_ADD(buf##_e,  0, 'N', _k); AD_ENC_ADD(buf##_e,  1, 't', _k);    \
        AD_ENC_ADD(buf##_e,  2, 'D', _k); AD_ENC_ADD(buf##_e,  3, 'e', _k);    \
        AD_ENC_ADD(buf##_e,  4, 'l', _k); AD_ENC_ADD(buf##_e,  5, 'a', _k);    \
        AD_ENC_ADD(buf##_e,  6, 'y', _k); AD_ENC_ADD(buf##_e,  7, 'E', _k);    \
        AD_ENC_ADD(buf##_e,  8, 'x', _k); AD_ENC_ADD(buf##_e,  9, 'e', _k);    \
        AD_ENC_ADD(buf##_e, 10, 'c', _k); AD_ENC_ADD(buf##_e, 11, 'u', _k);    \
        AD_ENC_ADD(buf##_e, 12, 't', _k); AD_ENC_ADD(buf##_e, 13, 'i', _k);    \
        AD_ENC_ADD(buf##_e, 14, 'o', _k); AD_ENC_ADD(buf##_e, 15, 'n', _k);    \
        AD_DECODE_BUF_ADD(buf##_e, 16, _k);                                     \
        for (unsigned _ci = 0; _ci < 17; _ci++) (buf)[_ci] = buf##_e[_ci];     \
    } while (0)
#endif

// ---------------------------------------------------------------------------
// "NtCreateThreadEx" — 16 chars → buf_size 17  (ROT encoding)
// ---------------------------------------------------------------------------
#ifndef AD_STRENC_NtCreateThreadEx_DEFINED
#define AD_STRENC_NtCreateThreadEx_DEFINED
#ifndef AD_STRENC_NtCreateThreadEx
#define AD_STRENC_NtCreateThreadEx(buf)                                         \
    do {                                                                         \
        const u8 _k = AD_STR_KEY(0xD7);                                         \
        char buf##_e[17];                                                        \
        AD_ENC_ROT(buf##_e,  0, 'N', _k); AD_ENC_ROT(buf##_e,  1, 't', _k);   \
        AD_ENC_ROT(buf##_e,  2, 'C', _k); AD_ENC_ROT(buf##_e,  3, 'r', _k);   \
        AD_ENC_ROT(buf##_e,  4, 'e', _k); AD_ENC_ROT(buf##_e,  5, 'a', _k);   \
        AD_ENC_ROT(buf##_e,  6, 't', _k); AD_ENC_ROT(buf##_e,  7, 'e', _k);   \
        AD_ENC_ROT(buf##_e,  8, 'T', _k); AD_ENC_ROT(buf##_e,  9, 'h', _k);   \
        AD_ENC_ROT(buf##_e, 10, 'r', _k); AD_ENC_ROT(buf##_e, 11, 'e', _k);   \
        AD_ENC_ROT(buf##_e, 12, 'a', _k); AD_ENC_ROT(buf##_e, 13, 'd', _k);   \
        AD_ENC_ROT(buf##_e, 14, 'E', _k); AD_ENC_ROT(buf##_e, 15, 'x', _k);   \
        AD_DECODE_BUF_ROT(buf##_e, 16, _k);                                     \
        for (unsigned _ci = 0; _ci < 17; _ci++) (buf)[_ci] = buf##_e[_ci];     \
    } while (0)
#endif // AD_STRENC_NtCreateThreadEx
#endif // AD_STRENC_NtCreateThreadEx_DEFINED

// ---------------------------------------------------------------------------
// "NtResumeThread" — 14 chars → buf_size 15  (XOR encoding)
// ---------------------------------------------------------------------------
#ifndef AD_STRENC_NtResumeThread_DEFINED
#define AD_STRENC_NtResumeThread_DEFINED
#define AD_STRENC_NtResumeThread(buf)                                           \
    do {                                                                         \
        const u8 _k = AD_STR_KEY(0xE9);                                         \
        char buf##_e[15];                                                        \
        AD_ENC(buf##_e,  0, 'N', _k); AD_ENC(buf##_e,  1, 't', _k);            \
        AD_ENC(buf##_e,  2, 'R', _k); AD_ENC(buf##_e,  3, 'e', _k);            \
        AD_ENC(buf##_e,  4, 's', _k); AD_ENC(buf##_e,  5, 'u', _k);            \
        AD_ENC(buf##_e,  6, 'm', _k); AD_ENC(buf##_e,  7, 'e', _k);            \
        AD_ENC(buf##_e,  8, 'T', _k); AD_ENC(buf##_e,  9, 'h', _k);            \
        AD_ENC(buf##_e, 10, 'r', _k); AD_ENC(buf##_e, 11, 'e', _k);            \
        AD_ENC(buf##_e, 12, 'a', _k); AD_ENC(buf##_e, 13, 'd', _k);            \
        AD_DECODE_BUF(buf##_e, 14, _k);                                         \
        for (unsigned _ci = 0; _ci < 15; _ci++) (buf)[_ci] = buf##_e[_ci];     \
    } while (0)
#endif

// ---------------------------------------------------------------------------
// "NtCreateFile" — 12 chars → buf_size 13  (XOR encoding)
// ---------------------------------------------------------------------------
#ifndef AD_STRENC_NtCreateFile_DEFINED
#define AD_STRENC_NtCreateFile_DEFINED
#define AD_STRENC_NtCreateFile(buf)                                             \
    do {                                                                         \
        const u8 _k = AD_STR_KEY(0xB4);                                         \
        char buf##_e[13];                                                        \
        AD_ENC(buf##_e,  0, 'N', _k); AD_ENC(buf##_e,  1, 't', _k);           \
        AD_ENC(buf##_e,  2, 'C', _k); AD_ENC(buf##_e,  3, 'r', _k);           \
        AD_ENC(buf##_e,  4, 'e', _k); AD_ENC(buf##_e,  5, 'a', _k);           \
        AD_ENC(buf##_e,  6, 't', _k); AD_ENC(buf##_e,  7, 'e', _k);           \
        AD_ENC(buf##_e,  8, 'F', _k); AD_ENC(buf##_e,  9, 'i', _k);           \
        AD_ENC(buf##_e, 10, 'l', _k); AD_ENC(buf##_e, 11, 'e', _k);           \
        AD_DECODE_BUF(buf##_e, 12, _k);                                         \
        for (unsigned _ci = 0; _ci < 13; _ci++) (buf)[_ci] = buf##_e[_ci];     \
    } while (0)
#endif

// ---------------------------------------------------------------------------
// "NtSystemDebugControl" — 20 chars → buf_size 21  (XOR encoding)
// ---------------------------------------------------------------------------
#ifndef AD_STRENC_NtSystemDebugControl_DEFINED
#define AD_STRENC_NtSystemDebugControl_DEFINED
#define AD_STRENC_NtSystemDebugControl(buf)                                     \
    do {                                                                         \
        const u8 _k = AD_STR_KEY(0xC5);                                         \
        char buf##_e[21];                                                        \
        AD_ENC(buf##_e,  0, 'N', _k); AD_ENC(buf##_e,  1, 't', _k);           \
        AD_ENC(buf##_e,  2, 'S', _k); AD_ENC(buf##_e,  3, 'y', _k);           \
        AD_ENC(buf##_e,  4, 's', _k); AD_ENC(buf##_e,  5, 't', _k);           \
        AD_ENC(buf##_e,  6, 'e', _k); AD_ENC(buf##_e,  7, 'm', _k);           \
        AD_ENC(buf##_e,  8, 'D', _k); AD_ENC(buf##_e,  9, 'e', _k);           \
        AD_ENC(buf##_e, 10, 'b', _k); AD_ENC(buf##_e, 11, 'u', _k);           \
        AD_ENC(buf##_e, 12, 'g', _k); AD_ENC(buf##_e, 13, 'C', _k);           \
        AD_ENC(buf##_e, 14, 'o', _k); AD_ENC(buf##_e, 15, 'n', _k);           \
        AD_ENC(buf##_e, 16, 't', _k); AD_ENC(buf##_e, 17, 'r', _k);           \
        AD_ENC(buf##_e, 18, 'o', _k); AD_ENC(buf##_e, 19, 'l', _k);           \
        AD_DECODE_BUF(buf##_e, 20, _k);                                         \
        for (unsigned _ci = 0; _ci < 21; _ci++) (buf)[_ci] = buf##_e[_ci];     \
    } while (0)
#endif

#endif // ANTIDEBUG_STRENC_EXTRA_H
