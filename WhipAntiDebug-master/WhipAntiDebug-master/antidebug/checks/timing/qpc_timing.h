// ===== file: antidebug/checks/timing/qpc_timing.h =====
//
// Timing-based anti-debug via NtQueryPerformanceCounter syscall.
//
// Unlike RDTSC (which can be trapped by a hypervisor and returned a fake
// value), NtQueryPerformanceCounter goes through the kernel — harder to
// transparently intercept from user-mode.
//
// Technique:
//   1. Read QPC before a known-cost operation
//   2. Perform the operation (a calibrated loop)
//   3. Read QPC after
//   4. If delta exceeds threshold → single-stepping detected
//
#ifndef ANTIDEBUG_QPC_TIMING_H
#define ANTIDEBUG_QPC_TIMING_H

#include "../../core/types.h"
#include "../../core/macros.h"
#include "../../core/config.h"
#include "../../core/syscall_bridge.h"
#include "../../core/string_encrypt.h"
#include "../../core/value_guard.h"

// QPC threshold: delta above this means debugger instrumentation
#ifndef AD_QPC_THRESHOLD
#define AD_QPC_THRESHOLD  5000ULL
#endif

// Calibration loop iterations (must be consistent with threshold)
#ifndef AD_QPC_LOOP_ITERS
#define AD_QPC_LOOP_ITERS 200U
#endif

// LARGE_INTEGER layout (Windows)
typedef struct {
    u32 LowPart;
    s32 HighPart;
} AD_LARGE_INTEGER;

// ---------------------------------------------------------------------------
// Encrypted string: "NtQueryPerformanceCounter" (25 chars)
// ---------------------------------------------------------------------------
#define AD_STRENC_NtQueryPerformanceCounter(buf)                              \
    do {                                                                      \
        const u8 _k = AD_STR_KEY(0x9F);                                      \
        char buf##_e[26];                                                     \
        AD_ENC(buf##_e,  0, 'N', _k); AD_ENC(buf##_e,  1, 't', _k);        \
        AD_ENC(buf##_e,  2, 'Q', _k); AD_ENC(buf##_e,  3, 'u', _k);        \
        AD_ENC(buf##_e,  4, 'e', _k); AD_ENC(buf##_e,  5, 'r', _k);        \
        AD_ENC(buf##_e,  6, 'y', _k); AD_ENC(buf##_e,  7, 'P', _k);        \
        AD_ENC(buf##_e,  8, 'e', _k); AD_ENC(buf##_e,  9, 'r', _k);        \
        AD_ENC(buf##_e, 10, 'f', _k); AD_ENC(buf##_e, 11, 'o', _k);        \
        AD_ENC(buf##_e, 12, 'r', _k); AD_ENC(buf##_e, 13, 'm', _k);        \
        AD_ENC(buf##_e, 14, 'a', _k); AD_ENC(buf##_e, 15, 'n', _k);        \
        AD_ENC(buf##_e, 16, 'c', _k); AD_ENC(buf##_e, 17, 'e', _k);        \
        AD_ENC(buf##_e, 18, 'C', _k); AD_ENC(buf##_e, 19, 'o', _k);        \
        AD_ENC(buf##_e, 20, 'u', _k); AD_ENC(buf##_e, 21, 'n', _k);        \
        AD_ENC(buf##_e, 22, 't', _k); AD_ENC(buf##_e, 23, 'e', _k);        \
        AD_ENC(buf##_e, 24, 'r', _k);                                        \
        AD_DECODE_BUF(buf##_e, 25, _k);                                      \
        for (unsigned _ci = 0; _ci < 26; _ci++) (buf)[_ci] = buf##_e[_ci];   \
    } while (0)

// Internal: read QPC via syscall
ANTIDEBUG_INLINE u64 ad_qpc_read(u16 ssn) {
    AD_LARGE_INTEGER counter;
    AD_ZERO_BUF(&counter, sizeof(counter));

    // NtQueryPerformanceCounter(PLARGE_INTEGER Counter, PLARGE_INTEGER Frequency)
    ad_ntstatus_t st = AD_SYSCALL2(
        ssn,
        &counter,
        (u64)0  // frequency = NULL, don't need it
    );

    if (!AD_NT_SUCCESS(st)) return 0;
    return ((u64)(u32)counter.HighPart << 32) | (u64)counter.LowPart;
}

// ---------------------------------------------------------------------------
// Check: QPC timing delta
//
// Runs a calibrated loop between two QPC reads. If the delta is too large,
// something is instrumenting our execution (debugger, DBI framework).
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE b32 ad_qpc_timing(void) {
    static u16 s_ssn = AD_SSN_UNRESOLVED;
    AD_RESOLVE_SSN_ENC(s_ssn, NtQueryPerformanceCounter, 26);
    if (s_ssn == AD_SSN_FAILED) return 0;

    u64 before = ad_qpc_read(s_ssn);
    if (before == 0) return 0;

    // Calibrated busy loop — LCG with volatile sink to prevent optimization
    volatile u32 acc = ad_derive32(0x1F2E3D4Cu, 0x0D1A2774u);  // = 0x12345678
    u32 i;
    u32 qpc_iters = ad_derive32(0xE7B3A1C8u, 0xE7B3A100u);    // = 0xC8 = 200
    for (i = 0; i < qpc_iters; i++) {
        acc = acc * 1103515245u + 12345u;
    }
    AD_UNUSED(acc);

    u64 after = ad_qpc_read(s_ssn);
    if (after == 0) return 0;

    u64 delta = after - before;
    return ad_opaque_gt_u64(delta, (u64)AD_GET_QPC());
}

#endif // ANTIDEBUG_QPC_TIMING_H
