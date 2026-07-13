// ===== file: antidebug/checks/timing/tsc_qpc_drift.h =====
//
// TSC vs QPC Ratio Drift — hypervisor / TTD detection via clock divergence.
//
// On bare-metal Windows 10/11, both __rdtsc() and QueryPerformanceCounter()
// derive from the CPU's TSC. Their ratio is a fixed constant (QPC_freq is
// reported by QueryPerformanceFrequency; TSC_freq is the CPU's invariant
// TSC rate). Over ANY window the ratio TSC_delta / QPC_delta should equal
// TSC_freq / QPC_freq within < 1 % noise.
//
// Under a hypervisor that virtualizes rdtsc (VMware with TSC-scaling, old
// Hyper-V without invariant TSC passthrough, nested VT-x, Xen HVM) OR
// under WinDbg Time-Travel Debugging, one of the two clocks is emulated
// differently than the other — the ratio drifts 10-10000 %.
//
// Calibrate the ratio once at init over a 50 ms sampling window. Then on
// each subsequent check sample the ratio over a short window and flag
// drift > 15 %.
//
// Works on Windows 7+, 10, 11. No CPU feature required beyond rdtsc and
// QueryPerformanceCounter (both universal on x64 Windows).
//
#ifndef ANTIDEBUG_TSC_QPC_DRIFT_H
#define ANTIDEBUG_TSC_QPC_DRIFT_H

#include "../../core/types.h"
#include "../../core/macros.h"

// kernel32 imports — tests only use declspec; lib links through the standard
// kernel32.lib brought in by the project.
#ifdef _MSC_VER
__declspec(dllimport) int __stdcall QueryPerformanceCounter(u64* lpPerformanceCount);
__declspec(dllimport) int __stdcall QueryPerformanceFrequency(u64* lpFrequency);
__declspec(dllimport) void __stdcall Sleep(unsigned long ms);
#endif

typedef struct {
    u64 tsc_per_qpc_q16;   // calibrated ratio, fixed-point Q16.16 for precision
    u32 calibrated;
} ad_tsc_qpc_ctx_t;

#define AD_TSC_QPC_CALIBRATE_MS   50U       // calibration window
#define AD_TSC_QPC_CHECK_MS       2U        // per-check sampling window
#define AD_TSC_QPC_DRIFT_PCT      15U       // 15 % drift = flag
#define AD_TSC_QPC_MIN_QPC_DELTA  100ULL    // avoid divide-by-zero on tiny windows

// Take a (tsc, qpc) snapshot in a tight fence-wrapped sequence.
ANTIDEBUG_INLINE void ad_tsc_qpc_sample(u64* tsc_out, u64* qpc_out) {
    AD_LFENCE();
    u64 t = __rdtsc();
    AD_LFENCE();
    QueryPerformanceCounter(qpc_out);
    AD_LFENCE();
    *tsc_out = t;
}

// Calibrate the ratio. Call once at init — blocks for AD_TSC_QPC_CALIBRATE_MS.
ANTIDEBUG_INLINE void ad_tsc_qpc_calibrate(ad_tsc_qpc_ctx_t* ctx) {
    u64 tsc0, qpc0, tsc1, qpc1;
    ad_tsc_qpc_sample(&tsc0, &qpc0);
    Sleep(AD_TSC_QPC_CALIBRATE_MS);
    ad_tsc_qpc_sample(&tsc1, &qpc1);

    u64 tsc_delta = tsc1 - tsc0;
    u64 qpc_delta = qpc1 - qpc0;
    if (qpc_delta < AD_TSC_QPC_MIN_QPC_DELTA) {
        ctx->calibrated = 0;
        return;
    }

    // ratio in Q16.16 : (tsc_delta << 16) / qpc_delta. Typical TSC_freq is
    // 2.5–5 GHz; QPC_freq on Win10/11 is usually 10 MHz (reported by
    // QueryPerformanceFrequency). So ratio is roughly 250–500, fits Q16.16.
    ctx->tsc_per_qpc_q16 = (tsc_delta << 16) / qpc_delta;
    ctx->calibrated = 1;
}

// Main check. Returns 1 if the TSC/QPC ratio drifted more than
// AD_TSC_QPC_DRIFT_PCT from calibration. 0 otherwise, or if uncalibrated.
ANTIDEBUG_INLINE b32 ad_tsc_qpc_drift_check(ad_tsc_qpc_ctx_t* ctx) {
    if (!ctx || !ctx->calibrated) return 0;

    u64 tsc0, qpc0, tsc1, qpc1;
    ad_tsc_qpc_sample(&tsc0, &qpc0);
    Sleep(AD_TSC_QPC_CHECK_MS);
    ad_tsc_qpc_sample(&tsc1, &qpc1);

    u64 tsc_delta = tsc1 - tsc0;
    u64 qpc_delta = qpc1 - qpc0;
    if (qpc_delta < AD_TSC_QPC_MIN_QPC_DELTA) return 0;

    u64 observed_q16 = (tsc_delta << 16) / qpc_delta;
    u64 cal = ctx->tsc_per_qpc_q16;

    // Absolute drift as percentage of calibration.
    u64 diff = observed_q16 > cal ? observed_q16 - cal : cal - observed_q16;
    // drift_pct = 100 * diff / cal, no overflow: diff < cal typically, cal is
    // under 2^24 in practice.
    u64 drift_pct = (diff * 100ULL) / cal;

    return (b32)(drift_pct > (u64)AD_TSC_QPC_DRIFT_PCT);
}

// Diagnostic variant — returns the observed drift percentage (0-10000+)
// instead of a boolean. Useful in harnesses.
ANTIDEBUG_INLINE u64 ad_tsc_qpc_drift_pct(ad_tsc_qpc_ctx_t* ctx) {
    if (!ctx || !ctx->calibrated) return 0;

    u64 tsc0, qpc0, tsc1, qpc1;
    ad_tsc_qpc_sample(&tsc0, &qpc0);
    Sleep(AD_TSC_QPC_CHECK_MS);
    ad_tsc_qpc_sample(&tsc1, &qpc1);

    u64 tsc_delta = tsc1 - tsc0;
    u64 qpc_delta = qpc1 - qpc0;
    if (qpc_delta < AD_TSC_QPC_MIN_QPC_DELTA) return 0;

    u64 observed_q16 = (tsc_delta << 16) / qpc_delta;
    u64 cal = ctx->tsc_per_qpc_q16;
    u64 diff = observed_q16 > cal ? observed_q16 - cal : cal - observed_q16;
    return (diff * 100ULL) / cal;
}

#endif // ANTIDEBUG_TSC_QPC_DRIFT_H
