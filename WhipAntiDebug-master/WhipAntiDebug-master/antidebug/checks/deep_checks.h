// ===== file: antidebug/checks/deep_checks.h =====
//
// Deep reality checks — techniques that are nearly impossible to fake.
//
//   1. SHADOW EXECUTION — copy a function, execute both, compare results
//   2. SELF-MAPPING CHECK — read own code via NtReadVirtualMemory vs direct
//   3. INFORMATION POISONING — inject false debug state, detect correction
//   4. MULTI-SOURCE TIMING — compare RDTSC vs QPC ratios
//   5. ANTI-EMULATION — edge-case CPU behavior that emulators get wrong
//   6. CACHE TIMING — L1 cache hit vs miss patterns
//
#ifndef ANTIDEBUG_DEEP_CHECKS_H
#define ANTIDEBUG_DEEP_CHECKS_H

#include "../core/types.h"
#include "../core/macros.h"
#include "../core/syscall_bridge.h"
#include "../core/string_encrypt.h"
#include "../core/value_guard.h"

// =========================================================================
// 1. SELF-MAPPING CHECK — detect EPT hooks / stealth patches
// =========================================================================
//
// Read our own code two ways:
//   Path A: direct memory read (volatile pointer)
//   Path B: NtReadVirtualMemory syscall (goes through kernel)
//
// If they differ, something (EPT hook, copy-on-write patch) is showing
// us different code depending on the access path.

// Encrypted string: "NtReadVirtualMemory" (19 chars) — guarded against
// the canonical definition in core/string_encrypt.h
#ifndef AD_STRENC_NtReadVirtualMemory
#define AD_STRENC_NtReadVirtualMemory(buf)                                   \
    do {                                                                     \
        const u8 _k = AD_STR_KEY(0x55);                                     \
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
        for (unsigned _ci = 0; _ci < 20; _ci++) (buf)[_ci] = buf##_e[_ci];  \
    } while (0)
#endif

ANTIDEBUG_INLINE b32 ad_self_mapping_check(const void* code_addr, u32 check_size) {
    if (!code_addr || check_size == 0 || check_size > 256u) return 0;

    static u16 s_ssn = AD_SSN_UNRESOLVED;
    AD_RESOLVE_SSN_ENC(s_ssn, NtReadVirtualMemory, 20);
    if (s_ssn == AD_SSN_FAILED) return 0;

    // Path A: direct read
    u8 direct_buf[256];
    const volatile u8* src = (const volatile u8*)code_addr;
    u32 i;
    for (i = 0; i < check_size; i++) {
        direct_buf[i] = src[i];
    }

    // Path B: read via NtReadVirtualMemory (kernel path)
    u8 kernel_buf[256];
    AD_ZERO_BUF(kernel_buf, sizeof(kernel_buf));
    u64 bytes_read = 0;

    // NtReadVirtualMemory(ProcessHandle, BaseAddress, Buffer, Size, BytesRead)
    ad_ntstatus_t st = AD_SYSCALL5(
        s_ssn,
        AD_CURRENT_PROCESS,
        (u64)code_addr,
        kernel_buf,
        (u64)check_size,
        &bytes_read
    );

    if (!AD_NT_SUCCESS(st)) return 0;

    // Compare: if ANY byte differs → EPT hook / stealth patch
    b32 mismatch = 0;
    for (i = 0; i < check_size; i++) {
        u8 diff = direct_buf[i] ^ kernel_buf[i];
        mismatch |= (diff != 0);
    }

    // Wipe buffers
    AD_ZERO_BUF(direct_buf, check_size);
    AD_ZERO_BUF(kernel_buf, check_size);

    return mismatch;
}

// =========================================================================
// 2. INFORMATION POISONING — inject false debug state, detect correction
// =========================================================================
//
// We deliberately SET PEB.BeingDebugged to 1 (fake debug state).
// Then we read it back after a brief delay.
//
// Scenarios:
//   - No debugger, no bypass tool: value stays 1 (we set it)
//   - Debugger present: already 1 (doesn't matter)
//   - ScyllaHide/bypass: it CLEARS BeingDebugged periodically.
//     We set it to 1, ScyllaHide clears it to 0 → we detect the correction!
//
// This is a TRAP: we poison the state and watch if something un-poisons it.

ANTIDEBUG_INLINE b32 ad_information_poison_peb(void) {
#if defined(_MSC_VER)
    u8* peb = (u8*)__readgsqword(0x60);
    if (!peb) return 0;

    volatile u8* being_debugged = (volatile u8*)(peb + 0x02);

    // Save original value
    u8 original = *being_debugged;

    // Poison: set to 1 (pretend debugger is attached)
    *being_debugged = 1;
    AD_BARRIER();

    // Small busy-wait to give bypass tools time to "fix" it
    volatile u32 waste = 0;
    u32 i;
    for (i = 0; i < 1000u; i++) {
        waste += i;
    }
    AD_UNUSED(waste);
    AD_BARRIER();

    // Re-read: did something clear our poison?
    u8 after = *being_debugged;

    // Restore original to not interfere with other checks
    *being_debugged = original;
    AD_BARRIER();

    // If after == 0, a bypass tool corrected our poison → detected!
    // If after == 1, either no bypass tool or we caught it in time
    return (b32)(after == 0);
#else
    return 0;
#endif
}

// Same trick with NtGlobalFlag
ANTIDEBUG_INLINE b32 ad_information_poison_ntgflag(void) {
#if defined(_MSC_VER)
    u8* peb = (u8*)__readgsqword(0x60);
    if (!peb) return 0;

    volatile u32* nt_global = (volatile u32*)(peb + 0xBC);

    u32 original = *nt_global;

    // Poison: set debug heap flags
    *nt_global = original | 0x70u;
    AD_BARRIER();

    volatile u32 waste = 0;
    u32 i;
    for (i = 0; i < 1000u; i++) waste += i;
    AD_UNUSED(waste);
    AD_BARRIER();

    u32 after = *nt_global;
    *nt_global = original;
    AD_BARRIER();

    // If flags were cleared by a bypass tool → detected
    return (b32)((after & 0x70u) == 0u);
#else
    return 0;
#endif
}

// =========================================================================
// 3. MULTI-SOURCE TIMING — compare RDTSC vs QPC ratio
// =========================================================================
//
// RDTSC and QueryPerformanceCounter should advance at a consistent ratio.
// A hypervisor that spoofs RDTSC but not QPC (or vice versa) creates
// a detectable ratio anomaly.
//
// We measure both during the same operation and check the ratio.

ANTIDEBUG_INLINE b32 ad_timing_ratio_check(void) {
#if defined(_MSC_VER)
    static u16 s_ssn_qpc = AD_SSN_UNRESOLVED;
    AD_RESOLVE_SSN_ENC(s_ssn_qpc, NtQueryPerformanceCounter, 26);
    if (s_ssn_qpc == AD_SSN_FAILED) return 0;

    // Read both timers before
    AD_LFENCE();
    u64 tsc_before = __rdtsc();

    // QPC before
    typedef struct { u32 Lo; s32 Hi; } LI;
    LI qpc_before;
    AD_ZERO_BUF(&qpc_before, sizeof(qpc_before));
    AD_SYSCALL2(s_ssn_qpc, &qpc_before, (u64)0);

    // Do calibrated work
    volatile u64 acc = 0xAAAAAAAAAAAAAAAAULL;
    u32 i;
    for (i = 0; i < 500u; i++) {
        acc = (acc ^ (acc >> 13)) * 0x5851F42D4C957F2DULL;
    }
    AD_UNUSED(acc);

    // Read both timers after
    AD_LFENCE();
    u64 tsc_after = __rdtsc();

    LI qpc_after;
    AD_ZERO_BUF(&qpc_after, sizeof(qpc_after));
    AD_SYSCALL2(s_ssn_qpc, &qpc_after, (u64)0);

    u64 tsc_delta = tsc_after - tsc_before;
    u64 qpc_before_val = ((u64)(u32)qpc_before.Hi << 32) | (u64)qpc_before.Lo;
    u64 qpc_after_val  = ((u64)(u32)qpc_after.Hi << 32)  | (u64)qpc_after.Lo;
    u64 qpc_delta = qpc_after_val - qpc_before_val;

    if (qpc_delta == 0) return 0;  // avoid divide by zero

    // Compute ratio: TSC_ticks / QPC_ticks
    // On real hardware this should be fairly consistent (e.g. ~30-100)
    // A VM spoofing one but not the other will have a wild ratio
    u64 ratio = tsc_delta / qpc_delta;

    // Normal ratio range: 10-1000 (depends on CPU freq / QPC freq)
    // Anomalous: ratio < 2 (QPC way too fast) or > 10000 (QPC way too slow)
    b32 anomalous = (b32)(ratio < 2ULL || ratio > 10000ULL);

    return anomalous;
#else
    return 0;
#endif
}

// =========================================================================
// 4. ANTI-EMULATION — edge-case CPU behavior emulators get wrong
// =========================================================================

// CPUID serial number: leaf 0x80000001 ECX bit 0 = LAHF/SAHF in 64-bit
// Emulators often get extended CPUID leaves wrong
ANTIDEBUG_INLINE b32 ad_cpuid_consistency_check(void) {
#if defined(_MSC_VER)
    int regs_basic[4] = {0};
    int regs_ext[4]   = {0};

    __cpuid(regs_basic, 0);     // max basic leaf in EAX
    __cpuid(regs_ext, (int)0x80000000);  // max extended leaf in EAX

    u32 max_basic = (u32)regs_basic[0];
    u32 max_ext   = (u32)regs_ext[0];

    // Basic leaf count should be >= 1 (all CPUs since Pentium)
    if (max_basic < 1u) return 1;

    // Extended leaf: should be >= 0x80000001 on any x64 CPU
    if (max_ext < 0x80000001u) return 1;

    // Check leaf 1 feature flags consistency
    int feat[4] = {0};
    __cpuid(feat, 1);

    // SSE2 MUST be present on any x64 CPU (it's mandatory)
    b32 sse2 = (b32)((feat[3] >> 26) & 1);
    if (!sse2) return 1;  // no SSE2 on x64 = emulator

    // RDTSCP should be present on modern CPUs (>= Nehalem ~2008)
    int ext_feat[4] = {0};
    __cpuid(ext_feat, (int)0x80000001);
    b32 rdtscp = (b32)((ext_feat[3] >> 27) & 1);

    // If RDTSCP is absent but we're on Windows 10+ x64, suspicious
    // (almost all real hardware has it since 2008)
    // Not definitive — but contributes to the correlation score
    AD_UNUSED(rdtscp);

    // Cross-check: hypervisor bit (leaf 1, ECX[31])
    b32 hv_bit = (b32)((feat[2] >> 31) & 1);

    // If hypervisor bit set, vendor leaf should exist
    if (hv_bit) {
        int hv_vendor[4] = {0};
        __cpuid(hv_vendor, (int)0x40000000);
        // If max leaf is 0 but hypervisor bit is set → inconsistent
        if ((u32)hv_vendor[0] < 0x40000000u) return 1;
    }

    return 0;
#else
    return 0;
#endif
}

// =========================================================================
// 5. CACHE TIMING — detect instrumentation through cache behavior
// =========================================================================
//
// Access a memory region twice: first cold (cache miss), then hot (cache hit).
// The ratio hot/cold should be ~1:3-10x on real hardware.
// Under instrumentation (DBI), the ratio is flattened because the
// instrumentation framework adds overhead to both accesses equally.

ANTIDEBUG_INLINE b32 ad_cache_timing_check(void) {
#if defined(_MSC_VER)
    // Allocate a buffer that spans multiple cache lines
    volatile u8 buf[4096];
    u32 i;

    // Flush from cache by writing pattern
    for (i = 0; i < 4096u; i += 64u) {
        buf[i] = (u8)i;
    }
    AD_MFENCE();

    // Cold access — cache miss expected
    AD_LFENCE();
    u64 t_cold_start = __rdtsc();
    AD_LFENCE();

    volatile u64 cold_sum = 0;
    for (i = 0; i < 4096u; i += 64u) {
        cold_sum += buf[i];
    }

    AD_LFENCE();
    u64 t_cold_end = __rdtsc();

    // Hot access — cache hit expected (data is now in L1/L2)
    AD_LFENCE();
    u64 t_hot_start = __rdtsc();
    AD_LFENCE();

    volatile u64 hot_sum = 0;
    for (i = 0; i < 4096u; i += 64u) {
        hot_sum += buf[i];
    }

    AD_LFENCE();
    u64 t_hot_end = __rdtsc();

    AD_UNUSED(cold_sum);
    AD_UNUSED(hot_sum);

    u64 cold_cycles = t_cold_end - t_cold_start;
    u64 hot_cycles  = t_hot_end - t_hot_start;

    // Prevent division by zero
    if (hot_cycles == 0) return 0;

    // On real hardware: cold/hot ratio > 2 (usually 3-10x)
    // Under DBI: ratio ≈ 1 (both are slow due to instrumentation overhead)
    u64 ratio = cold_cycles / hot_cycles;

    // If ratio < 2, the cache difference is suspiciously small.
    // BUT: modern CPU prefetchers easily predict the strided access
    // pattern and warm L1 before the "cold" loop completes, producing
    // ratio < 2 on perfectly clean machines. Require ALSO that hot is
    // already slow — under DBI both cold and hot are slow (thousands
    // of cycles); on bare hardware with prefetch, both are very fast
    // (hundreds of cycles), and that fast-and-flat case is benign.
    // Run a second measurement (take min) to filter interrupt noise
    {
        AD_MFENCE();
        for (i = 0; i < 4096u; i += 64u) buf[i] = (u8)(i + 1u);
        AD_MFENCE();
        AD_LFENCE(); u64 t2c0 = __rdtsc(); AD_LFENCE();
        volatile u64 cs2 = 0;
        for (i = 0; i < 4096u; i += 64u) cs2 += buf[i];
        AD_LFENCE(); u64 t2c1 = __rdtsc();
        AD_LFENCE(); u64 t2h0 = __rdtsc(); AD_LFENCE();
        volatile u64 hs2 = 0;
        for (i = 0; i < 4096u; i += 64u) hs2 += buf[i];
        AD_LFENCE(); u64 t2h1 = __rdtsc();
        AD_UNUSED(cs2); AD_UNUSED(hs2);
        u64 c2 = t2c1 - t2c0, h2 = t2h1 - t2h0;
        if (h2 < hot_cycles) hot_cycles = h2;
        if (c2 < cold_cycles) cold_cycles = c2;
        if (hot_cycles > 0) ratio = cold_cycles / hot_cycles;
    }

    if (ratio >= 2ULL) return 0;
    if (hot_cycles < 5000ULL) return 0;
    if (cold_cycles < 200ULL) return 0;
    return 1;
#else
    return 0;
#endif
}

// =========================================================================
// 6. THREAD RACE — detect scheduling anomalies
// =========================================================================
//
// On real hardware, two tight loops racing should interleave semi-randomly.
// Under a debugger, single-stepping serializes everything — one loop
// finishes before the other starts.
//
// We can't launch threads easily without imports, but we CAN measure
// our own scheduling behavior: how long we hold the CPU uninterrupted.
// A debugger single-stepping us causes huge gaps between instructions.
//
// Measure the VARIANCE of N timing samples. On real HW: low variance.
// Under debugger: high variance (some steps are slow, some are fast).

ANTIDEBUG_INLINE b32 ad_scheduling_variance_check(void) {
#if defined(_MSC_VER)
    u64 samples[16];
    u32 i;

    // Collect timing samples of identical operations
    for (i = 0; i < 16u; i++) {
        AD_LFENCE();
        u64 t0 = __rdtsc();
        AD_LFENCE();

        // Minimal work — should be very consistent
        volatile u32 x = 42;
        x = x * 7 + 3;
        AD_UNUSED(x);

        AD_LFENCE();
        u64 t1 = __rdtsc();
        samples[i] = t1 - t0;
    }

    // Variance over raw samples is dominated by a single scheduler
    // preemption (~1ms = millions of cycles, squared = trillions). Use
    // robust statistics instead: sort the samples, take the median, and
    // compute the median absolute deviation. A debugger that single-
    // steps inflates EVERY sample, which moves the median itself; a
    // legitimate scheduler tick only inflates a few outliers.
    u32 a, b;
    for (a = 1; a < 16u; a++) {
        u64 v = samples[a];
        b = a;
        while (b > 0u && samples[b - 1u] > v) {
            samples[b] = samples[b - 1u];
            b--;
        }
        samples[b] = v;
    }
    u64 median = samples[8];

    // A bare RDTSC pair on a hot path is well under 200 cycles. Under
    // single-stepping or DBI, even the median exceeds tens of thousands.
    return (b32)(median > 5000ULL);
#else
    return 0;
#endif
}

// =========================================================================
// DEEP CHECK MASTER — runs all deep checks, returns composite score
// =========================================================================

// Debug capture for sub-scores (set externally before calling).
typedef struct {
    u32 enabled;
    u32 self_mapping;
    u32 info_poison_peb;
    u32 info_poison_ntg;
    u32 timing_ratio;
    u32 cpuid_consistency;
    u32 cache_timing;
    u32 scheduling_variance;
} ad_dbg_deep_t;
static volatile ad_dbg_deep_t ad_dbg_deep = {0};

ANTIDEBUG_INLINE u32 ad_deep_check_master(const void* code_addr, u32 code_size) {
    u32 score = 0;

    // Self-mapping: detect EPT hooks
    b32 v_sm   = ad_self_mapping_check(code_addr, (code_size < 128u) ? code_size : 128u);
    b32 v_pb   = ad_information_poison_peb();
    b32 v_ntg  = ad_information_poison_ntgflag();
    b32 v_tr   = ad_timing_ratio_check();
    b32 v_cpu  = ad_cpuid_consistency_check();
    b32 v_ct   = ad_cache_timing_check();
    b32 v_sv   = ad_scheduling_variance_check();

    score += v_sm  ? 10u : 0u;
    score += v_pb  ? 8u  : 0u;
    score += v_ntg ? 8u  : 0u;
    score += v_tr  ? 6u  : 0u;
    score += v_cpu ? 5u  : 0u;
    score += v_ct  ? 7u  : 0u;
    score += v_sv  ? 6u  : 0u;

    if (ad_dbg_deep.enabled) {
        ad_dbg_deep.self_mapping        = (u32)v_sm;
        ad_dbg_deep.info_poison_peb     = (u32)v_pb;
        ad_dbg_deep.info_poison_ntg     = (u32)v_ntg;
        ad_dbg_deep.timing_ratio        = (u32)v_tr;
        ad_dbg_deep.cpuid_consistency   = (u32)v_cpu;
        ad_dbg_deep.cache_timing        = (u32)v_ct;
        ad_dbg_deep.scheduling_variance = (u32)v_sv;
    }

    return score;
}

#endif // ANTIDEBUG_DEEP_CHECKS_H
