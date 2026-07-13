// ===== file: antidebug/checks/vm/vm_timing_vmexit.h =====
//
// Advanced timing-based VM detection — detect hypervisor VM exits.
//
// Techniques:
//   1. CPUID per-leaf timing variance (VM-exit-inducing leaves cost more)
//   2. IN instruction timing (privileged instruction overhead)
//   3. RDTSC granularity analysis (hypervisor TSC offsetting artifacts)
//   4. Multi-sample CPUID timing (statistical outlier detection)
//   5. Instruction serialization timing (LFENCE vs MFENCE vs CPUID cost)
//   6. Mixed instruction sequence timing (interleaved sensitive insns)
//   7. RDTSC backward detection (VM TSC offset adjustment)
//
// No CRT, no imports — pure intrinsics + SEH.
//
#ifndef ANTIDEBUG_VM_TIMING_VMEXIT_H
#define ANTIDEBUG_VM_TIMING_VMEXIT_H

#include "../../core/types.h"
#include "../../core/macros.h"
#include "../../core/config.h"

#if defined(_MSC_VER)

#ifndef EXCEPTION_EXECUTE_HANDLER
#define EXCEPTION_EXECUTE_HANDLER 1
#endif

// ---------------------------------------------------------------------------
// Helper: detect Windows 11 VBS/HVCI ("Microsoft Hv" root partition).
// When this is true, CPUID timing is elevated due to Hyper-V VM exits
// but the machine is NOT a guest VM. All timing checks should suppress
// or raise thresholds to avoid false positives.
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE b32 ad_vm_is_msft_root_partition(void) {
    int regs[4] = {0};
    __cpuid(regs, (int)0x40000000);
    if ((u32)regs[0] < 0x40000000u) return 0;

    static const u8 msft[12] = {'M','i','c','r','o','s','o','f','t',' ','H','v'};
    u8 v[12]; u32 t, j;
    t=(u32)regs[1]; v[0]=(u8)t; v[1]=(u8)(t>>8); v[2]=(u8)(t>>16); v[3]=(u8)(t>>24);
    t=(u32)regs[2]; v[4]=(u8)t; v[5]=(u8)(t>>8); v[6]=(u8)(t>>16); v[7]=(u8)(t>>24);
    t=(u32)regs[3]; v[8]=(u8)t; v[9]=(u8)(t>>8); v[10]=(u8)(t>>16); v[11]=(u8)(t>>24);
    b32 is_msft = 1;
    for (j = 0u; j < 12u && is_msft; j++) if (v[j] != msft[j]) is_msft = 0;
    return is_msft;
}

// ---------------------------------------------------------------------------
// 1. Per-leaf CPUID timing variance
//
// Different CPUID leaves have different VM-exit costs:
//   - Leaf 0 (vendor): typically intercepted, moderate cost
//   - Leaf 1 (features): heavily intercepted (hypervisor bit masking)
//   - Leaf 0x40000000 (hypervisor): always intercepted
//   - Leaf 4 (cache): may or may not be intercepted
//
// On bare metal, all leaves take roughly the same time (~100-300 cycles).
// Under a VM, intercepted leaves take 500-10000+ cycles due to VM exit.
//
// Measure the variance between leaf costs. High variance = VM.
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE u32 ad_vm_cpuid_leaf_timing(void) {
    u32 score = 0u;
    int dummy[4];

    // Windows 11 VBS causes legitimate CPUID VM exits — skip
    if (ad_vm_is_msft_root_partition()) return 0u;

    // Warm up cache
    __cpuid(dummy, 0);
    __cpuid(dummy, 1);

    // Time leaf 0 (vendor — always intercepted under VMs)
    AD_LFENCE();
    u64 t0 = __rdtsc();
    AD_LFENCE();
    __cpuid(dummy, 0);
    AD_LFENCE();
    u64 t1 = __rdtsc();
    u64 d_leaf0 = t1 - t0;

    // Time leaf 2 (cache descriptors — often NOT intercepted)
    AD_LFENCE();
    t0 = __rdtsc();
    AD_LFENCE();
    __cpuid(dummy, 2);
    AD_LFENCE();
    t1 = __rdtsc();
    u64 d_leaf2 = t1 - t0;

    // Time leaf 0x40000000 (hypervisor — ALWAYS intercepted if present)
    AD_LFENCE();
    t0 = __rdtsc();
    AD_LFENCE();
    __cpuid(dummy, (int)0x40000000);
    AD_LFENCE();
    t1 = __rdtsc();
    u64 d_leaf_hv = t1 - t0;

    // Time leaf 0x80000000 (extended max — may or may not intercept)
    AD_LFENCE();
    t0 = __rdtsc();
    AD_LFENCE();
    __cpuid(dummy, (int)0x80000000);
    AD_LFENCE();
    t1 = __rdtsc();
    u64 d_leaf_ext = t1 - t0;

    // On bare metal: all deltas are similar (100-300 range)
    // Under VM: intercepted leaves are 3-100x more expensive

    // Check if hypervisor leaf is much more expensive than leaf 2
    if (d_leaf2 > 0u && d_leaf_hv > d_leaf2 * 5u)
        score += 3u;

    // Check if leaf 0 is much more expensive than expected
    if (d_leaf0 > 1000u) score += 2u;

    // Check if any leaf exceeds bare-metal maximum (~500 cycles)
    if (d_leaf_hv > 2000u) score += 2u;

    // Compute variance across all measurements
    u64 avg = (d_leaf0 + d_leaf2 + d_leaf_hv + d_leaf_ext) / 4u;
    u64 variance = 0u;
    {
        u64 diffs[4] = {
            (d_leaf0 > avg) ? (d_leaf0 - avg) : (avg - d_leaf0),
            (d_leaf2 > avg) ? (d_leaf2 - avg) : (avg - d_leaf2),
            (d_leaf_hv > avg) ? (d_leaf_hv - avg) : (avg - d_leaf_hv),
            (d_leaf_ext > avg) ? (d_leaf_ext - avg) : (avg - d_leaf_ext)
        };
        u32 i;
        for (i = 0u; i < 4u; i++) variance += diffs[i] * diffs[i];
        variance /= 4u;
    }

    // High variance = VM (some leaves intercepted, others not)
    // Bare metal variance: < 10000. VM variance: often > 100000.
    if (variance > 100000ULL) score += 3u;
    else if (variance > 50000ULL) score += 2u;

    return score;
}

// ---------------------------------------------------------------------------
// 2. IN instruction timing
//
// Time the cost of an IN instruction to a typically-unused port.
// On bare metal: #GP after 0 cycles of execution time (exception is fast).
// Under a VM: the IN causes a VM exit, which takes 500-5000+ cycles
// BEFORE the exception (if any) is delivered to the guest.
//
// We measure the time INCLUDING the exception handling.
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE u32 ad_vm_in_timing(void) {
    u32 score = 0u;

    if (ad_vm_is_msft_root_partition()) return 0u;

    AD_LFENCE();
    u64 t0 = __rdtsc();
    AD_LFENCE();

    __try {
        u32 val = __indword(0x5658);
        AD_UNUSED(val);
        // If we get here, VM intercepted it (no exception)
        AD_LFENCE();
        u64 t1 = __rdtsc();
        u64 delta = t1 - t0;
        // VM interception itself takes time
        if (delta > 500u) score += 2u;
        score += 3u;  // Port access succeeded = VM
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        // Bare metal: got #GP
        AD_LFENCE();
        u64 t1 = __rdtsc();
        u64 delta = t1 - t0;
        // On bare metal, the exception path is fast (< 5000 cycles)
        // Under a VM that passes the #GP to guest, the VM exit + inject
        // adds significant overhead (> 10000 cycles)
        if (delta > 10000u) score += 2u;
    }

    return score;
}

// ---------------------------------------------------------------------------
// 3. RDTSC granularity analysis
//
// On real hardware, back-to-back RDTSC reads produce small but variable
// deltas. The LSBs change naturally due to pipeline state.
//
// Some hypervisors apply a fixed TSC offset, which can create patterns:
//   - All deltas are exact multiples of some base unit
//   - LSB bits are always the same (truncated or rounded)
//   - Deltas are unnaturally uniform
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE u32 ad_vm_rdtsc_granularity(void) {
    u32 score = 0u;
    u64 samples[32];
    u32 i;

    // Windows 11 VBS can affect RDTSC granularity
    if (ad_vm_is_msft_root_partition()) return 0u;

    // Collect 32 back-to-back RDTSC deltas
    AD_LFENCE();
    u64 prev = __rdtsc();
    for (i = 0u; i < 32u; i++) {
        AD_LFENCE();
        u64 cur = __rdtsc();
        samples[i] = cur - prev;
        prev = cur;
    }

    // Check 1: count how many deltas share the same LSB pattern (bits 0-3)
    u32 lsb_pattern[16] = {0};
    for (i = 0u; i < 32u; i++) {
        u32 lsb = (u32)(samples[i] & 0xFu);
        lsb_pattern[lsb]++;
    }
    // On real hardware: LSBs are well-distributed
    // Under VM with TSC rounding: one or two buckets dominate
    u32 max_bucket = 0u;
    for (i = 0u; i < 16u; i++) {
        if (lsb_pattern[i] > max_bucket) max_bucket = lsb_pattern[i];
    }
    // If > 75% of samples have the same LSB pattern → TSC is quantized
    if (max_bucket >= 24u) score += 3u;
    else if (max_bucket >= 20u) score += 2u;

    // Check 2: count zero deltas
    u32 zero_count = 0u;
    for (i = 0u; i < 32u; i++) {
        if (samples[i] == 0u) zero_count++;
    }
    if (zero_count >= 4u) score += 3u;

    // Check 3: check if all deltas are exactly the same (fake TSC)
    b32 all_same = 1;
    for (i = 1u; i < 32u; i++) {
        if (samples[i] != samples[0]) { all_same = 0; break; }
    }
    if (all_same && samples[0] > 0u) score += 4u;

    // Check 4: check for exact power-of-2 deltas (common VM artifact)
    u32 pow2_count = 0u;
    for (i = 0u; i < 32u; i++) {
        u64 d = samples[i];
        if (d > 0u && (d & (d - 1u)) == 0u) pow2_count++;
    }
    if (pow2_count >= 16u) score += 2u;

    return score;
}

// ---------------------------------------------------------------------------
// 4. Multi-sample CPUID timing with statistical analysis
//
// Take N samples of CPUID timing, sort them, and analyze the distribution.
// On bare metal: tight distribution around 100-300 cycles.
// Under VM: bimodal distribution (some from cache, some from VM exit).
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE u32 ad_vm_cpuid_stats(void) {
    u32 score = 0u;
    u64 samples[16];
    int dummy[4];
    u32 i;

    // Windows 11 VBS causes legitimate elevated CPUID cost — skip
    if (ad_vm_is_msft_root_partition()) return 0u;

    // Warm up
    __cpuid(dummy, 0);
    __cpuid(dummy, 0);

    // Collect 16 samples of CPUID leaf 1 timing
    for (i = 0u; i < 16u; i++) {
        AD_LFENCE();
        u64 t0 = __rdtsc();
        AD_LFENCE();
        __cpuid(dummy, 1);
        AD_LFENCE();
        u64 t1 = __rdtsc();
        samples[i] = t1 - t0;
    }

    // Sort (insertion sort)
    u32 a, b;
    for (a = 1u; a < 16u; a++) {
        u64 v = samples[a];
        b = a;
        while (b > 0u && samples[b - 1u] > v) {
            samples[b] = samples[b - 1u];
            b--;
        }
        samples[b] = v;
    }

    // Median
    u64 median = samples[8];

    // On bare metal: median < 500 cycles
    // Under VM: median > 500 cycles (typical: 1000-5000)
    if (median > 1500u) score += 3u;
    else if (median > 700u) score += 2u;

    // IQR (interquartile range): samples[12] - samples[4]
    u64 iqr = samples[12] - samples[4];

    // High IQR = bimodal = VM (some samples from VM exit, some cached)
    if (iqr > 500u) score += 2u;

    // Max vs min ratio
    if (samples[0] > 0u) {
        u64 ratio = samples[15] / samples[0];
        // Ratio > 10 = extreme variance = VM
        if (ratio > 10u) score += 2u;
    }

    return score;
}

// ---------------------------------------------------------------------------
// 5. Serialization instruction timing comparison
//
// Compare the cost of different serialization methods:
//   - LFENCE: lightweight, no VM exit
//   - MFENCE: heavier, usually no VM exit
//   - CPUID: full serialization, ALWAYS causes VM exit under hypervisor
//
// On bare metal: CPUID / LFENCE ratio ≈ 3-10
// Under VM: CPUID / LFENCE ratio ≈ 20-500
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE u32 ad_vm_serialize_timing(void) {
    u32 score = 0u;

    // Windows 11 VBS: CPUID is intercepted by Hyper-V, inflating the ratio
    if (ad_vm_is_msft_root_partition()) return 0u;

    // Time LFENCE (8 iterations)
    AD_LFENCE();
    u64 t0 = __rdtsc();
    AD_LFENCE(); AD_LFENCE(); AD_LFENCE(); AD_LFENCE();
    AD_LFENCE(); AD_LFENCE(); AD_LFENCE(); AD_LFENCE();
    u64 t1 = __rdtsc();
    u64 lfence_time = t1 - t0;

    // Time CPUID (8 iterations)
    int dummy[4];
    AD_LFENCE();
    t0 = __rdtsc();
    __cpuid(dummy, 0); __cpuid(dummy, 0);
    __cpuid(dummy, 0); __cpuid(dummy, 0);
    __cpuid(dummy, 0); __cpuid(dummy, 0);
    __cpuid(dummy, 0); __cpuid(dummy, 0);
    AD_LFENCE();
    t1 = __rdtsc();
    u64 cpuid_time = t1 - t0;

    // Ratio analysis
    if (lfence_time > 0u) {
        u64 ratio = cpuid_time / lfence_time;
        // Bare metal: ratio 3-15
        // VM: ratio 20-500
        if (ratio > 30u) score += 3u;
        else if (ratio > 15u) score += 2u;
    }

    // Absolute CPUID cost: > 2000 cycles for 8 CPUIDs = > 250/each
    if (cpuid_time > 4000u) score += 2u;

    return score;
}

// ---------------------------------------------------------------------------
// 6. Mixed sensitive instruction sequence
//
// Execute a sequence mixing CPUID, RDTSC, and computation. Under a VM,
// the total time is dominated by VM exit overhead on each CPUID.
// On bare metal, CPUID is fast and the computation dominates.
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE u32 ad_vm_mixed_sequence(void) {
    u32 score = 0u;

    if (ad_vm_is_msft_root_partition()) return 0u;

    int dummy[4];
    volatile u32 acc = 0x12345678u;

    AD_LFENCE();
    u64 t0 = __rdtsc();

    // Interleaved: CPUID + computation + RDTSC reads
    __cpuid(dummy, 0);
    acc = acc * 7u + 3u;
    __cpuid(dummy, 1);
    acc = acc * 13u + 5u;
    u64 mid_tsc = __rdtsc();
    __cpuid(dummy, 0);
    acc = acc * 11u + 7u;
    __cpuid(dummy, 1);
    acc = acc * 17u + 11u;

    AD_LFENCE();
    u64 t1 = __rdtsc();
    AD_UNUSED(acc);
    AD_UNUSED(mid_tsc);

    u64 total = t1 - t0;

    // Bare metal: 4 CPUIDs + arithmetic ≈ 800-2000 cycles
    // VM: 4 CPUIDs ≈ 4000-40000 cycles (VM exit each)
    if (total > 8000u) score += 3u;
    else if (total > 3000u) score += 1u;

    return score;
}

// ---------------------------------------------------------------------------
// 7. RDTSC backward / discontinuity detection
//
// Some hypervisors adjust the TSC offset when migrating between
// physical cores or rebalancing. This can cause:
//   - RDTSC going backward briefly
//   - Large forward jumps
//
// On bare metal, RDTSC is monotonically increasing with small,
// consistent increments.
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE u32 ad_vm_rdtsc_backward(void) {
    u32 score = 0u;
    u64 prev;
    u32 backward_count = 0u;
    u32 jump_count = 0u;
    u32 i;

    AD_LFENCE();
    prev = __rdtsc();

    for (i = 0u; i < 64u; i++) {
        AD_LFENCE();
        u64 cur = __rdtsc();

        if (cur < prev) {
            // TSC went backward!
            backward_count++;
        } else {
            u64 delta = cur - prev;
            // Normal delta: < 200 cycles for LFENCE+RDTSC
            // Large jump: > 5000 cycles (possible VM exit or migration)
            if (delta > 5000u) jump_count++;
        }

        prev = cur;
    }

    // Any backward TSC = definite hypervisor TSC adjustment
    if (backward_count > 0u) score += 4u;

    // Multiple large jumps = VM exit interference
    // Single jump is normal (scheduler preemption, interrupt). Need >= 3.
    if (jump_count >= 5u) score += 3u;
    else if (jump_count >= 3u) score += 2u;

    return score;
}

// ---------------------------------------------------------------------------
// MASTER: timing VM exit composite score
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE u32 ad_vm_timing_master(void) {
    u32 score = 0u;
    score += ad_vm_cpuid_leaf_timing();
    score += ad_vm_in_timing();
    score += ad_vm_rdtsc_granularity();
    score += ad_vm_cpuid_stats();
    score += ad_vm_serialize_timing();
    score += ad_vm_mixed_sequence();
    score += ad_vm_rdtsc_backward();
    return score;
}

#else

ANTIDEBUG_INLINE u32 ad_vm_cpuid_leaf_timing(void)   { return 0; }
ANTIDEBUG_INLINE u32 ad_vm_in_timing(void)            { return 0; }
ANTIDEBUG_INLINE u32 ad_vm_rdtsc_granularity(void)    { return 0; }
ANTIDEBUG_INLINE u32 ad_vm_cpuid_stats(void)          { return 0; }
ANTIDEBUG_INLINE u32 ad_vm_serialize_timing(void)     { return 0; }
ANTIDEBUG_INLINE u32 ad_vm_mixed_sequence(void)       { return 0; }
ANTIDEBUG_INLINE u32 ad_vm_rdtsc_backward(void)       { return 0; }
ANTIDEBUG_INLINE u32 ad_vm_timing_master(void)        { return 0; }

#endif // _MSC_VER

#endif // ANTIDEBUG_VM_TIMING_VMEXIT_H