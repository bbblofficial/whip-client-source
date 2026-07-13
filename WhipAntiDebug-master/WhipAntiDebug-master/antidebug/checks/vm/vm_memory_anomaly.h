// ===== file: antidebug/checks/vm/vm_memory_anomaly.h =====
//
// Memory and system resource anomalies that indicate VM execution.
//
// Techniques:
//   1. Physical memory size check (VMs often have less RAM)
//   2. System uptime check (fresh VM snapshots have very short uptimes)
//   3. Disk size heuristic via SystemPerformanceInformation
//   4. Processor count cross-validation (KUSD vs CPUID vs PEB)
//   5. Screen resolution anomaly (VM default resolutions)
//   6. SystemBasicInformation physical page check
//   7. Working set size anomaly
//
// Uses KUSER_SHARED_DATA and NtQuerySystemInformation syscalls.
//
#ifndef ANTIDEBUG_VM_MEMORY_ANOMALY_H
#define ANTIDEBUG_VM_MEMORY_ANOMALY_H

#include "../../core/types.h"
#include "../../core/macros.h"
#include "../../core/config.h"
#include "../../core/syscall_bridge.h"
#include "../../core/string_encrypt.h"

#if defined(_MSC_VER)

// =========================================================================
// 1. Physical memory size check
//
// Query NtQuerySystemInformation(SystemBasicInformation = 0) to get
// NumberOfPhysicalPages. Real desktop/laptop: typically >= 2GB (500K pages).
// Sandboxes/VMs often allocate minimum memory: 1GB or less.
//
// SystemBasicInformation layout:
//   ULONG Reserved;                // +0x00
//   ULONG TimerResolution;         // +0x04
//   ULONG PageSize;                // +0x08
//   ULONG NumberOfPhysicalPages;   // +0x0C
//   ULONG LowestPhysicalPageNumber;// +0x10
//   ULONG HighestPhysicalPageNumber;//+0x14
//   ULONG AllocationGranularity;   // +0x18
//   ULONG_PTR MinimumUserModeAddress;// +0x20
//   ULONG_PTR MaximumUserModeAddress;// +0x28
//   ULONG_PTR ActiveProcessorsAffinityMask;// +0x30
//   UCHAR NumberOfProcessors;      // +0x38
// =========================================================================
ANTIDEBUG_INLINE u32 ad_vm_physical_mem_low(void) {
    static u16 s_ssn_qsi = AD_SSN_UNRESOLVED;
    AD_RESOLVE_SSN_ENC(s_ssn_qsi, NtQuerySystemInformation, 25);
    if (s_ssn_qsi == AD_SSN_FAILED) return 0u;

    u32 score = 0u;

    // SystemBasicInformation (class 0)
    u8 basic_info[64];
    AD_ZERO_BUF(basic_info, sizeof(basic_info));
    u32 ret_len = 0u;

    ad_ntstatus_t st = AD_SYSCALL4(s_ssn_qsi, (u64)0,
        basic_info, (u64)sizeof(basic_info), &ret_len);

    if (AD_NT_SUCCESS(st)) {
        u32 page_size   = *(u32*)(basic_info + 0x08);
        u32 phys_pages  = *(u32*)(basic_info + 0x0C);
        u32 num_procs   = *(u8*)(basic_info + 0x38);

        // Calculate approximate physical memory in MB
        if (page_size > 0u) {
            u64 phys_mb = ((u64)phys_pages * (u64)page_size) / (1024ULL * 1024ULL);

            // Less than 2GB = very likely VM/sandbox
            if (phys_mb < 2048ULL) score += 3u;
            // Less than 1GB = almost certainly sandbox
            if (phys_mb < 1024ULL) score += 3u;
            // Less than 512MB = extreme sandbox
            if (phys_mb < 512ULL) score += 4u;

            // Non-power-of-2 RAM size = VM artifact.
            // Real hardware: 2, 4, 8, 12, 16, 24, 32, 48, 64, 128 GB
            // VMs: 3, 5, 6, 7, 9, 10, 11 GB etc. — bizarre sizes
            // Check: phys_gb should be one of the standard sizes.
            // Round to nearest GB (allow ~5% tolerance for reserved memory)
            u64 phys_gb = (phys_mb + 512ULL) / 1024ULL;  // rounded GB
            if (phys_gb >= 2ULL && phys_gb <= 128ULL) {
                // Standard desktop sizes (GB): 2,4,6,8,12,16,24,32,48,64,128
                // Non-standard = suspicious
                b32 standard = 0;
                if (phys_gb == 2ULL || phys_gb == 4ULL || phys_gb == 6ULL ||
                    phys_gb == 8ULL || phys_gb == 12ULL || phys_gb == 16ULL ||
                    phys_gb == 24ULL || phys_gb == 32ULL || phys_gb == 48ULL ||
                    phys_gb == 64ULL || phys_gb == 96ULL || phys_gb == 128ULL)
                    standard = 1;
                // Allow ±1 GB tolerance for BIOS-reserved memory
                if (!standard) {
                    if (phys_gb == 3ULL || phys_gb == 7ULL || phys_gb == 15ULL ||
                        phys_gb == 31ULL || phys_gb == 63ULL || phys_gb == 127ULL)
                        standard = 1;  // likely 4/8/16/32/64/128 minus reserved
                }
                if (!standard) score += 3u;
            }
        }

        // Single processor from BasicInfo
        if (num_procs <= 1u) score += 2u;
    }

    return score;
}

// =========================================================================
// 2. System uptime check
//
// KUSER_SHARED_DATA.TickCountLow at offset 0x0320 gives the system
// uptime in tick units (~15.6ms each). A fresh VM snapshot typically
// has very low uptime (< 5 minutes = < 19200 ticks).
//
// Also check BootId at offset 0x02BC — incremented on each boot.
// Very low BootId (1-2) suggests a fresh install or VM.
// =========================================================================
ANTIDEBUG_INLINE u32 ad_vm_uptime_check(void) {
    u32 score = 0u;
    volatile u8* kusd = (volatile u8*)0x7FFE0000ULL;

    // TickCountLow at +0x0320
    u32 tick_low = *(volatile u32*)(kusd + 0x0320);

    // Convert to seconds: tick_low * ~15.625ms / 1000
    // Approximate: tick_low / 64 ≈ seconds
    u32 uptime_secs = tick_low / 64u;

    // Less than 5 minutes = very fresh (likely VM snapshot resume)
    if (uptime_secs < 300u) score += 3u;
    // Less than 1 minute
    if (uptime_secs < 60u) score += 3u;

    // BootId at +0x02BC — removed: too many FP on fresh installs and
    // machines that are rarely rebooted (low but nonzero boot_id).

    return score;
}

// =========================================================================
// 3. Processor count cross-validation
//
// Compare processor count from three independent sources:
//   - KUSER_SHARED_DATA.ActiveProcessorCount (+0x03C0)
//   - PEB.NumberOfProcessors (+0xB8)
//   - CPUID leaf 1 EBX[23:16]
//   - SystemBasicInformation NumberOfProcessors
//
// If they disagree, something is being spoofed. VMs with mismatched
// CPUID emulation often have inconsistencies.
// =========================================================================
ANTIDEBUG_INLINE u32 ad_vm_proc_count_cross(void) {
    u32 score = 0u;

    // Source 1: KUSD
    volatile u8* kusd = (volatile u8*)0x7FFE0000ULL;
    u32 build = *(volatile u32*)(kusd + 0x0260);
    u32 kusd_procs = 0u;
    if (build >= 17763u) {
        kusd_procs = *(volatile u32*)(kusd + 0x03C0);
    }

    // Source 2: PEB
    u8* peb = (u8*)__readgsqword(0x60);
    u32 peb_procs = peb ? *(u32*)(peb + 0xB8) : 0u;

    // Source 3: CPUID leaf 1
    int regs[4] = {0};
    __cpuid(regs, 1);
    u32 cpuid_procs = (u32)((regs[1] >> 16) & 0xFF);

    // Source 4: CPUID leaf 0x0B (if available)
    int max_leaf[4] = {0};
    __cpuid(max_leaf, 0);
    u32 topo_procs = 0u;
    if ((u32)max_leaf[0] >= 0x0Bu) {
        int topo[4] = {0};
        __cpuidex(topo, 0x0B, 1);  // Core level
        topo_procs = (u32)topo[1] & 0xFFFFu;
    }

    // Cross-validate: all non-zero sources should agree
    u32 sources[4] = {kusd_procs, peb_procs, cpuid_procs, topo_procs};
    u32 valid_count = 0u;
    u32 first_valid = 0u;
    u32 i;

    for (i = 0u; i < 4u; i++) {
        if (sources[i] > 0u) {
            if (valid_count == 0u) first_valid = sources[i];
            else if (sources[i] != first_valid) score += 2u;
            valid_count++;
        }
    }

    // Only one valid source = can't cross-validate (slightly suspicious)
    if (valid_count <= 1u) score += 1u;

    // All report 1 CPU = sandbox
    if (first_valid == 1u && valid_count >= 2u) score += 2u;

    return score;
}

// =========================================================================
// 4. KUSD system time anomaly
//
// KUSER_SHARED_DATA contains multiple time sources. VMs that snapshot
// and restore may have inconsistencies between:
//   - SystemTime (+0x14)
//   - InterruptTime (+0x08)
//   - TickCount (+0x320)
//
// Also check if timezone bias looks odd (offset 0x20).
// =========================================================================
ANTIDEBUG_INLINE u32 ad_vm_time_anomaly(void) {
    u32 score = 0u;
    volatile u8* kusd = (volatile u8*)0x7FFE0000ULL;

    // SystemTime: 100ns intervals since 1601-01-01
    u64 sys_time_lo = *(volatile u32*)(kusd + 0x14);
    u64 sys_time_hi = *(volatile u32*)(kusd + 0x1C);  // High2Time
    u64 sys_time = (sys_time_hi << 32) | sys_time_lo;

    // InterruptTime: 100ns intervals since boot
    u64 int_time_lo = *(volatile u32*)(kusd + 0x08);
    u64 int_time_hi = *(volatile u32*)(kusd + 0x10);
    u64 int_time = (int_time_hi << 32) | int_time_lo;

    // SystemTime should be > InterruptTime (system time is wall clock since 1601)
    // On a very fresh VM, system time might be suspiciously close to a round date
    // Windows epoch is Jan 1, 1601. Year 2020 ≈ 132500000000000000 (in 100ns units)
    u64 year_2020 = 132500000000000000ULL;
    u64 year_2015 = 130000000000000000ULL;

    // System time before 2015 = very suspicious (old VM image?)
    if (sys_time < year_2015 && sys_time > 0ULL) score += 3u;

    // InterruptTime > 0 but very small = fresh boot (< 30 seconds)
    // 30 seconds in 100ns units = 300000000
    if (int_time > 0ULL && int_time < 300000000ULL) score += 2u;

    // TimeZoneBias (+0x20): if this is exactly 0 and locale isn't UTC,
    // it might indicate a poorly configured VM
    u64 tz_bias = *(volatile u64*)(kusd + 0x20);
    AD_UNUSED(tz_bias);

    return score;
}

// =========================================================================
// 5. System performance information anomaly
//
// NtQuerySystemInformation(SystemPerformanceInformation = 2) returns
// system-wide performance data. VMs with limited resources show
// unusual patterns:
//   - Very low CommitLimit (total virtual memory)
//   - Very low AvailablePages
//   - Zero or near-zero cache counters
// =========================================================================
ANTIDEBUG_INLINE u32 ad_vm_perf_info_check(void) {
    static u16 s_ssn_qsi = AD_SSN_UNRESOLVED;
    AD_RESOLVE_SSN_ENC(s_ssn_qsi, NtQuerySystemInformation, 25);
    if (s_ssn_qsi == AD_SSN_FAILED) return 0u;

    u32 score = 0u;

    // SystemPerformanceInformation (class 2) is a large struct (~312 bytes)
    u8 perf_info[320];
    AD_ZERO_BUF(perf_info, sizeof(perf_info));
    u32 ret_len = 0u;

    ad_ntstatus_t st = AD_SYSCALL4(s_ssn_qsi, (u64)2,
        perf_info, (u64)sizeof(perf_info), &ret_len);

    if (AD_NT_SUCCESS(st)) {
        // IdleProcessTime at +0x00 (LARGE_INTEGER = 8 bytes)
        u64 idle_time = *(u64*)(perf_info + 0x00);

        // On x64, page counts are ULONG (4 bytes):
        // AvailablePages at +0x2C
        u32 avail_pages = *(u32*)(perf_info + 0x2C);

        // CommittedPages at +0x30
        u32 committed_pages = *(u32*)(perf_info + 0x30);

        // CommitLimit at +0x34
        u32 commit_limit = *(u32*)(perf_info + 0x34);

        // Very low commit limit (< ~1GB in pages, page = 4096)
        // 1GB = 262144 pages
        if (commit_limit > 0u && commit_limit < 262144u) score += 2u;

        // Very low available pages (< 128MB = 32768 pages)
        if (avail_pages > 0u && avail_pages < 32768u) score += 1u;

        // Zero idle time = extremely fresh (or broken emulation)
        if (idle_time == 0ULL) score += 2u;

        AD_UNUSED(committed_pages);
    }

    return score;
}

// =========================================================================
// 6. Screen resolution and color depth check
//
// VM environments often use default resolutions:
//   - 800x600, 1024x768 (very common VM defaults)
//   - 16-bit color depth (older VMs)
//
// We can detect screen info from KUSD's SharedDataFlags or from
// NtUserGetSystemMetrics. Without imports, use KUSD fields:
// KUSD doesn't directly have screen res, but NumberOfPhysicalPages
// relative to expected desktop size can indicate a sandbox.
//
// Alternative: check MaximumUserModeAddress from SystemBasicInformation.
// VMs sometimes restrict the user address space.
// =========================================================================
ANTIDEBUG_INLINE u32 ad_vm_address_space_check(void) {
    u32 score = 0u;

    // Check maximum user mode address from PEB
    u8* peb = (u8*)__readgsqword(0x60);
    if (!peb) return 0u;

    // On x64, user address space should go up to 0x7FFFFFFEFFFF (or
    // 0x7FFFFFFFFFFFF with large address aware). If it's significantly
    // lower, something is restricting it.
    // PEB doesn't directly store this, but we can check via
    // SystemBasicInformation or infer from module load addresses.

    // Check if we're running in WoW64 (32-bit on 64-bit)
    // PEB.wow64 process flag at offset 0x02 bit analysis
    // Actually, on x64 native, __readgsqword works. If we're here,
    // we're 64-bit. Just check for unusually low module addresses.

    // Image base from PEB
    void* image_base = *(void**)(peb + 0x10);
    u64 base_addr = (u64)(uintptr_t)image_base;

    // Typical x64 image base: 0x140000000 (default ASLR range)
    // or 0x7FF600000000+ for system DLLs
    // If base is in a very low range (< 0x10000000), might be emulated
    if (base_addr < 0x10000000ULL && base_addr > 0ULL) score += 1u;

    return score;
}

// =========================================================================
// 7. NUMA topology check
//
// Real multi-socket systems have NUMA nodes. Single-socket desktops
// have 1 NUMA node. VMs also typically have 1 node, but some VMs
// with multiple vCPUs across nodes have inconsistent NUMA topology.
//
// CPUID leaf 0x80000008 ECX[7:0] = number of physical cores - 1
// CPUID leaf 0x8000001E ECX = NodeId (AMD)
// =========================================================================
ANTIDEBUG_INLINE u32 ad_vm_numa_check(void) {
    u32 score = 0u;

    int ext_max[4] = {0};
    __cpuid(ext_max, (int)0x80000000);
    u32 max_ext = (u32)ext_max[0];

    if (max_ext >= 0x80000008u) {
        int r8[4] = {0};
        __cpuid(r8, (int)0x80000008);

        u32 phys_core_count = ((u32)r8[2] & 0xFFu) + 1u;
        u32 apic_id_size    = ((u32)r8[2] >> 12) & 0xFu;

        // 1 physical core = sandbox/minimal VM
        if (phys_core_count == 1u) score += 2u;

        // APIC ID size = 0 but multiple cores reported = inconsistent
        if (apic_id_size == 0u && phys_core_count > 1u) score += 2u;
    }

    // AMD-specific: leaf 0x8000001E
    if (max_ext >= 0x8000001Eu) {
        int r1e[4] = {0};
        __cpuid(r1e, (int)0x8000001E);

        u32 threads_per_core = (((u32)r1e[1] >> 8) & 0xFFu) + 1u;
        u32 node_id = (u32)r1e[2] & 0xFFu;

        // Threads per core > 2 = unusual (real CPUs have 1 or 2)
        if (threads_per_core > 2u) score += 2u;

        AD_UNUSED(node_id);
    }

    return score;
}

// =========================================================================
// 8. Disk size heuristic
//
// Query total commit limit (RAM + pagefile) as a proxy for system resources.
// Also query SystemProcessorPerformanceInformation to detect low-resource
// VMs. Real desktops: commit limit >= 4GB. VMs often have 1-3GB total.
//
// Additionally, check commit limit vs physical RAM ratio.
// Real systems: pagefile ≈ 1-2x RAM. VM sandboxes often have no pagefile
// or very small one, so commit limit ≈ physical RAM exactly.
// =========================================================================
ANTIDEBUG_INLINE u32 ad_vm_disk_size_heuristic(void) {
    static u16 s_ssn_qsi = AD_SSN_UNRESOLVED;
    AD_RESOLVE_SSN_ENC(s_ssn_qsi, NtQuerySystemInformation, 25);
    if (s_ssn_qsi == AD_SSN_FAILED) return 0u;

    u32 score = 0u;

    // Get physical pages from BasicInfo
    u8 basic_info[64];
    AD_ZERO_BUF(basic_info, sizeof(basic_info));
    u32 ret_len = 0u;
    ad_ntstatus_t st = AD_SYSCALL4(s_ssn_qsi, (u64)0,
        basic_info, (u64)sizeof(basic_info), &ret_len);

    u64 phys_pages = 0ULL;
    u32 page_size = 4096u;
    if (AD_NT_SUCCESS(st)) {
        page_size   = *(u32*)(basic_info + 0x08);
        phys_pages  = (u64)*(u32*)(basic_info + 0x0C);
    }

    // Get commit limit from PerformanceInfo
    u8 perf_info[320];
    AD_ZERO_BUF(perf_info, sizeof(perf_info));
    st = AD_SYSCALL4(s_ssn_qsi, (u64)2,
        perf_info, (u64)sizeof(perf_info), &ret_len);

    if (AD_NT_SUCCESS(st) && phys_pages > 0ULL) {
        // CommitLimit at +0x34 (ULONG, 4 bytes)
        u64 commit_limit = (u64)*(u32*)(perf_info + 0x34);

        // Commit limit very close to physical RAM = no pagefile (VM sandbox)
        if (commit_limit > 0ULL && phys_pages > 0ULL) {
            u64 threshold = phys_pages + (phys_pages / 20u);  // +5%
            if (commit_limit <= threshold) score += 2u;
        }

        // Commit limit < 2GB (in pages) = extremely constrained VM
        u64 commit_mb = (commit_limit * (u64)page_size) / (1024ULL * 1024ULL);
        if (commit_mb > 0ULL && commit_mb < 2048ULL) score += 2u;
    }

    return score;
}

// =========================================================================
// 9. Bizarre hardware configuration detector
//
// Real hardware has predictable configurations. VMs often have unusual
// combinations that never appear on real machines:
//   - Very few cores but lots of RAM (or vice versa)
//   - 1 core with 64GB RAM = impossible on real desktop
//   - 32 cores with 512MB RAM = impossible
//   - Max basic CPUID leaf suspiciously low (real CPUs: >= 0x0D since ~2012)
//   - Physical address bits too low (< 36 on real x64 hardware)
// =========================================================================
ANTIDEBUG_INLINE u32 ad_vm_bizarre_config(void) {
    u32 score = 0u;

    // Get processor count
    u8* peb = (u8*)__readgsqword(0x60);
    u32 num_procs = peb ? *(u32*)(peb + 0xB8) : 0u;

    // Get physical memory
    static u16 s_ssn_qsi = AD_SSN_UNRESOLVED;
    AD_RESOLVE_SSN_ENC(s_ssn_qsi, NtQuerySystemInformation, 25);
    u64 phys_gb = 0ULL;
    if (s_ssn_qsi != AD_SSN_FAILED) {
        u8 basic[64];
        AD_ZERO_BUF(basic, sizeof(basic));
        u32 ret = 0u;
        ad_ntstatus_t st = AD_SYSCALL4(s_ssn_qsi, (u64)0,
            basic, (u64)sizeof(basic), &ret);
        if (AD_NT_SUCCESS(st)) {
            u32 pages = *(u32*)(basic + 0x0C);
            u32 pgsz  = *(u32*)(basic + 0x08);
            phys_gb = ((u64)pages * (u64)pgsz) / (1024ULL * 1024ULL * 1024ULL);
        }
    }

    // Bizarre: 1 core + > 16GB RAM (never on real single-core machines)
    if (num_procs == 1u && phys_gb >= 16ULL) score += 3u;

    // Bizarre: many cores + very little RAM
    if (num_procs >= 8u && phys_gb > 0ULL && phys_gb < 2ULL) score += 3u;

    // Max basic CPUID leaf — real CPUs since Sandy Bridge have >= 0x0D
    // Modern CPUs (2020+): >= 0x14. Very low = old emulator or stripped VM.
    {
        int ml[4] = {0};
        __cpuid(ml, 0);
        u32 max_leaf = (u32)ml[0];
        if (max_leaf < 0x07u) score += 3u;       // pre-2011 or emulator
        else if (max_leaf < 0x0Du) score += 1u;   // pre-2013
    }

    // Physical address bits (CPUID 0x80000008 EAX[7:0])
    // Real x64 CPUs: 36-52 bits. Emulators may report 32 or 0.
    {
        int ext_max[4] = {0};
        __cpuid(ext_max, (int)0x80000000);
        if ((u32)ext_max[0] >= 0x80000008u) {
            int r8[4] = {0};
            __cpuid(r8, (int)0x80000008);
            u32 pa_bits = (u32)r8[0] & 0xFFu;
            if (pa_bits > 0u && pa_bits < 36u) score += 3u;
            if (pa_bits == 0u) score += 4u;  // not even reported
        }
    }

    return score;
}

// =========================================================================
// Diagnostic: read raw hardware values (for test output, not scoring)
// =========================================================================
typedef struct {
    u64 phys_mb;            // Physical RAM in MB
    u64 commit_limit_mb;    // Commit limit in MB
    u32 num_procs_peb;      // Processor count from PEB
    u32 num_procs_cpuid;    // Processor count from CPUID leaf 1
    u32 max_cpuid_leaf;     // Max basic CPUID leaf
    u32 pa_bits;            // Physical address bits
    u32 va_bits;            // Virtual address bits
    u32 uptime_secs;        // System uptime in seconds
    u32 cache_levels;       // Number of cache levels
} ad_vm_hw_diag_t;

ANTIDEBUG_INLINE void ad_vm_read_hw_diag(ad_vm_hw_diag_t* d) {
    AD_ZERO_BUF(d, sizeof(*d));

    // PEB procs
    u8* peb = (u8*)__readgsqword(0x60);
    d->num_procs_peb = peb ? *(u32*)(peb + 0xB8) : 0u;

    // CPUID leaf 1 procs
    int regs[4] = {0};
    __cpuid(regs, 1);
    d->num_procs_cpuid = (u32)((regs[1] >> 16) & 0xFF);

    // Max CPUID leaf
    int ml[4] = {0};
    __cpuid(ml, 0);
    d->max_cpuid_leaf = (u32)ml[0];

    // PA/VA bits
    int ext_max[4] = {0};
    __cpuid(ext_max, (int)0x80000000);
    if ((u32)ext_max[0] >= 0x80000008u) {
        int r8[4] = {0};
        __cpuid(r8, (int)0x80000008);
        d->pa_bits = (u32)r8[0] & 0xFFu;
        d->va_bits = ((u32)r8[0] >> 8) & 0xFFu;
    }

    // Physical memory + commit limit via syscall
    static u16 s_ssn_qsi = AD_SSN_UNRESOLVED;
    AD_RESOLVE_SSN_ENC(s_ssn_qsi, NtQuerySystemInformation, 25);
    if (s_ssn_qsi != AD_SSN_FAILED) {
        u8 basic[64];
        AD_ZERO_BUF(basic, sizeof(basic));
        u32 ret = 0u;
        ad_ntstatus_t st = AD_SYSCALL4(s_ssn_qsi, (u64)0,
            basic, (u64)sizeof(basic), &ret);
        if (AD_NT_SUCCESS(st)) {
            u32 pages = *(u32*)(basic + 0x0C);
            u32 pgsz  = *(u32*)(basic + 0x08);
            d->phys_mb = ((u64)pages * (u64)pgsz) / (1024ULL * 1024ULL);
        }

        u8 perf[320];
        AD_ZERO_BUF(perf, sizeof(perf));
        st = AD_SYSCALL4(s_ssn_qsi, (u64)2, perf, (u64)sizeof(perf), &ret);
        if (AD_NT_SUCCESS(st)) {
            // CommitLimit is a ULONG (4 bytes) at offset 0x34 on x64
            u32 cl = *(u32*)(perf + 0x34);
            d->commit_limit_mb = ((u64)cl * 4096ULL) / (1024ULL * 1024ULL);
        }
    }

    // Uptime
    volatile u8* kusd = (volatile u8*)0x7FFE0000ULL;
    u32 tick_low = *(volatile u32*)(kusd + 0x0320);
    d->uptime_secs = tick_low / 64u;

    // Cache levels (Intel: leaf 4, AMD: leaf 0x8000001D)
    {
        u32 idx;
        d->cache_levels = 0u;
        // Try Intel leaf 4 first
        for (idx = 0u; idx < 8u; idx++) {
            int cr[4] = {0};
            __cpuidex(cr, 4, (int)idx);
            if (((u32)(cr[0]) & 0x1Fu) == 0u) break;
            d->cache_levels++;
        }
        // If zero, try AMD leaf 0x8000001D
        if (d->cache_levels == 0u) {
            int em[4] = {0};
            __cpuid(em, (int)0x80000000);
            if ((u32)em[0] >= 0x8000001Du) {
                for (idx = 0u; idx < 8u; idx++) {
                    int cr[4] = {0};
                    __cpuidex(cr, (int)0x8000001D, (int)idx);
                    if (((u32)(cr[0]) & 0x1Fu) == 0u) break;
                    d->cache_levels++;
                }
            }
        }
    }
}

// =========================================================================
// MASTER: memory anomaly composite score
// =========================================================================
ANTIDEBUG_INLINE u32 ad_vm_memory_master(void) {
    u32 score = 0u;
    score += ad_vm_physical_mem_low();
    score += ad_vm_uptime_check();
    score += ad_vm_proc_count_cross();
    score += ad_vm_time_anomaly();
    score += ad_vm_perf_info_check();
    score += ad_vm_address_space_check();
    score += ad_vm_numa_check();
    score += ad_vm_disk_size_heuristic();
    score += ad_vm_bizarre_config();
    return score;
}

#else

ANTIDEBUG_INLINE u32 ad_vm_physical_mem_low(void)   { return 0; }
ANTIDEBUG_INLINE u32 ad_vm_uptime_check(void)       { return 0; }
ANTIDEBUG_INLINE u32 ad_vm_proc_count_cross(void)   { return 0; }
ANTIDEBUG_INLINE u32 ad_vm_time_anomaly(void)       { return 0; }
ANTIDEBUG_INLINE u32 ad_vm_perf_info_check(void)    { return 0; }
ANTIDEBUG_INLINE u32 ad_vm_address_space_check(void) { return 0; }
ANTIDEBUG_INLINE u32 ad_vm_numa_check(void)          { return 0; }
ANTIDEBUG_INLINE u32 ad_vm_disk_size_heuristic(void) { return 0; }
ANTIDEBUG_INLINE u32 ad_vm_bizarre_config(void)      { return 0; }
ANTIDEBUG_INLINE u32 ad_vm_memory_master(void)       { return 0; }

#endif // _MSC_VER

#endif // ANTIDEBUG_VM_MEMORY_ANOMALY_H