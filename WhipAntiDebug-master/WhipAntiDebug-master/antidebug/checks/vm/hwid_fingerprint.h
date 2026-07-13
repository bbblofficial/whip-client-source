// ===== file: antidebug/checks/vm/hwid_fingerprint.h =====
//
// HWID / environment fingerprint — detect sandboxes, cloned VMs, and
// analysis environments through hardware anomalies that are hard to fake.
//
// Techniques:
//   1. CPUID topology: real CPUs have consistent core/thread/cache topology.
//      Sandboxes often expose 1 core, 0 cache descriptors, or nonsensical
//      topology (e.g. 1 logical processor but 4 NUMA nodes).
//   2. KUSD machine fingerprint: KUSER_SHARED_DATA fields that sandboxes
//      rarely bother faking (ActiveProcessorCount, NtProductType,
//      NtBuildNumber, PhysicalMemoryPages range).
//   3. TSC frequency sanity: CPUID leaf 0x15/0x16 (if available) reports
//      the core crystal/base frequency. Emulators report 0 or absurd values.
//   4. Firmware SMBIOS marker: NtQuerySystemInformation(76) returns the raw
//      SMBIOS table. Sandboxes often have generic "QEMU"/"Bochs"/"innotek"
//      strings in the BIOS vendor / system manufacturer fields.
//
#ifndef ANTIDEBUG_HWID_FINGERPRINT_H
#define ANTIDEBUG_HWID_FINGERPRINT_H

#include "../../core/types.h"
#include "../../core/macros.h"
#include "../../core/syscall_bridge.h"
#include "../../core/string_encrypt.h"

#if defined(_MSC_VER)

// =========================================================================
// 1. CPUID topology anomaly
// =========================================================================
ANTIDEBUG_INLINE u32 ad_hwid_topology_check(void) {
    u32 score = 0u;

    // Leaf 1: logical processor count (EBX[23:16])
    int regs[4] = {0};
    __cpuid(regs, 1);
    u32 logical_cpus = (u32)((regs[1] >> 16) & 0xFF);

    // Also read ActiveProcessorCount from KUSD (+0x03C0 on RS5+, but
    // the simpler NumberOfProcessors is at PEB+0xB8).
    u8* peb = (u8*)__readgsqword(0x60);
    u32 peb_procs = peb ? *(u32*)(peb + 0xB8) : 0u;

    // Sandbox indicator: 1 logical CPU
    if (logical_cpus <= 1u) score += 2u;
    if (peb_procs <= 1u)    score += 2u;

    // CPUID topology mismatch: leaf 1 says N CPUs but PEB says M
    if (logical_cpus > 0u && peb_procs > 0u) {
        if (logical_cpus != peb_procs) score += 3u;
    }

    // Leaf 4 (deterministic cache parameters): Intel-only. AMD CPUs return
    // 0 from leaf 4 (they use leaf 0x8000_0005/6/1D instead). On AMD this
    // would always score 3 — false positive on Ryzen / EPYC. Skip on AMD.
    {
        int vendor_regs[4] = {0};
        __cpuid(vendor_regs, 0);
        // "AuthenticAMD" → ebx=0x68747541
        b32 is_amd = (vendor_regs[1] == 0x68747541);
        if (!is_amd) {
            u32 cache_levels = 0u;
            u32 idx;
            for (idx = 0u; idx < 8u; idx++) {
                int cr[4] = {0};
                __cpuidex(cr, 4, (int)idx);
                u32 cache_type = (u32)(cr[0] & 0x1F);
                if (cache_type == 0u) break;
                cache_levels++;
            }
            if (cache_levels < 2u) score += 3u;
        }
    }

    return score;
}

// =========================================================================
// 2. KUSD / system profile anomalies
// =========================================================================
ANTIDEBUG_INLINE u32 ad_hwid_system_profile(void) {
    u32 score = 0u;
    volatile u8* kusd = (volatile u8*)0x7FFE0000ULL;

    // NtBuildNumber at offset 0x0260 (u32) — real Win10/11 is >= 10240
    u32 build = *(volatile u32*)(kusd + 0x0260);
    if (build < 7600u) score += 3u;  // Pre-Win7 or emulated OS

    // NtProductType at offset 0x0264 (u32): 1=Workstation, 2=DomainCtrl, 3=Server
    u32 prod = *(volatile u32*)(kusd + 0x0264);
    if (prod == 0u || prod > 3u) score += 2u;  // Invalid product type

    // ActiveProcessorCount at offset 0x03C0 (u32) — available since RS5
    // On older builds this may be 0, so only flag if build >= 17763
    if (build >= 17763u) {
        u32 active_procs = *(volatile u32*)(kusd + 0x03C0);
        if (active_procs <= 1u) score += 2u;
    }

    // PhysicalPages via PEB.NumberOfPhysicalPages isn't in KUSD.
    // Use CPUID leaf 0x80000008 for physical address bits instead.
    // Real hardware: 36-52 physical address bits.
    // Emulators sometimes report 0 or 32.
    {
        int ext_regs[4] = {0};
        __cpuid(ext_regs, (int)0x80000008);
        u32 phys_bits = (u32)(ext_regs[0] & 0xFF);
        if (phys_bits < 36u) score += 2u;
    }

    return score;
}

// =========================================================================
// 3. TSC frequency sanity (CPUID 0x15 / 0x16)
// =========================================================================
ANTIDEBUG_INLINE u32 ad_hwid_tsc_freq_check(void) {
    u32 score = 0u;

    // Check if leaf 0x15 is available
    int max_leaf[4] = {0};
    __cpuid(max_leaf, 0);
    if ((u32)max_leaf[0] < 0x15u) return 0u;

    // Leaf 0x15: EAX=denominator, EBX=numerator, ECX=crystal freq (Hz)
    // If EAX/EBX are 0 but leaf exists → emulator didn't fill it
    int freq[4] = {0};
    __cpuid(freq, 0x15);
    u32 denom   = (u32)freq[0];
    u32 numer   = (u32)freq[1];
    u32 crystal = (u32)freq[2];

    if (denom == 0u && numer == 0u) {
        // Leaf exists but empty — not necessarily suspicious on all CPUs
        // (Haswell/Broadwell don't fill this). Only flag if crystal is also 0.
        if (crystal == 0u) score += 1u;
    } else if (denom != 0u && numer != 0u && crystal != 0u) {
        // Compute TSC frequency: crystal * numer / denom
        u64 tsc_hz = ((u64)crystal * (u64)numer) / (u64)denom;
        // Sane range: 500 MHz - 6 GHz
        if (tsc_hz < 500000000ULL || tsc_hz > 6000000000ULL)
            score += 3u;
    }

    // Leaf 0x16 (if available): EAX = base freq in MHz
    if ((u32)max_leaf[0] >= 0x16u) {
        int freq16[4] = {0};
        __cpuid(freq16, 0x16);
        u32 base_mhz = (u32)freq16[0] & 0xFFFFu;
        // Sane: 500 - 6000 MHz
        if (base_mhz > 0u && (base_mhz < 500u || base_mhz > 6000u))
            score += 2u;
    }

    return score;
}

// =========================================================================
// 4. SMBIOS firmware string scan
// =========================================================================
// NtQuerySystemInformation(SystemFirmwareTableInformation = 76)
// The SMBIOS raw table contains BIOS vendor, system manufacturer, product
// name as null-terminated strings. Sandboxes often have "QEMU", "Bochs",
// "innotek GmbH" (VirtualBox), "VMware", "Xen", "Microsoft Corporation"
// (Hyper-V), "BHYVE", or "Amazon EC2" in these fields.

// Small case-insensitive substring search (no CRT)
ANTIDEBUG_INLINE b32 ad_smbios_find(const u8* hay, u32 hay_len,
                                     const char* needle, u32 needle_len) {
    if (needle_len > hay_len) return 0;
    u32 limit = hay_len - needle_len;
    u32 i, j;
    for (i = 0u; i <= limit; i++) {
        b32 match = 1;
        for (j = 0u; j < needle_len; j++) {
            u8 a = hay[i + j];
            u8 b = (u8)needle[j];
            // Cheap case-insensitive: force both to lowercase
            if (a >= 'A' && a <= 'Z') a += 32u;
            if (b >= 'A' && b <= 'Z') b += 32u;
            if (a != b) { match = 0; break; }
        }
        if (match) return 1;
    }
    return 0;
}

// SystemFirmwareTableInformation request structure
typedef struct {
    u32 ProviderSignature;  // 'RSMB' = 0x52534D42
    u32 Action;             // 0 = enumerate, 1 = get table
    u32 TableID;            // 0 for SMBIOS
    u32 TableBufferLength;
    u8  TableBuffer[1];
} AD_FIRMWARE_TABLE_INFO;

ANTIDEBUG_INLINE u32 ad_hwid_smbios_check(void) {
    static u16 s_ssn_qsi   = AD_SSN_UNRESOLVED;
    static u16 s_ssn_alloc = AD_SSN_UNRESOLVED;
    static u16 s_ssn_free  = AD_SSN_UNRESOLVED;
    AD_RESOLVE_SSN_ENC(s_ssn_qsi,   NtQuerySystemInformation, 25);
    AD_RESOLVE_SSN_ENC(s_ssn_alloc, NtAllocateVirtualMemory,  24);
    AD_RESOLVE_SSN_ENC(s_ssn_free,  NtFreeVirtualMemory,      20);
    if (s_ssn_qsi == AD_SSN_FAILED || s_ssn_alloc == AD_SSN_FAILED ||
        s_ssn_free == AD_SSN_FAILED) return 0u;

    // Allocate buffer for the request + SMBIOS data
    void* buf = (void*)0;
    u64 buf_size = 0x10000ULL;  // 64KB should be enough for SMBIOS
    ad_ntstatus_t st = AD_SYSCALL6(s_ssn_alloc,
        AD_CURRENT_PROCESS, &buf, (u64)0, &buf_size,
        (u64)(0x1000UL | 0x2000UL), (u64)0x04UL);
    if (!AD_NT_SUCCESS(st) || !buf) return 0u;

    // Fill the request header
    AD_FIRMWARE_TABLE_INFO* req = (AD_FIRMWARE_TABLE_INFO*)buf;
    req->ProviderSignature = 0x52534D42u; // 'RSMB'
    req->Action            = 1u;          // get table
    req->TableID           = 0u;
    req->TableBufferLength = (u32)(buf_size - 16u);

    u32 needed = 0u;
    st = AD_SYSCALL4(s_ssn_qsi, (u64)76, buf, (u64)buf_size, &needed);

    u32 score = 0u;
    if (AD_NT_SUCCESS(st) && needed > 16u) {
        u32 data_len = needed - 16u;
        if (data_len > (u32)(buf_size - 16u)) data_len = (u32)(buf_size - 16u);
        const u8* data = req->TableBuffer;

        // Scan for known sandbox/VM vendor strings
        if (ad_smbios_find(data, data_len, "QEMU",    4u)) score += 4u;
        if (ad_smbios_find(data, data_len, "Bochs",   5u)) score += 4u;
        if (ad_smbios_find(data, data_len, "innotek", 7u)) score += 4u;
        if (ad_smbios_find(data, data_len, "VMware",  6u)) score += 3u;
        if (ad_smbios_find(data, data_len, "Xen",     3u)) score += 3u;
        if (ad_smbios_find(data, data_len, "BHYVE",   5u)) score += 4u;
        if (ad_smbios_find(data, data_len, "Amazon EC2", 10u)) score += 3u;
        if (ad_smbios_find(data, data_len, "Google Compute", 14u)) score += 3u;
        if (ad_smbios_find(data, data_len, "Parallels", 9u)) score += 3u;
        // "Virtual Machine" in product name (Hyper-V)
        if (ad_smbios_find(data, data_len, "Virtual Machine", 15u)) score += 3u;
    }

    // Free buffer
    {
        void* free_base = buf;
        u64   free_size = 0ULL;
        AD_SYSCALL4(s_ssn_free, AD_CURRENT_PROCESS, &free_base, &free_size, (u64)0x8000UL);
    }

    return score;
}

// =========================================================================
// MASTER — composite HWID fingerprint score
// =========================================================================
ANTIDEBUG_INLINE u32 ad_hwid_fingerprint_master(void) {
    u32 score = 0u;
    score += ad_hwid_topology_check();
    score += ad_hwid_system_profile();
    score += ad_hwid_tsc_freq_check();
    score += ad_hwid_smbios_check();
    return score;
}

#else
ANTIDEBUG_INLINE u32 ad_hwid_fingerprint_master(void) { return 0; }
#endif // _MSC_VER

#endif // ANTIDEBUG_HWID_FINGERPRINT_H
