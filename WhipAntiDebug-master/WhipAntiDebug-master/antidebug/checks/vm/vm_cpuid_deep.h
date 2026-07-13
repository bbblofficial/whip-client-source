// ===== file: antidebug/checks/vm/vm_cpuid_deep.h =====
//
// Deep CPUID-based VM detection — goes far beyond the basic hypervisor bit.
//
// Techniques:
//   1. Nested hypervisor detection via leaf 0x40000001 feature bits
//   2. CPU brand string scan for VM-injected indicators
//   3. Feature flag cross-validation across leaves (impossible combos)
//   4. Performance monitoring CPUID leaf anomaly (VMs simplify PMC)
//   5. Thermal / power reporting anomaly (VMs don't report thermals)
//   6. Extended topology enumeration (leaf 0x0B) consistency
//   7. SGX reported but not functional on any known hypervisor
//   8. Structured extended feature (leaf 7) cross-check
//
// No CRT, no imports — pure CPUID intrinsics.
//
#ifndef ANTIDEBUG_VM_CPUID_DEEP_H
#define ANTIDEBUG_VM_CPUID_DEEP_H

#include "../../core/types.h"
#include "../../core/macros.h"
#include "../../core/config.h"

#if defined(_MSC_VER)

// ---------------------------------------------------------------------------
// 1. Nested hypervisor detection
//
// Leaf 0x40000001 is the hypervisor "interface identification" leaf.
// On real hardware with no hypervisor, this leaf returns zeros.
// Under a hypervisor, it returns interface ID and feature bits.
// Some hypervisors (KVM, Hyper-V) report enlightenments here that
// reveal their identity even if the vendor string is spoofed.
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE u32 ad_vm_nested_hv(void) {
    u32 score = 0u;

    // First check if hypervisor is present
    int regs[4] = {0};
    __cpuid(regs, (int)0x40000000);
    u32 max_hv_leaf = (u32)regs[0];
    if (max_hv_leaf < 0x40000000u) return 0u;

    // Suppress for "Microsoft Hv" — Windows 11 VBS/HVCI root partition
    // is NOT a VM guest. Same suppression as ad_vm_cpuid_hypervisor_bit.
    {
        static const u8 msft[12] = {'M','i','c','r','o','s','o','f','t',' ','H','v'};
        u8 v[12]; u32 t, j;
        t=(u32)regs[1]; v[0]=(u8)t; v[1]=(u8)(t>>8); v[2]=(u8)(t>>16); v[3]=(u8)(t>>24);
        t=(u32)regs[2]; v[4]=(u8)t; v[5]=(u8)(t>>8); v[6]=(u8)(t>>16); v[7]=(u8)(t>>24);
        t=(u32)regs[3]; v[8]=(u8)t; v[9]=(u8)(t>>8); v[10]=(u8)(t>>16); v[11]=(u8)(t>>24);
        b32 is_msft = 1;
        for (j = 0u; j < 12u && is_msft; j++) if (v[j] != msft[j]) is_msft = 0;
        if (is_msft) return 0u;  // Windows VBS — not a real VM
    }

    // Leaf 0x40000001: hypervisor interface signature
    if (max_hv_leaf >= 0x40000001u) {
        int hv1[4] = {0};
        __cpuid(hv1, (int)0x40000001);
        u32 iface_sig = (u32)hv1[0];
        if (iface_sig != 0u) score += 2u;
        if ((u32)hv1[1] != 0u) score += 1u;
    }

    // Leaf 0x40000003: Hyper-V implementation limits
    if (max_hv_leaf >= 0x40000003u) {
        int hv3[4] = {0};
        __cpuid(hv3, (int)0x40000003);
        if ((u32)hv3[0] != 0u && (u32)hv3[1] != 0u) score += 2u;
    }

    // Leaf 0x40000006: Hyper-V hardware features detected
    if (max_hv_leaf >= 0x40000006u) {
        int hv6[4] = {0};
        __cpuid(hv6, (int)0x40000006);
        if ((u32)hv6[0] != 0u) score += 2u;
    }

    // Many hypervisor leaves available = strong indicator
    if (max_hv_leaf >= 0x40000010u) score += 3u;
    else if (max_hv_leaf >= 0x40000005u) score += 1u;

    return score;
}

// ---------------------------------------------------------------------------
// 2. CPU brand string scan for VM indicators
//
// CPUID leaves 0x80000002..0x80000004 return the processor brand string
// (48 ASCII chars). Some hypervisors inject identifying text:
//   - QEMU: "QEMU Virtual CPU" or "Common KVM processor"
//   - VirtualBox: may contain "VirtualBox" or unusual model
//   - Generic: "Virtual" anywhere in string
//
// We also check for unrealistic brand strings (all spaces, empty, etc.)
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE u32 ad_vm_cpuid_brand_scan(void) {
    u32 score = 0u;

    // Check max extended leaf
    int ext_max[4] = {0};
    __cpuid(ext_max, (int)0x80000000);
    if ((u32)ext_max[0] < 0x80000004u) {
        // No brand string support — extremely unusual on x64
        return 3u;
    }

    // Read brand string (48 bytes)
    u8 brand[48];
    {
        int r2[4] = {0}, r3[4] = {0}, r4[4] = {0};
        __cpuid(r2, (int)0x80000002);
        __cpuid(r3, (int)0x80000003);
        __cpuid(r4, (int)0x80000004);

        u32 off, reg;
        u32* src;

        src = (u32*)r2;
        for (reg = 0u; reg < 4u; reg++) {
            u32 v = src[reg];
            off = reg * 4u;
            brand[off+0u] = (u8)(v);
            brand[off+1u] = (u8)(v >> 8);
            brand[off+2u] = (u8)(v >> 16);
            brand[off+3u] = (u8)(v >> 24);
        }
        src = (u32*)r3;
        for (reg = 0u; reg < 4u; reg++) {
            u32 v = src[reg];
            off = 16u + reg * 4u;
            brand[off+0u] = (u8)(v);
            brand[off+1u] = (u8)(v >> 8);
            brand[off+2u] = (u8)(v >> 16);
            brand[off+3u] = (u8)(v >> 24);
        }
        src = (u32*)r4;
        for (reg = 0u; reg < 4u; reg++) {
            u32 v = src[reg];
            off = 32u + reg * 4u;
            brand[off+0u] = (u8)(v);
            brand[off+1u] = (u8)(v >> 8);
            brand[off+2u] = (u8)(v >> 16);
            brand[off+3u] = (u8)(v >> 24);
        }
    }

    // Scan for VM-related substrings (case-insensitive)
    // Patterns: "QEMU", "Virtual", "KVM", "vCPU"
    {
        u32 i;
        for (i = 0u; i < 44u; i++) {
            u8 a = brand[i]; if (a >= 'A' && a <= 'Z') a += 32u;
            u8 b = brand[i+1u]; if (b >= 'A' && b <= 'Z') b += 32u;
            u8 c = brand[i+2u]; if (c >= 'A' && c <= 'Z') c += 32u;
            u8 d = brand[i+3u]; if (d >= 'A' && d <= 'Z') d += 32u;

            // "qemu"
            if (a=='q' && b=='e' && c=='m' && d=='u') { score += 4u; break; }
            // "kvm "  or "kvm\0"
            if (a=='k' && b=='v' && c=='m' && (d==' ' || d==0)) { score += 4u; break; }
            // "vcpu"
            if (a=='v' && b=='c' && c=='p' && d=='u') { score += 3u; break; }
        }

        // "virtual" (7 chars)
        for (i = 0u; i < 41u; i++) {
            u8 v[7];
            u32 j;
            for (j = 0u; j < 7u; j++) {
                v[j] = brand[i+j];
                if (v[j] >= 'A' && v[j] <= 'Z') v[j] += 32u;
            }
            if (v[0]=='v' && v[1]=='i' && v[2]=='r' && v[3]=='t' &&
                v[4]=='u' && v[5]=='a' && v[6]=='l') {
                score += 3u;
                break;
            }
        }
    }

    // Check for all-zero brand (emulator not filling it)
    {
        u32 zero_count = 0u;
        u32 i;
        for (i = 0u; i < 48u; i++) {
            if (brand[i] == 0u) zero_count++;
        }
        if (zero_count >= 40u) score += 3u;
    }

    return score;
}

// ---------------------------------------------------------------------------
// 3. Feature flag cross-validation
//
// Detect impossible or inconsistent feature flag combinations:
//   - SSE2 mandatory on x64, but some emulators miss it
//   - AVX2 (leaf 7 EBX[5]) without AVX (leaf 1 ECX[28]) = impossible
//   - AES-NI without SSE2 = impossible
//   - XSAVE without OSXSAVE = OS hasn't enabled it (not necessarily VM,
//     but unusual for modern Windows)
//   - POPCNT (ECX[23]) without SSE4.2 (ECX[20]) = odd (Intel always pairs)
//   - CPUID vendor mismatch with feature set
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE u32 ad_vm_cpuid_feature_cross(void) {
    u32 score = 0u;

    int regs1[4] = {0};
    __cpuid(regs1, 1);
    u32 ecx = (u32)regs1[2];
    u32 edx = (u32)regs1[3];

    // SSE2 is mandatory on x64
    if (!((edx >> 26) & 1u)) score += 4u;

    // Check AVX2 consistency
    int max_leaf[4] = {0};
    __cpuid(max_leaf, 0);
    if ((u32)max_leaf[0] >= 7u) {
        int regs7[4] = {0};
        __cpuidex(regs7, 7, 0);
        u32 ebx7 = (u32)regs7[1];

        // AVX2 (leaf7 EBX[5]) requires AVX (leaf1 ECX[28])
        b32 has_avx2 = (b32)((ebx7 >> 5) & 1u);
        b32 has_avx  = (b32)((ecx >> 28) & 1u);
        if (has_avx2 && !has_avx) score += 4u;

        // BMI1 (leaf7 EBX[3]) and BMI2 (leaf7 EBX[8]) typically come together
        b32 has_bmi1 = (b32)((ebx7 >> 3) & 1u);
        b32 has_bmi2 = (b32)((ebx7 >> 8) & 1u);
        if (has_bmi2 && !has_bmi1) score += 2u;

        // SHA (leaf7 EBX[29]) requires SSE2
        b32 has_sha = (b32)((ebx7 >> 29) & 1u);
        if (has_sha && !((edx >> 26) & 1u)) score += 3u;
    }

    // AES-NI (ECX[25]) without SSE2 = impossible
    if (((ecx >> 25) & 1u) && !((edx >> 26) & 1u)) score += 3u;

    // XSAVE (ECX[26]) should be paired with OSXSAVE (ECX[27]) on modern Win
    // Benign without OSXSAVE: OS simply hasn't enabled it yet (early boot,
    // some VBS configs). Only flag in combination with other anomalies.
    AD_UNUSED(ecx);  // XSAVE/OSXSAVE check removed — too many FP

    // CMPXCHG16B (ECX[13]) is mandatory on Win x64 (since Vista)
    if (!((ecx >> 13) & 1u)) score += 3u;

    // Check vendor vs feature consistency
    {
        u8 vendor[12];
        u32 t;
        t = (u32)max_leaf[1];
        vendor[0]=(u8)(t); vendor[1]=(u8)(t>>8); vendor[2]=(u8)(t>>16); vendor[3]=(u8)(t>>24);
        t = (u32)max_leaf[3];
        vendor[4]=(u8)(t); vendor[5]=(u8)(t>>8); vendor[6]=(u8)(t>>16); vendor[7]=(u8)(t>>24);
        t = (u32)max_leaf[2];
        vendor[8]=(u8)(t); vendor[9]=(u8)(t>>8); vendor[10]=(u8)(t>>16); vendor[11]=(u8)(t>>24);

        // Check if vendor is "GenuineIntel"
        static const u8 intel[12] = {'G','e','n','u','i','n','e','I','n','t','e','l'};
        static const u8 amd[12] = {'A','u','t','h','e','n','t','i','c','A','M','D'};
        b32 is_intel = 1, is_amd = 1;
        u32 j;
        for (j = 0u; j < 12u; j++) {
            if (vendor[j] != intel[j]) is_intel = 0;
            if (vendor[j] != amd[j]) is_amd = 0;
        }

        // Unknown vendor string = suspicious
        if (!is_intel && !is_amd) score += 2u;

        // MONITOR/MWAIT on AMD: Zen3+ supports MONITORX, and some AMD
        // server parts report standard MONITOR too. Too weak to flag.
        AD_UNUSED(is_amd);
    }

    return score;
}

// ---------------------------------------------------------------------------
// 4. Performance monitoring CPUID leaf anomaly
//
// Leaf 0x0A (Intel) reports architectural performance monitoring version,
// number of GP counters, and bit width. Real Intel CPUs always have >= v1.
// Emulators often return 0 for the version or nonsensical counter counts.
//
// AMD doesn't use leaf 0x0A, so we skip for AMD.
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE u32 ad_vm_cpuid_perf_mon(void) {
    u32 score = 0u;

    // Check vendor first
    int v[4] = {0};
    __cpuid(v, 0);
    u32 max_leaf = (u32)v[0];

    static const u8 intel[12] = {'G','e','n','u','i','n','e','I','n','t','e','l'};
    u8 vendor[12];
    u32 t;
    t = (u32)v[1];
    vendor[0]=(u8)t; vendor[1]=(u8)(t>>8); vendor[2]=(u8)(t>>16); vendor[3]=(u8)(t>>24);
    t = (u32)v[3];
    vendor[4]=(u8)t; vendor[5]=(u8)(t>>8); vendor[6]=(u8)(t>>16); vendor[7]=(u8)(t>>24);
    t = (u32)v[2];
    vendor[8]=(u8)t; vendor[9]=(u8)(t>>8); vendor[10]=(u8)(t>>16); vendor[11]=(u8)(t>>24);

    b32 is_intel = 1;
    u32 j;
    for (j = 0u; j < 12u; j++)
        if (vendor[j] != intel[j]) { is_intel = 0; break; }

    if (!is_intel) return 0u;
    if (max_leaf < 0x0Au) return 0u;

    int pmc[4] = {0};
    __cpuid(pmc, 0x0A);

    u32 pmc_version = (u32)(pmc[0]) & 0xFFu;
    u32 gp_counters = ((u32)(pmc[0]) >> 8) & 0xFFu;
    u32 bit_width   = ((u32)(pmc[0]) >> 16) & 0xFFu;

    // Version 0 = PMC not supported (unusual on any Intel since Core)
    if (pmc_version == 0u) score += 2u;

    // 0 GP counters with version >= 1 = inconsistent
    if (pmc_version >= 1u && gp_counters == 0u) score += 3u;

    // Bit width 0 with version >= 1 = inconsistent
    if (pmc_version >= 1u && bit_width == 0u) score += 2u;

    // Sane GP counter count: 2-8. More or 0 is odd.
    if (gp_counters > 8u) score += 2u;

    // Sane bit width: 32-48
    if (bit_width > 0u && (bit_width < 32u || bit_width > 48u)) score += 2u;

    return score;
}

// ---------------------------------------------------------------------------
// 5. Thermal / power reporting anomaly
//
// Leaf 0x06 reports thermal and power management features.
// Real CPUs always have at least DTS (Digital Thermal Sensor) or
// ARAT (Always Running APIC Timer). Emulators often return all zeros.
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE u32 ad_vm_cpuid_thermal(void) {
    u32 score = 0u;

    // Leaf 6 is Intel-centric. AMD reports minimal or zero data here
    // even on real hardware (Zen reports EAX=0x4 typically). Only check
    // on Intel to avoid FP on AMD.
    int v[4] = {0};
    __cpuid(v, 0);
    if ((u32)v[0] < 6u) return 0u;

    static const u8 intel_id[12] = {'G','e','n','u','i','n','e','I','n','t','e','l'};
    u8 vendor[12]; u32 t, j;
    t=(u32)v[1]; vendor[0]=(u8)t; vendor[1]=(u8)(t>>8); vendor[2]=(u8)(t>>16); vendor[3]=(u8)(t>>24);
    t=(u32)v[3]; vendor[4]=(u8)t; vendor[5]=(u8)(t>>8); vendor[6]=(u8)(t>>16); vendor[7]=(u8)(t>>24);
    t=(u32)v[2]; vendor[8]=(u8)t; vendor[9]=(u8)(t>>8); vendor[10]=(u8)(t>>16); vendor[11]=(u8)(t>>24);
    b32 is_intel = 1;
    for (j = 0u; j < 12u; j++) if (vendor[j] != intel_id[j]) { is_intel = 0; break; }
    if (!is_intel) return 0u;  // Skip for AMD — leaf 6 is sparse on real AMD

    int therm[4] = {0};
    __cpuid(therm, 6);
    u32 eax = (u32)therm[0];

    // ARAT (Always Running APIC Timer) — bit 2 — present on all Intel since
    // Nehalem (2008). If missing on Intel x64, suspicious.
    b32 has_arat = (b32)((eax >> 2) & 1u);
    if (!has_arat) score += 2u;

    // All zero EAX for leaf 6 on Intel = emulator not implementing it
    if (eax == 0u) score += 3u;

    return score;
}

// ---------------------------------------------------------------------------
// 6. Extended topology enumeration (leaf 0x0B)
//
// Leaf 0x0B with subleaf index gives the extended topology info.
// Real CPUs: subleaf 0 = SMT level, subleaf 1 = Core level.
// VMs with simplified topology often don't implement this leaf,
// or report inconsistent levels (e.g., 0 logical processors at SMT level).
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE u32 ad_vm_cpuid_topology_ext(void) {
    u32 score = 0u;

    int max_leaf[4] = {0};
    __cpuid(max_leaf, 0);
    if ((u32)max_leaf[0] < 0x0Bu) return 0u;

    // Subleaf 0: SMT level
    int topo0[4] = {0};
    __cpuidex(topo0, 0x0B, 0);

    // ECX[15:8] = level type (1=SMT, 2=Core, 0=invalid)
    u32 level_type_0 = ((u32)topo0[2] >> 8) & 0xFFu;
    u32 num_logical_0 = (u32)topo0[1] & 0xFFFFu;

    // Subleaf 1: Core level
    int topo1[4] = {0};
    __cpuidex(topo1, 0x0B, 1);

    u32 level_type_1 = ((u32)topo1[2] >> 8) & 0xFFu;
    u32 num_logical_1 = (u32)topo1[1] & 0xFFFFu;

    // Both subleaves return type 0 = not implemented (emulator)
    if (level_type_0 == 0u && level_type_1 == 0u) score += 2u;

    // SMT should be type 1, Core should be type 2
    if (level_type_0 != 0u && level_type_0 != 1u) score += 2u;
    if (level_type_1 != 0u && level_type_1 != 2u) score += 2u;

    // Core level should report >= SMT level logical processors
    if (num_logical_1 > 0u && num_logical_0 > 0u) {
        if (num_logical_1 < num_logical_0) score += 3u;
    }

    // 0 logical processors at SMT but > 0 at Core = inconsistent
    if (num_logical_0 == 0u && num_logical_1 > 0u) score += 2u;

    return score;
}

// ---------------------------------------------------------------------------
// 7. SGX / TME / MKTME feature anomaly
//
// SGX (leaf 7 EBX[2]) requires hardware support that no hypervisor fully
// emulates correctly. If SGX is reported, check subleaf 0x12 for SGX
// capabilities. VMs that report SGX but don't implement leaf 0x12 properly
// are detectable.
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE u32 ad_vm_cpuid_sgx_check(void) {
    u32 score = 0u;

    int max_leaf[4] = {0};
    __cpuid(max_leaf, 0);
    if ((u32)max_leaf[0] < 7u) return 0u;

    int regs7[4] = {0};
    __cpuidex(regs7, 7, 0);
    b32 has_sgx = (b32)(((u32)regs7[1] >> 2) & 1u);

    if (has_sgx) {
        // SGX is reported — check leaf 0x12 for EPC sections
        if ((u32)max_leaf[0] >= 0x12u) {
            int sgx0[4] = {0};
            __cpuidex(sgx0, 0x12, 0);

            // SGX1 should be in EAX[0]
            b32 sgx1 = (b32)((u32)sgx0[0] & 1u);
            if (!sgx1) score += 2u;  // SGX flag set but SGX1 not available

            // Check for EPC sections (subleaf 2+)
            int sgx2[4] = {0};
            __cpuidex(sgx2, 0x12, 2);
            u32 epc_type = (u32)sgx2[0] & 0xFu;
            // Type 0 = invalid, 1 = EPC section
            // If SGX is reported but no EPC sections → VM
            if (epc_type == 0u) score += 2u;
        } else {
            // SGX flag set but leaf 0x12 doesn't exist → VM emulation
            score += 3u;
        }
    }

    return score;
}

// ---------------------------------------------------------------------------
// 8. Structured extended feature cross-check (leaf 7 subleaves)
//
// Leaf 7 subleaf 0 ECX[0] reports the max subleaf count.
// Real CPUs: 0 or 1-2 subleaves. Emulators may report garbage.
// Also check leaf 7 subleaf 1 (if available) for consistency.
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE u32 ad_vm_cpuid_leaf7_cross(void) {
    u32 score = 0u;

    int max_leaf[4] = {0};
    __cpuid(max_leaf, 0);
    if ((u32)max_leaf[0] < 7u) return 0u;

    int regs7[4] = {0};
    __cpuidex(regs7, 7, 0);
    u32 max_subleaf = (u32)regs7[0];

    // Max subleaf > 3 is unusual (as of 2025, max is 2)
    if (max_subleaf > 10u) score += 3u;

    // CLFLUSHOPT (leaf 7 EBX[23]) should exist on any CPU supporting
    // AVX-512 or newer. Not definitive alone.

    // WAITPKG (leaf 7 ECX[5]) requires MWAIT (leaf 1 ECX[3])
    u32 ecx7 = (u32)regs7[2];
    b32 has_waitpkg = (b32)((ecx7 >> 5) & 1u);
    if (has_waitpkg) {
        int feat1[4] = {0};
        __cpuid(feat1, 1);
        b32 has_mwait = (b32)(((u32)feat1[2] >> 3) & 1u);
        if (!has_mwait) score += 3u;
    }

    // MOVDIRI (leaf 7 ECX[27]) and MOVDIR64B (ECX[28]) usually come together
    b32 has_movdiri  = (b32)((ecx7 >> 27) & 1u);
    b32 has_movdir64 = (b32)((ecx7 >> 28) & 1u);
    if (has_movdir64 && !has_movdiri) score += 2u;

    return score;
}

// ---------------------------------------------------------------------------
// MASTER: Deep CPUID composite score
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE u32 ad_vm_cpuid_deep_master(void) {
    u32 score = 0u;
    score += ad_vm_nested_hv();
    score += ad_vm_cpuid_brand_scan();
    score += ad_vm_cpuid_feature_cross();
    score += ad_vm_cpuid_perf_mon();
    score += ad_vm_cpuid_thermal();
    score += ad_vm_cpuid_topology_ext();
    score += ad_vm_cpuid_sgx_check();
    score += ad_vm_cpuid_leaf7_cross();
    return score;
}

#else  // Non-MSVC stubs

ANTIDEBUG_INLINE u32 ad_vm_nested_hv(void)           { return 0; }
ANTIDEBUG_INLINE u32 ad_vm_cpuid_brand_scan(void)    { return 0; }
ANTIDEBUG_INLINE u32 ad_vm_cpuid_feature_cross(void) { return 0; }
ANTIDEBUG_INLINE u32 ad_vm_cpuid_perf_mon(void)      { return 0; }
ANTIDEBUG_INLINE u32 ad_vm_cpuid_thermal(void)       { return 0; }
ANTIDEBUG_INLINE u32 ad_vm_cpuid_topology_ext(void)  { return 0; }
ANTIDEBUG_INLINE u32 ad_vm_cpuid_sgx_check(void)     { return 0; }
ANTIDEBUG_INLINE u32 ad_vm_cpuid_leaf7_cross(void)   { return 0; }
ANTIDEBUG_INLINE u32 ad_vm_cpuid_deep_master(void)   { return 0; }

#endif // _MSC_VER

#endif // ANTIDEBUG_VM_CPUID_DEEP_H