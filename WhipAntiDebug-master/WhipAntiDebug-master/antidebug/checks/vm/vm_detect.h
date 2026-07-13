// ===== file: antidebug/checks/vm/vm_detect.h =====
//
// Virtual machine / hypervisor detection.
// Techniques: CPUID hypervisor bit, vendor string, RDTSC overhead anomaly.
// No WinAPI, no imports.
//
#ifndef ANTIDEBUG_VM_DETECT_H
#define ANTIDEBUG_VM_DETECT_H

#include "../../core/types.h"
#include "../../core/macros.h"
#include "../../core/config.h"
#include "../../core/value_guard.h"

#if defined(_MSC_VER)

// ---------------------------------------------------------------------------
// Check: CPUID hypervisor present bit (leaf 1, ECX bit 31)
//
// VMware, VirtualBox, Hyper-V, KVM, QEMU/KVM all set ECX[31] = 1
// when running as a guest, per the x86 hypervisor CPUID convention.
// Bare-metal CPUs leave this bit 0.
//
// Exception: Windows 11 with VBS/HVCI/WSL2 sets this bit even on bare-metal
// hardware (Microsoft Hyper-V runs as the kernel hypervisor, but the OS is
// the root partition, NOT a VM guest).  We suppress the flag when the vendor
// string identifies "Microsoft Hv" — ad_vm_rdtsc_overhead() still catches
// real Hyper-V guests via VM-exit overhead.
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE b32 ad_vm_cpuid_hypervisor_bit(void) {
    int regs[4] = {0};
    __cpuid(regs, 1);
    if (!((regs[2] >> 31) & 1)) return 0;

    // Bit is set — check vendor before flagging
    int vr[4] = {0};
    __cpuid(vr, (int)0x40000000);
    static const u8 msft[12] = {'M','i','c','r','o','s','o','f','t',' ','H','v'};
    u8 v[12]; u32 t, j;
    t=(u32)vr[1]; v[0]=(u8)t; v[1]=(u8)(t>>8); v[2]=(u8)(t>>16); v[3]=(u8)(t>>24);
    t=(u32)vr[2]; v[4]=(u8)t; v[5]=(u8)(t>>8); v[6]=(u8)(t>>16); v[7]=(u8)(t>>24);
    t=(u32)vr[3]; v[8]=(u8)t; v[9]=(u8)(t>>8); v[10]=(u8)(t>>16); v[11]=(u8)(t>>24);
    b32 is_msft = 1;
    for (j = 0u; j < 12u && is_msft; j++) if (v[j] != msft[j]) is_msft = 0;
    return (b32)(!is_msft);
}

// ---------------------------------------------------------------------------
// Check: hypervisor vendor string (leaf 0x40000000)
//
// When running as a VM guest, CPUID leaf 0x40000000 returns the hypervisor's
// identity string in EBX/ECX/EDX (12 ASCII chars, NOT null-terminated there).
// Known strings:
//   VMware:     "VMwareVMware"
//   VirtualBox: "VBoxVBoxVBox"
//   Hyper-V:    "Microsoft Hv"
//   KVM:        "KVMKVMKVM\0\0\0"
//   QEMU:       "TCGTCGTCGTCG"
//
// We detect ANY non-zero vendor by checking whether any of the three
// registers is non-zero. A bare-metal CPU returns zeros here (or garbage
// that repeats the standard vendor string from leaf 0).
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE b32 ad_vm_hypervisor_vendor(void) {
    int regs[4] = {0};
    __cpuid(regs, (int)0x40000000);
    if ((u32)regs[0] < 0x40000000u) return 0;

    // A hypervisor responded. Exclude "Microsoft Hv" — same rationale as
    // ad_vm_cpuid_hypervisor_bit: Windows 11 VBS/WSL2 root partition.
    static const u8 msft[12] = {'M','i','c','r','o','s','o','f','t',' ','H','v'};
    u8 v[12]; u32 t, j;
    t=(u32)regs[1]; v[0]=(u8)t; v[1]=(u8)(t>>8); v[2]=(u8)(t>>16); v[3]=(u8)(t>>24);
    t=(u32)regs[2]; v[4]=(u8)t; v[5]=(u8)(t>>8); v[6]=(u8)(t>>16); v[7]=(u8)(t>>24);
    t=(u32)regs[3]; v[8]=(u8)t; v[9]=(u8)(t>>8); v[10]=(u8)(t>>16); v[11]=(u8)(t>>24);
    b32 is_msft = 1;
    for (j = 0u; j < 12u && is_msft; j++) if (v[j] != msft[j]) is_msft = 0;
    return (b32)(!is_msft);
}

// ---------------------------------------------------------------------------
// Check: RDTSC overhead anomaly (VM RDTSC interception)
//
// Many hypervisors intercept RDTSC to provide a virtual time source.
// Intercepting RDTSC costs a VM exit, which is orders of magnitude more
// expensive than a native RDTSC (~20–50 cycles vs. 500–10,000 cycles).
//
// Strategy: interleave CPUID (always intercepted) and RDTSC; measure
// if the combined cost exceeds what is possible on real hardware.
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE b32 ad_vm_rdtsc_overhead(void) {
    int dummy[4];

    // Round 1
    __cpuid(dummy, 0);
    u64 t0 = __rdtsc();

    // Round 2
    __cpuid(dummy, 0);
    u64 t1 = __rdtsc();

    // Round 3
    __cpuid(dummy, 0);
    u64 t2 = __rdtsc();

    u64 d0 = t1 - t0;
    u64 d1 = t2 - t1;

    // On real hardware: CPUID+RDTSC pair ≈ 150–500 cycles
    // Under a VM intercepting both: 1,000–50,000 cycles
    u64 vm_thresh = (u64)AD_GET_VM_RDTSC();
    return (b32)(ad_opaque_gt_u64(d0, vm_thresh) | ad_opaque_gt_u64(d1, vm_thresh));
}

// ---------------------------------------------------------------------------
// Check: hypervisor vendor string — exact match against known VM families
//
// CPUID(0x40000000) fills EBX/ECX/EDX with a 12-char identity string.
// We copy the three registers into a byte buffer and compare against
// every known VM vendor. This gives precise VM family identification
// (not just "some hypervisor is present" like ad_vm_hypervisor_vendor).
//
// Known strings:
//   "VMwareVMware"  — VMware Workstation/ESXi
//   "VBoxVBoxVBox"  — VirtualBox
//   "KVMKVMKVM\0\0\0" — KVM (Linux)
//   "Microsoft Hv"  — Hyper-V / Azure
//   "TCGTCGTCGTCG"  — QEMU TCG (pure emulation)
//   "XenVMMXenVMM"  — Xen
//   "prl hyperv  "  — Parallels
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE b32 ad_vm_vendor_known(void) {
    int regs[4] = {0, 0, 0, 0};
    __cpuid(regs, (int)0x40000000);

    // Build 12-byte string from EBX (regs[1]), ECX (regs[2]), EDX (regs[3])
    u8 v[12];
    u32 t;
    t = (u32)regs[1];
    v[0]=(u8)(t); v[1]=(u8)(t>>8); v[2]=(u8)(t>>16); v[3]=(u8)(t>>24);
    t = (u32)regs[2];
    v[4]=(u8)(t); v[5]=(u8)(t>>8); v[6]=(u8)(t>>16); v[7]=(u8)(t>>24);
    t = (u32)regs[3];
    v[8]=(u8)(t); v[9]=(u8)(t>>8); v[10]=(u8)(t>>16); v[11]=(u8)(t>>24);

    // Known 12-byte signatures (stored as u8 arrays, not C strings — avoids
    // null-termination issues with KVM's trailing zeroes)
    static const u8 sig_vmware[12] = {
        'V','M','w','a','r','e','V','M','w','a','r','e'};
    static const u8 sig_vbox[12]   = {
        'V','B','o','x','V','B','o','x','V','B','o','x'};
    static const u8 sig_kvm[12]    = {
        'K','V','M','K','V','M','K','V','M', 0,  0,  0 };
    // NOTE: "Microsoft Hv" intentionally excluded — Windows 11 with VBS/HVCI
    // reports this string on bare-metal hardware (Hyper-V used for kernel
    // isolation).  It is not a reliable indicator of a guest VM.
    // ad_vm_hypervisor_vendor() and ad_vm_rdtsc_overhead() cover Hyper-V guests.
    static const u8 sig_qemu[12]   = {
        'T','C','G','T','C','G','T','C','G','T','C','G'};
    static const u8 sig_xen[12]    = {
        'X','e','n','V','M','M','X','e','n','V','M','M'};
    static const u8 sig_prl[12]    = {
        'p','r','l',' ','h','y','p','e','r','v',' ',' '};

    static const u8* const sigs[6] = {
        sig_vmware, sig_vbox, sig_kvm,
        sig_qemu, sig_xen, sig_prl
    };

    u32 s, j;
    for (s = 0u; s < 6u; s++) {
        b32 match = 1;
        for (j = 0u; j < 12u && match; j++) {
            if (v[j] != sigs[s][j]) match = 0;
        }
        if (match) return 1;
    }
    return 0;
}

// ---------------------------------------------------------------------------
// Check: specific VMware CPUID signature (leaf 0x40000010)
//
// VMware exposes its interface version at leaf 0x40000010.
// If EAX is non-zero at this leaf, VMware (or a compatible hypervisor) is
// likely present.
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE b32 ad_vm_vmware_signature(void) {
    int regs[4] = {0};
    __cpuid(regs, (int)0x40000010);
    return (b32)(regs[0] != 0);
}

#else  // Non-MSVC stubs

ANTIDEBUG_INLINE b32 ad_vm_cpuid_hypervisor_bit(void)  { return 0; }
ANTIDEBUG_INLINE b32 ad_vm_hypervisor_vendor(void)      { return 0; }
ANTIDEBUG_INLINE b32 ad_vm_rdtsc_overhead(void)         { return 0; }
ANTIDEBUG_INLINE b32 ad_vm_vmware_signature(void)       { return 0; }
ANTIDEBUG_INLINE b32 ad_vm_vendor_known(void)           { return 0; }

#endif // _MSC_VER

#endif // ANTIDEBUG_VM_DETECT_H
