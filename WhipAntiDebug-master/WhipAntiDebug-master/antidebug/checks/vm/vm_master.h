// ===== file: antidebug/checks/vm/vm_master.h =====
//
// VM detection master — aggregates ALL VM detection sub-modules.
//
// Sub-modules:
//   1. vm_detect.h          — Basic CPUID hypervisor / vendor / RDTSC overhead
//   2. hwid_fingerprint.h   — HWID topology, KUSD, TSC freq, SMBIOS vendor
//   3. anti_emulation.h     — CPUID edge cases, FPU, RDTSC, undocumented insn
//   4. vm_cpuid_deep.h      — Nested HV, brand scan, feature cross, PMC, thermal
//   5. vm_firmware_scan.h   — ACPI OEM, SMBIOS baseboard/chassis, BIOS date
//   6. vm_device_artifacts.h— VM DLL modules, module count, path anomaly
//   7. vm_io_backdoor.h     — VMware/VBox ports, VMCALL probe, port timing
//   8. vm_memory_anomaly.h  — Physical mem, uptime, proc cross, time, perf info
//   9. vm_timing_vmexit.h   — Leaf timing, IN timing, granularity, serialization
//
// Returns composite u32 score. Higher = more likely virtualized.
//
// Debug breakdown captured in ad_dbg_vm_t for diagnostics.
//
#ifndef ANTIDEBUG_VM_MASTER_H
#define ANTIDEBUG_VM_MASTER_H

#include "../../core/types.h"
#include "../../core/macros.h"
#include "../../core/config.h"

// Sub-modules
#include "vm_detect.h"
#include "hwid_fingerprint.h"
#include "anti_emulation.h"
#include "vm_cpuid_deep.h"
#include "vm_firmware_scan.h"
#include "vm_device_artifacts.h"
#include "vm_io_backdoor.h"
#include "vm_memory_anomaly.h"
#include "vm_timing_vmexit.h"

// Debug breakdown
typedef struct {
    u32 enabled;
    u32 basic_hypervisor;   // ad_vm_cpuid_hypervisor_bit
    u32 basic_vendor;       // ad_vm_vendor_known
    u32 basic_rdtsc;        // ad_vm_rdtsc_overhead
    u32 basic_vmware_sig;   // ad_vm_vmware_signature
    u32 hwid;               // ad_hwid_fingerprint_master
    u32 emulation;          // ad_emu_master
    u32 cpuid_deep;         // ad_vm_cpuid_deep_master
    u32 firmware;           // ad_vm_firmware_master
    u32 device;             // ad_vm_device_master
    u32 io_backdoor;        // ad_vm_io_master
    u32 memory;             // ad_vm_memory_master
    u32 timing;             // ad_vm_timing_master
} ad_dbg_vm_t;
static volatile ad_dbg_vm_t ad_dbg_vm = {0};

// =========================================================================
// VM MASTER — runs all VM sub-checks, returns composite score
//
// Weights:
//   Basic checks:     ×1 (already proven, low FP)
//   HWID fingerprint: ×1 (scoring-based, self-calibrated)
//   Emulation:        ×1 (boolean, well-tested)
//   CPUID deep:       ×1 (scoring-based)
//   Firmware scan:    ×1 (scoring-based, high confidence)
//   Device artifacts: ×1 (scoring-based)
//   I/O backdoor:     ×1 (high confidence when positive)
//   Memory anomaly:   ×1 (scoring-based)
//   Timing VM exit:   ×1 (scoring-based, can have FP under load)
// =========================================================================
ANTIDEBUG_INLINE u32 ad_vm_full_master(void) {
    u32 score = 0u;

    // ── Layer 1: Basic CPUID checks (boolean) ──────────────────────────
#if AD_ENABLE_VM_HYPERVISOR
    {
        b32 v = ad_vm_cpuid_hypervisor_bit();
        if (v) score += 5u;
        if (ad_dbg_vm.enabled) ad_dbg_vm.basic_hypervisor = (u32)v;
    }
#endif

#if AD_ENABLE_VM_VENDOR
    {
        b32 v = ad_vm_vendor_known();
        if (v) score += 8u;
        if (ad_dbg_vm.enabled) ad_dbg_vm.basic_vendor = (u32)v;
    }
    {
        b32 v = ad_vm_vmware_signature();
        if (v) score += 6u;
        if (ad_dbg_vm.enabled) ad_dbg_vm.basic_vmware_sig = (u32)v;
    }
#endif

#if AD_ENABLE_VM_RDTSC
    {
        b32 v = ad_vm_rdtsc_overhead();
        if (v) score += 7u;
        if (ad_dbg_vm.enabled) ad_dbg_vm.basic_rdtsc = (u32)v;
    }
#endif

    // ── Layer 2: HWID fingerprint (scoring) ──────────────────────────
#if AD_ENABLE_HWID_FINGERPRINT
    {
        u32 v = ad_hwid_fingerprint_master();
        score += v;
        if (ad_dbg_vm.enabled) ad_dbg_vm.hwid = v;
    }
#endif

    // ── Layer 3: Anti-emulation (boolean master) ────────────────────
#if AD_ENABLE_ANTI_EMULATION
    {
        b32 v = ad_emu_master();
        if (v) score += 6u;
        if (ad_dbg_vm.enabled) ad_dbg_vm.emulation = (u32)v;
    }
#endif

    // ── Layer 4: Deep CPUID analysis (scoring) ─────────────────────
#if AD_ENABLE_VM_CPUID_DEEP
    {
        u32 v = ad_vm_cpuid_deep_master();
        score += v;
        if (ad_dbg_vm.enabled) ad_dbg_vm.cpuid_deep = v;
    }
#endif

    // ── Layer 5: Firmware / SMBIOS scan (scoring) ──────────────────
#if AD_ENABLE_VM_FIRMWARE
    {
        u32 v = ad_vm_firmware_master();
        score += v;
        if (ad_dbg_vm.enabled) ad_dbg_vm.firmware = v;
    }
#endif

    // ── Layer 6: Device artifacts (scoring) ────────────────────────
#if AD_ENABLE_VM_DEVICE
    {
        u32 v = ad_vm_device_master();
        score += v;
        if (ad_dbg_vm.enabled) ad_dbg_vm.device = v;
    }
#endif

    // ── Layer 7: I/O backdoor probes (scoring) ─────────────────────
#if AD_ENABLE_VM_IO_BACKDOOR
    {
        u32 v = ad_vm_io_master();
        score += v;
        if (ad_dbg_vm.enabled) ad_dbg_vm.io_backdoor = v;
    }
#endif

    // ── Layer 8: Memory & resource anomalies (scoring) ─────────────
#if AD_ENABLE_VM_MEMORY
    {
        u32 v = ad_vm_memory_master();
        score += v;
        if (ad_dbg_vm.enabled) ad_dbg_vm.memory = v;
    }
#endif

    // ── Layer 9: Advanced timing / VM exit analysis (scoring) ──────
#if AD_ENABLE_VM_TIMING
    {
        u32 v = ad_vm_timing_master();
        score += v;
        if (ad_dbg_vm.enabled) ad_dbg_vm.timing = v;
    }
#endif

    return score;
}

#endif // ANTIDEBUG_VM_MASTER_H