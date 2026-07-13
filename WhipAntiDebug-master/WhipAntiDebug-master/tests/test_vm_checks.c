// ===== file: tests/test_vm_checks.c =====
//
// VM detection diagnostic: run all VM checks and print detailed results.
// Shows raw hardware values + per-check scores.
//

#include "antidebug/core/syscall_bridge.h"
#include "antidebug/checks/vm/vm_master.h"

#include <stdio.h>

int main(void) {
    whip_bridge_init();

    printf("========================================\n");
    printf("  VM Detection Diagnostic\n");
    printf("========================================\n\n");

    ad_dbg_vm.enabled = 1;

    // ── Hardware diagnostics ─────────────────────────────────────────
    printf("[Hardware Info]\n");
    {
        ad_vm_hw_diag_t hw;
        ad_vm_read_hw_diag(&hw);
        printf("  RAM              = %llu MB (%llu GB)\n", hw.phys_mb, (hw.phys_mb + 512) / 1024);
        printf("  Commit limit     = %llu MB (%llu GB)\n", hw.commit_limit_mb, (hw.commit_limit_mb + 512) / 1024);
        printf("  Processors (PEB) = %u\n", hw.num_procs_peb);
        printf("  Processors (CPU) = %u\n", hw.num_procs_cpuid);
        printf("  Max CPUID leaf   = 0x%X\n", hw.max_cpuid_leaf);
        printf("  PA bits          = %u\n", hw.pa_bits);
        printf("  VA bits          = %u\n", hw.va_bits);
        printf("  Cache levels     = %u\n", hw.cache_levels);
        printf("  Uptime           = %u sec (%u min)\n\n", hw.uptime_secs, hw.uptime_secs / 60);

        // Flag bizarre values
        u64 gb = (hw.phys_mb + 512) / 1024;
        b32 standard_ram = (gb==2||gb==3||gb==4||gb==6||gb==7||gb==8||gb==12||gb==15||
                            gb==16||gb==24||gb==31||gb==32||gb==48||gb==63||gb==64||
                            gb==96||gb==127||gb==128);
        if (!standard_ram && gb >= 2)
            printf("  >>> BIZARRE: %llu GB RAM is non-standard!\n", gb);
        if (hw.num_procs_peb <= 1)
            printf("  >>> BIZARRE: only %u processor(s)\n", hw.num_procs_peb);
        if (hw.cache_levels < 2)
            printf("  >>> BIZARRE: only %u cache level(s) (real CPUs have >= 2)\n", hw.cache_levels);
        if (hw.pa_bits > 0 && hw.pa_bits < 36)
            printf("  >>> BIZARRE: %u PA bits (real x64 CPUs have >= 36)\n", hw.pa_bits);
        if (hw.max_cpuid_leaf < 0x0D)
            printf("  >>> BIZARRE: max CPUID leaf 0x%X (modern CPUs have >= 0x0D)\n", hw.max_cpuid_leaf);
        printf("\n");
    }

    // ── Layer 1: Deep CPUID ──────────────────────────────────────────
    printf("[CPUID Deep]                         score\n");
    {
        u32 v;
        v = ad_vm_nested_hv();           printf("  nested_hv          = %u\n", v);
        v = ad_vm_cpuid_brand_scan();    printf("  brand_scan         = %u\n", v);
        v = ad_vm_cpuid_feature_cross(); printf("  feature_cross      = %u\n", v);
        v = ad_vm_cpuid_perf_mon();      printf("  perf_mon           = %u\n", v);
        v = ad_vm_cpuid_thermal();       printf("  thermal            = %u\n", v);
        v = ad_vm_cpuid_topology_ext();  printf("  topology_ext       = %u\n", v);
        v = ad_vm_cpuid_sgx_check();     printf("  sgx_check          = %u\n", v);
        v = ad_vm_cpuid_leaf7_cross();   printf("  leaf7_cross        = %u\n", v);
        v = ad_vm_cpuid_deep_master();   printf("  --- SUBTOTAL       = %u\n\n", v);
    }

    // ── Layer 2: Firmware ────────────────────────────────────────────
    printf("[Firmware Scan]\n");
    {
        u32 v;
        v = ad_vm_acpi_oem_scan();       printf("  acpi_oem_scan      = %u\n", v);
        v = ad_vm_smbios_extended();     printf("  smbios_extended    = %u\n", v);
        v = ad_vm_bios_date_check();     printf("  bios_date          = %u\n", v);
        v = ad_vm_firmware_master();     printf("  --- SUBTOTAL       = %u\n\n", v);
    }

    // ── Layer 3: Device Artifacts ────────────────────────────────────
    printf("[Device Artifacts]\n");
    {
        u32 v;
        v = ad_vm_driver_modules();      printf("  driver_modules     = %u\n", v);
        v = ad_vm_module_count_check();  printf("  module_count       = %u\n", v);
        v = ad_vm_path_anomaly();        printf("  path_anomaly       = %u\n", v);
        v = ad_vm_system_modules();      printf("  system_modules     = %u\n", v);
        v = ad_vm_device_master();       printf("  --- SUBTOTAL       = %u\n\n", v);
    }

    // ── Layer 4: I/O Backdoor ────────────────────────────────────────
    printf("[I/O Backdoor]\n");
    {
        u32 v;
        v = (u32)ad_vm_vmware_port();    printf("  vmware_port        = %u\n", v);
        v = (u32)ad_vm_vmware_hb_port(); printf("  vmware_hb_port     = %u\n", v);
        v = (u32)ad_vm_vbox_detect();    printf("  vbox_detect        = %u\n", v);
        v = ad_vm_vmcall_probe();        printf("  vmcall_probe       = %u\n", v);
        v = ad_vm_port_timing();         printf("  port_timing        = %u\n", v);
        v = ad_vm_io_master();           printf("  --- SUBTOTAL       = %u\n\n", v);
    }

    // ── Layer 5: Memory Anomaly ──────────────────────────────────────
    printf("[Memory & Resources]\n");
    {
        u32 v;
        v = ad_vm_physical_mem_low();    printf("  physical_mem_low   = %u\n", v);
        v = ad_vm_uptime_check();        printf("  uptime_check       = %u\n", v);
        v = ad_vm_proc_count_cross();    printf("  proc_count_cross   = %u\n", v);
        v = ad_vm_time_anomaly();        printf("  time_anomaly       = %u\n", v);
        v = ad_vm_perf_info_check();     printf("  perf_info_check    = %u\n", v);
        v = ad_vm_address_space_check(); printf("  addr_space_check   = %u\n", v);
        v = ad_vm_numa_check();          printf("  numa_check         = %u\n", v);
        v = ad_vm_disk_size_heuristic(); printf("  disk_heuristic     = %u\n", v);
        v = ad_vm_bizarre_config();      printf("  bizarre_config     = %u\n", v);
        v = ad_vm_memory_master();       printf("  --- SUBTOTAL       = %u\n\n", v);
    }

    // ── Layer 6: Timing / VMEXIT ─────────────────────────────────────
    printf("[Timing VMEXIT]\n");
    {
        u32 v;
        v = ad_vm_cpuid_leaf_timing();   printf("  cpuid_leaf_timing  = %u\n", v);
        v = ad_vm_in_timing();           printf("  in_timing          = %u\n", v);
        v = ad_vm_rdtsc_granularity();   printf("  rdtsc_granularity  = %u\n", v);
        v = ad_vm_cpuid_stats();         printf("  cpuid_stats        = %u\n", v);
        v = ad_vm_serialize_timing();    printf("  serialize_timing   = %u\n", v);
        v = ad_vm_mixed_sequence();      printf("  mixed_sequence     = %u\n", v);
        v = ad_vm_rdtsc_backward();      printf("  rdtsc_backward     = %u\n", v);
        v = ad_vm_timing_master();       printf("  --- SUBTOTAL       = %u\n\n", v);
    }

    // ── Existing checks ──────────────────────────────────────────────
    printf("[Existing Pre-existing Checks]\n");
    {
        u32 v;
        v = (u32)ad_vm_cpuid_hypervisor_bit(); printf("  hypervisor_bit     = %u\n", v);
        v = (u32)ad_vm_hypervisor_vendor();    printf("  hypervisor_vendor  = %u\n", v);
        v = (u32)ad_vm_rdtsc_overhead();       printf("  rdtsc_overhead     = %u\n", v);
        v = (u32)ad_vm_vendor_known();         printf("  vendor_known       = %u\n", v);
        v = (u32)ad_vm_vmware_signature();     printf("  vmware_sig         = %u\n", v);
        v = ad_hwid_fingerprint_master();      printf("  hwid_fingerprint   = %u\n", v);
        v = (u32)ad_emu_master();              printf("  emu_master         = %u\n\n", v);
    }

    // ── Full master ──────────────────────────────────────────────────
    u32 total = ad_vm_full_master();
    printf("========================================\n");
    printf("  VM FULL MASTER SCORE = %u\n", total);
    printf("========================================\n");

    if (total == 0u)
        printf("\n  CLEAN -- no VM detected\n");
    else if (total < 10u)
        printf("\n  LOW -- minor anomalies (%u pts)\n", total);
    else if (total < 30u)
        printf("\n  MEDIUM -- likely VM (%u pts)\n", total);
    else
        printf("\n  HIGH -- definitely VM/sandbox (%u pts)\n", total);

    return 0;
}
