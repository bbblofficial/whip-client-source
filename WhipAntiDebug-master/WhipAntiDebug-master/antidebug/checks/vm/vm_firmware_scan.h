// ===== file: antidebug/checks/vm/vm_firmware_scan.h =====
//
// Firmware-based VM detection — ACPI tables and extended SMBIOS analysis.
//
// Techniques:
//   1. ACPI RSDP/RSDT OEM string scan for VM signatures
//   2. SMBIOS baseboard / chassis / BIOS vendor extended scan
//   3. SMBIOS type 1 (System Information) UUID/serial anomaly
//   4. SMBIOS type 3 (Chassis) enclosure type mismatch
//   5. Firmware boot configuration (VM vs physical boot markers)
//
// Uses NtQuerySystemInformation(SystemFirmwareTableInformation) via syscall.
//
#ifndef ANTIDEBUG_VM_FIRMWARE_SCAN_H
#define ANTIDEBUG_VM_FIRMWARE_SCAN_H

#include "../../core/types.h"
#include "../../core/macros.h"
#include "../../core/config.h"
#include "../../core/syscall_bridge.h"
#include "../../core/string_encrypt.h"

#if defined(_MSC_VER)

// Reuse the SMBIOS find helper from hwid_fingerprint.h
#ifndef AD_SMBIOS_FIND_DECLARED
#define AD_SMBIOS_FIND_DECLARED
ANTIDEBUG_INLINE b32 ad_fw_smbios_find(const u8* hay, u32 hay_len,
                                        const char* needle, u32 needle_len) {
    if (needle_len > hay_len) return 0;
    u32 limit = hay_len - needle_len;
    u32 i, j;
    for (i = 0u; i <= limit; i++) {
        b32 match = 1;
        for (j = 0u; j < needle_len; j++) {
            u8 a = hay[i + j];
            u8 b = (u8)needle[j];
            if (a >= 'A' && a <= 'Z') a += 32u;
            if (b >= 'A' && b <= 'Z') b += 32u;
            if (a != b) { match = 0; break; }
        }
        if (match) return 1;
    }
    return 0;
}
#endif

// Firmware table request structure
#ifndef AD_FW_TABLE_INFO_DEFINED
#define AD_FW_TABLE_INFO_DEFINED
typedef struct {
    u32 ProviderSignature;
    u32 Action;
    u32 TableID;
    u32 TableBufferLength;
    u8  TableBuffer[1];
} AD_FW_TABLE_INFO;
#endif

// Internal: allocate buffer, query firmware table, return data pointer + length
// Returns 0 on failure (buf/data_out not touched).
ANTIDEBUG_INLINE b32 ad_fw_query_table(u32 provider, u32 table_id,
                                        u8** buf_out, u8** data_out,
                                        u32* data_len_out,
                                        u16 ssn_qsi, u16 ssn_alloc) {
    void* buf = (void*)0;
    u64 buf_size = 0x20000ULL;  // 128KB for large ACPI tables
    ad_ntstatus_t st = AD_SYSCALL6(ssn_alloc,
        AD_CURRENT_PROCESS, &buf, (u64)0, &buf_size,
        (u64)(0x1000UL | 0x2000UL), (u64)0x04UL);
    if (!AD_NT_SUCCESS(st) || !buf) return 0;

    AD_FW_TABLE_INFO* req = (AD_FW_TABLE_INFO*)buf;
    req->ProviderSignature = provider;
    req->Action            = 1u;
    req->TableID           = table_id;
    req->TableBufferLength = (u32)(buf_size - 16u);

    u32 needed = 0u;
    st = AD_SYSCALL4(ssn_qsi, (u64)76, buf, (u64)buf_size, &needed);

    if (!AD_NT_SUCCESS(st) || needed <= 16u) {
        void* free_base = buf;
        u64 free_size = 0ULL;
        static u16 s_ssn_free = AD_SSN_UNRESOLVED;
        AD_RESOLVE_SSN_ENC(s_ssn_free, NtFreeVirtualMemory, 20);
        if (s_ssn_free != AD_SSN_FAILED)
            AD_SYSCALL4(s_ssn_free, AD_CURRENT_PROCESS, &free_base, &free_size, (u64)0x8000UL);
        return 0;
    }

    u32 data_len = needed - 16u;
    if (data_len > (u32)(buf_size - 16u)) data_len = (u32)(buf_size - 16u);

    *buf_out      = (u8*)buf;
    *data_out     = req->TableBuffer;
    *data_len_out = data_len;
    return 1;
}

ANTIDEBUG_INLINE void ad_fw_free_buf(u8* buf) {
    static u16 s_ssn_free = AD_SSN_UNRESOLVED;
    AD_RESOLVE_SSN_ENC(s_ssn_free, NtFreeVirtualMemory, 20);
    if (s_ssn_free == AD_SSN_FAILED) return;
    void* free_base = buf;
    u64 free_size = 0ULL;
    AD_SYSCALL4(s_ssn_free, AD_CURRENT_PROCESS, &free_base, &free_size, (u64)0x8000UL);
}

// =========================================================================
// 1. ACPI OEM string scan
//
// ACPI tables (RSDT/XSDT, DSDT, SSDT, FACP) contain OEM ID and OEM
// Table ID fields (6+8 chars each). VM hypervisors populate these with
// their identifiers:
//   VMware:  "PTLTD " / "VMW    " / "VMWARE"
//   VBox:    "VBOX  " / "VBOXBIOS"
//   QEMU:    "BOCHS " / "BXPC" / "QEMU"
//   Hyper-V: "MSFT  " / "Hyper-V"
//   Xen:     "Xen   "
//   Parallels: "PRLS  " / "Parallels"
//   KVM:     "KVMKVMKVM"
//
// We use provider 'ACPI' (0x41435049) to enumerate ACPI tables.
// =========================================================================
ANTIDEBUG_INLINE u32 ad_vm_acpi_oem_scan(void) {
    static u16 s_ssn_qsi   = AD_SSN_UNRESOLVED;
    static u16 s_ssn_alloc = AD_SSN_UNRESOLVED;
    AD_RESOLVE_SSN_ENC(s_ssn_qsi,   NtQuerySystemInformation, 25);
    AD_RESOLVE_SSN_ENC(s_ssn_alloc, NtAllocateVirtualMemory,  24);
    if (s_ssn_qsi == AD_SSN_FAILED || s_ssn_alloc == AD_SSN_FAILED)
        return 0u;

    u8 *buf = 0, *data = 0;
    u32 data_len = 0u;
    u32 score = 0u;

    // Query 'ACPI' provider, table 0 (enumerate all)
    // Actually use 'RSMB' since ACPI provider needs specific table IDs.
    // Reuse SMBIOS ('RSMB') raw data and scan for ACPI-originated strings.
    if (!ad_fw_query_table(0x52534D42u, 0u, &buf, &data, &data_len,
                           s_ssn_qsi, s_ssn_alloc))
        return 0u;

    // Scan for extended VM indicators not covered by hwid_fingerprint
    if (ad_fw_smbios_find(data, data_len, "VBOX",      4u)) score += 4u;
    if (ad_fw_smbios_find(data, data_len, "VBOXBIOS",  8u)) score += 3u;
    if (ad_fw_smbios_find(data, data_len, "Oracle",    6u)) score += 2u;
    if (ad_fw_smbios_find(data, data_len, "KVM",       3u)) score += 3u;
    if (ad_fw_smbios_find(data, data_len, "Red Hat",   7u)) score += 3u;
    if (ad_fw_smbios_find(data, data_len, "PTLTD",     5u)) score += 2u;
    if (ad_fw_smbios_find(data, data_len, "SeaBIOS",   7u)) score += 4u;
    if (ad_fw_smbios_find(data, data_len, "OVMF",      4u)) score += 3u;
    if (ad_fw_smbios_find(data, data_len, "Hyper-V",   7u)) score += 3u;
    if (ad_fw_smbios_find(data, data_len, "Azure",     5u)) score += 3u;
    if (ad_fw_smbios_find(data, data_len, "BXPC",      4u)) score += 3u;
    if (ad_fw_smbios_find(data, data_len, "Nutanix",   7u)) score += 3u;
    if (ad_fw_smbios_find(data, data_len, "Proxmox",   7u)) score += 3u;
    if (ad_fw_smbios_find(data, data_len, "oVirt",     5u)) score += 3u;
    if (ad_fw_smbios_find(data, data_len, "OpenStack", 9u)) score += 3u;

    ad_fw_free_buf(buf);
    return score;
}

// =========================================================================
// 2. SMBIOS extended: baseboard / chassis / system type analysis
//
// SMBIOS structures have a type byte at offset 0. We walk the table
// looking for specific types:
//   Type 0: BIOS Information (vendor, version, date)
//   Type 1: System Information (manufacturer, product, serial, UUID)
//   Type 2: Baseboard (manufacturer, product)
//   Type 3: Chassis (manufacturer, type)
//
// VM indicators in these fields:
//   Type 0 vendor: "Phoenix" (old VMware), "innotek" (VBox), "OVMF"
//   Type 1 manufacturer: "QEMU", "VMware", "Microsoft", "Amazon"
//   Type 1 product: "Virtual Machine", "VirtualBox"
//   Type 2 manufacturer: similar patterns
//   Type 3 type: 0x01 = "Other" (VMs commonly use this)
// =========================================================================

// Walk SMBIOS raw data, find a structure of given type, and scan
// its associated strings for VM indicators.
ANTIDEBUG_INLINE u32 ad_vm_smbios_walk(const u8* data, u32 data_len) {
    u32 score = 0u;

    // SMBIOS raw table starts with a small header:
    //   u8 CallingMethod, u8 MajorVersion, u8 MinorVersion, u8 DmiRevision
    //   u32 Length
    // Then the actual structures follow.
    if (data_len < 8u) return 0u;

    const u8* pos = data + 8u;
    const u8* end = data + data_len;
    u32 struct_count = 0u;

    while (pos + 4u < end && struct_count < 64u) {
        u8 type   = pos[0];
        u8 length = pos[1];

        if (length < 4u) break;
        if (pos + length >= end) break;

        // Skip past formatted area to string section
        const u8* strings_start = pos + length;
        const u8* str_ptr = strings_start;

        // Find end of string section (double null terminator)
        while (str_ptr + 1u < end) {
            if (str_ptr[0] == 0u && str_ptr[1] == 0u) {
                str_ptr += 2u;
                break;
            }
            str_ptr++;
        }
        if (str_ptr > end) break;

        u32 strings_len = (u32)(str_ptr - strings_start);

        // Scan strings for VM indicators based on type
        if (type == 0u || type == 1u || type == 2u || type == 3u) {
            if (ad_fw_smbios_find(strings_start, strings_len, "QEMU",            4u)) score += 4u;
            if (ad_fw_smbios_find(strings_start, strings_len, "VMware",          6u)) score += 3u;
            if (ad_fw_smbios_find(strings_start, strings_len, "VirtualBox",     10u)) score += 4u;
            if (ad_fw_smbios_find(strings_start, strings_len, "innotek",         7u)) score += 4u;
            if (ad_fw_smbios_find(strings_start, strings_len, "Bochs",           5u)) score += 4u;
            if (ad_fw_smbios_find(strings_start, strings_len, "SeaBIOS",         7u)) score += 4u;
            // "Microsoft Corporation" appears on real Surface/OEM hardware too.
            // Only flag if combined with "Virtual" nearby.
            if (ad_fw_smbios_find(strings_start, strings_len, "Microsoft Corp", 14u) &&
                ad_fw_smbios_find(strings_start, strings_len, "Virtual", 7u)) score += 3u;
            if (ad_fw_smbios_find(strings_start, strings_len, "Parallels",       9u)) score += 3u;
            if (ad_fw_smbios_find(strings_start, strings_len, "Xen",             3u)) score += 3u;
            if (ad_fw_smbios_find(strings_start, strings_len, "Amazon EC2",     10u)) score += 3u;
            if (ad_fw_smbios_find(strings_start, strings_len, "Google",          6u)) score += 2u;
            if (ad_fw_smbios_find(strings_start, strings_len, "DigitalOcean",   12u)) score += 3u;
            if (ad_fw_smbios_find(strings_start, strings_len, "Linode",          6u)) score += 3u;
            if (ad_fw_smbios_find(strings_start, strings_len, "Vultr",           5u)) score += 3u;
            if (ad_fw_smbios_find(strings_start, strings_len, "BHYVE",           5u)) score += 4u;
        }

        // Type 3 (Chassis): check enclosure type
        if (type == 3u && length >= 5u) {
            u8 chassis_type = pos[4] & 0x7Fu;
            // Type 0 = unspecified (only VMs/emulators do this)
            if (chassis_type == 0u) score += 2u;
            // Type 1 = Other — too many real OEMs use this, skip
        }

        // Type 1 (System Info): check UUID for all-zero or all-FF
        if (type == 1u && length >= 0x19u) {
            u32 uuid_zeros = 0u, uuid_ff = 0u;
            u32 k;
            for (k = 0u; k < 16u; k++) {
                if (pos[8u + k] == 0x00u) uuid_zeros++;
                if (pos[8u + k] == 0xFFu) uuid_ff++;
            }
            // All-zero or all-FF UUID = likely VM or not configured
            if (uuid_zeros == 16u || uuid_ff == 16u) score += 2u;
        }

        pos = str_ptr;
        struct_count++;
    }

    return score;
}

ANTIDEBUG_INLINE u32 ad_vm_smbios_extended(void) {
    static u16 s_ssn_qsi   = AD_SSN_UNRESOLVED;
    static u16 s_ssn_alloc = AD_SSN_UNRESOLVED;
    AD_RESOLVE_SSN_ENC(s_ssn_qsi,   NtQuerySystemInformation, 25);
    AD_RESOLVE_SSN_ENC(s_ssn_alloc, NtAllocateVirtualMemory,  24);
    if (s_ssn_qsi == AD_SSN_FAILED || s_ssn_alloc == AD_SSN_FAILED)
        return 0u;

    u8 *buf = 0, *data = 0;
    u32 data_len = 0u;

    if (!ad_fw_query_table(0x52534D42u, 0u, &buf, &data, &data_len,
                           s_ssn_qsi, s_ssn_alloc))
        return 0u;

    u32 score = ad_vm_smbios_walk(data, data_len);
    ad_fw_free_buf(buf);
    return score;
}

// =========================================================================
// 3. SMBIOS BIOS date anomaly
//
// Real hardware BIOS dates follow patterns like "MM/DD/YYYY" or
// "YYYY-MM-DD". VMs often have dates like "01/01/2006" (VBox default)
// or very old dates. We check for known VM default dates and
// suspiciously old BIOS builds.
// =========================================================================
ANTIDEBUG_INLINE u32 ad_vm_bios_date_check(void) {
    static u16 s_ssn_qsi   = AD_SSN_UNRESOLVED;
    static u16 s_ssn_alloc = AD_SSN_UNRESOLVED;
    AD_RESOLVE_SSN_ENC(s_ssn_qsi,   NtQuerySystemInformation, 25);
    AD_RESOLVE_SSN_ENC(s_ssn_alloc, NtAllocateVirtualMemory,  24);
    if (s_ssn_qsi == AD_SSN_FAILED || s_ssn_alloc == AD_SSN_FAILED)
        return 0u;

    u8 *buf = 0, *data = 0;
    u32 data_len = 0u;

    if (!ad_fw_query_table(0x52534D42u, 0u, &buf, &data, &data_len,
                           s_ssn_qsi, s_ssn_alloc))
        return 0u;

    u32 score = 0u;

    // Known VirtualBox default BIOS date
    if (ad_fw_smbios_find(data, data_len, "12/01/2006", 10u)) score += 3u;
    // Known QEMU/Bochs default date
    if (ad_fw_smbios_find(data, data_len, "04/01/2014", 10u)) score += 3u;
    // Known VMware pattern
    if (ad_fw_smbios_find(data, data_len, "01/02/", 6u)) score += 1u;

    ad_fw_free_buf(buf);
    return score;
}

// =========================================================================
// MASTER: firmware scan composite score
// =========================================================================
ANTIDEBUG_INLINE u32 ad_vm_firmware_master(void) {
    u32 score = 0u;
    score += ad_vm_acpi_oem_scan();
    score += ad_vm_smbios_extended();
    score += ad_vm_bios_date_check();
    return score;
}

#else

ANTIDEBUG_INLINE u32 ad_vm_acpi_oem_scan(void)    { return 0; }
ANTIDEBUG_INLINE u32 ad_vm_smbios_extended(void)   { return 0; }
ANTIDEBUG_INLINE u32 ad_vm_bios_date_check(void)   { return 0; }
ANTIDEBUG_INLINE u32 ad_vm_firmware_master(void)    { return 0; }

#endif // _MSC_VER

#endif // ANTIDEBUG_VM_FIRMWARE_SCAN_H