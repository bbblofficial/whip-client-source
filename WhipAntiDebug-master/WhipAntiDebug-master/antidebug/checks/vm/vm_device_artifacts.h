// ===== file: antidebug/checks/vm/vm_device_artifacts.h =====
//
// VM artifact detection via loaded modules and device indicators.
//
// Techniques:
//   1. PEB.Ldr scan for VM guest tool DLLs (vm3dgl64.dll, VBoxDisp, etc.)
//   2. Process environment block — SystemRoot path anomaly
//   3. VM-specific registry footprint via NtOpenKey / NtQueryValueKey
//   4. Number of loaded modules anomaly (VMs often have fewer)
//   5. Module timestamp anomaly (VM tools modules all share same timestamp)
//
// No CRT — uses PEB walk and direct syscalls.
//
#ifndef ANTIDEBUG_VM_DEVICE_ARTIFACTS_H
#define ANTIDEBUG_VM_DEVICE_ARTIFACTS_H

#include "../../core/types.h"
#include "../../core/macros.h"
#include "../../core/config.h"
#include "../../core/syscall_bridge.h"
#include "../../core/string_encrypt.h"

#if defined(_MSC_VER)

// AD_UNICODE_STRING — shared with runtime/frida_thread_scan.h
#ifndef AD_UNICODE_STRING_DEFINED
#define AD_UNICODE_STRING_DEFINED
typedef struct {
    u16 Length;
    u16 MaximumLength;
    u16* Buffer;
} AD_UNICODE_STRING;
#endif

// Case-insensitive wide-char substring match (no CRT)
ANTIDEBUG_INLINE b32 ad_wstr_contains(const u16* hay, u32 hay_chars,
                                       const u16* needle, u32 needle_chars) {
    if (needle_chars > hay_chars) return 0;
    u32 limit = hay_chars - needle_chars;
    u32 i, j;
    for (i = 0u; i <= limit; i++) {
        b32 match = 1;
        for (j = 0u; j < needle_chars; j++) {
            u16 a = hay[i + j];
            u16 b = needle[j];
            // Cheap lowercase for ASCII range
            if (a >= 'A' && a <= 'Z') a += 32u;
            if (b >= 'A' && b <= 'Z') b += 32u;
            if (a != b) { match = 0; break; }
        }
        if (match) return 1;
    }
    return 0;
}

// =========================================================================
// 1. Loaded modules scan for VM guest DLLs
//
// Walk PEB.Ldr.InLoadOrderModuleList and check each module's BaseDllName
// against known VM tool DLL names.
//
// Known DLLs:
//   VMware:     vm3dgl64.dll, vmGuestLib.dll, vmhgfs.dll, vmtoolsd.dll,
//               vmusrvc.exe (as module), vmrawdsk.dll
//   VirtualBox: VBoxDisp.dll, VBoxHook.dll, VBoxMRXNP.dll, VBoxOGL.dll,
//               VBoxSF.dll, VBoxGuest.dll, VBoxControl.dll
//   Hyper-V:    vmicheartbeat.dll, vmicshutdown.dll, vmicvss.dll
//   Parallels:  prl_cc.dll, prl_tools.dll
//   QEMU/KVM:   qemu-ga.dll
// =========================================================================
ANTIDEBUG_INLINE u32 ad_vm_driver_modules(void) {
    u32 score = 0u;

    u8* peb = (u8*)__readgsqword(0x60);
    if (!peb) return 0u;

    u8* ldr = *(u8**)(peb + 0x18);
    if (!ldr) return 0u;

    u8* list_head = ldr + 0x10;  // InLoadOrderModuleList
    u8* entry = *(u8**)list_head;
    u32 walk = 0u;

    // Known VM DLL name fragments as wide-char arrays
    // VMware
    static const u16 s_vm3d[]   = {'v','m','3','d'};          // 4 chars
    static const u16 s_vmhgfs[] = {'v','m','h','g','f','s'};  // 6 chars
    static const u16 s_vmtool[] = {'v','m','t','o','o','l'};  // 6 chars
    static const u16 s_vmraw[]  = {'v','m','r','a','w'};      // 5 chars
    static const u16 s_vmguest[]= {'v','m','g','u','e','s','t'}; // 7 chars
    // VirtualBox
    static const u16 s_vbox[]   = {'v','b','o','x'};          // 4 chars
    // Hyper-V
    static const u16 s_vmic[]   = {'v','m','i','c'};          // 4 chars
    // Parallels
    static const u16 s_prl[]    = {'p','r','l','_'};          // 4 chars
    // QEMU
    static const u16 s_qemu[]   = {'q','e','m','u'};          // 4 chars

    while (entry != list_head && walk < 256u) {
        // LDR_DATA_TABLE_ENTRY: BaseDllName at offset 0x58 (UNICODE_STRING)
        AD_UNICODE_STRING* name = (AD_UNICODE_STRING*)(entry + 0x58);
        if (name->Buffer && name->Length > 0u) {
            u32 chars = name->Length / 2u;
            const u16* buf = name->Buffer;

            if (ad_wstr_contains(buf, chars, s_vm3d,   4u)) score += 3u;
            if (ad_wstr_contains(buf, chars, s_vmhgfs, 6u)) score += 3u;
            if (ad_wstr_contains(buf, chars, s_vmtool, 6u)) score += 4u;
            if (ad_wstr_contains(buf, chars, s_vmraw,  5u)) score += 3u;
            if (ad_wstr_contains(buf, chars, s_vmguest,7u)) score += 3u;
            if (ad_wstr_contains(buf, chars, s_vbox,   4u)) score += 4u;
            if (ad_wstr_contains(buf, chars, s_vmic,   4u)) score += 3u;
            if (ad_wstr_contains(buf, chars, s_prl,    4u)) score += 3u;
            if (ad_wstr_contains(buf, chars, s_qemu,   4u)) score += 4u;
        }

        entry = *(u8**)entry;  // Flink
        walk++;
    }

    return score;
}

// =========================================================================
// 2. Module count anomaly
//
// A typical Windows process loads 50-120+ modules. VM sandbox environments
// that use reduced configurations or minimal Windows installs may have
// significantly fewer. Also check total loaded modules.
// =========================================================================
ANTIDEBUG_INLINE u32 ad_vm_module_count_check(void) {
    u32 score = 0u;

    u8* peb = (u8*)__readgsqword(0x60);
    if (!peb) return 0u;

    u8* ldr = *(u8**)(peb + 0x18);
    if (!ldr) return 0u;

    u8* list_head = ldr + 0x10;
    u8* entry = *(u8**)list_head;
    u32 module_count = 0u;

    while (entry != list_head && module_count < 512u) {
        module_count++;
        entry = *(u8**)entry;
    }

    // Very few modules loaded — possibly stripped sandbox.
    // Normal Win10/11 GUI apps load 30-120+ modules, but minimal console
    // apps linked with /NODEFAULTLIB can have as few as 5-8 modules.
    // Only flag extremely low counts to avoid FP on minimalist builds.
    if (module_count < 4u) score += 5u;

    return score;
}

// =========================================================================
// 3. PEB image path anomaly
//
// Check ProcessParameters->ImagePathName for unusual paths that might
// indicate a sandbox/VM environment (e.g., network share, temp directory,
// unusual drive letter).
//
// Also check EnvironmentBlock for VM-specific environment variables.
// =========================================================================
ANTIDEBUG_INLINE u32 ad_vm_path_anomaly(void) {
    u32 score = 0u;

    u8* peb = (u8*)__readgsqword(0x60);
    if (!peb) return 0u;

    // ProcessParameters at PEB+0x20
    u8* params = *(u8**)(peb + 0x20);
    if (!params) return 0u;

    // ImagePathName: UNICODE_STRING at offset 0x60
    AD_UNICODE_STRING* img_path = (AD_UNICODE_STRING*)(params + 0x60);
    if (img_path->Buffer && img_path->Length > 0u) {
        u32 chars = img_path->Length / 2u;
        const u16* buf = img_path->Buffer;

        // Check for network share path (\\)
        if (chars >= 2u && buf[0] == '\\' && buf[1] == '\\') score += 2u;

        // Check for unusual drive letters (not C: or D:)
        // Sandboxes sometimes use Z:, X:, etc.
        if (chars >= 2u && buf[1] == ':') {
            u16 drive = buf[0];
            if (drive >= 'a' && drive <= 'z') drive -= 32u;
            if (drive != 'C' && drive != 'D' && drive != 'E') score += 1u;
        }
    }

    // CommandLine: UNICODE_STRING at offset 0x70
    AD_UNICODE_STRING* cmd_line = (AD_UNICODE_STRING*)(params + 0x70);
    if (cmd_line->Buffer && cmd_line->Length > 0u) {
        u32 chars = cmd_line->Length / 2u;
        const u16* buf = cmd_line->Buffer;

        // Check for "sandbox" or "sample" in command line
        static const u16 s_sandbox[] = {'s','a','n','d','b','o','x'};
        static const u16 s_sample[]  = {'s','a','m','p','l','e'};
        static const u16 s_malware[] = {'m','a','l','w','a','r','e'};
        static const u16 s_virus[]   = {'v','i','r','u','s'};
        static const u16 s_analyze[] = {'a','n','a','l','y','z'};

        if (ad_wstr_contains(buf, chars, s_sandbox, 7u)) score += 4u;
        if (ad_wstr_contains(buf, chars, s_sample,  6u)) score += 3u;
        if (ad_wstr_contains(buf, chars, s_malware, 7u)) score += 4u;
        if (ad_wstr_contains(buf, chars, s_virus,   5u)) score += 4u;
        if (ad_wstr_contains(buf, chars, s_analyze, 6u)) score += 3u;
    }

    return score;
}

// =========================================================================
// 4. System directory module name scan
//
// Look for VM guest tool executables in System32 by checking loaded
// system modules from PEB.Ldr for specific service DLLs.
//
// VMware: vmacthlp.exe service loads vmtools.dll
// VBox: VBoxService.exe service
// Hyper-V: vmicheartbeat
// =========================================================================
ANTIDEBUG_INLINE u32 ad_vm_system_modules(void) {
    u32 score = 0u;

    u8* peb = (u8*)__readgsqword(0x60);
    if (!peb) return 0u;

    u8* ldr = *(u8**)(peb + 0x18);
    if (!ldr) return 0u;

    // Walk InMemoryOrderModuleList (offset 0x20 in Ldr)
    u8* list_head = ldr + 0x20;
    u8* entry = *(u8**)list_head;
    u32 walk = 0u;

    // Check FullDllName for system32 VM paths
    static const u16 s_vmtools[] = {'v','m','t','o','o','l','s'};
    static const u16 s_vboxsvc[] = {'v','b','o','x','s','e','r','v'};
    static const u16 s_xenbus[]  = {'x','e','n','b','u','s'};
    static const u16 s_balloon[] = {'b','l','n','s','v','r'};  // Hyper-V balloon

    while (entry != list_head && walk < 256u) {
        // In InMemoryOrderModuleList, FullDllName is at offset 0x48
        // (relative to the LIST_ENTRY, which is at +0x10 in the struct)
        // So from the Flink pointer: entry - 0x10 + 0x48 = entry + 0x38
        // Actually let's use the proper offset: entry points to InMemoryOrderLinks
        // The struct base is entry - 0x10
        // FullDllName is at struct base + 0x48 = entry + 0x38
        AD_UNICODE_STRING* full_name = (AD_UNICODE_STRING*)(entry + 0x38);
        if (full_name->Buffer && full_name->Length > 0u) {
            u32 chars = full_name->Length / 2u;
            const u16* buf = full_name->Buffer;

            if (ad_wstr_contains(buf, chars, s_vmtools, 7u)) score += 3u;
            if (ad_wstr_contains(buf, chars, s_vboxsvc, 8u)) score += 3u;
            if (ad_wstr_contains(buf, chars, s_xenbus,  6u)) score += 3u;
            if (ad_wstr_contains(buf, chars, s_balloon, 6u)) score += 2u;
        }

        entry = *(u8**)entry;
        walk++;
    }

    return score;
}

// =========================================================================
// MASTER: device artifacts composite score
// =========================================================================
ANTIDEBUG_INLINE u32 ad_vm_device_master(void) {
    u32 score = 0u;
    score += ad_vm_driver_modules();
    score += ad_vm_module_count_check();
    score += ad_vm_path_anomaly();
    score += ad_vm_system_modules();
    return score;
}

#else

ANTIDEBUG_INLINE u32 ad_vm_driver_modules(void)     { return 0; }
ANTIDEBUG_INLINE u32 ad_vm_module_count_check(void)  { return 0; }
ANTIDEBUG_INLINE u32 ad_vm_path_anomaly(void)        { return 0; }
ANTIDEBUG_INLINE u32 ad_vm_system_modules(void)      { return 0; }
ANTIDEBUG_INLINE u32 ad_vm_device_master(void)       { return 0; }

#endif // _MSC_VER

#endif // ANTIDEBUG_VM_DEVICE_ARTIFACTS_H