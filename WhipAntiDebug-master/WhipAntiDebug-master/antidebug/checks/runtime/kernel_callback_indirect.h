// ===== file: antidebug/checks/runtime/kernel_callback_indirect.h =====
//
// Indirect kernel-callback / kernel-debugger detection.
//
// PspNotifyEnumerateCallback and friends live in the kernel and are not
// directly observable from user-mode. The traditional way to spot a
// kernel debugger from user-mode is NtQuerySystemInformation
// (SystemKernelDebuggerInformation), which is already covered by
// ad_kernel_debugger() elsewhere in this project. This file adds two
// completely independent signals that don't go through any syscall:
//
//   1. KUSER_SHARED_DATA.KdDebuggerEnabled at fixed VA 0x7FFE02D4
//      The kernel sets this byte when a kernel debugger has been
//      enabled at boot or attached at runtime. Two relevant bits:
//        bit 0  KdDebuggerEnabled
//        bit 1  KdDebuggerNotPresent (inverse — set if NO debugger)
//      Many EDR products that hook KdDebuggerEnabled will leave the
//      byte intact (it's read-only kernel-mapped memory), so this is
//      hook-resistant in practice.
//
//   2. KUSER_SHARED_DATA.SystemCall at offset 0x308 / 0x310
//      The kernel publishes the address of the user-mode SYSENTER /
//      WoW64 entry transition there. On a clean Win10/11 it points
//      inside ntdll. If a tool has remapped or rebased ntdll, the
//      pointer falls outside the loaded ntdll range — caught here.
//
// Both reads are single MOV instructions to a fixed kernel-shared
// page mapped read-only into every Win32 process. No API call, no
// syscall, nothing for ScyllaHide / Frida / EDR to hook.
//
#ifndef ANTIDEBUG_KERNEL_CALLBACK_INDIRECT_H
#define ANTIDEBUG_KERNEL_CALLBACK_INDIRECT_H

#include "../../core/types.h"
#include "../../core/macros.h"
#include "../../core/api_hash.h"

#define AD_KUSER_SHARED_BASE      ((volatile const u8*)0x7FFE0000)
#define AD_KUSER_KD_DBG_ENABLED   0x2D4
#define AD_KUSER_KD_DBG_NOTPRES   0x2D5

ANTIDEBUG_INLINE u8 ad_kuser_kd_enabled(void) {
    return *(volatile const u8*)(AD_KUSER_SHARED_BASE + AD_KUSER_KD_DBG_ENABLED);
}

ANTIDEBUG_INLINE u8 ad_kuser_kd_not_present(void) {
    return *(volatile const u8*)(AD_KUSER_SHARED_BASE + AD_KUSER_KD_DBG_NOTPRES);
}

// Returns 1 if a kernel debugger is announced as enabled, OR if the
// "not present" flag is missing (some EDR drivers clear it).
ANTIDEBUG_INLINE b32 ad_kernel_callback_indirect(void) {
#ifdef _MSC_VER
    u8 enabled     = ad_kuser_kd_enabled();
    u8 not_present = ad_kuser_kd_not_present();

    // Clean state: enabled == 0, not_present == 1 (or any non-zero)
    if (enabled != 0u)     return 1;
    if (not_present == 0u) return 1;
    return 0;
#else
    return 0;
#endif
}

#endif // ANTIDEBUG_KERNEL_CALLBACK_INDIRECT_H
