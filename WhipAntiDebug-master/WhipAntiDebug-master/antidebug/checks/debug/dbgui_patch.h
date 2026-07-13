// ===== file: antidebug/checks/debug/dbgui_patch.h =====
//
// Hook detection on ntdll debugger entry-point functions.
//
// When a debugger attaches to a process, Windows calls DbgUiRemoteBreakin
// in the target process (via a remote thread). Debuggers and anti-anti-debug
// tools often PATCH these stubs to intercept or suppress the attach notification.
//
// Functions checked:
//   - DbgUiRemoteBreakin  : entry point for remote attach (NtSetInformationThread +
//                           DbgBreakPoint). Patching it prevents clean attach detection.
//   - DbgBreakPoint        : single INT3 stub. Patched by some tools to a NOP/RET.
//   - NtCreateDebugObject  : syscall stub. Hooked by tools that intercept debug port
//                           creation to prevent NtQueryInformationProcess(ProcessDebugPort)
//                           from returning a valid handle.
//
// Detection: reads first 4 bytes of each function via NtReadVirtualMemory (direct
// syscall, bypasses any user-mode read hook). Flags FF25 (indirect JMP), E9
// (relative JMP), and EB (short JMP) as hooks.
//
#ifndef ANTIDEBUG_DBGUI_PATCH_H
#define ANTIDEBUG_DBGUI_PATCH_H

#include "../../core/types.h"
#include "../../core/macros.h"
#include "../../core/syscall_bridge.h"
#include "../../core/string_encrypt.h"
#include "../../stack/moonwalk.h"           // ad_ntdll_base()
#include "../runtime/write_watch.h"         // ad_pe_find_export()

#if defined(_MSC_VER)

ANTIDEBUG_INLINE b32 ad_dbgui_patch_check(void) {
    static u16 s_ssn_rvm = AD_SSN_UNRESOLVED;
    AD_RESOLVE_SSN_ENC(s_ssn_rvm, NtReadVirtualMemory, 20);
    if (s_ssn_rvm == AD_SSN_FAILED) return 0;

    void* ntdll = ad_ntdll_base();
    if (!ntdll) return 0;

    // Functions to inspect — stored as const char[] so no .rdata string literal
    static const char s_dbgui[]   = {'D','b','g','U','i','R','e','m','o','t','e',
                                     'B','r','e','a','k','i','n','\0'};
    static const char s_dbgbp[]   = {'D','b','g','B','r','e','a','k','P','o','i',
                                     'n','t','\0'};
    static const char s_ntcdbg[]  = {'N','t','C','r','e','a','t','e','D','e','b',
                                     'u','g','O','b','j','e','c','t','\0'};

    // DbgBreakPoint is legitimately CC;C3 — only check JMP-style hooks on it
    // Index 1 = s_dbgbp → skip the CC check for that entry
    static const char* const targets[3] = { s_dbgui, s_dbgbp, s_ntcdbg };

    u32 hooked = 0u;
    u32 i;
    for (i = 0u; i < 3u; i++) {
        void* fn = ad_pe_find_export((const u8*)ntdll, targets[i]);
        if (!fn) continue;

        u8  buf[4] = {0, 0, 0, 0};
        u64 read   = 0;
        AD_SYSCALL5(s_ssn_rvm,
            AD_CURRENT_PROCESS,
            fn,
            buf,
            (u64)4,
            &read);

        // FF 25 xx xx xx xx — indirect JMP (6-byte; FF 25 visible in first 2 bytes)
        if (buf[0] == 0xFF && buf[1] == 0x25) { hooked++; continue; }
        // E9 xx xx xx xx   — relative near JMP (5-byte)
        if (buf[0] == 0xE9)                   { hooked++; continue; }
        // EB xx            — short JMP (2-byte)
        if (buf[0] == 0xEB)                   { hooked++; continue; }
        // CC — INT3 soft breakpoint; skip for DbgBreakPoint (i==1) which is
        // normally CC;C3 by design. Flag for DbgUiRemoteBreakin/NtCreateDebugObject.
        if (buf[0] == 0xCC && i != 1u)        { hooked++; continue; }

        // DbgBreakPoint extra: if first byte is NOT CC, the INT3 was removed/patched
        // (e.g. replaced with 0x90 NOP or C3 RET to suppress the initial break)
        if (i == 1u && buf[0] != 0xCC)        { hooked++; continue; }
    }

    return (b32)(hooked > 0u);
}

#else
ANTIDEBUG_INLINE b32 ad_dbgui_patch_check(void) { return 0; }
#endif // _MSC_VER

#endif // ANTIDEBUG_DBGUI_PATCH_H