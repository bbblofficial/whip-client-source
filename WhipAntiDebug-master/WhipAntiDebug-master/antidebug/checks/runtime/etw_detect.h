// ===== file: antidebug/checks/runtime/etw_detect.h =====
//
// Detect hooks on ETW (Event Tracing for Windows) functions.
//
// Many analysis tools (API Monitor, Frida, some sandbox agents) hook
// ntdll!EtwEventWrite to intercept or suppress ETW events emitted by the
// target process. This is also common in advanced anti-anti-debug setups
// that instrument the process at the tracing layer.
//
// We also check EtwEventWriteFull and EtwNotificationRegister as secondary
// targets — tools that patch ETW often patch multiple entry points.
//
// Detection: read first 4 bytes via NtReadVirtualMemory (direct syscall).
//   FF 25 → indirect JMP (hook trampoline)
//   E9    → relative near JMP (inline hook)
//   EB    → short JMP (inline hook, short range)
//   CC    → INT3 (debug breakpoint)
//
#ifndef ANTIDEBUG_ETW_DETECT_H
#define ANTIDEBUG_ETW_DETECT_H

#include "../../core/types.h"
#include "../../core/macros.h"
#include "../../core/syscall_bridge.h"
#include "../../core/string_encrypt.h"
#include "../../stack/moonwalk.h"       // ad_ntdll_base()
#include "write_watch.h"                // ad_pe_find_export()

#if defined(_MSC_VER)

ANTIDEBUG_INLINE b32 ad_etw_hook_detect(void) {
    static u16 s_ssn_rvm = AD_SSN_UNRESOLVED;
    AD_RESOLVE_SSN_ENC(s_ssn_rvm, NtReadVirtualMemory, 20);
    if (s_ssn_rvm == AD_SSN_FAILED) return 0;

    void* ntdll = ad_ntdll_base();
    if (!ntdll) return 0;

    // ETW functions commonly hooked by analysis tools
    static const char s_etw_write[]     = {'E','t','w','E','v','e','n','t','W',
                                           'r','i','t','e','\0'};
    static const char s_etw_full[]      = {'E','t','w','E','v','e','n','t','W',
                                           'r','i','t','e','F','u','l','l','\0'};
    static const char s_etw_notify[]    = {'E','t','w','N','o','t','i','f','i',
                                           'c','a','t','i','o','n','R','e','g',
                                           'i','s','t','e','r','\0'};

    static const char* const targets[3] = {
        s_etw_write, s_etw_full, s_etw_notify
    };

    u32 hooked = 0u;
    u32 i;
    for (i = 0u; i < 3u; i++) {
        void* fn = ad_pe_find_export((const u8*)ntdll, targets[i]);
        if (!fn) continue;

        u8  buf[4] = {0, 0, 0, 0};
        u64 read   = 0;
        AD_SYSCALL5(s_ssn_rvm,
            AD_CURRENT_PROCESS, fn, buf, (u64)4, &read);

        if (buf[0] == 0xFF && buf[1] == 0x25) { hooked++; continue; }
        if (buf[0] == 0xE9)                   { hooked++; continue; }
        if (buf[0] == 0xEB)                   { hooked++; continue; }
        if (buf[0] == 0xCC)                   { hooked++; continue; }
    }

    // Any ETW hook is suspicious — legitimate software does not hook these
    return (b32)(hooked > 0u);
}

#else
ANTIDEBUG_INLINE b32 ad_etw_hook_detect(void) { return 0; }
#endif // _MSC_VER

#endif // ANTIDEBUG_ETW_DETECT_H
