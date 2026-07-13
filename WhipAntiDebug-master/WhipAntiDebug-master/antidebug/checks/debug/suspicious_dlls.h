// ===== file: antidebug/checks/debug/suspicious_dlls.h =====
//
// Detect known debugger / injector DLLs loaded in our process.
//
// When x64dbg, ScyllaHide, or DBI frameworks are in use, they inject helper
// DLLs into the target process. Walking PEB.Ldr.InLoadOrderModuleList and
// comparing DLL base names (case-insensitive, no CRT) against a blacklist
// reveals their presence with zero IAT footprint.
//
// Blacklist (case-insensitive substring match on BaseDllName):
//   - scyllahide    : ScyllaHide plugin (*.dll injected by x64dbg)
//   - x64bridge     : x64dbg bridge DLL loaded into debuggee
//   - wow64log      : used by x64dbg for logging in x86 targets
//   - titanhide     : TitanHide (ScyllaHide alternative)
//   - frida-agent   : Frida dynamic instrumentation
//   - dbgshim       : VS / dotnet debug shim
//   - vsdbg         : Visual Studio debugger host DLL
//
#ifndef ANTIDEBUG_SUSPICIOUS_DLLS_H
#define ANTIDEBUG_SUSPICIOUS_DLLS_H

#include "../../core/types.h"
#include "../../core/macros.h"

#if defined(_MSC_VER)

// ---------------------------------------------------------------------------
// Case-insensitive ASCII-range wide-char comparison helpers
// ---------------------------------------------------------------------------

// Lowercase a single wide char (ASCII range only)
static __forceinline u16 ad_wlower(u16 c) {
    if (c >= (u16)'A' && c <= (u16)'Z') return (u16)(c + 32u);
    return c;
}

// Returns 1 if wide string [haystack, haystack+hay_len) contains [needle,
// needle+needle_len) as a substring (case-insensitive, ASCII range).
static __forceinline b32 ad_wstr_contains_ci(
    const u16* haystack, u32 hay_len,
    const u16* needle,   u32 needle_len)
{
    if (needle_len == 0u || needle_len > hay_len) return 0;
    u32 limit = hay_len - needle_len;
    u32 i, j;
    for (i = 0u; i <= limit; i++) {
        b32 match = 1;
        for (j = 0u; j < needle_len; j++) {
            if (ad_wlower(haystack[i + j]) != ad_wlower(needle[j])) {
                match = 0;
                break;
            }
        }
        if (match) return 1;
    }
    return 0;
}

// ---------------------------------------------------------------------------
// Blacklist of known suspicious DLL name substrings (wide char, static)
// Each entry: { pointer, length-in-chars (not counting null) }
// ---------------------------------------------------------------------------
typedef struct { const u16* str; u32 len; } ad_wstr_entry_t;

ANTIDEBUG_INLINE b32 ad_suspicious_dlls_check(void) {
#if defined(_MSC_VER)
    // Blacklist entries — static const wide string arrays, no .rdata string literals
    static const u16 w_scylla[]   = {'s','c','y','l','l','a','h','i','d','e'};
    static const u16 w_x64br[]    = {'x','6','4','b','r','i','d','g','e'};
    static const u16 w_wow64log[] = {'w','o','w','6','4','l','o','g'};
    static const u16 w_titan[]    = {'t','i','t','a','n','h','i','d','e'};
    static const u16 w_frida[]    = {'f','r','i','d','a','-','a','g','e','n','t'};
    static const u16 w_dbgshim[]  = {'d','b','g','s','h','i','m'};
    static const u16 w_vsdbg[]    = {'v','s','d','b','g'};

    static const ad_wstr_entry_t blacklist[] = {
        { w_scylla,   10u },
        { w_x64br,     9u },
        { w_wow64log,  8u },
        { w_titan,     9u },
        { w_frida,    11u },
        { w_dbgshim,   7u },
        { w_vsdbg,     5u },
    };
    static const u32 blacklist_count = 7u;

    // ── Walk PEB.Ldr.InLoadOrderModuleList ───────────────────────────────
    u8* peb = (u8*)__readgsqword(0x60);
    u8* ldr = *(u8**)(peb + 0x18);
    // InLoadOrderModuleList.Flink is at ldr+0x10
    u8* head  = ldr + 0x10;
    u8* entry = *(u8**)head;

    u32 visited = 0u;   // prevent infinite loop on corrupt list
    while (entry != head && visited < 512u) {
        visited++;

        // BaseDllName is at entry+0x58 (UNICODE_STRING: Length u16, MaxLength u16,
        // 4-byte pad, Buffer u64*)
        u16    name_len  = *(u16*)(entry + 0x58);        // bytes, not chars
        u16*   name_buf  = *(u16**)(entry + 0x60);
        u32    name_chars = (u32)(name_len / 2u);

        if (name_buf && name_chars > 0u) {
            u32 b;
            for (b = 0u; b < blacklist_count; b++) {
                if (ad_wstr_contains_ci(name_buf, name_chars,
                                        blacklist[b].str, blacklist[b].len)) {
                    return 1;
                }
            }
        }

        // Flink is at entry+0x00 (InLoadOrderModuleList doubly linked)
        entry = *(u8**)entry;
    }
    return 0;
#else
    return 0;
#endif
}

#else
ANTIDEBUG_INLINE b32 ad_suspicious_dlls_check(void) { return 0; }
#endif // _MSC_VER

#endif // ANTIDEBUG_SUSPICIOUS_DLLS_H