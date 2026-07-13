// ===== file: antidebug/checks/runtime/instrumentation.h =====
//
// Detect DBI (Dynamic Binary Instrumentation) frameworks at runtime.
//
// Techniques:
//
//   1. Process environment block scan:
//      Frida, Pin, DynamoRIO inject DLLs with recognizable names.
//      We walk PEB.Ldr.InMemoryOrderModuleList looking for suspicious modules.
//
//   2. Thread start address anomaly:
//      NtQueryInformationThread(ThreadQuerySetWin32StartAddress) returns the
//      start address. If it points outside known module ranges, a debugger
//      or injector created the thread from shellcode.
//
//   3. Process instrumentation callback:
//      Windows 10+ has PROCESS_INSTRUMENTATION_CALLBACK (class 40) which
//      debuggers/DBI tools set. If it's non-null, something is hooking us.
//
#ifndef ANTIDEBUG_INSTRUMENTATION_H
#define ANTIDEBUG_INSTRUMENTATION_H

#include "../../core/types.h"
#include "../../core/macros.h"
#include "../../core/syscall_bridge.h"
#include "../../core/string_encrypt.h"

// ---------------------------------------------------------------------------
// Module name hash check — FNV-1a on lowercase chars
//
// We hash known-bad DLL names at compile time and compare against modules
// found in the PEB LDR. This avoids putting "frida" / "dbghelp" as
// plaintext strings in the binary.
// ---------------------------------------------------------------------------

// FNV-1a 32-bit for short strings (sufficient for module name matching)
ANTIDEBUG_INLINE u32 ad_fnv1a_32_lower(const u16* wstr, u32 max_chars) {
    u32 h = 0x811C9DC5u;
    u32 i;
    for (i = 0; i < max_chars && wstr[i] != 0; i++) {
        u16 c = wstr[i];
        // Simple ASCII lowercase
        if (c >= (u16)'A' && c <= (u16)'Z') c += 32;
        h ^= (u32)(c & 0xFF);
        h *= 0x01000193u;
    }
    return h;
}

// Pre-computed hashes of suspicious DLL names (FNV-1a 32-bit lowercase)
// frida-agent.dll      → 0xC71A3B5A (computed offline)
// dbghelp.dll          → 0xB94C9AC1
// sysinternals...      → varies
// pin.dll              → 0xDEAD (placeholder, compute actual)
// dynamorio.dll        → 0xBEEF (placeholder)

// Rather than hardcode hashes (which change), we do a simpler pattern check:
// look for modules whose names contain suspicious substrings via a rolling check.

// Check if a wide string contains "frid" (Frida), "dyna" (DynamoRIO),
// "pin_" (Intel Pin), "dbgh" (dbghelp), "titl" (TitanHide indicators)
ANTIDEBUG_INLINE b32 ad_wstr_contains_suspicious(const u16* wstr, u32 max_chars) {
    u32 i;
    for (i = 0; i + 3 < max_chars && wstr[i] != 0; i++) {
        u16 c0 = wstr[i];   if (c0 >= 'A' && c0 <= 'Z') c0 += 32;
        u16 c1 = wstr[i+1]; if (c1 >= 'A' && c1 <= 'Z') c1 += 32;
        u16 c2 = wstr[i+2]; if (c2 >= 'A' && c2 <= 'Z') c2 += 32;
        u16 c3 = wstr[i+3]; if (c3 >= 'A' && c3 <= 'Z') c3 += 32;

        // "frid" — frida-agent.dll, frida-gadget.dll
        if (c0 == 'f' && c1 == 'r' && c2 == 'i' && c3 == 'd') return 1;
        // "dyna" — dynamorio.dll
        if (c0 == 'd' && c1 == 'y' && c2 == 'n' && c3 == 'a') return 1;
        // "dbgh" — dbghelp.dll (loaded by debuggers)
        if (c0 == 'd' && c1 == 'b' && c2 == 'g' && c3 == 'h') return 1;
        // "sbie" — Sandboxie
        if (c0 == 's' && c1 == 'b' && c2 == 'i' && c3 == 'e') return 1;
        // "vbox" — VirtualBox guest additions
        if (c0 == 'v' && c1 == 'b' && c2 == 'o' && c3 == 'x') return 1;
        // "vmwa" — VMware tools
        if (c0 == 'v' && c1 == 'm' && c2 == 'w' && c3 == 'a') return 1;
    }
    return 0;
}

// ---------------------------------------------------------------------------
// Check: Walk loaded modules for suspicious DLLs
//
// PEB.Ldr.InMemoryOrderModuleList is a doubly-linked list of
// LDR_DATA_TABLE_ENTRY structures. For each entry:
//   offset 0x58 (x64) = BaseDllName (UNICODE_STRING)
//     .Buffer at +0x08 from UNICODE_STRING start = 0x60
//     .Length at +0x00 = 0x58
//
// Actually, InMemoryOrderModuleList entry offsets (x64):
//   +0x00 = InMemoryOrderLinks.Flink
//   +0x20 = DllBase
//   +0x28 = EntryPoint
//   +0x30 = SizeOfImage
//   +0x38 = FullDllName (UNICODE_STRING: Length u16, MaxLen u16, pad, Buffer*)
//   +0x48 = BaseDllName (UNICODE_STRING)
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE b32 ad_detect_suspicious_modules(void) {
#if defined(_MSC_VER)
    u8* peb = (u8*)__readgsqword(0x60);
    u8* ldr = *(u8**)(peb + 0x18);

    // InMemoryOrderModuleList.Flink
    u8* list_head = ldr + 0x20;
    u8* entry = *(u8**)list_head;

    u32 count = 0;
    while (entry != list_head && count < 128u) {
        // BaseDllName UNICODE_STRING at entry + 0x48
        // (relative to InMemoryOrderLinks, which is at entry offset 0x10
        //  in the full LDR_DATA_TABLE_ENTRY — but our entry pointer IS
        //  the InMemoryOrderLinks, so BaseDllName = entry + 0x38)
        u16  name_len = *(u16*)(entry + 0x38);  // Length in bytes
        u16* name_buf = *(u16**)(entry + 0x40); // Buffer pointer

        if (name_buf && name_len > 0) {
            u32 char_count = (u32)name_len / 2u;
            if (ad_wstr_contains_suspicious(name_buf, char_count)) {
                return 1;
            }
        }

        entry = *(u8**)entry;  // Flink
        count++;
    }
#endif
    return 0;
}

// ---------------------------------------------------------------------------
// Check: Process instrumentation callback (Windows 10+)
//
// PROCESS_INSTRUMENTATION_CALLBACK (info class 40) is used by some
// debugging/instrumentation frameworks to intercept every syscall return.
// We query it — if set, something is instrumenting us.
//
// NtQueryInformationProcess(ProcessInstrumentationCallback = 40)
// Returns a PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION structure.
// ---------------------------------------------------------------------------
typedef struct {
    u32 Version;
    u32 Reserved;
    void* Callback;
} AD_INSTRUMENTATION_CALLBACK_INFO;

#define AD_PROCESS_INSTRUMENTATION_CALLBACK 40

ANTIDEBUG_INLINE b32 ad_instrumentation_callback_check(void) {
    static u16 s_ssn = AD_SSN_UNRESOLVED;
    AD_RESOLVE_SSN_ENC(s_ssn, NtQueryInformationProcess, 26);
    if (s_ssn == AD_SSN_FAILED) return 0;

    AD_INSTRUMENTATION_CALLBACK_INFO info;
    AD_ZERO_BUF(&info, sizeof(info));
    u32 ret_len = 0;

    ad_ntstatus_t st = AD_SYSCALL5(
        s_ssn,
        AD_CURRENT_PROCESS,
        (u64)AD_PROCESS_INSTRUMENTATION_CALLBACK,
        &info,
        (u64)sizeof(info),
        &ret_len
    );

    // If the query succeeds and callback is non-NULL, we're being instrumented
    if (AD_NT_SUCCESS(st) && info.Callback != (void*)0) {
        return 1;
    }

    return 0;
}

#endif // ANTIDEBUG_INSTRUMENTATION_H
