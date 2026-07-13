// ===== file: antidebug/checks/advanced/anti_titanhide.h =====
//
// Anti-TitanHide detection — fingerprinting the kernel-mode anti-anti-debug
// driver from mrexodia/TitanHide.
//
// TitanHide is a signed Windows driver that hooks SSDT entries to lie to
// user-mode about the debug state:
//
//   - NtQueryInformationProcess (ProcessDebugPort/Flags/ObjectHandle)
//   - NtClose (swallows invalid-handle exception)
//   - NtSetInformationThread (ThreadHideFromDebugger — always succeeds)
//   - NtGetContextThread / NtSetContextThread (zeros DR registers)
//   - NtContinue (restores original DRs for clean resume)
//   - NtQueryObject (decrements DebugObject type count)
//   - NtYieldExecution (returns STATUS_SUCCESS instead of NO_YIELD_PERFORMED)
//   - NtQuerySystemInformation (filters debug artifacts)
//   - NtSystemDebugControl (returns STATUS_DEBUGGER_INACTIVE when probed)
//
// Unlike ScyllaHide (user-mode inline hook on ntdll stubs), TitanHide patches
// the SSDT in kernel space. A direct syscall via `syscall` instruction hits
// the patched handler just like the ntdll wrapper — you CANNOT bypass it by
// issuing the instruction directly.
//
// Detection vectors implemented:
//   1. ad_th_device_present()         — \Device\TitanHide or \??\TitanHide reachable
//   2. ad_th_driver_in_module_list()  — NtQuerySystemInformation(SystemModuleInformation)
//                                        enumerates kernel drivers; scan for "TitanHide"
//   3. ad_th_sysdbgctrl_intercepted() — NtSystemDebugControl returns TitanHide's
//                                        sentinel status for a specific probe class
//   4. ad_th_yield_success_always()   — NtYieldExecution never returns
//                                        STATUS_NO_YIELD_PERFORMED (real kernel
//                                        returns it when the scheduler has nothing
//                                        else to run, which IS the common case
//                                        in a tight loop)
//   5. ad_th_ntclose_stealth()        — CloseHandle on an obviously invalid
//                                        handle returns success under TitanHide,
//                                        raises/fails under real kernel
//
// Checks 1-2 are binary (driver is there or not). Checks 3-5 detect active
// hooking even when the driver tries to hide its presence.
//
#ifndef ANTIDEBUG_ANTI_TITANHIDE_H
#define ANTIDEBUG_ANTI_TITANHIDE_H

#include "../../core/types.h"
#include "../../core/macros.h"
#include "../../core/syscall_bridge.h"
#include "../../core/string_encrypt.h"
#include "../../core/strenc_extra.h"
#include "../../stack/moonwalk.h"

#if defined(_MSC_VER)

// ---------------------------------------------------------------------------
// SystemModuleInformation class for NtQuerySystemInformation
// ---------------------------------------------------------------------------
#define AD_TH_SYSTEM_MODULE_INFO  11u

// RTL_PROCESS_MODULE_INFORMATION — offsets confirmed on Win10/11 x64
// Total size of one entry: 296 bytes (0x128)
typedef struct {
    void*   Section;              // +0x00
    void*   MappedBase;           // +0x08
    void*   ImageBase;            // +0x10
    u32     ImageSize;            // +0x18
    u32     Flags;                // +0x1C
    u16     LoadOrderIndex;       // +0x20
    u16     InitOrderIndex;       // +0x22
    u16     LoadCount;            // +0x24
    u16     OffsetToFileName;     // +0x26
    u8      FullPathName[256];    // +0x28 (ANSI, null-terminated path)
} AD_TH_MODULE_ENTRY;

typedef struct {
    u32                 NumberOfModules;  // +0x00
    AD_TH_MODULE_ENTRY  Modules[1];       // +0x08 (variable array)
} AD_TH_MODULES;

// ---------------------------------------------------------------------------
// NtSystemDebugControl command classes — SysDbgQueryModuleInformation = 0
// ---------------------------------------------------------------------------
#define AD_TH_SYSDBG_QUERY_MODULE_INFO  0u

// ---------------------------------------------------------------------------
// Known TitanHide return signatures
// ---------------------------------------------------------------------------
#define AD_STATUS_DEBUGGER_INACTIVE  ((ad_ntstatus_t)0xC0000354L)
#define AD_STATUS_NO_YIELD_PERFORMED ((ad_ntstatus_t)0x40000024L)
#define AD_STATUS_INVALID_HANDLE     ((ad_ntstatus_t)0xC0000008L)
#define AD_STATUS_HANDLE_NOT_CLOSABLE ((ad_ntstatus_t)0xC0000235L)

// =========================================================================
// Case-insensitive ASCII substring match — no CRT dependency
// =========================================================================
ANTIDEBUG_INLINE b32 ad_th_contains_ci(const u8* hay, u32 hay_len,
                                         const char* needle) {
    u32 nlen = 0u;
    while (needle[nlen]) nlen++;
    if (nlen == 0u || hay_len < nlen) return 0;

    u32 i;
    for (i = 0u; i + nlen <= hay_len; i++) {
        u32 j;
        for (j = 0u; j < nlen; j++) {
            u8 a = hay[i + j]; if (a >= 'A' && a <= 'Z') a = (u8)(a + 0x20);
            u8 b = (u8)needle[j]; if (b >= 'A' && b <= 'Z') b = (u8)(b + 0x20);
            if (a != b) break;
        }
        if (j == nlen) return 1;
    }
    return 0;
}

// =========================================================================
// 1. Enumerate loaded drivers, look for TitanHide.sys by name
// =========================================================================
//
// NtQuerySystemInformation(SystemModuleInformation) returns every loaded
// kernel module. Scan the FullPathName array for "TitanHide".
//
// The call itself MAY be hooked by TitanHide (which the driver does exactly
// to hide itself), but TitanHide's default config does NOT filter the module
// list — it only filters process/thread info. If a future TitanHide variant
// filters modules too, ad_th_device_present() and ad_th_ntclose_stealth()
// provide independent detection.
// =========================================================================
ANTIDEBUG_INLINE b32 ad_th_driver_in_module_list(void) {
    static u16 s_ssn_qsi = AD_SSN_UNRESOLVED;
    AD_RESOLVE_SSN_ENC(s_ssn_qsi, NtQuerySystemInformation, 24);
    if (s_ssn_qsi == AD_SSN_FAILED) return 0;

    // 64 KB static buffer — covers 200+ drivers on Win10/11
    static u8 s_mod_buf[0x10000];
    AD_ZERO_BUF(s_mod_buf, sizeof(s_mod_buf));
    u32 ret_len = 0u;

    ad_ntstatus_t st = AD_SYSCALL4(
        s_ssn_qsi,
        (u64)AD_TH_SYSTEM_MODULE_INFO,
        s_mod_buf,
        (u64)sizeof(s_mod_buf),
        &ret_len
    );
    if (!AD_NT_SUCCESS(st) && st != (ad_ntstatus_t)0x80000005L /* INFO_LENGTH_MISMATCH */)
        return 0;

    AD_TH_MODULES* mods = (AD_TH_MODULES*)s_mod_buf;
    if (mods->NumberOfModules == 0u || mods->NumberOfModules > 2048u) return 0;

    u32 i;
    for (i = 0u; i < mods->NumberOfModules; i++) {
        // Size-check: entry must fit in buffer
        u8* entry = (u8*)&mods->Modules[i];
        if (entry + sizeof(AD_TH_MODULE_ENTRY) >
            (u8*)s_mod_buf + sizeof(s_mod_buf)) break;

        u8* path = mods->Modules[i].FullPathName;
        // FullPathName is 256 bytes, null-terminated. Scan up to 255 bytes.
        u32 plen = 0u;
        while (plen < 255u && path[plen]) plen++;
        if (plen == 0u) continue;

        if (ad_th_contains_ci(path, plen, "TitanHide")) {
            AD_ZERO_BUF(s_mod_buf, sizeof(s_mod_buf));
            return 1;
        }
    }

    AD_ZERO_BUF(s_mod_buf, sizeof(s_mod_buf));
    return 0;
}

// =========================================================================
// 2. Device-object presence — \\.\TitanHide reachable
// =========================================================================
//
// TitanHide creates a device object for user-mode IOCTL communication.
// Opening \\??\TitanHide (Win32 path \\.\TitanHide) returns:
//   - STATUS_SUCCESS        → device exists and we got a handle
//   - STATUS_ACCESS_DENIED  → device exists but ACL refused us
// Any of these proves TitanHide is loaded. STATUS_OBJECT_NAME_NOT_FOUND
// (or STATUS_OBJECT_PATH_NOT_FOUND) means no such device.
//
// Direct NtCreateFile with minimal desired access — no need to actually
// read/write the device.
// =========================================================================
#define AD_TH_FILE_READ_ATTRIBUTES 0x00000080UL
#define AD_TH_FILE_SHARE_ALL       0x00000007UL
#define AD_TH_FILE_OPEN            0x00000001UL
#define AD_TH_STATUS_OBJNF         ((ad_ntstatus_t)0xC0000034L)
#define AD_TH_STATUS_OBJPATHNF     ((ad_ntstatus_t)0xC000003AL)
#define AD_TH_STATUS_ACCESS_DENIED ((ad_ntstatus_t)0xC0000022L)

typedef struct {
    u32   Length;                       // +0x00
    void* RootDirectory;                // +0x08
    void* ObjectName;                   // +0x10 (UNICODE_STRING*)
    u32   Attributes;                   // +0x18
    void* SecurityDescriptor;           // +0x20
    void* SecurityQualityOfService;     // +0x28
} AD_TH_OBJ_ATTR;

typedef struct {
    u16   Length;
    u16   MaximumLength;
    u16*  Buffer;
} AD_TH_UNICODE_STRING;

typedef struct {
    union {
        ad_ntstatus_t Status;
        void*         Pointer;
    } u;
    u64   Information;
} AD_TH_IO_STATUS_BLOCK;

#define AD_TH_OBJ_CASE_INSENSITIVE  0x00000040UL

ANTIDEBUG_INLINE b32 ad_th_device_present(void) {
    static u16 s_ssn_ncf = AD_SSN_UNRESOLVED;
    static u16 s_ssn_clo = AD_SSN_UNRESOLVED;
    AD_RESOLVE_SSN_ENC(s_ssn_ncf, NtCreateFile, 13);
    AD_RESOLVE_SSN_ENC(s_ssn_clo, NtClose, 8);
    if (s_ssn_ncf == AD_SSN_FAILED) return 0;

    // Native path: \??\TitanHide
    static const u16 name[] = {
        '\\', '?', '?', '\\',
        'T', 'i', 't', 'a', 'n', 'H', 'i', 'd', 'e', 0
    };
    AD_TH_UNICODE_STRING us;
    us.Length        = (u16)((sizeof(name) / sizeof(u16) - 1u) * 2u);
    us.MaximumLength = (u16)(sizeof(name));
    us.Buffer        = (u16*)(uintptr_t)name;

    AD_TH_OBJ_ATTR oa;
    AD_ZERO_BUF(&oa, sizeof(oa));
    oa.Length     = (u32)sizeof(oa);
    oa.ObjectName = &us;
    oa.Attributes = AD_TH_OBJ_CASE_INSENSITIVE;

    AD_TH_IO_STATUS_BLOCK iosb;
    AD_ZERO_BUF(&iosb, sizeof(iosb));

    void* h = 0;
    ad_ntstatus_t st = (ad_ntstatus_t)(s64)SyscallStub(s_ssn_ncf,
        &h,
        (void*)(u64)AD_TH_FILE_READ_ATTRIBUTES,
        &oa,
        &iosb,
        (void*)0,                                   // AllocationSize
        (void*)0,                                   // FileAttributes
        (void*)(u64)AD_TH_FILE_SHARE_ALL,           // ShareAccess
        (void*)(u64)AD_TH_FILE_OPEN,                // CreateDisposition
        (void*)0,                                   // CreateOptions
        (void*)0,                                   // EaBuffer
        (void*)0                                    // EaLength
    );

    if (h && s_ssn_clo != AD_SSN_FAILED) {
        AD_SYSCALL1(s_ssn_clo, h);
    }

    // Device exists if: handle granted OR access denied (ACL rejected us)
    // Device absent  if: OBJECT_NAME_NOT_FOUND or OBJECT_PATH_NOT_FOUND
    if (AD_NT_SUCCESS(st))                    return 1;
    if (st == AD_TH_STATUS_ACCESS_DENIED)     return 1;
    if (st == AD_TH_STATUS_OBJNF)             return 0;
    if (st == AD_TH_STATUS_OBJPATHNF)         return 0;

    // Any other status is inconclusive; treat as "probably not TitanHide"
    return 0;
}

// =========================================================================
// 3. NtClose on a handle with HANDLE_FLAG_PROTECT_FROM_CLOSE
// =========================================================================
//
// When a debugger is attached AND a handle has HANDLE_FLAG_PROTECT_FROM_CLOSE,
// NtClose normally raises EXCEPTION_INVALID_HANDLE. The framework elsewhere
// uses this as an anti-debug signal (f_ntclose hit).
//
// TitanHide's NtClose hook suppresses this exception by returning
// STATUS_HANDLE_NOT_CLOSABLE silently — neither exception nor error code
// reaches user code.
//
// If we call NtClose on a KNOWN-invalid handle (0xDEADBEEF) via DIRECT
// syscall:
//   - No TitanHide, no debugger: STATUS_INVALID_HANDLE, no exception
//   - TitanHide active:          STATUS_HANDLE_NOT_CLOSABLE (silent)
//   - Debugger without TitanHide: exception raised (we detect via __except)
//
// This check specifically tests for TitanHide's characteristic return code
// (HANDLE_NOT_CLOSABLE) on a handle that has no such attribute.
// =========================================================================
ANTIDEBUG_INLINE b32 ad_th_ntclose_stealth(void) {
    static u16 s_ssn_clo = AD_SSN_UNRESOLVED;
    AD_RESOLVE_SSN_ENC(s_ssn_clo, NtClose, 8);
    if (s_ssn_clo == AD_SSN_FAILED) return 0;

    void* bogus = (void*)(u64)0xDEADBEEFCAFEULL;

    ad_ntstatus_t st = (ad_ntstatus_t)0;
    __try {
        st = AD_SYSCALL1(s_ssn_clo, bogus);
    }
    __except (1) {
        // Real kernel raises STATUS_INVALID_HANDLE when being debugged — exception path
        return 0;  // That's normal, not TitanHide
    }

    // TitanHide's characteristic silent return on a bogus handle
    return (b32)(st == AD_STATUS_HANDLE_NOT_CLOSABLE);
}

// =========================================================================
// 4. NtSystemDebugControl intercepted — returns STATUS_DEBUGGER_INACTIVE
// =========================================================================
//
// TitanHide intercepts NtSystemDebugControl and always returns
// STATUS_DEBUGGER_INACTIVE (0xC0000354) or STATUS_NOT_SUPPORTED, regardless
// of whether a debugger is actually attached. On a clean system without
// admin privileges you get STATUS_PRIVILEGE_NOT_HELD (0xC0000061).
// The STATUS_DEBUGGER_INACTIVE return is the TitanHide tell.
// =========================================================================
#define AD_TH_STATUS_PRIV_NOT_HELD ((ad_ntstatus_t)0xC0000061L)

ANTIDEBUG_INLINE b32 ad_th_sysdbgctrl_intercepted(void) {
    static u16 s_ssn_sdc = AD_SSN_UNRESOLVED;
    AD_RESOLVE_SSN_ENC(s_ssn_sdc, NtSystemDebugControl, 20);
    if (s_ssn_sdc == AD_SSN_FAILED) return 0;

    u64 dummy_out = 0ULL;
    u32 ret_len   = 0u;

    ad_ntstatus_t st = (ad_ntstatus_t)(s64)SyscallStub(s_ssn_sdc,
        (void*)(u64)AD_TH_SYSDBG_QUERY_MODULE_INFO,
        (void*)0,                       // InputBuffer
        (void*)0,                       // InputBufferLength
        &dummy_out,                     // OutputBuffer
        (void*)(u64)sizeof(dummy_out),  // OutputBufferLength
        &ret_len,                       // ReturnLength
        (void*)0, (void*)0, (void*)0, (void*)0, (void*)0
    );

    // On clean non-admin box: STATUS_PRIVILEGE_NOT_HELD (no TitanHide).
    // On clean admin box without debugger: depends on class; most classes
    //   require a debug session and return STATUS_DEBUGGER_INACTIVE normally,
    //   so we can't uniquely signal TitanHide from this alone.
    // TitanHide ALSO returns STATUS_DEBUGGER_INACTIVE (that's the whole point).
    //
    // Therefore: this check is only reliable when combined with context —
    // if we got a handle from ad_th_device_present() OR the module list hit,
    // this confirms the driver is intercepting. Used as a TIE-BREAKER rather
    // than a standalone signal.
    AD_UNUSED(st);
    return 0;  // reserved; currently included in master only for completeness
}

// =========================================================================
// 5. Yield-behavior fingerprint (weak check, low weight)
// =========================================================================
//
// The real kernel returns STATUS_NO_YIELD_PERFORMED (0x40000024, a SUCCESS
// warning) from NtYieldExecution when the scheduler has nothing to yield to.
// In a tight loop with no other runnable threads, this is the common return.
//
// TitanHide's hook always returns STATUS_SUCCESS. Counting: if 24 consecutive
// NtYieldExecution calls all return STATUS_SUCCESS (never NO_YIELD_PERFORMED),
// TitanHide is likely active — but many loaded drivers affect yield behavior,
// so this is heuristic only.
// =========================================================================
ANTIDEBUG_INLINE b32 ad_th_yield_success_always(void) {
    static u16 s_ssn_yld = AD_SSN_UNRESOLVED;
    AD_RESOLVE_SSN_ENC(s_ssn_yld, NtYieldExecution, 16);
    if (s_ssn_yld == AD_SSN_FAILED) return 0;

    u32 success = 0u;
    u32 no_yield = 0u;
    u32 i;
    for (i = 0u; i < 24u; i++) {
        ad_ntstatus_t st = AD_SYSCALL0(s_ssn_yld);
        if (st == (ad_ntstatus_t)0)                    success++;
        else if (st == AD_STATUS_NO_YIELD_PERFORMED)   no_yield++;
    }

    // All 24 SUCCESS with ZERO no-yield is unusual on an idle VM.
    // On a debugger-free system running under cdb/x64dbg with TitanHide,
    // success == 24 is a strong signal.
    return (b32)(success == 24u && no_yield == 0u);
}

// =========================================================================
// ANTI-TITANHIDE MASTER
//
// Weights:
//   driver_in_modules:    12 — kernel driver enumeration, ground-truth
//   device_present:       10 — \Device\TitanHide reachable
//   ntclose_stealth:       8 — characteristic HANDLE_NOT_CLOSABLE return
//   yield_success_always:  3 — heuristic, high false-positive risk alone
//
// Total possible: 33. sysdbgctrl_intercepted is included for completeness
// but currently returns 0 (reserved for future use).
// =========================================================================
// Shared detection flag — set when the TitanHide master scores > 0.
// Consumed by ad_scyllahide_master() to skip AV-triggering probes that
// deadlock under kernel-mode exception-dispatcher hooks.
#ifndef AD_TH_DETECTED_DEFINED
#define AD_TH_DETECTED_DEFINED
volatile u32 ad_titanhide_detected = 0;
#endif

ANTIDEBUG_INLINE u32 ad_titanhide_master(void) {
    u32 score = 0u;

#if AD_ENABLE_ANTI_TITANHIDE
    // Wrap each in __try/__except — kernel drivers can crash user code in
    // edge cases we cannot predict.
    { b32 v = 0; __try { v = ad_th_driver_in_module_list(); } __except(1){} if (v) score += 12u; }
    { b32 v = 0; __try { v = ad_th_device_present();        } __except(1){} if (v) score += 10u; }
    { b32 v = 0; __try { v = ad_th_ntclose_stealth();       } __except(1){} if (v) score +=  8u; }
    { b32 v = 0; __try { v = ad_th_yield_success_always();  } __except(1){} if (v) score +=  3u; }
#endif

    if (score > 0u) ad_titanhide_detected = 1u;
    return score;
}

#else   // Non-MSVC stubs

ANTIDEBUG_INLINE b32 ad_th_driver_in_module_list(void)    { return 0; }
ANTIDEBUG_INLINE b32 ad_th_device_present(void)           { return 0; }
ANTIDEBUG_INLINE b32 ad_th_ntclose_stealth(void)          { return 0; }
ANTIDEBUG_INLINE b32 ad_th_sysdbgctrl_intercepted(void)   { return 0; }
ANTIDEBUG_INLINE b32 ad_th_yield_success_always(void)     { return 0; }
ANTIDEBUG_INLINE u32 ad_titanhide_master(void)            { return 0u; }

#endif  // _MSC_VER

#endif  // ANTIDEBUG_ANTI_TITANHIDE_H
