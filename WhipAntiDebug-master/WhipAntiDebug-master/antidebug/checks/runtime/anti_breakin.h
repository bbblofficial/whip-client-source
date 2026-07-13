// ===== file: antidebug/checks/runtime/anti_breakin.h =====
//
// Anti-Attach via DbgUiRemoteBreakin trampoline.
//
// When a debugger (x64dbg, WinDbg, OllyDbg, IDA) attaches to a running
// process, it calls DebugActiveProcess() which ultimately spawns a remote
// thread inside the target whose start address is ntdll!DbgUiRemoteBreakin.
// That function normally calls DbgBreakPoint() to give the debugger an
// initial breakpoint to latch onto.
//
// We patch DbgUiRemoteBreakin in our own process with a tiny trampoline
// that calls RtlExitUserProcess(1) instead. The result:
//
//   reverser hits "Attach to process" in their debugger
//   -> debugger calls DebugActiveProcess
//   -> kernel injects a thread at our patched DbgUiRemoteBreakin
//   -> our trampoline runs RtlExitUserProcess(1)
//   -> process dies before the debugger can present any state
//
// The reverser sees a "process exited" event with no useful context, no
// loaded module list, no register dump. The function name is never spelled
// in the binary because we resolve it via FNV-1a hash through the existing
// api_hash module, so static analysis sees only an opaque u32 constant.
//
// This is one-shot install, called once at startup. ad_anti_breakin_verify()
// can be invoked from a periodic check to detect ScyllaHide-style unpatches.
//
#ifndef ANTIDEBUG_ANTI_BREAKIN_H
#define ANTIDEBUG_ANTI_BREAKIN_H

#include "../../core/types.h"
#include "../../core/macros.h"
#include "../../core/api_hash.h"
#include "../../core/syscall_bridge.h"
#include "../../core/string_encrypt.h"
#include "../../core/strenc_extra.h"

#ifndef AD_PAGE_EXECUTE_READWRITE
#define AD_PAGE_EXECUTE_READWRITE 0x40UL
#endif
#ifndef AD_PAGE_EXECUTE_READ
#define AD_PAGE_EXECUTE_READ      0x20UL
#endif

// Reuse the NtProtectVirtualMemory string-encrypt macro from anti_dump.h
// when available. If anti_dump.h is not included, define our own copy.
#ifndef AD_STRENC_NtProtectVirtualMemory
#define AD_STRENC_NtProtectVirtualMemory(buf)                                \
    do {                                                                     \
        const u8 _k = AD_STR_KEY(0x3B);                                     \
        char buf##_e[23];                                                    \
        AD_ENC(buf##_e,  0, 'N', _k); AD_ENC(buf##_e,  1, 't', _k);       \
        AD_ENC(buf##_e,  2, 'P', _k); AD_ENC(buf##_e,  3, 'r', _k);       \
        AD_ENC(buf##_e,  4, 'o', _k); AD_ENC(buf##_e,  5, 't', _k);       \
        AD_ENC(buf##_e,  6, 'e', _k); AD_ENC(buf##_e,  7, 'c', _k);       \
        AD_ENC(buf##_e,  8, 't', _k); AD_ENC(buf##_e,  9, 'V', _k);       \
        AD_ENC(buf##_e, 10, 'i', _k); AD_ENC(buf##_e, 11, 'r', _k);       \
        AD_ENC(buf##_e, 12, 't', _k); AD_ENC(buf##_e, 13, 'u', _k);       \
        AD_ENC(buf##_e, 14, 'a', _k); AD_ENC(buf##_e, 15, 'l', _k);       \
        AD_ENC(buf##_e, 16, 'M', _k); AD_ENC(buf##_e, 17, 'e', _k);       \
        AD_ENC(buf##_e, 18, 'm', _k); AD_ENC(buf##_e, 19, 'o', _k);       \
        AD_ENC(buf##_e, 20, 'r', _k); AD_ENC(buf##_e, 21, 'y', _k);       \
        AD_DECODE_BUF(buf##_e, 22, _k);                                     \
        for (unsigned _ci = 0; _ci < 23; _ci++) (buf)[_ci] = buf##_e[_ci];  \
    } while (0)
#endif

// ---------------------------------------------------------------------------
// Stack-built API hashes. The literal NUL-terminated names never appear in
// .rdata — only the FNV-1a u32 result, after ad_hash_str() runs.
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE u32 ad_hash_dbgui_remote_breakin(void) {
    char b[19];
    b[ 0]='D'; b[ 1]='b'; b[ 2]='g'; b[ 3]='U'; b[ 4]='i';
    b[ 5]='R'; b[ 6]='e'; b[ 7]='m'; b[ 8]='o'; b[ 9]='t';
    b[10]='e'; b[11]='B'; b[12]='r'; b[13]='e'; b[14]='a';
    b[15]='k'; b[16]='i'; b[17]='n'; b[18]=0;
    return ad_hash_str(b);
}

ANTIDEBUG_INLINE u32 ad_hash_rtl_exit_user_process(void) {
    char b[19];
    b[ 0]='R'; b[ 1]='t'; b[ 2]='l'; b[ 3]='E'; b[ 4]='x';
    b[ 5]='i'; b[ 6]='t'; b[ 7]='U'; b[ 8]='s'; b[ 9]='e';
    b[10]='r'; b[11]='P'; b[12]='r'; b[13]='o'; b[14]='c';
    b[15]='e'; b[16]='s'; b[17]='s'; b[18]=0;
    return ad_hash_str(b);
}

// ---------------------------------------------------------------------------
// Install the trampoline. Idempotent.
//
// Returns 1 on successful install (or already installed), 0 on any failure.
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE b32 ad_anti_breakin_install(void) {
#ifdef _MSC_VER
    static b32 s_installed = 0;
    if (s_installed) return 1;

    void* breakin = ad_resolve_api(AD_HASH_NTDLL, ad_hash_dbgui_remote_breakin());
    if (!breakin) return 0;
    void* exit_fn = ad_resolve_api(AD_HASH_NTDLL, ad_hash_rtl_exit_user_process());
    if (!exit_fn) return 0;

    static u16 s_ssn = AD_SSN_UNRESOLVED;
    AD_RESOLVE_SSN_ENC(s_ssn, NtProtectVirtualMemory, 23);
    if (s_ssn == AD_SSN_FAILED) return 0;

    // Trampoline (17 bytes):
    //   B9 01 00 00 00          mov ecx, 1                ; ExitStatus = 1
    //   48 B8 <imm64>           mov rax, RtlExitUserProcess
    //   FF E0                   jmp rax
    u8 stub[17];
    stub[ 0] = 0xB9; stub[ 1] = 0x01; stub[ 2] = 0x00;
    stub[ 3] = 0x00; stub[ 4] = 0x00;
    stub[ 5] = 0x48; stub[ 6] = 0xB8;
    u64 abs = (u64)exit_fn;
    stub[ 7] = (u8)( abs        & 0xFFu);
    stub[ 8] = (u8)((abs >>  8) & 0xFFu);
    stub[ 9] = (u8)((abs >> 16) & 0xFFu);
    stub[10] = (u8)((abs >> 24) & 0xFFu);
    stub[11] = (u8)((abs >> 32) & 0xFFu);
    stub[12] = (u8)((abs >> 40) & 0xFFu);
    stub[13] = (u8)((abs >> 48) & 0xFFu);
    stub[14] = (u8)((abs >> 56) & 0xFFu);
    stub[15] = 0xFF; stub[16] = 0xE0;

    void* addr  = breakin;
    u64   size  = (u64)sizeof(stub);
    u32   old   = 0;
    ad_ntstatus_t st = (ad_ntstatus_t)(s64)AD_SYSCALL5(
        s_ssn,
        AD_CURRENT_PROCESS,
        &addr,
        &size,
        (u64)AD_PAGE_EXECUTE_READWRITE,
        &old
    );
    if (!AD_NT_SUCCESS(st)) return 0;

    {
        volatile u8* dst = (volatile u8*)breakin;
        unsigned i;
        for (i = 0; i < sizeof(stub); i++) dst[i] = stub[i];
    }

    addr  = breakin;
    size  = (u64)sizeof(stub);
    u32 dummy = 0;
    (void)AD_SYSCALL5(
        s_ssn,
        AD_CURRENT_PROCESS,
        &addr,
        &size,
        (u64)AD_PAGE_EXECUTE_READ,
        &dummy
    );

    s_installed = 1;
    return 1;
#else
    return 0;
#endif
}

// ---------------------------------------------------------------------------
// Variant — install with caller-supplied target function pointer.
// The same `mov ecx, 1; mov rax, target; jmp rax` trampoline, but the kernel-
// injected DbgUiRemoteBreakin thread is redirected to `target_fn(1)` instead
// of RtlExitUserProcess. Used by Sentinel_bridge to interpose a "notify
// server, then exit" handler — the server gets the REVERSE_DETECTED report
// before the process tears down.
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE b32 ad_anti_breakin_install_with_target(void* target_fn) {
#ifdef _MSC_VER
    static b32 s_installed_ex = 0;
    if (s_installed_ex) return 1;
    if (!target_fn) return 0;

    void* breakin = ad_resolve_api(AD_HASH_NTDLL, ad_hash_dbgui_remote_breakin());
    if (!breakin) return 0;

    static u16 s_ssn = AD_SSN_UNRESOLVED;
    AD_RESOLVE_SSN_ENC(s_ssn, NtProtectVirtualMemory, 23);
    if (s_ssn == AD_SSN_FAILED) return 0;

    u8 stub[17];
    stub[ 0] = 0xB9; stub[ 1] = 0x01; stub[ 2] = 0x00;
    stub[ 3] = 0x00; stub[ 4] = 0x00;
    stub[ 5] = 0x48; stub[ 6] = 0xB8;
    u64 abs = (u64)target_fn;
    stub[ 7] = (u8)( abs        & 0xFFu);
    stub[ 8] = (u8)((abs >>  8) & 0xFFu);
    stub[ 9] = (u8)((abs >> 16) & 0xFFu);
    stub[10] = (u8)((abs >> 24) & 0xFFu);
    stub[11] = (u8)((abs >> 32) & 0xFFu);
    stub[12] = (u8)((abs >> 40) & 0xFFu);
    stub[13] = (u8)((abs >> 48) & 0xFFu);
    stub[14] = (u8)((abs >> 56) & 0xFFu);
    stub[15] = 0xFF; stub[16] = 0xE0;

    void* addr  = breakin;
    u64   size  = (u64)sizeof(stub);
    u32   old   = 0;
    ad_ntstatus_t st = (ad_ntstatus_t)(s64)AD_SYSCALL5(
        s_ssn, AD_CURRENT_PROCESS, &addr, &size,
        (u64)AD_PAGE_EXECUTE_READWRITE, &old);
    if (!AD_NT_SUCCESS(st)) return 0;

    {
        volatile u8* dst = (volatile u8*)breakin;
        unsigned i;
        for (i = 0; i < sizeof(stub); i++) dst[i] = stub[i];
    }

    addr  = breakin;
    size  = (u64)sizeof(stub);
    u32 dummy = 0;
    (void)AD_SYSCALL5(
        s_ssn, AD_CURRENT_PROCESS, &addr, &size,
        (u64)AD_PAGE_EXECUTE_READ, &dummy);

    s_installed_ex = 1;
    return 1;
#else
    (void)target_fn;
    return 0;
#endif
}

// ---------------------------------------------------------------------------
// Verify trampoline integrity. Returns 1 if the first byte is no longer
// 0xB9 (someone — likely ScyllaHide unpatch or x64dbg "restore code" — has
// reverted the patch). Run periodically alongside other checks.
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE b32 ad_anti_breakin_verify(void) {
#ifdef _MSC_VER
    void* breakin = ad_resolve_api(AD_HASH_NTDLL, ad_hash_dbgui_remote_breakin());
    if (!breakin) return 0;
    return (b32)(*(volatile u8*)breakin != 0xB9u);
#else
    return 0;
#endif
}

#endif // ANTIDEBUG_ANTI_BREAKIN_H
