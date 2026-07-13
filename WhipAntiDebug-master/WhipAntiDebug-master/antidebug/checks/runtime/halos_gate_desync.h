// ===== file: antidebug/checks/runtime/halos_gate_desync.h =====
//
// Halo's Gate desynchronisation hook detector.
//
// Idea
// ----
// We resolve the SSN of NtClose two different ways:
//
//   1. Direct: pull the syscall number from a fresh ntdll!NtClose stub
//      using the existing whip_bridge_resolve() (Halo's Gate logic in
//      WhipSysCall, which extracts the SSN by parsing the stub bytes).
//
//   2. Indirect: take the function pointer from PEB→Ldr→ntdll exports via
//      api_hash, cast it to a fn_pointer, and CALL it through the stub.
//
// We then invoke NtClose(INVALID_HANDLE_VALUE) twice — once via our direct
// SyscallStub (bypasses any user-mode hook), once via the resolved stub
// pointer (goes through whatever ntdll bytes currently look like).
//
// In a clean environment both calls return STATUS_INVALID_HANDLE
// (0xC0000008). If a debugger / EDR / ScyllaHide / Frida has placed a
// user-mode hook on ntdll!NtClose, the indirect call will be intercepted:
//   - the hook returns STATUS_SUCCESS or some sanitised status,
//   - or it routes through a trampoline that mutates rcx,
//   - or it reads the stack and skips the syscall entirely.
//
// In any of those cases, status_indirect != status_direct → hook detected.
//
// Why this is painful to bypass
// -----------------------------
// To bypass it, the reverser must hook NtClose so that the *indirect*
// path also returns exactly STATUS_INVALID_HANDLE for the
// INVALID_HANDLE_VALUE input — which is the one input most existing
// hooks intercept first (because they treat invalid handles as a flag
// for "this is a probe, hide our presence"). Many ScyllaHide profiles
// fail this immediately.
//
#ifndef ANTIDEBUG_HALOS_GATE_DESYNC_H
#define ANTIDEBUG_HALOS_GATE_DESYNC_H

#include "../../core/types.h"
#include "../../core/macros.h"
#include "../../core/api_hash.h"
#include "../../core/syscall_bridge.h"
#include "../../core/string_encrypt.h"
#include "../../core/strenc_extra.h"

#ifndef AD_STATUS_INVALID_HANDLE
#define AD_STATUS_INVALID_HANDLE ((ad_ntstatus_t)0xC0000008L)
#endif

// "NtClose" stack-built FNV-1a hash
ANTIDEBUG_INLINE u32 ad_hash_nt_close(void) {
    char b[8];
    b[0]='N'; b[1]='t'; b[2]='C'; b[3]='l';
    b[4]='o'; b[5]='s'; b[6]='e'; b[7]=0;
    return ad_hash_str(b);
}

// "NtClose" string-encrypt for the SSN resolver
#ifndef AD_STRENC_NtClose
#define AD_STRENC_NtClose(buf)                                               \
    do {                                                                     \
        const u8 _k = AD_STR_KEY(0x4B);                                     \
        char buf##_e[8];                                                     \
        AD_ENC(buf##_e,  0, 'N', _k); AD_ENC(buf##_e,  1, 't', _k);       \
        AD_ENC(buf##_e,  2, 'C', _k); AD_ENC(buf##_e,  3, 'l', _k);       \
        AD_ENC(buf##_e,  4, 'o', _k); AD_ENC(buf##_e,  5, 's', _k);       \
        AD_ENC(buf##_e,  6, 'e', _k);                                       \
        AD_DECODE_BUF(buf##_e, 7, _k);                                      \
        for (unsigned _ci = 0; _ci < 8; _ci++) (buf)[_ci] = buf##_e[_ci];   \
    } while (0)
#endif

typedef ad_ntstatus_t (*ad_fn_nt_close_t)(void* handle);
typedef ad_ntstatus_t (*ad_fn_nt_qip_t)(void* p, u32 ic, void* buf, u32 len, u32* rl);
typedef ad_ntstatus_t (*ad_fn_nt_qsi_t)(u32 ic, void* buf, u32 len, u32* rl);
typedef ad_ntstatus_t (*ad_fn_nt_sit_t)(void* t, u32 ic, void* buf, u32 len);

// ---------------------------------------------------------------------------
// Stack-built API hashes for the additional syscalls
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE u32 ad_hash_nt_qip(void) {
    char b[26];
    b[ 0]='N'; b[ 1]='t'; b[ 2]='Q'; b[ 3]='u'; b[ 4]='e';
    b[ 5]='r'; b[ 6]='y'; b[ 7]='I'; b[ 8]='n'; b[ 9]='f';
    b[10]='o'; b[11]='r'; b[12]='m'; b[13]='a'; b[14]='t';
    b[15]='i'; b[16]='o'; b[17]='n'; b[18]='P'; b[19]='r';
    b[20]='o'; b[21]='c'; b[22]='e'; b[23]='s'; b[24]='s';
    b[25]=0;
    return ad_hash_str(b);
}
ANTIDEBUG_INLINE u32 ad_hash_nt_qsi(void) {
    char b[25];
    b[ 0]='N'; b[ 1]='t'; b[ 2]='Q'; b[ 3]='u'; b[ 4]='e';
    b[ 5]='r'; b[ 6]='y'; b[ 7]='S'; b[ 8]='y'; b[ 9]='s';
    b[10]='t'; b[11]='e'; b[12]='m'; b[13]='I'; b[14]='n';
    b[15]='f'; b[16]='o'; b[17]='r'; b[18]='m'; b[19]='a';
    b[20]='t'; b[21]='i'; b[22]='o'; b[23]='n'; b[24]=0;
    return ad_hash_str(b);
}
ANTIDEBUG_INLINE u32 ad_hash_nt_sit(void) {
    char b[24];
    b[ 0]='N'; b[ 1]='t'; b[ 2]='S'; b[ 3]='e'; b[ 4]='t';
    b[ 5]='I'; b[ 6]='n'; b[ 7]='f'; b[ 8]='o'; b[ 9]='r';
    b[10]='m'; b[11]='a'; b[12]='t'; b[13]='i'; b[14]='o';
    b[15]='n'; b[16]='T'; b[17]='h'; b[18]='r'; b[19]='e';
    b[20]='a'; b[21]='d'; b[22]=0;
    return ad_hash_str(b);
}

// ---------------------------------------------------------------------------
// Single-syscall NtClose probe (kept for backward compatibility).
//
// Returns 1 if NtClose direct vs indirect NTSTATUS disagreed.
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE b32 ad_halos_gate_desync(void) {
#ifdef _MSC_VER
    static u16 s_ssn = AD_SSN_UNRESOLVED;
    AD_RESOLVE_SSN_ENC(s_ssn, NtClose, 8);
    if (s_ssn == AD_SSN_FAILED) return 0;

    void* indirect_fn = ad_resolve_api(AD_HASH_NTDLL, ad_hash_nt_close());
    if (!indirect_fn) return 0;

    void* bad_handle = (void*)(uintptr_t)0xDEADBEEFCAFEBABEULL;

    ad_ntstatus_t st_direct   = (ad_ntstatus_t)(s64)AD_SYSCALL1(s_ssn, bad_handle);
    ad_fn_nt_close_t fn = (ad_fn_nt_close_t)indirect_fn;
    ad_ntstatus_t st_indirect = fn(bad_handle);

    return (b32)(st_direct != st_indirect);
#else
    return 0;
#endif
}

// ---------------------------------------------------------------------------
// Multi-syscall sweep.
//
// Probes four ntdll syscalls that EDRs / ScyllaHide / Frida / x64dbg
// hide-from-debugger plugins commonly hook:
//
//   1. NtClose                       — already covered above
//   2. NtQueryInformationProcess     — debug-port / debug-flags lies
//   3. NtQuerySystemInformation      — KernelDebugger info hiding
//   4. NtSetInformationThread        — ThreadHideFromDebugger swallowing
//
// For each syscall we call it twice with deliberately invalid arguments:
// once via the direct WhipSysCall stub (kernel sees the call as-is),
// once via the resolved ntdll stub bytes (any user-mode hook intercepts).
// We then compare the NTSTATUS pair. Disagreement on any of the four
// counts as a hook detection.
//
// The return value is the bit-mask of which syscalls disagreed:
//   bit 0 = NtClose
//   bit 1 = NtQueryInformationProcess
//   bit 2 = NtQuerySystemInformation
//   bit 3 = NtSetInformationThread
//
// Use ad_halos_gate_multi_count() if you only need a yes/no, or fold
// the bitmask into the score directly so the contribution scales with
// how many hooks are present.
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE u32 ad_halos_gate_multi(void) {
#ifdef _MSC_VER
    u32 mask = 0u;

    // ---- 1. NtClose ----
    {
        static u16 s = AD_SSN_UNRESOLVED;
        AD_RESOLVE_SSN_ENC(s, NtClose, 8);
        void* fn = ad_resolve_api(AD_HASH_NTDLL, ad_hash_nt_close());
        if (s != AD_SSN_FAILED && fn) {
            void* bh = (void*)(uintptr_t)0xDEADBEEFCAFEBABEULL;
            ad_ntstatus_t a = (ad_ntstatus_t)(s64)AD_SYSCALL1(s, bh);
            ad_ntstatus_t b = ((ad_fn_nt_close_t)fn)(bh);
            if (a != b) mask |= 1u;
        }
    }

    // ---- 2. NtQueryInformationProcess ----
    {
        static u16 s = AD_SSN_UNRESOLVED;
        AD_RESOLVE_SSN_ENC(s, NtQueryInformationProcess, 26);
        void* fn = ad_resolve_api(AD_HASH_NTDLL, ad_hash_nt_qip());
        if (s != AD_SSN_FAILED && fn) {
            void* bp = (void*)(uintptr_t)0x1A2B3C4D5E6F7081ULL;
            u8  buf[16] = {0};
            u32 rl = 0;
            ad_ntstatus_t a = (ad_ntstatus_t)(s64)AD_SYSCALL5(
                s, bp, (u64)0x9999u, buf, (u64)sizeof(buf), &rl);
            ad_ntstatus_t b = ((ad_fn_nt_qip_t)fn)(
                bp, 0x9999u, buf, sizeof(buf), &rl);
            if (a != b) mask |= 2u;
        }
    }

    // ---- 3. NtQuerySystemInformation ----
    {
        static u16 s = AD_SSN_UNRESOLVED;
        AD_RESOLVE_SSN_ENC(s, NtQuerySystemInformation, 25);
        void* fn = ad_resolve_api(AD_HASH_NTDLL, ad_hash_nt_qsi());
        if (s != AD_SSN_FAILED && fn) {
            u8  buf[16] = {0};
            u32 rl = 0;
            // 0x9998 is not a defined SYSTEM_INFORMATION_CLASS — kernel
            // returns STATUS_INVALID_INFO_CLASS on both paths in clean env.
            ad_ntstatus_t a = (ad_ntstatus_t)(s64)AD_SYSCALL4(
                s, (u64)0x9998u, buf, (u64)sizeof(buf), &rl);
            ad_ntstatus_t b = ((ad_fn_nt_qsi_t)fn)(
                0x9998u, buf, sizeof(buf), &rl);
            if (a != b) mask |= 4u;
        }
    }

    // ---- 4. NtSetInformationThread ----
    {
        static u16 s = AD_SSN_UNRESOLVED;
        AD_RESOLVE_SSN_ENC(s, NtSetInformationThread, 23);
        void* fn = ad_resolve_api(AD_HASH_NTDLL, ad_hash_nt_sit());
        if (s != AD_SSN_FAILED && fn) {
            void* bt = (void*)(uintptr_t)0xCAFEBABEDEADBEEFULL;
            u8  buf[8] = {0};
            ad_ntstatus_t a = (ad_ntstatus_t)(s64)AD_SYSCALL4(
                s, bt, (u64)0x9997u, buf, (u64)sizeof(buf));
            ad_ntstatus_t b = ((ad_fn_nt_sit_t)fn)(
                bt, 0x9997u, buf, sizeof(buf));
            if (a != b) mask |= 8u;
        }
    }

    return mask;
#else
    return 0u;
#endif
}

// Convenience: number of syscalls that disagreed (popcount of the mask).
ANTIDEBUG_INLINE u32 ad_halos_gate_multi_count(void) {
    u32 m = ad_halos_gate_multi();
    u32 c = 0;
    while (m) { c += (m & 1u); m >>= 1; }
    return c;
}

#endif // ANTIDEBUG_HALOS_GATE_DESYNC_H
