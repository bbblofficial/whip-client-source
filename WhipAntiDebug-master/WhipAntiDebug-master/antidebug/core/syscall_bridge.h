// ===== file: antidebug/core/syscall_bridge.h =====
//
// C-facing interface to WhipSysCall.
// The implementation lives in antidebug/syscall_bridge.cpp (the only C++ file).
// Include this header from pure-C translation units.
//
#ifndef ANTIDEBUG_SYSCALL_BRIDGE_H
#define ANTIDEBUG_SYSCALL_BRIDGE_H

#include "types.h"

#ifdef __cplusplus
extern "C" {
#endif

// ---------------------------------------------------------------------------
// Bridge lifetime
// ---------------------------------------------------------------------------

// Initialize the WhipSysCall resolver. Must be called once before any
// check that uses syscalls. Returns 1 on success, 0 on failure.
int whip_bridge_init(void);

// Resolve a NT function by name → System Service Number.
// Returns 0xFFFF if resolution fails (function not found or optimized out).
// Results are cached inside WhipSysCall's resolver; repeated calls are cheap.
u16 whip_bridge_resolve(const char* name);

// ---------------------------------------------------------------------------
// Raw syscall stub (from SyscallStub.asm — extern "C" in WhipSysCall)
// On x64 there is only one calling convention; __stdcall is a no-op.
//
// SyscallStub argument mapping (see SyscallStub.asm):
//   ssn  → EAX  (syscall number)
//   a1   → RCX  (syscall arg 1)
//   a2   → RDX  (syscall arg 2)
//   a3   → R8   (syscall arg 3)
//   a4   → R9   (syscall arg 4)
//   a5…a11 → stack (syscall args 5–11)
// ---------------------------------------------------------------------------
ad_ntstatus_t SyscallStub(
    u16   ssn,
    void* a1,  void* a2,  void* a3,  void* a4,
    void* a5,  void* a6,  void* a7,  void* a8,
    void* a9,  void* a10, void* a11
);

#ifdef __cplusplus
}
#endif

// ---------------------------------------------------------------------------
// Inline SSN resolution with per-call-site caching
//
// Usage:
//   static u16 s_ssn = AD_SSN_UNRESOLVED;
//   AD_RESOLVE_SSN(s_ssn, "NtQueryInformationProcess");
//   if (s_ssn == AD_SSN_FAILED) return 0;
// ---------------------------------------------------------------------------
#define AD_SSN_UNRESOLVED   ((u16)0xFFFF)
#define AD_SSN_FAILED       ((u16)0xFFFF)

#define AD_RESOLVE_SSN(var, name)               \
    do {                                        \
        if ((var) == AD_SSN_UNRESOLVED) {       \
            (var) = whip_bridge_resolve(name);  \
        }                                       \
    } while (0)

// ---------------------------------------------------------------------------
// Typed syscall call-site macros
// All non-pointer args should be cast to u64 before passing (e.g. (u64)7).
// The macro casts them to void* as required by SyscallStub.
// ---------------------------------------------------------------------------
#define AD_SYSCALL0(ssn) \
    SyscallStub((ssn), \
        (void*)0,(void*)0,(void*)0,(void*)0, \
        (void*)0,(void*)0,(void*)0,(void*)0, \
        (void*)0,(void*)0,(void*)0)

#define AD_SYSCALL1(ssn,a1) \
    SyscallStub((ssn), \
        (void*)(a1),(void*)0,(void*)0,(void*)0, \
        (void*)0,(void*)0,(void*)0,(void*)0, \
        (void*)0,(void*)0,(void*)0)

#define AD_SYSCALL2(ssn,a1,a2) \
    SyscallStub((ssn), \
        (void*)(a1),(void*)(a2),(void*)0,(void*)0, \
        (void*)0,(void*)0,(void*)0,(void*)0, \
        (void*)0,(void*)0,(void*)0)

#define AD_SYSCALL3(ssn,a1,a2,a3) \
    SyscallStub((ssn), \
        (void*)(a1),(void*)(a2),(void*)(a3),(void*)0, \
        (void*)0,(void*)0,(void*)0,(void*)0, \
        (void*)0,(void*)0,(void*)0)

#define AD_SYSCALL4(ssn,a1,a2,a3,a4) \
    SyscallStub((ssn), \
        (void*)(a1),(void*)(a2),(void*)(a3),(void*)(a4), \
        (void*)0,(void*)0,(void*)0,(void*)0, \
        (void*)0,(void*)0,(void*)0)

#define AD_SYSCALL5(ssn,a1,a2,a3,a4,a5) \
    SyscallStub((ssn), \
        (void*)(a1),(void*)(a2),(void*)(a3),(void*)(a4), \
        (void*)(a5),(void*)0,(void*)0,(void*)0, \
        (void*)0,(void*)0,(void*)0)

#define AD_SYSCALL6(ssn,a1,a2,a3,a4,a5,a6) \
    SyscallStub((ssn), \
        (void*)(a1),(void*)(a2),(void*)(a3),(void*)(a4), \
        (void*)(a5),(void*)(a6),(void*)0,(void*)0, \
        (void*)0,(void*)0,(void*)0)

#endif // ANTIDEBUG_SYSCALL_BRIDGE_H
