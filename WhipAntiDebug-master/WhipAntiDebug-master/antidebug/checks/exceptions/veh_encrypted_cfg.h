// ===== file: antidebug/checks/exceptions/veh_encrypted_cfg.h =====
//
// VEH-encrypted control flow.
//
// Idea
// ----
// We declare a "compute" function whose body is just a sequence of
// __debugbreak() (int3) instructions followed by a return. The function
// looks like dead air to a static disassembler — every instruction is
// 0xCC, the function literally cannot execute as-written.
//
// At init we install a high-priority Vectored Exception Handler that
// recognises the BP addresses inside our compute function and rebuilds
// the real semantics on the fly:
//
//   1. The handler is invoked with EXCEPTION_BREAKPOINT and a context
//      whose RIP points at the int3 byte.
//   2. The handler reads PEB.BeingDebugged + PEB.NtGlobalFlag and folds
//      them into a 32-bit "environment key".
//   3. The handler XORs that key into a designated register (Rax),
//      advances RIP by 1, and returns EXCEPTION_CONTINUE_EXECUTION.
//
// In a CLEAN environment, BeingDebugged = 0 and NtGlobalFlag is benign,
// so the environment key is exactly zero. Each int3 contributes 0 to
// Rax and the function returns its initial value unchanged.
//
// With a debugger attached, BeingDebugged becomes 1 and/or NtGlobalFlag
// shows the typical 0x70 / 0x40000000 markers. The environment key is
// non-zero, so each int3 corrupts Rax. The function's return value is
// wrong, the flag's score derivation is wrong, the decryption produces
// garbage.
//
// What the reverser sees in the disassembly
// -----------------------------------------
//   ad_veh_cfg_compute proc:
//       int3
//       int3
//       int3
//       int3
//       ret
//
// They cannot infer the semantics from the bytes. To understand it they
// must single-step into the VEH handler — which itself reads PEB fields
// the moment they single-step, so any debugger they use to study the
// handler will also feed PEB.BeingDebugged = 1 to the handler and the
// behaviour they observe is the corrupted path, not the clean one.
//
// Even better: if they bypass the handler entirely (e.g. NOP all int3s
// or replace the function body), the function returns its initial value
// unchanged, which IS the correct clean-environment value. So the
// reverser thinks they bypassed the protection — until ad_veh_cfg_verify
// runs and checks that ad_veh_cfg_dispatched > 0, which it never can be
// without our handler having executed.
//
#ifndef ANTIDEBUG_VEH_ENCRYPTED_CFG_H
#define ANTIDEBUG_VEH_ENCRYPTED_CFG_H

#include "../../core/types.h"
#include "../../core/macros.h"
#include "../../core/api_hash.h"

#ifdef _MSC_VER

// Minimal CONTEXT layout for x64. We only need to touch Rip and Rax.
// Field offsets are stable across all Win10/11 builds.
//   Rax  -> 0x78
//   Rip  -> 0xF8
typedef struct AD_VEH_CONTEXT_MINIMAL {
    u8 _pad[0xF8];
    u64 Rip;
} AD_VEH_CONTEXT_MIN;

// Re-use the AD_EXCEPTION_POINTERS / AD_EXCEPTION_RECORD definitions from
// veh_decoy.h when present, otherwise define a local copy.
#ifndef AD_EXCEPTION_RECORD_DEFINED
#define AD_EXCEPTION_RECORD_DEFINED
typedef struct {
    u32  ExceptionCode;
    u32  ExceptionFlags;
    void* ExceptionRecord;
    void* ExceptionAddress;
    u32  NumberParameters;
    u32  _pad;
    u64  ExceptionInformation[15];
} AD_EXC_RECORD;

typedef struct {
    AD_EXC_RECORD* ExceptionRecord;
    void*          ContextRecord;
} AD_EXC_POINTERS;
#else
typedef AD_EXCEPTION_RECORD   AD_EXC_RECORD;
typedef AD_EXCEPTION_POINTERS AD_EXC_POINTERS;
#endif

#define AD_EXCEPTION_BREAKPOINT_CODE   0x80000003u

// Storage guard so multiple includes do not multiply symbols.
#ifndef AD_VEH_CFG_STORAGE_DEFINED
#define AD_VEH_CFG_STORAGE_DEFINED
volatile u32 ad_veh_cfg_dispatched = 0;
volatile u32 ad_veh_cfg_acc        = 0;  // accumulator built by the int3 dispatch
volatile u32 ad_veh_cfg_step       = 0;  // index of the int3 we're about to dispatch
const  u8*   ad_veh_cfg_protect_lo = 0;
const  u8*   ad_veh_cfg_protect_hi = 0;
void*        ad_veh_cfg_handle     = 0;
// Constants xor'd into the accumulator, one per int3. They are chosen so
// the running XOR over the entire table is exactly zero — clean env.
//   0xA5 ^ 0x5A = 0xFF
//   0x77 ^ 0x88 = 0xFF
//   0xFF ^ 0xFF = 0x00
// In a debugger the env_key is non-zero and corrupts each contribution,
// so the final accumulator value is non-zero.
static const u8 ad_veh_cfg_xor_table[4] = { 0xA5u, 0x5Au, 0x77u, 0x88u };
#endif

// Stack-built API hashes (no plaintext in .rdata).
ANTIDEBUG_INLINE u32 ad_veh_cfg_hash_add(void) {
    char b[33];
    b[ 0]='R'; b[ 1]='t'; b[ 2]='l'; b[ 3]='A'; b[ 4]='d';
    b[ 5]='d'; b[ 6]='V'; b[ 7]='e'; b[ 8]='c'; b[ 9]='t';
    b[10]='o'; b[11]='r'; b[12]='e'; b[13]='d'; b[14]='E';
    b[15]='x'; b[16]='c'; b[17]='e'; b[18]='p'; b[19]='t';
    b[20]='i'; b[21]='o'; b[22]='n'; b[23]='H'; b[24]='a';
    b[25]='n'; b[26]='d'; b[27]='l'; b[28]='e'; b[29]='r';
    b[30]=0;  // 30-char ASCII length
    return ad_hash_str(b);
}

typedef long (*ad_veh_handler_t)(AD_EXC_POINTERS*);
typedef void* (*ad_fn_rtl_add_veh_t)(u32 first, ad_veh_handler_t handler);

// Compute the environment key. Reads PEB at the moment the handler runs.
// In clean env both fields are zero so the key is zero.
ANTIDEBUG_INLINE u32 ad_veh_cfg_env_key(void) {
    u8* peb = (u8*)__readgsqword(0x60);
    if (!peb) return 0;
    u8  bd  = peb[0x02];                  // BeingDebugged
    u32 ngf = *(u32*)(peb + 0xBC);        // NtGlobalFlag
    return ((u32)bd * 0x9E3779B9u) ^ ngf;
}

// Vectored handler. We claim only EXCEPTION_BREAKPOINT inside our
// protected RIP range; everything else falls through.
//
// Real semantic op: each int3 in the protected function contributes one
// constant from ad_veh_cfg_xor_table, XOR'd into the env_key, into the
// running accumulator. In clean env the env_key is zero, so the four
// constants XOR to exactly zero and ad_veh_cfg_acc returns to its
// initial value. In a debugger the env_key is non-zero, every byte of
// the accumulator is corrupted, the function returns garbage, and any
// downstream consumer that uses the return value (e.g. a flag-key
// derivation) produces garbage.
static long ad_veh_cfg_handler(AD_EXC_POINTERS* p) {
    if (!p || !p->ExceptionRecord || !p->ContextRecord) {
        return 0; // EXCEPTION_CONTINUE_SEARCH
    }
    if (p->ExceptionRecord->ExceptionCode != AD_EXCEPTION_BREAKPOINT_CODE) {
        return 0;
    }

    AD_VEH_CONTEXT_MIN* ctx = (AD_VEH_CONTEXT_MIN*)p->ContextRecord;
    const u8* rip = (const u8*)(uintptr_t)ctx->Rip;

    if (rip < ad_veh_cfg_protect_lo || rip >= ad_veh_cfg_protect_hi) {
        return 0; // not ours
    }

    u32 key  = ad_veh_cfg_env_key();
    u32 step = ad_veh_cfg_step;
    if (step < 4u) {
        u32 contribution = (u32)ad_veh_cfg_xor_table[step] ^ key;
        ad_veh_cfg_acc  ^= contribution;
        ad_veh_cfg_step  = step + 1u;
    }
    ad_veh_cfg_dispatched += 1u;

    // Advance past the 0xCC byte (1 byte wide) and resume.
    ctx->Rip += 1;
    return -1; // EXCEPTION_CONTINUE_EXECUTION
}

// The protected function. Body = 4 int3s + ret. The compiler does not
// know what these int3s "mean"; only our VEH does.
//
// Returns the accumulator after dispatch:
//   - 0 in clean env (the four xor table entries cancel out)
//   - non-zero with a debugger attached (env_key corrupts contributions)
//   - 0 with EVERY int3 NOPed by a reverser (because the accumulator
//     is reset to 0 at entry and never touched) — caught by the dispatched
//     counter, which stays at 0 in that case.
__declspec(noinline)
static u32 ad_veh_cfg_compute(void) {
    ad_veh_cfg_step = 0u;
    ad_veh_cfg_acc  = 0u;
    __debugbreak();
    __debugbreak();
    __debugbreak();
    __debugbreak();
    return ad_veh_cfg_acc;
}

// Install the handler and capture the protected RIP range.
ANTIDEBUG_INLINE b32 ad_veh_cfg_install(void) {
    if (ad_veh_cfg_handle) return 1;

    ad_fn_rtl_add_veh_t pAdd = (ad_fn_rtl_add_veh_t)
        ad_resolve_api(AD_HASH_NTDLL, ad_veh_cfg_hash_add());
    if (!pAdd) return 0;

    // Capture a generous range around the function pointer. The compiler
    // emits a small prologue, the four int3s, and a small epilogue/ret;
    // 64 bytes is plenty. We use the function pointer as the centre.
    const u8* fn = (const u8*)(uintptr_t)&ad_veh_cfg_compute;
    ad_veh_cfg_protect_lo = fn;
    ad_veh_cfg_protect_hi = fn + 64u;

    // First = 1 → install at the head of the VEH chain so we run before
    // any other handlers a debugger might have inserted.
    ad_veh_cfg_handle = pAdd(1u, &ad_veh_cfg_handler);
    return (b32)(ad_veh_cfg_handle != 0);
}

// Run the protected function and check both the dispatched counter and
// the accumulator. Returns 1 if any anomaly is detected:
//
//   - dispatched delta != 4 → at least one int3 was skipped
//     (debugger consumed it, body was patched, etc.)
//   - acc != 0              → handler ran but env_key was non-zero
//     (debugger attached, NtGlobalFlag dirty)
//
// In addition to returning the trip flag, ad_veh_cfg_compute() can be
// called directly by downstream code that wants to fold the accumulator
// into a key derivation. The clean-env return value is exactly 0, so
// any consumer can XOR it into a known value without changing the
// outcome — UNTIL a debugger flips one bit.
ANTIDEBUG_INLINE b32 ad_veh_cfg_verify(void) {
    if (!ad_veh_cfg_handle) return 0;  // not installed → cannot conclude

    u32 before = ad_veh_cfg_dispatched;
    u32 acc    = ad_veh_cfg_compute();
    u32 after  = ad_veh_cfg_dispatched;

    if ((after - before) != 4u) return 1;
    if (acc != 0u)               return 1;
    return 0;
}

// Direct accumulator accessor — re-runs compute() and returns the value.
// Downstream code can call this and XOR the result into a key byte; in
// clean env it changes nothing, in a debugged env it corrupts the key.
ANTIDEBUG_INLINE u32 ad_veh_cfg_run(void) {
    if (!ad_veh_cfg_handle) return 0xDEADBEEFu;  // not installed → poison
    return ad_veh_cfg_compute();
}

#else
ANTIDEBUG_INLINE b32 ad_veh_cfg_install(void) { return 0; }
ANTIDEBUG_INLINE b32 ad_veh_cfg_verify(void)  { return 0; }
#endif

#endif // ANTIDEBUG_VEH_ENCRYPTED_CFG_H
