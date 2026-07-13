// ===== file: antidebug/core/veh_dispatch.h =====
//
// VEH-based indirect function dispatch.
//
// Static CFG recovery (IDA, Ghidra, BinaryNinja) relies on being able to
// resolve `call <imm32>` and `call [mem]` instructions to their targets.
// This header replaces a conventional CALL with an `int3` instruction:
//
//     (normal)         call ad_noise_swarm_start
//     (this header)    AD_VEH_CALL(SLOT_NOISE_SWARM_START);
//                          → mov  [rel g_pending], MAGIC | SLOT
//                            int3
//
// A high-priority Vectored Exception Handler receives the breakpoint,
// decrypts the target function pointer from an indexed table, simulates
// a CALL by pushing the after-int3 address onto the stack, and sets RIP
// to the target. Target executes, returns via its own `ret`, which pops
// the address we pushed — control resumes after the macro.
//
// What the reverser sees
// ----------------------
//   * The caller's static disassembly contains `int3` at the dispatch
//     point, not a CALL. There is no cross-reference to the target.
//   * The target function has no inbound XREF from this call site.
//   * Resolving requires reading the encrypted table AND the per-slot
//     key AND the magic / slot computation — or single-stepping under a
//     debugger whose presence the rest of the framework detects.
//
// Scope
// -----
// This dispatcher supports no-argument `void (void)` functions only. The
// caller sets up no register arguments before the int3, and the target
// reads none. This covers all the "install" and "regenerate" side-effect
// functions in the project — enough to hide a meaningful slice of the
// control flow from static analysis.
//
// Safety
// ------
// The handler only dispatches when `g_veh_disp_pending` carries the
// AD_VEH_DISP_MAGIC tag. Any stray int3 elsewhere (from another handler,
// from a user's debugger, from anti-debug trap logic) sees `pending == 0`
// and falls through via EXCEPTION_CONTINUE_SEARCH.
//
// Thread safety: single-threaded by design. All uses wrap an install or
// a dispatch that is naturally serialised. A future multi-thread use
// would need a TLS slot or per-call ticketing.
//
#ifndef ANTIDEBUG_VEH_DISPATCH_H
#define ANTIDEBUG_VEH_DISPATCH_H

#include "types.h"
#include "macros.h"
#include "api_hash.h"

#ifdef _MSC_VER

// ---------------------------------------------------------------------------
// Table sizing — up to 32 distinct slots. Expand if more dispatchable
// functions are needed.
// ---------------------------------------------------------------------------
#define AD_VEH_DISP_SLOTS   32u
#define AD_VEH_DISP_MAGIC   0xBADC0DE0u
#define AD_VEH_DISP_MASK    0x0000001Fu   // low 5 bits = slot index

// ---------------------------------------------------------------------------
// Minimal CONTEXT layout — we need Rip (0xF8) and Rsp (0x98).
// ---------------------------------------------------------------------------
#ifndef AD_VEH_CONTEXT_DISP_DEFINED
#define AD_VEH_CONTEXT_DISP_DEFINED
typedef struct AD_VEH_CTX_DISP {
    u8   _pad0[0x98];
    u64  Rsp;
    u8   _pad1[0xF8 - 0x98 - 8];
    u64  Rip;
} AD_VEH_CTX_DISP;
#endif

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
#endif

#ifndef AD_EXCEPTION_BREAKPOINT_CODE
#define AD_EXCEPTION_BREAKPOINT_CODE   0x80000003u
#endif

// ---------------------------------------------------------------------------
// Encrypted table. Populated at init by `ad_veh_disp_register`.
// ---------------------------------------------------------------------------
#ifndef AD_VEH_DISP_STORAGE_DEFINED
#define AD_VEH_DISP_STORAGE_DEFINED
volatile u64 ad_veh_disp_table[AD_VEH_DISP_SLOTS] = {0};
volatile u64 ad_veh_disp_keys [AD_VEH_DISP_SLOTS] = {0};
volatile u32 ad_veh_disp_pending = 0u;
volatile u32 ad_veh_disp_count   = 0u;   // number of dispatches performed
void*        ad_veh_disp_handle  = 0;
#endif

typedef void (*ad_veh_disp_fn_t)(void);

// ---------------------------------------------------------------------------
// Register a no-arg function at a given slot. Must be called once before
// any AD_VEH_CALL(slot).
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE void ad_veh_disp_register(u32 slot, ad_veh_disp_fn_t fn) {
    if (slot >= AD_VEH_DISP_SLOTS) return;
    u64 k = (u64)__rdtsc() ^ ((u64)slot * 0x9E3779B97F4A7C15ULL);
    if (k == 0ULL) k = 0xA5A5A5A5A5A5A5A5ULL;
    ad_veh_disp_table[slot] = (u64)(uintptr_t)fn ^ k;
    ad_veh_disp_keys [slot] = k;
}

// ---------------------------------------------------------------------------
// The dispatch handler. Runs when an int3 fires. Checks the MAGIC tag in
// g_pending; if present, reads the slot, decrypts the target, and
// invokes it synchronously from inside the handler. Control returns
// through the kernel to just past the int3 when the handler returns
// EXCEPTION_CONTINUE_EXECUTION.
//
// Invoking the target here (instead of rewriting Rsp/Rip to simulate a
// user-mode CALL) keeps the stack frame intact and avoids the shadow-
// space overlap that a hand-rolled CALL simulation would cause. Static
// CFG recovery still sees no xref from the caller to the target — the
// call lives inside the exception handler, reached only by raising a
// breakpoint the static tool cannot predict.
// ---------------------------------------------------------------------------
static long ad_veh_disp_handler(AD_EXC_POINTERS* p) {
    if (!p || !p->ExceptionRecord || !p->ContextRecord) return 0;
    if (p->ExceptionRecord->ExceptionCode != AD_EXCEPTION_BREAKPOINT_CODE) return 0;

    u32 pending = ad_veh_disp_pending;
    if ((pending & 0xFFFFFFE0u) != AD_VEH_DISP_MAGIC) return 0;  // not ours

    u32 slot = pending & AD_VEH_DISP_MASK;
    u64 enc  = ad_veh_disp_table[slot];
    u64 key  = ad_veh_disp_keys [slot];
    u64 target = enc ^ key;
    if (target == 0ULL) return 0;  // slot empty, not ours

    ad_veh_disp_pending = 0u;

    // Invoke the target synchronously. Its stack frame nests inside the
    // handler's frame, the kernel restores everything for us afterward.
    ((ad_veh_disp_fn_t)(uintptr_t)target)();
    ad_veh_disp_count += 1u;

    AD_VEH_CTX_DISP* ctx = (AD_VEH_CTX_DISP*)p->ContextRecord;
    // Step past the 0xCC byte so resumption doesn't re-trigger this
    // handler on the same int3.
    ctx->Rip += 1ULL;
    return -1; // EXCEPTION_CONTINUE_EXECUTION
}

// ---------------------------------------------------------------------------
// Stack-built hash for RtlAddVectoredExceptionHandler.
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE u32 ad_veh_disp_hash_add(void) {
    char b[33];
    b[ 0]='R'; b[ 1]='t'; b[ 2]='l'; b[ 3]='A'; b[ 4]='d';
    b[ 5]='d'; b[ 6]='V'; b[ 7]='e'; b[ 8]='c'; b[ 9]='t';
    b[10]='o'; b[11]='r'; b[12]='e'; b[13]='d'; b[14]='E';
    b[15]='x'; b[16]='c'; b[17]='e'; b[18]='p'; b[19]='t';
    b[20]='i'; b[21]='o'; b[22]='n'; b[23]='H'; b[24]='a';
    b[25]='n'; b[26]='d'; b[27]='l'; b[28]='e'; b[29]='r';
    b[30]=0;
    return ad_hash_str(b);
}

typedef long (*ad_veh_disp_handler_t)(AD_EXC_POINTERS*);
typedef void* (*ad_veh_disp_fn_rtl_add_t)(u32 first, ad_veh_disp_handler_t handler);

// ---------------------------------------------------------------------------
// Install the handler at head of the VEH chain.
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE b32 ad_veh_disp_install(void) {
    if (ad_veh_disp_handle) return 1;
    ad_veh_disp_fn_rtl_add_t pAdd = (ad_veh_disp_fn_rtl_add_t)
        ad_resolve_api(AD_HASH_NTDLL, ad_veh_disp_hash_add());
    if (!pAdd) return 0;
    ad_veh_disp_handle = pAdd(1u, &ad_veh_disp_handler);
    return (b32)(ad_veh_disp_handle != 0);
}

// ---------------------------------------------------------------------------
// The dispatch macro. Sets the pending slot tag, then int3.
//
// Usage:
//    AD_VEH_CALL(SLOT_SOMETHING);
//
// WARNING: only use with void(*)(void) targets registered via
// ad_veh_disp_register. The target is called with no arguments and its
// return value is discarded.
// ---------------------------------------------------------------------------
#define AD_VEH_CALL(slot)                                                       \
    do {                                                                        \
        ad_veh_disp_pending =                                                   \
            AD_VEH_DISP_MAGIC | ((u32)(slot) & AD_VEH_DISP_MASK);               \
        __debugbreak();                                                         \
    } while(0)

// ---------------------------------------------------------------------------
// Project-specific slot IDs. Add new ones as needed; keep < 32.
// ---------------------------------------------------------------------------
#define AD_VEH_SLOT_NOISE_SWARM_START   0u
#define AD_VEH_SLOT_POLY_REGENERATE     1u
#define AD_VEH_SLOT_PAGE_GUARD_ARM      2u
#define AD_VEH_SLOT_ANTI_ATTACH         3u
#define AD_VEH_SLOT_DROP_SE_DEBUG       4u

#else  // !_MSC_VER
ANTIDEBUG_INLINE b32  ad_veh_disp_install(void) { return 0; }
ANTIDEBUG_INLINE void ad_veh_disp_register(u32 s, void* f) { (void)s; (void)f; }
#define AD_VEH_CALL(slot) ((void)(slot))
#endif // _MSC_VER

#endif // ANTIDEBUG_VEH_DISPATCH_H
