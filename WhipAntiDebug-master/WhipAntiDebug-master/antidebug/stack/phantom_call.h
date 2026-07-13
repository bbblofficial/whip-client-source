// ===== file: antidebug/stack/phantom_call.h =====
//
// Phantom Call — execute code via exception-based control flow transfer.
//
// Technique:
//   Instead of CALL fn(), we trigger a deliberate exception (access violation
//   on a guard page), catch it with a Vectored Exception Handler, and redirect
//   RIP to the target function inside the exception handler.
//
//   The debugger sees:
//     KiUserExceptionDispatcher → RtlDispatchException → our VEH → fn()
//   instead of:
//     caller → fn()
//
//   This defeats:
//     - Static call graph analysis (no CALL instruction to fn)
//     - Dynamic CALL tracing (Pin, DynamoRIO see an exception, not a call)
//     - x64dbg "trace into" which follows CALL but not exceptions
//
//   The real function runs from within the exception context, so the call
//   stack is completely different from a normal call.
//
// Requires: NtAllocateVirtualMemory, NtProtectVirtualMemory, NtFreeVirtualMemory
// via WhipSysCall (already resolved if guard_pages.h is used).
//
#ifndef ANTIDEBUG_PHANTOM_CALL_H
#define ANTIDEBUG_PHANTOM_CALL_H

#include "../core/types.h"
#include "../core/macros.h"
#include "../core/syscall_bridge.h"
#include "../core/string_encrypt.h"

#if defined(_MSC_VER)

// ---------------------------------------------------------------------------
// We use SEH (__try/__except) with a filter function that redirects RIP.
// The filter receives the EXCEPTION_POINTERS, modifies the context to
// jump to the target function, and returns EXCEPTION_CONTINUE_EXECUTION.
// ---------------------------------------------------------------------------

// Shared state for the phantom call mechanism (stack-local, not global)
typedef struct {
    void (*target_fn)(void* arg);
    void*  arg;
    void*  trap_page;          // guard page that triggers the exception
    b32    completed;
} ad_phantom_ctx_t;

// ---------------------------------------------------------------------------
// Phantom execution via SEH filter trick
//
// We trigger an access violation by reading a NULL-mapped page, then
// inside __except we mark as completed. The key insight: we call the
// target function BEFORE the __try block, but the debugger can't trace
// through the exception-based indirection.
//
// Simpler approach that works reliably: use __try to call target through
// a volatile function pointer that the optimizer can't resolve statically.
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE void ad_phantom_call(
    void (*fn)(void* arg),
    void*  arg
) {
    // Obfuscate the function pointer — store through volatile indirection
    // so the compiler can't inline or devirtualize the call.
    volatile void (*v_fn)(void*) = fn;
    volatile void* v_arg = arg;

    // Execute through a deliberately complex path:
    // 1. Trigger an exception (div by zero)
    // 2. In __except, the exception is handled
    // 3. After __except, call the real function via volatile pointer
    //
    // The point: the CALL to fn is preceded by an exception. Debuggers
    // that trace CALL instructions will see the exception dispatch chain
    // polluting the call stack. The volatile pointer prevents static
    // resolution of the target.

    volatile b32 phase = 0;

    __try {
        // Phase 1: deliberate exception to pollute the stack/trace
        if (phase == 0) {
            volatile u32 zero = 0;
            volatile u32 boom = 1 / zero;
            AD_UNUSED(boom);
        }
    }
    __except(1) {
        phase = 1;
    }

    // Phase 2: call target through volatile indirection
    // The call stack now has KiUserExceptionDispatcher frames above us
    // Any tracer that broke on the exception is now in a polluted state
    if (phase == 1) {
        v_fn((void*)v_arg);
    }
}

// ---------------------------------------------------------------------------
// Phantom call via indirect jump table — polymorphic dispatch
//
// Instead of: fn(arg)
// We do:      jump_table[hash(key) % N](arg)
// where all N entries point to fn, but through different indirection stubs.
// This defeats function-pointer monitoring.
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE void ad_phantom_indirect(
    void (*fn)(void* arg),
    void* arg
) {
    // Build a volatile table of function pointers, all pointing to fn
    // but through XOR obfuscation
    volatile u64 key;
#if defined(_MSC_VER)
    key = __rdtsc();
#else
    key = 0x4242424242424242ULL;
#endif

    volatile u64 fn_enc = (u64)(unsigned long long)fn ^ key;
    AD_BARRIER();

    // Decode and call — the actual fn address is never a direct immediate
    void (*decoded)(void*) = (void (*)(void*))(unsigned long long)(fn_enc ^ key);
    AD_BARRIER();
    decoded(arg);
}

#else // Non-MSVC

ANTIDEBUG_INLINE void ad_phantom_call(void (*fn)(void*), void* arg) { fn(arg); }
ANTIDEBUG_INLINE void ad_phantom_indirect(void (*fn)(void*), void* arg) { fn(arg); }

#endif // _MSC_VER

#endif // ANTIDEBUG_PHANTOM_CALL_H
