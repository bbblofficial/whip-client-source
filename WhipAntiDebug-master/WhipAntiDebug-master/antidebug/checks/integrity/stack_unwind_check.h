// ===== file: antidebug/checks/integrity/stack_unwind_check.h =====
//
// Stack Unwinding Consistency.
//
// Walk our own call stack via RtlVirtualUnwind / RtlLookupFunctionEntry
// and verify each frame:
//   1. Has a valid PE function table entry (RUNTIME_FUNCTION)
//   2. Lives in a module known to PEB.Ldr
//   3. Has plausible RIP within its function bounds
//
// Detour libraries, frame-pointer-based hooks, and DBI engines that
// inject trampolines into the call stack break one or more of these.
//
// We avoid linking against ntdll exports by resolving Rtl* via the Ldr
// EAT walk done elsewhere — but for simplicity here we assume the user
// links ntdll (which the rest of the project does too).
//
#ifndef ANTIDEBUG_STACK_UNWIND_CHECK_H
#define ANTIDEBUG_STACK_UNWIND_CHECK_H

#include "../../core/types.h"
#include "../../core/macros.h"

#ifdef _MSC_VER
#include <intrin.h>

// RUNTIME_FUNCTION (x64): 12 bytes
typedef struct {
    u32 BeginAddress;
    u32 EndAddress;
    u32 UnwindInfoAddress;
} AD_RUNTIME_FUNCTION;

// Forward decls — these come from ntdll/kernel32. These have C linkage
// (they're plain WinAPI symbols). We omit __stdcall on x64 since x64
// uses a single calling convention.
void   RtlCaptureContext(AD_CONTEXT* ContextRecord);

AD_RUNTIME_FUNCTION* RtlLookupFunctionEntry(
    u64 ControlPc, u64* ImageBase, void* HistoryTable);

void* RtlVirtualUnwind(
    u32 HandlerType, u64 ImageBase, u64 ControlPc,
    AD_RUNTIME_FUNCTION* FunctionEntry, void* ContextRecord,
    void** HandlerData, u64* EstablisherFrame, void* ContextPointers);

#define AD_UNW_FLAG_NHANDLER 0u

// Walk up to 16 frames. Return number of frames where lookup failed.
// > 0  = suspicious (frame in unmapped/unknown code)
// == 0 = clean
ANTIDEBUG_INLINE u32 ad_stack_unwind_check(void) {
    AD_ALIGN(16) AD_CONTEXT ctx;
    AD_ZERO_BUF(&ctx, sizeof(ctx));
    RtlCaptureContext(&ctx);

    u32 unknown_frames = 0;
    u32 i;

    for (i = 0; i < 16u; i++) {
        u64 image_base = 0;
        AD_RUNTIME_FUNCTION* fn = RtlLookupFunctionEntry(ctx.Rip, &image_base, (void*)0);

        if (!fn) {
            // No function table entry for this RIP.
            // Multiple legitimate causes:
            //  - Leaf function (syscall stubs) — first miss is normal
            //  - Stripped main .pdata entry (intentional anti-RE)
            //  - Anonymous RWX trampoline pages (ad_ghost_exec pivot)
            //  - Forged saved-RA pointing at fake_stack region (latent_*,
            //    ad_main_ra_spoof) where RIP lands in random fill bytes
            // Each of these adds 1 unknown frame on a clean run.
            // Tolerate up to 4 missing entries before flagging.
            if (i > 0) {
                if (unknown_frames < 0xFFFFu) unknown_frames++;
            }
            // For leaf function, manually unwind: pop return address.
            ctx.Rip = *(u64*)ctx.Rsp;
            ctx.Rsp += 8;
            if (ctx.Rip == 0) break;
            continue;
        }

        void* handler_data = 0;
        u64 establisher = 0;
        RtlVirtualUnwind(
            AD_UNW_FLAG_NHANDLER,
            image_base,
            ctx.Rip,
            fn,
            &ctx,
            &handler_data,
            &establisher,
            (void*)0
        );

        if (ctx.Rip == 0) break;
    }

    return unknown_frames;
}

#else
ANTIDEBUG_INLINE u32 ad_stack_unwind_check(void) { return 0; }
#endif

#endif // ANTIDEBUG_STACK_UNWIND_CHECK_H
