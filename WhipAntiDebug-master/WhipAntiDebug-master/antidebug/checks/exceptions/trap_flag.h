// ===== file: antidebug/checks/exceptions/trap_flag.h =====
//
// EFLAGS Trap Flag (TF) single-step detection.
//
// The x86/x64 Trap Flag (EFLAGS bit 8) causes the CPU to raise
// EXCEPTION_SINGLE_STEP (0x80000004) after executing exactly one instruction.
// This mechanism is used by debuggers to step through code one instruction
// at a time.
//
// Detection principle:
//   Set TF via __writeeflags, wrap in __try/__except. If the
//   EXCEPTION_SINGLE_STEP reaches our SEH handler → no interference.
//   If a tool intercepts or silently swallows the single-step exception before
//   it reaches our handler → s_tf_caught remains 0 → suspicious.
//
// Reliability notes:
//   - x64dbg with default settings passes EXCEPTION_SINGLE_STEP to the
//     application, so this check returns 0 (clean) under a standard x64dbg session.
//   - It fires against tools that silently consume single-step exceptions:
//     some sandboxes, certain DBIE frameworks, and some ScyllaHide configurations.
//   - Weight is intentionally low (4) — it is most useful in combination with
//     other checks rather than as a standalone detector.
//
// Second check — TF in exception CONTEXT:
//   Set TF, trigger a div-by-zero, verify TF is CLEARED in the delivered
//   exception CONTEXT (normal Windows behavior: kernel clears TF on exception
//   delivery). If TF is still SET in the CONTEXT, a hypervisor or emulator
//   improperly forwarded the CPU state without clearing TF.
//
#ifndef ANTIDEBUG_TRAP_FLAG_H
#define ANTIDEBUG_TRAP_FLAG_H

#include "../../core/types.h"
#include "../../core/macros.h"
#include "../../core/config.h"

#if defined(_MSC_VER)

// Reuse SEH helpers from anti_scyllahide.h if already included
#ifndef EXCEPTION_EXECUTE_HANDLER
#define EXCEPTION_EXECUTE_HANDLER      1
#define EXCEPTION_CONTINUE_SEARCH      0
#define EXCEPTION_CONTINUE_EXECUTION (-1)
#endif
#ifndef GetExceptionInformation
void* __cdecl _exception_info(void);
#define GetExceptionInformation() (_exception_info())
#endif
#ifndef GetExceptionCode
unsigned long __cdecl _exception_code(void);
#define GetExceptionCode() ((int)_exception_code())
#endif

#define AD_EXCEPTION_SINGLE_STEP   0x80000004UL
#define AD_EFLAGS_TRAP_FLAG        0x00000100UL   // bit 8

// Shared with ad_sh_dr_exception_clear if included — guarded
typedef struct { void* ExRec; AD_CONTEXT* Ctx; } AD_TF_EXCPTRS;

static volatile b32 s_tf_single_step_caught = 0;

// ---------------------------------------------------------------------------
// Check 1: EXCEPTION_SINGLE_STEP reaches our handler
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE b32 ad_trap_flag_single_step(void) {
    s_tf_single_step_caught = 0;
    AD_BARRIER();

    __try {
        // Set the Trap Flag — the VERY NEXT instruction will raise SINGLE_STEP
        __writeeflags(__readeflags() | (u64)AD_EFLAGS_TRAP_FLAG);
        // Volatile read ensures the compiler emits at least one instruction
        // between popfq and the end of the __try block
        volatile u32 dummy = 0;
        (void)dummy;
    }
    __except (
        GetExceptionCode() == (int)AD_EXCEPTION_SINGLE_STEP
            ? EXCEPTION_EXECUTE_HANDLER
            : EXCEPTION_CONTINUE_SEARCH
    ) {
        s_tf_single_step_caught = 1;
    }

    AD_BARRIER();
    // Normal behavior: handler fires (caught = 1) → return 0 (clean)
    // Suspicious:      handler did not fire (caught = 0) → return 1 (detected)
    return (b32)(s_tf_single_step_caught == 0);
}

// ---------------------------------------------------------------------------
// Check 2: TF preserved in exception CONTEXT (hypervisor / emulator anomaly)
//
// Normal: kernel clears EFLAGS.TF before delivering exception to user mode.
// Abnormal (emulator bug): TF bit still set in ContextRecord->EFlags.
// ---------------------------------------------------------------------------
static volatile u32 s_tf_eflags_in_ctx = 0u;

ANTIDEBUG_INLINE b32 ad_trap_flag_context_leak(void) {
    s_tf_eflags_in_ctx = 0u;
    AD_BARRIER();

    __try {
        __writeeflags(__readeflags() | (u64)AD_EFLAGS_TRAP_FLAG);
        volatile u32 dummy = 0;
        (void)dummy;
    }
    __except (
        (s_tf_eflags_in_ctx =
            (u32)((AD_TF_EXCPTRS*)GetExceptionInformation())->Ctx->EFlags,
         EXCEPTION_EXECUTE_HANDLER)
    ) {
        (void)0;
    }

    AD_BARRIER();
    // TF should be 0 in delivered CONTEXT.  If still 1 → emulator/hypervisor bug.
    return (b32)((s_tf_eflags_in_ctx & AD_EFLAGS_TRAP_FLAG) != 0u);
}

#else
ANTIDEBUG_INLINE b32 ad_trap_flag_single_step(void)  { return 0; }
ANTIDEBUG_INLINE b32 ad_trap_flag_context_leak(void) { return 0; }
#endif // _MSC_VER

#endif // ANTIDEBUG_TRAP_FLAG_H