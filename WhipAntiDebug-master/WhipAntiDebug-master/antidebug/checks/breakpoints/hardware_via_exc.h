// ===== file: antidebug/checks/breakpoints/hardware_via_exc.h =====
//
// ⚠️  DISABLED — DOES NOT WORK ON WINDOWS 10/11  ⚠️
// ────────────────────────────────────────────────────────────────────────
//  Empirical test (2026-04-19) proved that although the delivered CONTEXT
//  carries CONTEXT_DEBUG_REGISTERS in ContextFlags (CF=0x10005f observed
//  for STATUS_BREAKPOINT), the Dr0..Dr7 fields arrive ZEROED to user-mode
//  SEH/VEH handlers on Win10/11 even when DR registers are actively armed
//  in hardware. This is a kernel-side mitigation against DR leakage via
//  exception context. The classical NtGetContextThread path returned 1
//  (saw real DR values) during the same test, confirming the filtering
//  happens specifically in the exception-delivery path.
//
//  This file is kept for documentation; the public entry points are
//  stubbed below so the code compiles but always returns "clean".
//  Revisit if a newer Windows build changes this behavior, or pivot to
//  a cross-thread / kernel-driver approach.
// ────────────────────────────────────────────────────────────────────────
//
// Hardware-breakpoint detection via EXCEPTION_POINTERS — ScyllaHide bypass.
//
// The classical anti-HWBP check (breakpoints/hardware.h) calls
// NtGetContextThread and reads DR0-DR7. ScyllaHide, TitanHide, x64dbgHide
// and every modern DR-stealth plugin hook that syscall at the user-mode
// entry and return zeroed debug registers. Check neutralised.
//
// This file takes a different path. We deliberately raise an access
// violation and read the debug registers out of
//
//     EXCEPTION_POINTERS->ContextRecord->Dr0..Dr7
//
// That CONTEXT is built by the kernel in `KiDispatchException` from the
// thread's saved trap state, then handed to `KiUserExceptionDispatcher`
// in user-mode, which walks the VEH chain and finally delivers to our
// __except filter. ScyllaHide hooks user-mode API surfaces
// (NtGetContextThread, NtQueryInformationThread, …); it does NOT hook
// KiUserExceptionDispatcher. The DR values we observe here are the real
// values armed by the debugger.
//
// Additional capability: we can also LOCATE the HWBP — the DR0..DR3 we
// read are the exact linear addresses the debugger is watching. If any
// of them fall inside our own image, the reverser has placed a HW exec
// breakpoint on one of our functions; we can feed that address into
// latent-tamper logic or simply report it.
//
// Works on Windows 7 / 8 / 10 / 11. No CPU feature required.
//
#ifndef ANTIDEBUG_HARDWARE_VIA_EXC_H
#define ANTIDEBUG_HARDWARE_VIA_EXC_H

#include "../../core/types.h"
#include "../../core/macros.h"

#ifdef _MSC_VER

#ifndef EXCEPTION_EXECUTE_HANDLER
#define EXCEPTION_EXECUTE_HANDLER      1
#define EXCEPTION_CONTINUE_SEARCH      0
#define EXCEPTION_CONTINUE_EXECUTION (-1)
#endif
#ifndef GetExceptionInformation
void* __cdecl _exception_info(void);
#define GetExceptionInformation() (_exception_info())
#endif

// Minimal EXCEPTION_POINTERS shape — ContextRecord matches AD_CONTEXT from
// core/types.h so all DR fields are at the expected offsets.
typedef struct {
    void*       ExceptionRecord;
    AD_CONTEXT* ContextRecord;
} AD_HWE_POINTERS;

typedef struct {
    b32 detected;      // 1 if any DR armed
    u64 dr0, dr1, dr2, dr3, dr7;
    u32 enable_bits;   // low byte of DR7 (L0/G0/L1/G1/L2/G2/L3/G3)
    u32 ctx_flags;     // ContextRecord->ContextFlags at delivery
    u32 exc_code;      // ExceptionCode at delivery
} ad_hwe_result_t;

// Minimal EXCEPTION_RECORD shape — we need ExceptionCode at offset 0.
typedef struct {
    u32   ExceptionCode;
    u32   ExceptionFlags;
    void* ExceptionRecord;
    void* ExceptionAddress;
    u32   NumberParameters;
    u32   _pad;
    u64   ExceptionInformation[15];
} AD_HWE_EXC_RECORD;

// Stub returning 0 — see disabled warning at top of file.
ANTIDEBUG_INLINE b32 ad_hardware_bp_via_exception_stub(void) { return 0; }
ANTIDEBUG_INLINE void ad_hardware_bp_via_exception_ex_stub(ad_hwe_result_t* out) {
    if (out) {
        out->dr0 = out->dr1 = out->dr2 = out->dr3 = out->dr7 = 0;
        out->enable_bits = 0; out->ctx_flags = 0; out->exc_code = 0;
        out->detected = 0;
    }
}

#if 0  // original implementation — kept for documentation
ANTIDEBUG_INLINE b32 ad_hardware_bp_via_exception_original(void) {
    volatile u64 d0 = 0, d1 = 0, d2 = 0, d3 = 0, d7 = 0;

    __try {
        __debugbreak();   // raises STATUS_BREAKPOINT (0x80000003) — a debug
                          // exception, so the kernel includes DR registers
                          // in the delivered CONTEXT.
    }
    __except (
        (d0 = ((AD_HWE_POINTERS*)GetExceptionInformation())->ContextRecord->Dr0,
         d1 = ((AD_HWE_POINTERS*)GetExceptionInformation())->ContextRecord->Dr1,
         d2 = ((AD_HWE_POINTERS*)GetExceptionInformation())->ContextRecord->Dr2,
         d3 = ((AD_HWE_POINTERS*)GetExceptionInformation())->ContextRecord->Dr3,
         d7 = ((AD_HWE_POINTERS*)GetExceptionInformation())->ContextRecord->Dr7,
         EXCEPTION_EXECUTE_HANDLER)
    ) {
        (void)0;
    }

    if ((d0 | d1 | d2 | d3) != 0ULL) return 1;
    if ((d7 & 0xFFULL) != 0ULL)       return 1;
    return 0;
}

ANTIDEBUG_INLINE void ad_hardware_bp_via_exception_ex(ad_hwe_result_t* out) {
    volatile u64 d0 = 0, d1 = 0, d2 = 0, d3 = 0, d7 = 0;
    volatile u32 cf = 0, ec = 0;

    __try {
        __debugbreak();
    }
    __except (
        (ec = ((AD_HWE_EXC_RECORD*)((AD_HWE_POINTERS*)GetExceptionInformation())->ExceptionRecord)->ExceptionCode,
         cf = ((AD_HWE_POINTERS*)GetExceptionInformation())->ContextRecord->ContextFlags,
         d0 = ((AD_HWE_POINTERS*)GetExceptionInformation())->ContextRecord->Dr0,
         d1 = ((AD_HWE_POINTERS*)GetExceptionInformation())->ContextRecord->Dr1,
         d2 = ((AD_HWE_POINTERS*)GetExceptionInformation())->ContextRecord->Dr2,
         d3 = ((AD_HWE_POINTERS*)GetExceptionInformation())->ContextRecord->Dr3,
         d7 = ((AD_HWE_POINTERS*)GetExceptionInformation())->ContextRecord->Dr7,
         EXCEPTION_EXECUTE_HANDLER)
    ) {
        (void)0;
    }

    out->dr0 = d0; out->dr1 = d1; out->dr2 = d2; out->dr3 = d3; out->dr7 = d7;
    out->enable_bits = (u32)(d7 & 0xFFULL);
    out->ctx_flags = (u32)cf;
    out->exc_code  = (u32)ec;
    out->detected = (b32)(((d0 | d1 | d2 | d3) != 0ULL) || (out->enable_bits != 0u));
}
#endif  // 0 — disabled original implementation

// Public stubs wired to the "always clean" path.
#define ad_hardware_bp_via_exception    ad_hardware_bp_via_exception_stub
#define ad_hardware_bp_via_exception_ex ad_hardware_bp_via_exception_ex_stub

#else  // !_MSC_VER
ANTIDEBUG_INLINE b32 ad_hardware_bp_via_exception(void) { return 0; }
#endif // _MSC_VER

#endif // ANTIDEBUG_HARDWARE_VIA_EXC_H
