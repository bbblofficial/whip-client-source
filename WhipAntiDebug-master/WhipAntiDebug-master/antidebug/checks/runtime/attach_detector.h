// ===== file: antidebug/checks/runtime/attach_detector.h =====
//
// Live attach detector — instant trip on debugger attach.
//
// A dedicated background thread polls the four indicators that are kernel-
// authoritative and 0-FP even inside noisy hosts (Java/JVM, Office, browsers):
//
//   bit 0x1  PEB.BeingDebugged                  set by user-mode attach
//   bit 0x2  ProcessDebugPort != 0              kernel-set port handle
//   bit 0x4  ProcessDebugObjectHandle != NULL   kernel-set debug object
//   bit 0x8  ProcessDebugFlags flipped to 1     NoDebugInherit overridden
//
// JDWP / Wireshark / EDR hooks DO NOT set these — only an actual ring-3
// debugger attach via DebugActiveProcess does. The watchdog cycles every
// 25-100 ms (PRNG-jittered) so detection latency is bounded by one period.
//
// ad_attach_check_now() is also exported for synchronous one-shot polling
// from the supplemental pipeline.
//
#ifndef ANTIDEBUG_ATTACH_DETECTOR_H
#define ANTIDEBUG_ATTACH_DETECTOR_H

#include "../../core/types.h"
#include "../../core/macros.h"
#include "../../core/syscall_bridge.h"
#include "../../core/string_encrypt.h"
#include "../../core/strenc_extra.h"
#include "../debug/peb.h"
#include "../threads/hide_thread.h"
#include <stdio.h>

#ifdef _MSC_VER

#ifndef AD_AD_MIN_INTERVAL_MS
#define AD_AD_MIN_INTERVAL_MS   25u
#endif
#ifndef AD_AD_MAX_INTERVAL_MS
#define AD_AD_MAX_INTERVAL_MS   100u
#endif

// Reason bits returned by ad_attach_check_now().
#define AD_ATTACH_REASON_PEB_BD      0x1u
#define AD_ATTACH_REASON_DBG_PORT    0x2u
#define AD_ATTACH_REASON_DBG_OBJECT  0x4u
#define AD_ATTACH_REASON_FLAGS_FLIP  0x8u

typedef struct {
    volatile u32 detected;       // OR-ed reason mask (0 = clean)
    volatile u32 running;
    volatile u32 stopped;
    volatile u64 cycles;         // bumped each pass — heartbeat
    u64          prng_state;
    u32          check_flags_flip;  // 1 = also check ProcessDebugFlags flip
} ad_attach_ctx_t;

__declspec(dllimport) void* __stdcall CreateThread(void*, u64, void*, void*, unsigned long, unsigned long*);
__declspec(dllimport) void  __stdcall Sleep(unsigned long ms);
__declspec(dllimport) void  __stdcall RtlExitUserProcess(unsigned long);

ANTIDEBUG_INLINE u64 ad_ad_xs(u64* s) {
    u64 x = *s;
    x ^= x << 13; x ^= x >> 7; x ^= x << 17;
    *s = x;
    return x;
}

// One-shot synchronous poll. Returns OR-ed reason bits (0 = clean).
// `check_flags_flip` should be 1 only if the caller has actually installed
// ad_anti_attach_set_no_inherit() — otherwise bit 0x8 false-positives on
// any process that didn't set NoDebugInherit (i.e., almost all of them).
ANTIDEBUG_INLINE u32 ad_attach_check_now(u32 check_flags_flip) {
    u32 mask = 0u;

    // 1) PEB.BeingDebugged — direct GS read, no syscall
    if (ad_peb_ptr()[0x02] != 0u) mask |= AD_ATTACH_REASON_PEB_BD;

    // 2) ProcessDebugPort
    {
        static u16 s_qi = AD_SSN_UNRESOLVED;
        AD_RESOLVE_SSN_ENC(s_qi, NtQueryInformationProcess, 26);
        if (s_qi != AD_SSN_FAILED) {
            u64 port = 0;
            u32 ret  = 0;
            ad_ntstatus_t st = (ad_ntstatus_t)(s64)AD_SYSCALL5(
                s_qi,
                AD_CURRENT_PROCESS,
                (u64)AD_PROCESS_DEBUG_PORT,
                &port,
                (u64)sizeof(port),
                &ret
            );
            if (AD_NT_SUCCESS(st) && port != 0ULL)
                mask |= AD_ATTACH_REASON_DBG_PORT;
        }
    }

    // 3) ProcessDebugObjectHandle
    {
        static u16 s_qi2 = AD_SSN_UNRESOLVED;
        AD_RESOLVE_SSN_ENC(s_qi2, NtQueryInformationProcess, 26);
        if (s_qi2 != AD_SSN_FAILED) {
            u64 dbgobj = 0;
            u32 ret    = 0;
            ad_ntstatus_t st = (ad_ntstatus_t)(s64)AD_SYSCALL5(
                s_qi2,
                AD_CURRENT_PROCESS,
                (u64)AD_PROCESS_DEBUG_OBJECT_HANDLE,
                &dbgobj,
                (u64)sizeof(dbgobj),
                &ret
            );
            if (AD_NT_SUCCESS(st) && dbgobj != 0ULL)
                mask |= AD_ATTACH_REASON_DBG_OBJECT;
        }
    }

    // 4) ProcessDebugFlags flipped — only valid after NoDebugInherit install
    if (check_flags_flip) {
        static u16 s_qi3 = AD_SSN_UNRESOLVED;
        AD_RESOLVE_SSN_ENC(s_qi3, NtQueryInformationProcess, 26);
        if (s_qi3 != AD_SSN_FAILED) {
            u32 flags = 0;
            u32 ret   = 0;
            ad_ntstatus_t st = (ad_ntstatus_t)(s64)AD_SYSCALL5(
                s_qi3,
                AD_CURRENT_PROCESS,
                (u64)AD_PROCESS_DEBUG_FLAGS,
                &flags,
                (u64)sizeof(flags),
                &ret
            );
            if (AD_NT_SUCCESS(st) && flags != 0u)
                mask |= AD_ATTACH_REASON_FLAGS_FLIP;
        }
    }

    return mask;
}

// Background thread: poll loop with PRNG jitter.
// Latches the first detection into ctx->detected and keeps cycling so the
// heartbeat (ctx->cycles) never freezes from the watcher's side.
static unsigned long __stdcall ad_attach_thread(void* param) {
    ad_attach_ctx_t* ctx = (ad_attach_ctx_t*)param;
    if (!ctx) return 1;

    // Self-hide. If a debugger is already attached at this exact moment,
    // the kernel raises an exception that terminates the process — which
    // is itself the desired outcome.
    (void)ad_hide_thread();

    while (ctx->running) {
        u64 r = ad_ad_xs(&ctx->prng_state);
        u32 span = AD_AD_MAX_INTERVAL_MS - AD_AD_MIN_INTERVAL_MS;
        u32 ms = AD_AD_MIN_INTERVAL_MS + (u32)(r % span);
        Sleep(ms);

        u32 reason = ad_attach_check_now(ctx->check_flags_flip);
        if (reason != 0u) {
            // Latch (OR-merge — preserve first reason if multiple cycles trip).
            ctx->detected |= reason;
        }
        ctx->cycles++;

        // Heartbeat trace — independent of forwarder. Every 64 cycles ≈ ~4-6s.
        if ((ctx->cycles & 0x3F) == 0) {
            FILE* hb = fopen("attach_watchdog_hb.log", "a");
            if (hb) {
                fprintf(hb, "cycles=%llu detected=0x%X\n",
                        (unsigned long long)ctx->cycles, ctx->detected);
                fclose(hb);
            }
        }
    }

    ctx->stopped = 1u;
    return 0;
}

// Start the watchdog. `check_flags_flip` should be 1 only if you've called
// ad_anti_attach_set_no_inherit() prior to this. Returns 1 on success.
ANTIDEBUG_INLINE b32 ad_attach_detector_start(ad_attach_ctx_t* ctx, u32 check_flags_flip) {
    if (!ctx) return 0;
    u32 k;
    for (k = 0; k < (u32)sizeof(*ctx); k++) ((volatile u8*)ctx)[k] = 0;

    ctx->running          = 1u;
    ctx->prng_state       = __rdtsc() ^ 0xA5A5DEADC0DECAFEULL;
    ctx->check_flags_flip = check_flags_flip ? 1u : 0u;

    unsigned long tid = 0;
    void* th = CreateThread((void*)0, 0ULL,
                            (void*)ad_attach_thread, (void*)ctx,
                            0u, &tid);
    return (b32)(th != (void*)0);
}

ANTIDEBUG_INLINE void ad_attach_detector_stop(ad_attach_ctx_t* ctx) {
    if (!ctx) return;
    ctx->running = 0u;
}

// Non-blocking read — returns the latched reason mask (0 = no attach seen).
ANTIDEBUG_INLINE u32 ad_attach_was_detected(const ad_attach_ctx_t* ctx) {
    return ctx ? ctx->detected : 0u;
}

#else  // !_MSC_VER
typedef struct { u32 _u; } ad_attach_ctx_t;
ANTIDEBUG_INLINE u32  ad_attach_check_now(u32 f)                     { (void)f; return 0; }
ANTIDEBUG_INLINE b32  ad_attach_detector_start(ad_attach_ctx_t* c, u32 f) { (void)c; (void)f; return 0; }
ANTIDEBUG_INLINE void ad_attach_detector_stop(ad_attach_ctx_t* c)    { (void)c; }
ANTIDEBUG_INLINE u32  ad_attach_was_detected(const ad_attach_ctx_t* c) { (void)c; return 0; }
#endif // _MSC_VER

#endif // ANTIDEBUG_ATTACH_DETECTOR_H
