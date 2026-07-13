// ===== file: antidebug/checks/advanced/scheduler_sync.h =====
//
// Multi-Thread Scheduler Synchronization Detection.
// Spawns a worker thread that increments a shared counter while the main
// thread samples it. Under normal scheduling, the counter progresses
// smoothly. Under a debugger single-stepping the main thread, the worker
// runs freely (counter jumps wildly) or is frozen (counter stuck).
//
#ifndef ANTIDEBUG_SCHEDULER_SYNC_H
#define ANTIDEBUG_SCHEDULER_SYNC_H

#include "../../core/types.h"
#include "../../core/macros.h"
#include "../../core/syscall_bridge.h"
#include "../../core/string_encrypt.h"

// "NtCreateThreadEx" (17 chars). Guarded — strenc_extra.h also defines it.
#ifndef AD_STRENC_NtCreateThreadEx
#define AD_STRENC_NtCreateThreadEx(buf)                                      \
    do {                                                                     \
        const u8 _k = AD_STR_KEY(0x49);                                     \
        char buf##_e[18];                                                    \
        AD_ENC(buf##_e,  0, 'N', _k); AD_ENC(buf##_e,  1, 't', _k);       \
        AD_ENC(buf##_e,  2, 'C', _k); AD_ENC(buf##_e,  3, 'r', _k);       \
        AD_ENC(buf##_e,  4, 'e', _k); AD_ENC(buf##_e,  5, 'a', _k);       \
        AD_ENC(buf##_e,  6, 't', _k); AD_ENC(buf##_e,  7, 'e', _k);       \
        AD_ENC(buf##_e,  8, 'T', _k); AD_ENC(buf##_e,  9, 'h', _k);       \
        AD_ENC(buf##_e, 10, 'r', _k); AD_ENC(buf##_e, 11, 'e', _k);       \
        AD_ENC(buf##_e, 12, 'a', _k); AD_ENC(buf##_e, 13, 'd', _k);       \
        AD_ENC(buf##_e, 14, 'E', _k); AD_ENC(buf##_e, 15, 'x', _k);       \
        AD_ENC(buf##_e, 16, '\0', _k);                                      \
        AD_DECODE_BUF(buf##_e, 16, _k);                                     \
        for (unsigned _ci = 0; _ci < 17; _ci++) (buf)[_ci] = buf##_e[_ci];  \
    } while (0)
#endif // AD_STRENC_NtCreateThreadEx

// "NtWaitForSingleObject" (21 chars)
#define AD_STRENC_NtWaitForSingleObject(buf)                                 \
    do {                                                                     \
        const u8 _k = AD_STR_KEY(0x5D);                                     \
        char buf##_e[22];                                                    \
        AD_ENC(buf##_e,  0, 'N', _k); AD_ENC(buf##_e,  1, 't', _k);       \
        AD_ENC(buf##_e,  2, 'W', _k); AD_ENC(buf##_e,  3, 'a', _k);       \
        AD_ENC(buf##_e,  4, 'i', _k); AD_ENC(buf##_e,  5, 't', _k);       \
        AD_ENC(buf##_e,  6, 'F', _k); AD_ENC(buf##_e,  7, 'o', _k);       \
        AD_ENC(buf##_e,  8, 'r', _k); AD_ENC(buf##_e,  9, 'S', _k);       \
        AD_ENC(buf##_e, 10, 'i', _k); AD_ENC(buf##_e, 11, 'n', _k);       \
        AD_ENC(buf##_e, 12, 'g', _k); AD_ENC(buf##_e, 13, 'l', _k);       \
        AD_ENC(buf##_e, 14, 'e', _k); AD_ENC(buf##_e, 15, 'O', _k);       \
        AD_ENC(buf##_e, 16, 'b', _k); AD_ENC(buf##_e, 17, 'j', _k);       \
        AD_ENC(buf##_e, 18, 'e', _k); AD_ENC(buf##_e, 19, 'c', _k);       \
        AD_ENC(buf##_e, 20, 't', _k);                                       \
        AD_DECODE_BUF(buf##_e, 21, _k);                                     \
        for (unsigned _ci = 0; _ci < 22; _ci++) (buf)[_ci] = buf##_e[_ci];  \
    } while (0)

// Shared data between main and worker thread
typedef struct {
    volatile u64 counter;
    volatile u32 stop;
} ad_sched_shared_t;

// Worker function — runs in separate thread, increments counter
static unsigned long __stdcall ad_sched_worker_fn(void* param) {
    ad_sched_shared_t* shared = (ad_sched_shared_t*)param;
    while (!shared->stop) {
        shared->counter++;
        // Yield occasionally to let scheduler interleave
        if ((shared->counter & 0xFFFu) == 0) {
            volatile u32 spin = 0;
            while (spin < 10u) spin++;
        }
    }
    return 0;
}

// ---------------------------------------------------------------------------
// Scheduler sync check
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE b32 ad_scheduler_sync_check(void) {
#ifdef _MSC_VER
    static u16 s_create_ssn = AD_SSN_UNRESOLVED;
    static u16 s_wait_ssn   = AD_SSN_UNRESOLVED;
    AD_RESOLVE_SSN_ENC(s_create_ssn, NtCreateThreadEx, 18);
    AD_RESOLVE_SSN_ENC(s_wait_ssn, NtWaitForSingleObject, 22);
    if (s_create_ssn == AD_SSN_FAILED || s_wait_ssn == AD_SSN_FAILED) return 0;

    ad_sched_shared_t shared;
    shared.counter = 0;
    shared.stop = 0;

    // Spawn worker thread via syscall
    ad_handle_t thread_h = 0;
    ad_ntstatus_t st = (ad_ntstatus_t)(s64)SyscallStub(s_create_ssn,
        &thread_h,                          // ThreadHandle out
        (void*)(u64)0x1FFFFF,               // DesiredAccess (THREAD_ALL_ACCESS)
        (void*)0,                           // ObjectAttributes
        AD_CURRENT_PROCESS,                 // ProcessHandle
        (void*)ad_sched_worker_fn,          // StartRoutine
        (void*)&shared,                     // Argument
        (void*)0,                           // CreateFlags (0 = run immediately)
        (void*)0, (void*)0, (void*)0, (void*)0
    );

    if (!AD_NT_SUCCESS(st) || !thread_h) return 0;

    // Warm-up: spin until worker has incremented counter at least once, or until
    // a generous timeout. On a normal multi-core system the worker is scheduled
    // within a few hundred microseconds of creation; on a single-core or heavily
    // loaded system it may take longer. Without this, all 8 samples could be
    // taken before the worker ever runs, causing a false "frozen worker" positive.
    {
        volatile u32 warmup = 0u;
        while (shared.counter == 0u && warmup < 2000000u) warmup++;
    }

    // Main thread: sample counter at intervals
    u64 samples[8];
    u32 i;
    for (i = 0; i < 8u; i++) {
        // Spin for a bit to let worker progress between samples
        volatile u32 spin = 0;
        while (spin < 50000u) spin++;
        AD_BARRIER();
        samples[i] = shared.counter;
    }

    // Stop worker
    shared.stop = 1;

    // Wait for thread (100ms timeout as LARGE_INTEGER = -1000000)
    s64 timeout = -1000000LL;  // 100ms in 100ns units
    SyscallStub(s_wait_ssn,
        thread_h, (void*)0, (void*)&timeout,
        (void*)0, (void*)0, (void*)0, (void*)0,
        (void*)0, (void*)0, (void*)0, (void*)0
    );

    // Close thread handle
    static u16 s_close_ssn = AD_SSN_UNRESOLVED;
    AD_RESOLVE_SSN_ENC(s_close_ssn, NtClose, 8);
    if (s_close_ssn != AD_SSN_FAILED) {
        SyscallStub(s_close_ssn, thread_h,
            (void*)0, (void*)0, (void*)0, (void*)0, (void*)0,
            (void*)0, (void*)0, (void*)0, (void*)0, (void*)0);
    }

    // Analysis: check counter progression pattern
    // Under normal scheduling: samples are monotonically increasing with
    // moderate deltas (worker runs freely between our spins)
    // Under debugger: samples are either (a) identical (worker frozen) or
    // (b) wildly different magnitude (debugger held main thread for seconds)

    // Check 1: did the worker run at all?
    if (samples[7] == 0) return 1;  // worker never ran = suspended by debugger

    // Check 2: are all samples identical (worker frozen)?
    u32 stuck = 1;
    for (i = 1; i < 8u; i++) {
        if (samples[i] != samples[0]) { stuck = 0; break; }
    }
    if (stuck) return 1;

    // Check 3 (removed): total_delta threshold was unreliable.
    // On modern multi-core CPUs, the OS scheduler can preempt the main thread
    // for a full time-slice (15 ms) between any two samples. During that slice
    // the free-running worker accumulates hundreds of millions of increments,
    // triggering a false positive on clean systems.
    // Checks 1 and 2 (worker never ran / worker completely frozen) are reliable
    // enough — they require deliberate scheduler manipulation by a debugger,
    // not just normal OS preemption.

    return 0;
#else
    return 0;
#endif
}

#endif // ANTIDEBUG_SCHEDULER_SYNC_H
