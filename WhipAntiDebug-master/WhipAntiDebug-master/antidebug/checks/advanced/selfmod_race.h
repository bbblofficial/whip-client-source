// ===== file: antidebug/checks/advanced/selfmod_race.h =====
//
// Self-Modifying Code + Race Condition Detection.
// Allocates an RWX page, writes executable code, then modifies it
// from a second thread while the main thread executes it.
// Under normal execution: race is benign (code always returns).
// Under debugger: serialized execution produces anomalous timing/behavior.
//
#ifndef ANTIDEBUG_SELFMOD_RACE_H
#define ANTIDEBUG_SELFMOD_RACE_H

#include "../../core/types.h"
#include "../../core/macros.h"
#include "../../core/syscall_bridge.h"
#include "../../core/string_encrypt.h"

// NtAllocateVirtualMemory and NtFreeVirtualMemory macros already defined
// in guard_pages.h — we reuse them via AD_RESOLVE_SSN_ENC.

typedef struct {
    volatile u8* code_region;
    u64          region_size;
    volatile u32 stop;
    volatile u32 write_count;
} ad_selfmod_ctx_t;

// Writer thread: continuously modifies the code region
static unsigned long __stdcall ad_selfmod_writer(void* param) {
    ad_selfmod_ctx_t* ctx = (ad_selfmod_ctx_t*)param;
    // RET instruction = 0xC3
    // NOP instruction = 0x90
    while (!ctx->stop) {
        // Alternate between NOP sled + RET and just RET
        u32 cnt = ctx->write_count++;
        u8 fill = (cnt & 1u) ? 0x90 : 0xCC;
        volatile u8* p = ctx->code_region;
        u32 i;
        for (i = 0; i < 60u; i++) p[i] = fill;
        p[60] = 0xC3;  // always end with RET
        p[61] = 0xC3;
        p[62] = 0xC3;
        p[63] = 0xC3;
    }
    return 0;
}

ANTIDEBUG_INLINE b32 ad_selfmod_race_check(void) {
#ifdef _MSC_VER
    b32 result = 0;
    static u16 s_alloc_ssn = AD_SSN_UNRESOLVED;
    static u16 s_free_ssn  = AD_SSN_UNRESOLVED;
    AD_RESOLVE_SSN_ENC(s_alloc_ssn, NtAllocateVirtualMemory, 24);
    AD_RESOLVE_SSN_ENC(s_free_ssn, NtFreeVirtualMemory, 20);
    if (s_alloc_ssn == AD_SSN_FAILED) return 0;

    // Allocate RWX page via syscall
    void* base_addr = 0;
    u64 alloc_size = 4096;
    // MEM_COMMIT|MEM_RESERVE = 0x3000, PAGE_EXECUTE_READWRITE = 0x40
    ad_ntstatus_t st = (ad_ntstatus_t)(s64)SyscallStub(s_alloc_ssn,
        AD_CURRENT_PROCESS, &base_addr, (void*)0, &alloc_size,
        (void*)(u64)0x3000, (void*)(u64)0x40,
        (void*)0, (void*)0, (void*)0, (void*)0, (void*)0
    );
    if (!AD_NT_SUCCESS(st) || !base_addr) return 0;

    // Fill with RET
    volatile u8* code = (volatile u8*)base_addr;
    u32 i;
    for (i = 0; i < 64u; i++) code[i] = 0xC3;

    ad_selfmod_ctx_t ctx;
    ctx.code_region = code;
    ctx.region_size = alloc_size;
    ctx.stop = 0;
    ctx.write_count = 0;

    // Spawn writer thread
    static u16 s_create_ssn = AD_SSN_UNRESOLVED;
    AD_RESOLVE_SSN_ENC(s_create_ssn, NtCreateThreadEx, 18);
    if (s_create_ssn == AD_SSN_FAILED) goto cleanup;

    ad_handle_t thread_h = 0;
    st = (ad_ntstatus_t)(s64)SyscallStub(s_create_ssn,
        &thread_h, (void*)(u64)0x1FFFFF, (void*)0,
        AD_CURRENT_PROCESS, (void*)ad_selfmod_writer, (void*)&ctx,
        (void*)0, (void*)0, (void*)0, (void*)0, (void*)0
    );
    if (!AD_NT_SUCCESS(st)) goto cleanup;

    // Main thread: call into the code region during the race for stress,
    // but DO NOT measure timing here — concurrent SMC machine clears
    // dominate the measurement and produce huge legitimate spikes.
    typedef void (*code_fn_t)(void);
    for (i = 0; i < 16u; i++) {
        ((code_fn_t)base_addr)();
    }

    // Stop the writer and wait for it to finish so the page is quiescent.
    ctx.stop = 1;

    static u16 s_wait_ssn = AD_SSN_UNRESOLVED;
    AD_RESOLVE_SSN_ENC(s_wait_ssn, NtWaitForSingleObject, 22);
    if (s_wait_ssn != AD_SSN_FAILED) {
        s64 timeout = -10000000LL; // 1s
        SyscallStub(s_wait_ssn, thread_h, (void*)0, &timeout,
            (void*)0, (void*)0, (void*)0, (void*)0,
            (void*)0, (void*)0, (void*)0, (void*)0);
    }

    // Re-prime the page with bare RETs so we measure clean execution.
    for (i = 0; i < 64u; i++) code[i] = 0xC3;
    // Warmup (cold ITLB / cache after writer's churn).
    for (i = 0; i < 4u; i++) {
        ((code_fn_t)base_addr)();
    }
    u64 call_times[16];
    for (i = 0; i < 16u; i++) {
        AD_LFENCE();
        u64 t0 = __rdtsc();
        ((code_fn_t)base_addr)();
        u64 t1 = __rdtsc();
        AD_LFENCE();
        call_times[i] = t1 - t0;
    }

    // Close handle
    static u16 s_close_ssn = AD_SSN_UNRESOLVED;
    AD_RESOLVE_SSN_ENC(s_close_ssn, NtClose, 8);
    if (s_close_ssn != AD_SSN_FAILED) {
        SyscallStub(s_close_ssn, thread_h,
            (void*)0, (void*)0, (void*)0, (void*)0, (void*)0,
            (void*)0, (void*)0, (void*)0, (void*)0, (void*)0);
    }

    // Analyze timing: take the median to reject outliers caused by
    // legitimate cache-line ping-pong with the writer thread, machine
    // clears from self-modifying code, and scheduler jitter.
    // Under a debugger that instruments RWX execution, ALL samples are
    // slow, not just the tail.
    u32 j, k;
    for (j = 1; j < 16u; j++) {
        u64 v = call_times[j];
        k = j;
        while (k > 0u && call_times[k - 1u] > v) {
            call_times[k] = call_times[k - 1u];
            k--;
        }
        call_times[k] = v;
    }
    // Use the lower quartile rather than the median: this rejects up to
    // 75% of samples being inflated by scheduler preemption (a 1ms tick
    // on a 3+ GHz CPU is millions of cycles and can easily land in
    // half of a 16-sample run on Debug builds).
    u64 q1 = call_times[4];

    // A bare RET on a hot RWX page costs hundreds of cycles even in
    // Debug builds. A debugger that instruments / single-steps RWX
    // execution makes every single sample (including the lower
    // quartile) extremely slow. 200k is well above any legitimate
    // scheduler / cache jitter while still catching instrumentation.
    result = (b32)(q1 > 200000ULL);

cleanup:
    if (s_free_ssn != AD_SSN_FAILED && base_addr) {
        u64 free_size = 0;
        SyscallStub(s_free_ssn, AD_CURRENT_PROCESS, &base_addr,
            &free_size, (void*)(u64)0x8000,  // MEM_RELEASE
            (void*)0, (void*)0, (void*)0, (void*)0, (void*)0, (void*)0, (void*)0);
    }

    return result;
#else
    return 0;
#endif
}

#endif // ANTIDEBUG_SELFMOD_RACE_H
