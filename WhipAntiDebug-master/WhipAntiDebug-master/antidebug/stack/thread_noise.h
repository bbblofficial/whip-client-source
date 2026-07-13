// ===== file: antidebug/stack/thread_noise.h =====
//
// Thread Noise — 100% direct syscall, no user-mode library calls.
//
// Spawns N hidden worker threads via NtCreateThreadEx (syscall).
// Each thread is hidden via NtSetInformationThread(ThreadHideFromDebugger).
// Workers do random-looking syscalls (NtYieldExecution, NtQueryPerformance,
// PEB reads, RDTSC, CPUID) to look like anti-debug checks.
//
// Unlike the previous RtlQueueWorkItem approach, this is unhookable
// by Frida/DBI — every call goes through WhipSysCall's SyscallStub.
//
#ifndef ANTIDEBUG_THREAD_NOISE_H
#define ANTIDEBUG_THREAD_NOISE_H

#include "../core/types.h"
#include "../core/macros.h"
#include "../core/syscall_bridge.h"

#if defined(_MSC_VER)

#define AD_NOISE_THREAD_COUNT   6u

// `__declspec(selectany)` makes these COMDAT-merged across translation units.
// Without it, every TU that includes this header gets its own static copy —
// causing cross-TU bugs where ad_noise_swarm_start spawns threads that
// reference TU-A's g_noise_kill, but ad_noise_swarm_stop sets TU-B's copy →
// threads never see the kill flag and survive past DLL unload → AV when
// they wake up in unmapped memory.
#if defined(_MSC_VER)
__declspec(selectany) volatile b32 g_noise_kill = 0;
#else
static volatile b32 g_noise_kill = 0;
#endif

typedef struct {
    u32 personality;
} ad_noise_work_t;

#if defined(_MSC_VER)
__declspec(selectany) ad_noise_work_t g_noise_work[AD_NOISE_THREAD_COUNT] = {{0}};
__declspec(selectany) void*           g_noise_handles[AD_NOISE_THREAD_COUNT] = {0};
#else
static ad_noise_work_t g_noise_work[AD_NOISE_THREAD_COUNT] = {{0}};
static void*           g_noise_handles[AD_NOISE_THREAD_COUNT] = {0};
#endif

#define AD_NOISE_RNG(s) do { (s) ^= (s) << 13; (s) ^= (s) >> 17; (s) ^= (s) << 5; } while(0)

static unsigned long __stdcall ad_noise_thread_entry(void* param) {
    ad_noise_work_t* w = (ad_noise_work_t*)param;
    u32 seed = w->personality;

    // Resolve via raw names — no STRENC macros needed for noise
    static u16 s_yield = AD_SSN_UNRESOLVED;
    static u16 s_delay = AD_SSN_UNRESOLVED;
    static u16 s_qpc   = AD_SSN_UNRESOLVED;

    if (s_yield == AD_SSN_UNRESOLVED) {
        char n[] = {'N','t','Y','i','e','l','d','E','x','e','c','u','t','i','o','n',0};
        s_yield = whip_bridge_resolve(n);
    }
    if (s_delay == AD_SSN_UNRESOLVED) {
        char n[] = {'N','t','D','e','l','a','y','E','x','e','c','u','t','i','o','n',0};
        s_delay = whip_bridge_resolve(n);
    }
    if (s_qpc == AD_SSN_UNRESOLVED) {
        char n[] = {'N','t','Q','u','e','r','y','P','e','r','f','o','r','m','a','n','c','e','C','o','u','n','t','e','r',0};
        s_qpc = whip_bridge_resolve(n);
    }

    while (!g_noise_kill) {
        AD_NOISE_RNG(seed);
        u32 action = seed & 7u;

        switch (action) {
        case 0:
            if (s_yield != AD_SSN_FAILED) AD_SYSCALL0(s_yield);
            break;
        case 1: {
            if (s_delay != AD_SSN_FAILED) {
                AD_NOISE_RNG(seed);
                s64 delay = -((s64)(seed % 100000u) + 10000LL);
                AD_SYSCALL2(s_delay, (u64)0, &delay);
            }
            break;
        }
        case 2: {
            if (s_qpc != AD_SSN_FAILED) {
                u64 counter = 0;
                AD_SYSCALL2(s_qpc, &counter, (u64)0);
            }
            break;
        }
        case 3: {
            volatile u8* peb = (volatile u8*)__readgsqword(0x60);
            volatile u8 bd = peb[0x02];
            volatile u32 ntg = *(volatile u32*)(peb + 0xBC);
            AD_UNUSED(bd); AD_UNUSED(ntg);
            break;
        }
        case 4: {
            int cpuid_buf[4];
            __cpuid(cpuid_buf, 0);
            volatile u64 tsc = __rdtsc();
            AD_UNUSED(tsc);
            break;
        }
        case 5: {
            volatile u8* kusd = (volatile u8*)0x7FFE0000ULL;
            volatile u32 tick = *(volatile u32*)(kusd + 0x320);
            AD_UNUSED(tick);
            break;
        }
        default: {
            AD_NOISE_RNG(seed);
            volatile u64 acc = seed;
            u32 iters = (seed & 0x3Fu) + 32u;
            u32 j;
            for (j = 0; j < iters; j++)
                acc = (acc ^ (acc >> 13)) * 0x5851F42D4C957F2DULL;
            AD_UNUSED(acc);
            break;
        }
        }

        // Small sleep between ops — all via syscall
        if (s_delay != AD_SSN_FAILED) {
            s64 gap = -50000LL;  // 5ms
            AD_SYSCALL2(s_delay, (u64)0, &gap);
        }

        w->personality = seed;
    }

    return 0;
}

#undef AD_NOISE_RNG

ANTIDEBUG_INLINE void ad_noise_swarm_start(void) {
    static u16 s_create = AD_SSN_UNRESOLVED;
    static u16 s_seti   = AD_SSN_UNRESOLVED;
    static u16 s_resume = AD_SSN_UNRESOLVED;

    if (s_create == AD_SSN_UNRESOLVED) {
        char n[] = {'N','t','C','r','e','a','t','e','T','h','r','e','a','d','E','x',0};
        s_create = whip_bridge_resolve(n);
    }
    if (s_seti == AD_SSN_UNRESOLVED) {
        char n[] = {'N','t','S','e','t','I','n','f','o','r','m','a','t','i','o','n','T','h','r','e','a','d',0};
        s_seti = whip_bridge_resolve(n);
    }
    if (s_resume == AD_SSN_UNRESOLVED) {
        char n[] = {'N','t','R','e','s','u','m','e','T','h','r','e','a','d',0};
        s_resume = whip_bridge_resolve(n);
    }

    if (s_create == AD_SSN_FAILED || s_resume == AD_SSN_FAILED) return;

    g_noise_kill = 0;

    // ── Code cave injection (REMOVED) ─────────────────────────────────────
    // An earlier version of this function searched ntdll's executable
    // sections for 64 consecutive 0x00/0xCC bytes ("padding") and wrote
    // PIC shellcode into the cave so one noise thread would run with
    // CIP inside ntdll. The heuristic was unsound on Windows 11: real
    // ntdll code contains zero-runs (immediates, hot-patch nop slides,
    // forwarder thunks) that the scanner couldn't distinguish from
    // section-end padding. Overwriting those locations corrupted live
    // ntdll code → ~10-15 % of clean runs AV'd in another thread the
    // next time ntdll executed that region.
    //
    // The noise threads below still spawn and run normally from
    // `ad_noise_thread_entry`; only the in-ntdll persona is gone.
    // To re-enable safely we'd need a real PE parser that reads
    // SizeOfRawData vs VirtualSize on each section to find the *true*
    // padding zone — not worth the complexity for this single persona.

    u32 i;
    for (i = 0; i < AD_NOISE_THREAD_COUNT; i++) {
        g_noise_work[i].personality = 0xDEAD0000u ^ (i * 0x9E3779B9u);

        void* start_routine = (void*)ad_noise_thread_entry;
        void* start_arg     = (void*)&g_noise_work[i];

        void* handle = (void*)0;
        ad_ntstatus_t st = (ad_ntstatus_t)(s64)SyscallStub(s_create,
            &handle,
            (void*)(u64)0x001FFFFFul,
            (void*)0,
            (void*)(u64)AD_CURRENT_PROCESS,
            start_routine,
            start_arg,
            (void*)(u64)0x00000004ul,  // CREATE_SUSPENDED
            (void*)0, (void*)0, (void*)0, (void*)0
        );
        if (!AD_NT_SUCCESS(st) || !handle) continue;
        g_noise_handles[i] = handle;

        // Hide from debugger
        if (s_seti != AD_SSN_FAILED)
            AD_SYSCALL4(s_seti, handle, (u64)17, (u64)0, (u64)0);

        // Resume
        u32 prev = 0;
        AD_SYSCALL2(s_resume, handle, &prev);
    }
}

ANTIDEBUG_INLINE void ad_noise_swarm_stop(void) {
    g_noise_kill = 1;
    AD_BARRIER();

    static u16 s_delay = AD_SSN_UNRESOLVED;
    static u16 s_close = AD_SSN_UNRESOLVED;
    if (s_delay == AD_SSN_UNRESOLVED) {
        char n[] = {'N','t','D','e','l','a','y','E','x','e','c','u','t','i','o','n',0};
        s_delay = whip_bridge_resolve(n);
    }
    if (s_close == AD_SSN_UNRESOLVED) {
        char n[] = {'N','t','C','l','o','s','e',0};
        s_close = whip_bridge_resolve(n);
    }

    // Wait for threads to exit
    if (s_delay != AD_SSN_FAILED) {
        s64 wait = -500000LL;  // 50ms
        AD_SYSCALL2(s_delay, (u64)0, &wait);
    }

    // Close handles
    if (s_close != AD_SSN_FAILED) {
        u32 i;
        for (i = 0; i < AD_NOISE_THREAD_COUNT; i++) {
            if (g_noise_handles[i]) {
                AD_SYSCALL1(s_close, g_noise_handles[i]);
                g_noise_handles[i] = (void*)0;
            }
        }
    }
}

#else
ANTIDEBUG_INLINE void ad_noise_swarm_start(void) {}
ANTIDEBUG_INLINE void ad_noise_swarm_stop(void) {}
#endif

#endif // ANTIDEBUG_THREAD_NOISE_H
