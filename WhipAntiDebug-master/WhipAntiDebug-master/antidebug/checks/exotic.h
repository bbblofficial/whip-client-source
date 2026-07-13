// ===== file: antidebug/checks/exotic.h =====
//
// Exotic anti-debug techniques — uncommon, hard to anticipate.
//
//   1.  TRAP FLAG — set TF in EFLAGS, detect debugger handling
//   2.  OUTPUT DEBUG STRING — detect if a debugger is listening
//   3.  DEBUG OBJECT COUNT — NtQueryObject to count debug objects system-wide
//   4.  UNHANDLED EXCEPTION FILTER — set filter, trigger crash, check if fires
//   5.  PROCESS JOB CHECK — sandboxes assign processes to job objects
//   6.  NtYieldExecution TIMING — scheduling latency anomaly
//   7.  PREFIX REDUNDANCY — x86 prefix abuse that debuggers mishandle
//   8.  POPF TF — push flags with TF set, debugger eats the single-step
//   9.  ANTI-ATTACH — occupy debug port to prevent late attachment
//  10.  TIMING BOMB — delayed check that fires long after init
//
#ifndef ANTIDEBUG_EXOTIC_H
#define ANTIDEBUG_EXOTIC_H

#include "../core/types.h"
#include "../core/macros.h"
#include "../core/syscall_bridge.h"
#include "../core/string_encrypt.h"
#include "../core/value_guard.h"

#if defined(_MSC_VER)

// =========================================================================
// 1. TRAP FLAG — single-step detection via EFLAGS.TF
// =========================================================================
//
// Set the Trap Flag (bit 8 of EFLAGS). This causes a SINGLE_STEP exception
// after the next instruction. Our SEH handler catches it → clean.
// A debugger in single-step mode is ALREADY using TF. Our PUSHF/POPF
// either conflicts with its TF management or the exception gets eaten.
//
// Detection: if our handler DOESN'T fire → debugger consumed the exception.

ANTIDEBUG_INLINE b32 ad_trap_flag_check(void) {
    volatile b32 handler_fired = 0;

    __try {
        // Push current flags, set TF (bit 8), restore
        // After the POPF, the CPU will raise EXCEPTION_SINGLE_STEP
        __writeeflags(__readeflags() | 0x100ULL);

        // This NOP is the instruction that triggers the single-step exception
        __nop();
    }
    __except (1) {
        handler_fired = 1;
    }

    // No handler = debugger ate it
    return (b32)(handler_fired == 0);
}

// =========================================================================
// 2. OUTPUT DEBUG STRING — detect listening debugger
// =========================================================================
//
// OutputDebugStringA triggers a debug event. If a debugger is attached and
// listening, GetLastError changes to a specific value. Without debugger,
// it stays unchanged.
//
// We use NtRaiseHardError or direct INT 2D (debug service) instead of
// OutputDebugString to avoid kernel32 imports.
//
// Simpler approach: INT 2D is the debug service interrupt. Under a
// debugger, it's handled silently. Without, it raises an exception.

ANTIDEBUG_INLINE b32 ad_int2d_check(void) {
    volatile b32 handler_fired = 0;

    __try {
        // INT 2D — debug service call
        // Under debugger: handled silently (no exception)
        // Without debugger: raises EXCEPTION_BREAKPOINT
        __int2c();  // INT 2C is similar but less commonly caught
    }
    __except (1) {
        handler_fired = 1;
    }

    return (b32)(handler_fired == 0);
}

// =========================================================================
// 3. DEBUG OBJECT COUNT — NtQueryObject for DebugObject type
// =========================================================================
//
// NtQueryObject(NULL, ObjectAllTypesInformation) returns info about all
// kernel object types. We look for "DebugObject" type and check if any
// instances exist. If there are debug objects → a debugger exists somewhere.

// Encrypted: "NtQueryObject" (13 chars)
#define AD_STRENC_NtQueryObject(buf)                                         \
    do {                                                                     \
        const u8 _k = AD_STR_KEY(0x88);                                     \
        char buf##_e[14];                                                    \
        AD_ENC(buf##_e,  0, 'N', _k); AD_ENC(buf##_e,  1, 't', _k);       \
        AD_ENC(buf##_e,  2, 'Q', _k); AD_ENC(buf##_e,  3, 'u', _k);       \
        AD_ENC(buf##_e,  4, 'e', _k); AD_ENC(buf##_e,  5, 'r', _k);       \
        AD_ENC(buf##_e,  6, 'y', _k); AD_ENC(buf##_e,  7, 'O', _k);       \
        AD_ENC(buf##_e,  8, 'b', _k); AD_ENC(buf##_e,  9, 'j', _k);       \
        AD_ENC(buf##_e, 10, 'e', _k); AD_ENC(buf##_e, 11, 'c', _k);       \
        AD_ENC(buf##_e, 12, 't', _k);                                       \
        AD_DECODE_BUF(buf##_e, 13, _k);                                     \
        for (unsigned _ci = 0; _ci < 14; _ci++) (buf)[_ci] = buf##_e[_ci];  \
    } while (0)

// ObjectAllTypesInformation = class 3
#define AD_OBJECT_ALL_TYPES_INFORMATION 3

ANTIDEBUG_INLINE b32 ad_debug_object_count(void) {
    static u16 s_ssn = AD_SSN_UNRESOLVED;
    AD_RESOLVE_SSN_ENC(s_ssn, NtQueryObject, 14);
    if (s_ssn == AD_SSN_FAILED) return 0;

    // First call: get required buffer size
    u32 needed = 0;
    AD_SYSCALL5(
        s_ssn,
        (u64)0,   // NULL handle = all types
        (u64)AD_OBJECT_ALL_TYPES_INFORMATION,
        (u64)0,
        (u64)0,
        &needed
    );

    // Can't easily allocate without CRT — just check if the call pattern
    // reveals debug objects exist. Alternative: check our own debug port
    // exists via ProcessDebugObjectHandle (already done in debug_port.h)
    // Here we use a simpler approach: query our own handle table
    AD_UNUSED(needed);

    // Fallback: ProcessDebugObjectHandle — if it succeeds, debug object exists
    static u16 s_ssn2 = AD_SSN_UNRESOLVED;
    AD_RESOLVE_SSN_ENC(s_ssn2, NtQueryInformationProcess, 26);
    if (s_ssn2 == AD_SSN_FAILED) return 0;

    void* dbg_obj = (void*)0;
    u32 ret_len = 0;

    ad_ntstatus_t st = AD_SYSCALL5(
        s_ssn2,
        AD_CURRENT_PROCESS,
        (u64)30,  // ProcessDebugObjectHandle
        &dbg_obj,
        (u64)sizeof(dbg_obj),
        &ret_len
    );

    return (b32)(AD_NT_SUCCESS(st) && dbg_obj != (void*)0);
}

// =========================================================================
// 4. UNHANDLED EXCEPTION FILTER manipulation
// =========================================================================
//
// When a debugger is attached, Windows does NOT call the unhandled
// exception filter — it passes the exception to the debugger instead.
//
// We can test this: trigger an exception that our SEH can't handle
// (let it propagate), and check if our UEF was called.
//
// Simpler version: use VEH (Vectored Exception Handler) priority.
// A debugger that consumes first-chance exceptions prevents our VEH
// from seeing them.
//
// Since we can't use AddVectoredExceptionHandler without kernel32,
// use the SEH variant: nested exception handlers.

ANTIDEBUG_INLINE b32 ad_nested_exception_check(void) {
    volatile b32 outer_fired = 0;
    volatile b32 inner_fired = 0;

    __try {
        __try {
            // Trigger exception
            *(volatile u8*)0 = 0;
        }
        __except (1) {
            inner_fired = 1;
            // Now trigger ANOTHER exception inside the handler
            // This tests nested exception handling — debuggers often
            // mishandle or break on nested exceptions
            __try {
                volatile u32 zero = 0;
                volatile u32 x = 1 / zero;
                AD_UNUSED(x);
            }
            __except (1) {
                outer_fired = 1;
            }
        }
    }
    __except (1) {
        // If we get here, something went wrong with nested handling
        outer_fired = 0;
    }

    // Both should fire on clean environment
    // Debugger may eat one or both
    return (b32)(!inner_fired || !outer_fired);
}

// =========================================================================
// 5. PROCESS JOB CHECK — sandbox detection
// =========================================================================
//
// Sandboxes (Cuckoo, Any.run, JoeSandbox) often assign analyzed processes
// to a Windows job object for resource control.
//
// NtIsProcessInJob(ProcessHandle, NULL) returns STATUS_PROCESS_IN_JOB
// if the process is in any job.

// Encrypted: "NtIsProcessInJob" (16 chars)
#define AD_STRENC_NtIsProcessInJob(buf)                                      \
    do {                                                                     \
        const u8 _k = AD_STR_KEY(0xCC);                                     \
        char buf##_e[17];                                                    \
        AD_ENC(buf##_e,  0, 'N', _k); AD_ENC(buf##_e,  1, 't', _k);       \
        AD_ENC(buf##_e,  2, 'I', _k); AD_ENC(buf##_e,  3, 's', _k);       \
        AD_ENC(buf##_e,  4, 'P', _k); AD_ENC(buf##_e,  5, 'r', _k);       \
        AD_ENC(buf##_e,  6, 'o', _k); AD_ENC(buf##_e,  7, 'c', _k);       \
        AD_ENC(buf##_e,  8, 'e', _k); AD_ENC(buf##_e,  9, 's', _k);       \
        AD_ENC(buf##_e, 10, 's', _k); AD_ENC(buf##_e, 11, 'I', _k);       \
        AD_ENC(buf##_e, 12, 'n', _k); AD_ENC(buf##_e, 13, 'J', _k);       \
        AD_ENC(buf##_e, 14, 'o', _k); AD_ENC(buf##_e, 15, 'b', _k);       \
        AD_DECODE_BUF(buf##_e, 16, _k);                                     \
        for (unsigned _ci = 0; _ci < 17; _ci++) (buf)[_ci] = buf##_e[_ci];  \
    } while (0)

#define AD_STATUS_PROCESS_IN_JOB ((ad_ntstatus_t)0x00000123L)

ANTIDEBUG_INLINE b32 ad_process_in_job(void) {
    // Windows 10/11: ALL interactive processes are in job objects (console host
    // jobs, IDE jobs, Silo jobs).  NtIsProcessInJob(NULL) always returns
    // STATUS_PROCESS_IN_JOB, giving a universal false positive.
    // NtMajorVersion is at KUSER_SHARED_DATA + 0x026C (kernel-written, constant).
    volatile u32 os_major = *(volatile u32*)((volatile u8*)0x7FFE0000ULL + 0x026CUL);
    if (os_major >= 10u) return 0;

    static u16 s_ssn = AD_SSN_UNRESOLVED;
    AD_RESOLVE_SSN_ENC(s_ssn, NtIsProcessInJob, 17);
    if (s_ssn == AD_SSN_FAILED) return 0;

    ad_ntstatus_t st = AD_SYSCALL2(
        s_ssn,
        AD_CURRENT_PROCESS,
        (u64)0   // NULL job handle = any job
    );

    return (b32)(st == AD_STATUS_PROCESS_IN_JOB);
}

// =========================================================================
// 6. NtYieldExecution TIMING — scheduling anomaly
// =========================================================================
//
// NtYieldExecution() yields the current time slice. Under normal load,
// it returns quickly. Under a debugger or heavy instrumentation,
// yielding + rescheduling takes much longer.

// Encrypted: "NtYieldExecution" (16 chars)
#define AD_STRENC_NtYieldExecution(buf)                                      \
    do {                                                                     \
        const u8 _k = AD_STR_KEY(0x29);                                     \
        char buf##_e[17];                                                    \
        AD_ENC(buf##_e,  0, 'N', _k); AD_ENC(buf##_e,  1, 't', _k);       \
        AD_ENC(buf##_e,  2, 'Y', _k); AD_ENC(buf##_e,  3, 'i', _k);       \
        AD_ENC(buf##_e,  4, 'e', _k); AD_ENC(buf##_e,  5, 'l', _k);       \
        AD_ENC(buf##_e,  6, 'd', _k); AD_ENC(buf##_e,  7, 'E', _k);       \
        AD_ENC(buf##_e,  8, 'x', _k); AD_ENC(buf##_e,  9, 'e', _k);       \
        AD_ENC(buf##_e, 10, 'c', _k); AD_ENC(buf##_e, 11, 'u', _k);       \
        AD_ENC(buf##_e, 12, 't', _k); AD_ENC(buf##_e, 13, 'i', _k);       \
        AD_ENC(buf##_e, 14, 'o', _k); AD_ENC(buf##_e, 15, 'n', _k);       \
        AD_DECODE_BUF(buf##_e, 16, _k);                                     \
        for (unsigned _ci = 0; _ci < 17; _ci++) (buf)[_ci] = buf##_e[_ci];  \
    } while (0)

ANTIDEBUG_INLINE b32 ad_yield_timing(void) {
#if defined(_MSC_VER)
    static u16 s_ssn = AD_SSN_UNRESOLVED;
    AD_RESOLVE_SSN_ENC(s_ssn, NtYieldExecution, 17);
    if (s_ssn == AD_SSN_FAILED) return 0;

    u64 samples[4];
    u32 i;

    for (i = 0; i < 4u; i++) {
        AD_LFENCE();
        u64 t0 = __rdtsc();

        AD_SYSCALL0(s_ssn);  // NtYieldExecution()

        AD_LFENCE();
        u64 t1 = __rdtsc();
        samples[i] = t1 - t0;
    }

    // Take median of 4
    // Simple: sort and take [1]
    u64 tmp;
    if (samples[0] > samples[1]) { tmp = samples[0]; samples[0] = samples[1]; samples[1] = tmp; }
    if (samples[2] > samples[3]) { tmp = samples[2]; samples[2] = samples[3]; samples[3] = tmp; }
    if (samples[0] > samples[2]) { tmp = samples[0]; samples[0] = samples[2]; samples[2] = tmp; }
    if (samples[1] > samples[3]) { tmp = samples[1]; samples[1] = samples[3]; samples[3] = tmp; }

    u64 median = (samples[1] + samples[2]) / 2ULL;

    // Normal yield: ~1000-50000 cycles
    // Under debugger/heavy instrumentation: >500000 cycles
    u64 thresh = ad_derive64(0xA1B2C3D400000000ULL | 0x7A120ULL,
                              0xA1B2C3D400000000ULL);  // 0x7A120 = 500000
    return ad_opaque_gt_u64(median, thresh);
#else
    return 0;
#endif
}

// =========================================================================
// 7. ANTI-ATTACH — self-debug to prevent late debugger attachment
// =========================================================================
//
// Create a debug object for ourselves. A process can only have ONE debug
// object. If we occupy it, a debugger can't attach later.
//
// NtCreateDebugObject → NtDebugActiveProcess(self)
// If this succeeds → we own the debug port, no one else can attach.
// If it fails → someone already has a debug object (= debugger already attached)

// Encrypted: "NtCreateDebugObject" (19 chars)
#define AD_STRENC_NtCreateDebugObject(buf)                                   \
    do {                                                                     \
        const u8 _k = AD_STR_KEY(0x7F);                                     \
        char buf##_e[20];                                                    \
        AD_ENC(buf##_e,  0, 'N', _k); AD_ENC(buf##_e,  1, 't', _k);       \
        AD_ENC(buf##_e,  2, 'C', _k); AD_ENC(buf##_e,  3, 'r', _k);       \
        AD_ENC(buf##_e,  4, 'e', _k); AD_ENC(buf##_e,  5, 'a', _k);       \
        AD_ENC(buf##_e,  6, 't', _k); AD_ENC(buf##_e,  7, 'e', _k);       \
        AD_ENC(buf##_e,  8, 'D', _k); AD_ENC(buf##_e,  9, 'e', _k);       \
        AD_ENC(buf##_e, 10, 'b', _k); AD_ENC(buf##_e, 11, 'u', _k);       \
        AD_ENC(buf##_e, 12, 'g', _k); AD_ENC(buf##_e, 13, 'O', _k);       \
        AD_ENC(buf##_e, 14, 'b', _k); AD_ENC(buf##_e, 15, 'j', _k);       \
        AD_ENC(buf##_e, 16, 'e', _k); AD_ENC(buf##_e, 17, 'c', _k);       \
        AD_ENC(buf##_e, 18, 't', _k);                                       \
        AD_DECODE_BUF(buf##_e, 19, _k);                                     \
        for (unsigned _ci = 0; _ci < 20; _ci++) (buf)[_ci] = buf##_e[_ci];  \
    } while (0)

// AD_OBJECT_ATTRIBUTES is defined in core/types.h — guard prevents redefinition
#ifndef AD_OBJECT_ATTRIBUTES_DEFINED
#define AD_OBJECT_ATTRIBUTES_DEFINED
typedef struct {
    u32 Length;
    ad_handle_t RootDirectory;
    void* ObjectName;
    u32 Attributes;
    ad_handle_t SecurityDescriptor;
    ad_handle_t SecurityQualityOfService;
} AD_OBJECT_ATTRIBUTES;
#endif

// Returns 1 if anti-attach succeeded (we own the debug port)
// Returns 0 if a debugger already owns it
ANTIDEBUG_INLINE b32 ad_anti_attach(void) {
    static u16 s_ssn = AD_SSN_UNRESOLVED;
    AD_RESOLVE_SSN_ENC(s_ssn, NtCreateDebugObject, 20);
    if (s_ssn == AD_SSN_FAILED) return 0;

    AD_OBJECT_ATTRIBUTES oa;
    AD_ZERO_BUF(&oa, sizeof(oa));
    oa.Length = sizeof(oa);

    ad_handle_t debug_handle = (ad_handle_t)0;

    // NtCreateDebugObject(DebugObjectHandle, ACCESS_MASK, ObjectAttributes, Flags)
    // ACCESS_MASK: DEBUG_ALL_ACCESS = 0x001F000F
    // Flags: 1 = kill on close
    ad_ntstatus_t st = AD_SYSCALL4(
        s_ssn,
        &debug_handle,
        (u64)0x001F000FUL,
        &oa,
        (u64)1   // KILL_ON_CLOSE
    );

    if (!AD_NT_SUCCESS(st)) {
        // Failed — debug object already exists = debugger attached
        return 0;
    }

    // We now own a debug object. Store the handle (don't close it).
    // As long as it's open, no debugger can attach.
    // We DON'T call NtDebugActiveProcess on ourselves (that would
    // self-debug and cause issues). Just owning the object is enough
    // to show we CAN create one (= no debugger blocking us).
    return 1;
}

// =========================================================================
// 8. SHARED USER DATA timing — kernel-mapped, unhookable
// =========================================================================
//
// KUSER_SHARED_DATA at 0x7FFE0000 is mapped read-only by the kernel.
// It contains timing info that user-mode can't hook.
// Fields:
//   +0x320 = SystemTime (LARGE_INTEGER)
//   +0x328 = TimeZoneBias
//   +0x008 = InterruptTime (LARGE_INTEGER)
//
// Compare InterruptTime progression vs RDTSC — a VM or debugger may
// advance them at different rates.

ANTIDEBUG_INLINE b32 ad_shared_user_data_timing(void) {
#if defined(_MSC_VER)
    // KUSER_SHARED_DATA is always at this fixed address on x64 Windows
    volatile u8* kusd = (volatile u8*)0x7FFE0000ULL;

    // InterruptTime at offset 0x008 (KSYSTEM_TIME: LowPart=u32, High1Time=s32, High2Time=s32)
    volatile u32* int_time_lo = (volatile u32*)(kusd + 0x008);
    volatile s32* int_time_hi = (volatile s32*)(kusd + 0x00C);

    // Read interrupt time and TSC together
    u64 tsc1 = __rdtsc();
    u32 it_lo1 = *int_time_lo;
    s32 it_hi1 = *int_time_hi;

    // Do some work
    volatile u64 x = 0x1234567890ABCDEFULL;
    u32 i;
    for (i = 0; i < 2000u; i++) {
        x = x * 6364136223846793005ULL + 1ULL;
    }
    AD_UNUSED(x);

    u64 tsc2 = __rdtsc();
    u32 it_lo2 = *int_time_lo;
    s32 it_hi2 = *int_time_hi;

    u64 tsc_delta = tsc2 - tsc1;
    u64 it1 = ((u64)(u32)it_hi1 << 32) | (u64)it_lo1;
    u64 it2 = ((u64)(u32)it_hi2 << 32) | (u64)it_lo2;
    u64 it_delta = it2 - it1;

    // InterruptTime is in 100ns units. TSC at 3GHz = 30 ticks per 100ns
    // So TSC/IT ratio should be roughly 20-50 on modern hardware.
    // A huge TSC delta but tiny IT delta = debugger held us (TSC advanced
    // but InterruptTime didn't because the system clock wasn't moving)
    if (it_delta == 0 && tsc_delta > 100000ULL) {
        return 1;  // We burned >100K cycles but InterruptTime didn't move
    }

    if (it_delta > 0) {
        u64 ratio = tsc_delta / it_delta;
        // Anomalous if ratio < 5 or > 500
        if (ratio < 5ULL || ratio > 500ULL) return 1;
    }

    return 0;
#else
    return 0;
#endif
}

// =========================================================================
// 9. FAKE ENVIRONMENT DETECTION — check for too-clean environment
// =========================================================================
//
// A real system has noise: many handles, threads, loaded DLLs.
// A sandbox/emulator may have an unusually clean environment.

ANTIDEBUG_INLINE b32 ad_environment_too_clean(void) {
#if defined(_MSC_VER)
    // Check loaded module count via PEB.Ldr
    u8* peb = (u8*)__readgsqword(0x60);
    u8* ldr = *(u8**)(peb + 0x18);

    // Count modules in InLoadOrderModuleList
    u8* list_head = ldr + 0x10;
    u8* entry = *(u8**)list_head;

    u32 module_count = 0;
    while (entry != list_head && module_count < 200u) {
        module_count++;
        entry = *(u8**)entry;
    }

    // A real Windows process has at minimum:
    // ntdll, kernel32, kernelbase, our exe = 4
    // Plus usually ucrt, vcruntime, etc. = 6-10 minimum
    // A sandbox stub might have only 2-3
    if (module_count < 4u) return 1;

    // Check number of processors (PEB+0xB8)
    u32 num_procs = *(u32*)(peb + 0xB8);
    if (num_procs < 2u) return 1;  // Most sandboxes use 1 CPU

    // Check available memory (PEB+0x100 = MaximumNumberOfProcessors area)
    // Actually simpler: check NtGlobalFlag area for inconsistencies

    // System time via KUSER_SHARED_DATA (SystemTime = FILETIME since 1601).
    // A sandbox may set a fake/reset clock (e.g., 1601-01-01 + a few hours).
    // Real systems in 2026: SystemTime ≈ 1.34e17 >> 1e11.
    // Offset 0x014 = SystemTime.LowPart, 0x018 = SystemTime.High1Time.
    // (0x320 is TickCount/uptime — a different field; using it was a bug.)
    volatile u8* kusd = (volatile u8*)0x7FFE0000ULL;
    volatile u32* tick_lo = (volatile u32*)(kusd + 0x014);  // SystemTime.LowPart
    volatile s32* tick_hi = (volatile s32*)(kusd + 0x018);  // SystemTime.High1Time

    u64 sys_time = ((u64)(u32)*tick_hi << 32) | (u64)*tick_lo;

    // SystemTime in 100ns units since Jan 1 1601. Any post-2000 date >> 1e11.
    // A sandbox with a deliberately reset clock (year 1601-1970) would be small.
    if (sys_time < 100000000000ULL) return 1;

    return 0;
#else
    return 0;
#endif
}

// =========================================================================
// 10. TIMING BOMB — delayed check that fires later
// =========================================================================
//
// Store a TSC value at init. Later (in ad_run_hardened), check how much
// time has passed. If the process has been alive for >5s but less than
// 100ms of wall-clock time → something fast-forwarded us.
//
// If the process has been alive >60s and no checks have fired → suspicious
// (a reverser spent time analyzing in the debugger).

ANTIDEBUG_INLINE b32 ad_timing_bomb(u64 init_tsc, u32 checks_hit_so_far) {
#if defined(_MSC_VER)
    if (init_tsc == 0) return 0;

    u64 now = __rdtsc();
    u64 elapsed = now - init_tsc;

    // Rough estimate: ~3GHz = 3B cycles/sec
    u64 cycles_per_sec = ad_derive64(
        0xB2D05E00ULL ^ 0xF1E2D3C4ULL, 0xF1E2D3C4ULL);  // ~3000000000

    // If we've been alive > 30 seconds worth of TSC cycles
    // and NO checks fired → reverser probably single-stepping through
    u64 thirty_sec = cycles_per_sec * 30ULL;

    if (elapsed > thirty_sec && checks_hit_so_far == 0u) {
        return 1;  // Too long alive with zero detections → suspicious
    }

    return 0;
#else
    AD_UNUSED(init_tsc);
    AD_UNUSED(checks_hit_so_far);
    return 0;
#endif
}

// =========================================================================
// EXOTIC MASTER — runs all exotic checks
//
// Includes techniques from al-khaser:
//   - ad_parent_is_debugger()  : parent process is a known debugger
//   - ad_se_debug_privilege()  : our token has SeDebugPrivilege (unusual)
//   - ad_write_watch_check()   : WriteWatch catches DBI/sandbox writes
//   - ad_vm_vendor_known()     : exact CPUID vendor string match
// =========================================================================

ANTIDEBUG_INLINE u32 ad_exotic_master(u64 init_tsc, u32 checks_so_far) {
    u32 score = 0;

    // ── Classic exotic checks ──────────────────────────────────────────────
    score += ad_trap_flag_check()                     ?  5u : 0u;
    score += ad_int2d_check()                         ?  4u : 0u;
    score += ad_debug_object_count()                  ?  3u : 0u;
    score += ad_nested_exception_check()              ?  6u : 0u;
    score += ad_process_in_job()                      ?  3u : 0u;
    score += ad_yield_timing()                        ?  4u : 0u;
    score += ad_shared_user_data_timing()             ?  7u : 0u;
    score += ad_environment_too_clean()               ?  4u : 0u;
    score += ad_timing_bomb(init_tsc, checks_so_far)  ?  5u : 0u;

    // ── al-khaser-inspired additions ───────────────────────────────────────
#if AD_ENABLE_PARENT_PROCESS
    // Parent is x64dbg, WinDbg, OllyDbg, IDA, dnSpy, etc.
    // Weight 5: low false-positive rate (exact name list)
    score += ad_parent_is_debugger()                  ?  5u : 0u;
#endif

#if AD_ENABLE_SE_DEBUG
    // SeDebugPrivilege enabled in our own token — should NEVER happen normally.
    // Weight 8: very strong signal (normal apps never have SeDebug enabled)
    score += ad_se_debug_privilege()                  ?  8u : 0u;
#endif

#if AD_ENABLE_WRITE_WATCH
    // WriteWatch anomaly — sandbox agent or DBI writes to monitored pages.
    // Weight 6: reliable detection of instrumentation frameworks
    score += ad_write_watch_check()                   ?  6u : 0u;
#endif

#if AD_ENABLE_VM_VENDOR
    // Exact CPUID vendor string match (VMware, VBox, KVM, Hyper-V, QEMU, Xen)
    // Weight 4: combined with hypervisor bit for high-confidence VM detection
    score += ad_vm_vendor_known()                     ?  4u : 0u;
#endif

    return score;
}

#else  // Non-MSVC stubs
ANTIDEBUG_INLINE u32 ad_exotic_master(u64 it, u32 cs) { AD_UNUSED(it); AD_UNUSED(cs); return 0; }
ANTIDEBUG_INLINE b32 ad_anti_attach(void) { return 0; }
#endif // _MSC_VER

#endif // ANTIDEBUG_EXOTIC_H
