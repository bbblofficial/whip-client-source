// ===== file: antidebug/checks/vm/anti_emulation.h =====
//
// Anti-emulation checks.
//
// Detects execution inside emulators (QEMU TCG, Unicorn, Bochs, Pin,
// DynamoRIO) rather than on real hardware or a full hypervisor.
//
// Techniques:
//   - CPUID unusual leaf probing (garbage detection)
//   - FPU state consistency (control word round-trip)
//   - RDTSC tight-loop consistency (delta anomalies)
//   - Undocumented instruction exception verification (__ud2)
//
// No CRT, no imports.
//
#ifndef ANTIDEBUG_ANTI_EMULATION_H
#define ANTIDEBUG_ANTI_EMULATION_H

#include "../../core/types.h"
#include "../../core/macros.h"
#include "../../core/config.h"

#if defined(_MSC_VER)

// ---------------------------------------------------------------------------
// SEH helpers -- reuse the project's standard pattern
// ---------------------------------------------------------------------------
#ifndef EXCEPTION_EXECUTE_HANDLER
#define EXCEPTION_EXECUTE_HANDLER      1
#endif
#ifndef GetExceptionInformation
void* __cdecl _exception_info(void);
#define GetExceptionInformation() (_exception_info())
#endif

// Minimal EXCEPTION_POINTERS layout for SEH filter extraction
#ifndef AD_EMU_EXC_TYPES_DEFINED
#define AD_EMU_EXC_TYPES_DEFINED
typedef struct {
    u32   ExceptionCode;
    u32   ExceptionFlags;
    void* ExceptionRecord;
    void* ExceptionAddress;
    u32   NumberParameters;
    u32   _pad;
    u64   ExceptionInformation[15];
} AD_EMU_EXC_RECORD;

typedef struct {
    AD_EMU_EXC_RECORD* ExceptionRecord;
    void*              ContextRecord;
} AD_EMU_EXC_POINTERS;
#endif

// ---------------------------------------------------------------------------
// Check 1: CPUID unusual-leaf probe
//
// Real CPUs return zeros (or repeat standard data) for unsupported CPUID
// leaves.  Some emulators return garbage, partially-initialized registers,
// or crash outright on extended leaves they don't implement.
//
// We query several unusual leaves and look for:
//   - Hypervisor brand strings in leaf 0x40000000 that match known
//     emulator signatures (TCGTCGTCGTCG = QEMU TCG)
//   - Non-zero returns from extremely high extended leaves that real
//     CPUs leave zeroed
//   - Feature flags in leaf 0x80000001 that are impossible on the
//     processor family reported by leaf 0x00000001
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE b32 ad_emu_cpuid_check(void) {
    int regs[4] = {0};
    b32 suspicious = 0;

    // --- Probe 1: hypervisor vendor string for QEMU TCG ---
    __cpuid(regs, (int)0x40000000);
    {
        static const u8 sig_tcg[12] = {
            'T','C','G','T','C','G','T','C','G','T','C','G'};
        u8 v[12];
        u32 t, j;
        t = (u32)regs[1];
        v[0]=(u8)(t); v[1]=(u8)(t>>8); v[2]=(u8)(t>>16); v[3]=(u8)(t>>24);
        t = (u32)regs[2];
        v[4]=(u8)(t); v[5]=(u8)(t>>8); v[6]=(u8)(t>>16); v[7]=(u8)(t>>24);
        t = (u32)regs[3];
        v[8]=(u8)(t); v[9]=(u8)(t>>8); v[10]=(u8)(t>>16); v[11]=(u8)(t>>24);
        b32 match = 1;
        for (j = 0u; j < 12u && match; j++)
            if (v[j] != sig_tcg[j]) match = 0;
        if (match) suspicious = 1;
    }

    // --- Probe 2: extended leaf 0x80000007 (APM) + 0x80000008 (address sizes)
    // Real CPUs: leaf 0x80000007 EAX/EBX/ECX are typically 0 on Intel.
    // Some emulators fill them with garbage or mirror lower leaves.
    {
        int r8[4] = {0};
        int r_max[4] = {0};
        __cpuid(r_max, (int)0x80000000);
        u32 max_ext = (u32)r_max[0];

        if (max_ext >= 0x80000008u) {
            __cpuid(r8, (int)0x80000008);

            // Virtual address bits (r8 EAX bits 15:8) should be 48 or 57
            // on real x64 CPUs.  Emulators sometimes report 0 or weird values.
            u32 va_bits = ((u32)r8[0] >> 8) & 0xFFu;
            if (va_bits != 0u && va_bits != 48u && va_bits != 57u)
                suspicious = 1;
        }

        // If max_ext < 0x80000000 the CPU doesn't support extended CPUID
        // at all -- extremely unusual on any real x64 processor.
        if (max_ext < 0x80000000u)
            suspicious = 1;
    }

    // --- Probe 3: very high unsupported leaf should return zeros ---
    {
        int rh[4] = {0};
        __cpuidex(rh, (int)0x8FFFFFFFu, 0);
        // Real CPUs: all zeros (or echo of leaf 0 data).
        // Some emulators return non-zero garbage.
        // We flag if ALL four registers are non-zero -- real CPUs never do this.
        if (rh[0] != 0 && rh[1] != 0 && rh[2] != 0 && rh[3] != 0)
            suspicious = 1;
    }

    return suspicious;
}

// ---------------------------------------------------------------------------
// Check 2: FPU state consistency
//
// Test FPU control-word round-trip and x87 status-word coherence.
// Real hardware faithfully preserves the control word through
// read/write cycles.  Some emulators (Unicorn, Bochs, QEMU in certain
// modes) fail to preserve unusual CW values, or report incorrect
// status-word fields after specific operations.
//
// Strategy:
//   1. Read the current x87 control word via _control87(0, 0)
//   2. Set an unusual rounding mode + precision (round-up, 24-bit)
//   3. Read it back and verify the bits stuck
//   4. Restore original control word
//   5. Also check MXCSR round-trip via _mm_getcsr / _mm_setcsr
//
// On x64 MSVC, inline asm is unavailable, so we use CRT-free intrinsics:
//   _mm_getcsr / _mm_setcsr for SSE, __control87_2 for x87.
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE b32 ad_emu_fpu_check(void) {
    b32 suspicious = 0;

    // --- Test 1: MXCSR round-trip ---
    // MXCSR has rounding control in bits 14:13.
    // 00 = round-nearest, 01 = round-down, 10 = round-up, 11 = round-toward-zero
    {
        u32 orig_mxcsr = _mm_getcsr();
        AD_BARRIER();

        // Set rounding to round-up (10b in bits 14:13 = 0x4000)
        u32 test_mxcsr = (orig_mxcsr & ~0x6000u) | 0x4000u;
        _mm_setcsr(test_mxcsr);
        AD_BARRIER();

        u32 readback = _mm_getcsr();
        AD_BARRIER();

        // Restore
        _mm_setcsr(orig_mxcsr);
        AD_BARRIER();

        // Verify the rounding bits stuck
        if ((readback & 0x6000u) != 0x4000u)
            suspicious = 1;
    }

    // --- Test 2: MXCSR denormals-are-zero + flush-to-zero round-trip ---
    // Bits 6 (DAZ) and 15 (FZ).  Some emulators ignore these.
    {
        u32 orig_mxcsr = _mm_getcsr();
        AD_BARRIER();

        // Set DAZ (bit 6) and FZ (bit 15)
        u32 test_mxcsr = orig_mxcsr | 0x8040u;
        _mm_setcsr(test_mxcsr);
        AD_BARRIER();

        u32 readback = _mm_getcsr();
        AD_BARRIER();

        _mm_setcsr(orig_mxcsr);
        AD_BARRIER();

        if ((readback & 0x8040u) != 0x8040u)
            suspicious = 1;
    }

    // --- Test 3: MXCSR exception mask bits should be preserved ---
    // Bits 12:7 are the exception masks.  Toggle them all on.
    {
        u32 orig_mxcsr = _mm_getcsr();
        AD_BARRIER();

        u32 test_mxcsr = orig_mxcsr | 0x1F80u;  // all masks set
        _mm_setcsr(test_mxcsr);
        AD_BARRIER();

        u32 readback = _mm_getcsr();
        AD_BARRIER();

        _mm_setcsr(orig_mxcsr);
        AD_BARRIER();

        if ((readback & 0x1F80u) != 0x1F80u)
            suspicious = 1;
    }

    return suspicious;
}

// ---------------------------------------------------------------------------
// Check 3: RDTSC tight-loop consistency
//
// Two back-to-back RDTSC reads on real hardware yield a delta of roughly
// 20-100 cycles (serialized with LFENCE).  Emulators that fake or intercept
// RDTSC often produce:
//   - Exactly 0 delta (constant fake TSC)
//   - Huge jumps (> 500 cycles for 2 consecutive reads)
//   - Perfectly uniform deltas (no natural jitter)
//
// We sample multiple pairs and flag anomalies.
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE b32 ad_emu_rdtsc_consistency(void) {
    u64 t0, t1, t2, t3;
    u64 d0, d1, d2;
    b32 suspicious = 0;

    AD_LFENCE();
    t0 = __rdtsc();
    AD_LFENCE();
    t1 = __rdtsc();
    AD_LFENCE();
    t2 = __rdtsc();
    AD_LFENCE();
    t3 = __rdtsc();
    AD_LFENCE();

    d0 = t1 - t0;
    d1 = t2 - t1;
    d2 = t3 - t2;

    // Anomaly 1: any delta is exactly 0 -- TSC is faked/constant
    if (d0 == 0u || d1 == 0u || d2 == 0u)
        suspicious = 1;

    // Anomaly 2: any delta exceeds 100 cycles -- emulator overhead
    // Real LFENCE+RDTSC+LFENCE pair: ~20-80 cycles on modern Intel/AMD
    if (d0 > 100u || d1 > 100u || d2 > 100u)
        suspicious = 1;

    // Anomaly 3: all three deltas are perfectly identical -- no jitter
    // Real hardware always has some variation due to pipeline/cache state
    if (d0 == d1 && d1 == d2 && d0 > 0u)
        suspicious = 1;

    return suspicious;
}

// ---------------------------------------------------------------------------
// Check 4: undocumented instruction exception-code verification
//
// Execute an instruction known to fault on real hardware and verify the
// exception code.  Real x86/x64 CPUs generate STATUS_ILLEGAL_INSTRUCTION
// (0xC000001D) for truly undefined opcodes.  Some emulators either:
//   - Don't fault at all (silently NOP the instruction)
//   - Produce a different exception code (e.g., STATUS_ACCESS_VIOLATION)
//
// We use __ud2() intrinsic which generates UD2 (0F 0B) -- architecturally
// defined to always raise #UD.
// ---------------------------------------------------------------------------
#define AD_STATUS_ILLEGAL_INSTRUCTION  ((u32)0xC000001DuL)

ANTIDEBUG_INLINE b32 ad_emu_undocumented_insn(void) {
    b32 suspicious = 0;

    // --- Test 1: UD2 via __ud2() -- must raise EXCEPTION_ILLEGAL_INSTRUCTION ---
    {
        volatile b32 faulted = 0;
        volatile u32 exc_code = 0;

        __try {
            // UD2: guaranteed #UD on all x86/x64 CPUs
            __ud2();
            // If we reach here, the emulator swallowed UD2
        }
        __except (
            exc_code = ((AD_EMU_EXC_POINTERS*)GetExceptionInformation())
                            ->ExceptionRecord->ExceptionCode,
            EXCEPTION_EXECUTE_HANDLER
        ) {
            faulted = 1;
        }

        if (!faulted) {
            // UD2 did not fault -- emulator silently NOP'd it
            suspicious = 1;
        } else if (exc_code != AD_STATUS_ILLEGAL_INSTRUCTION) {
            // Faulted but with wrong exception code -- emulator artifact
            suspicious = 1;
        }
    }

    // --- Test 2: INT 2C -- debug service interrupt ---
    // On real hardware without a debugger, INT 2C raises
    // EXCEPTION_ASSERTION_FAILURE (0xC0000420) or STATUS_BREAKPOINT.
    // Some emulators either don't fault or produce wrong exception codes.
    {
        volatile b32 faulted2 = 0;

        __try {
            __int2c();
            // If we reach here without exception, something is very wrong
            faulted2 = 0;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            faulted2 = 1;
        }

        if (!faulted2) {
            // INT 2C produced no exception -- highly suspicious
            suspicious = 1;
        }
    }

    return suspicious;
}

// ---------------------------------------------------------------------------
// Master: composite emulation score
//
// Weights:  cpuid=3, fpu=4, rdtsc=2, undoc=3
// Total possible: 12
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE b32 ad_emu_master(void) {
    u32 score = 0;

    score += ad_emu_cpuid_check()        * 3u;
    score += ad_emu_fpu_check()          * 4u;
    score += ad_emu_rdtsc_consistency()  * 2u;
    score += ad_emu_undocumented_insn()  * 3u;

    AD_BARRIER();

    return (b32)(score > 0u);
}

#else  // Non-MSVC stubs

ANTIDEBUG_INLINE b32 ad_emu_cpuid_check(void)        { return 0; }
ANTIDEBUG_INLINE b32 ad_emu_fpu_check(void)           { return 0; }
ANTIDEBUG_INLINE b32 ad_emu_rdtsc_consistency(void)   { return 0; }
ANTIDEBUG_INLINE b32 ad_emu_undocumented_insn(void)   { return 0; }
ANTIDEBUG_INLINE b32 ad_emu_master(void)               { return 0; }

#endif // _MSC_VER

#endif // ANTIDEBUG_ANTI_EMULATION_H
