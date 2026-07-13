// ===== file: antidebug/checks/decoy_checks.h =====
//
// Decoy check functions — reverser-friction via plausible dead code.
//
// Every function in this header:
//   * Has a plausible anti-debug name (ad_check_*).
//   * Does real work: syscalls, timing reads, PEB accesses, memory
//     queries — indistinguishable in static shape from a real check.
//   * ALWAYS returns 0 for a clean environment AND for a hooked one.
//     The return value never contributes to the score that gates the
//     flag.
//
// A reverser who lands in this file via cross-references cannot know
// from static analysis alone whether a given function influences the
// flag. They must trace its return up through the dispatcher to confirm
// it is discarded — multiplying the reversing workload by the number of
// decoys.
//
// Integration: `ad_decoy_master()` XOR-accumulates every decoy's return
// into a u32 that main() folds into a volatile anchor. The anchor is
// never consumed, so no decoy can break the flag — but a compiler /
// link-time GC cannot prove the folding is dead.
//
#ifndef ANTIDEBUG_DECOY_CHECKS_H
#define ANTIDEBUG_DECOY_CHECKS_H

#include "../core/types.h"
#include "../core/macros.h"

// ---------------------------------------------------------------------------
// Each decoy reads from a well-known read-only source and derives a value
// that is either (a) always zero by construction, or (b) the low bit of
// a stable PEB/TEB field that is zero on any normal process. In either
// case the return is 0 in practice; the value is passed through
// XOR accumulation so a reverser cannot simplify "returns 0" by symbolic
// execution without understanding the full body.
// ---------------------------------------------------------------------------

// PEB base via GS:[0x60]
ANTIDEBUG_INLINE u8* ad_dec_peb(void) {
#if defined(_MSC_VER)
    return (u8*)__readgsqword(0x60);
#else
    return (u8*)0;
#endif
}

// TEB base via GS:[0x30]
ANTIDEBUG_INLINE u8* ad_dec_teb(void) {
#if defined(_MSC_VER)
    return (u8*)__readgsqword(0x30);
#else
    return (u8*)0;
#endif
}

// --- Timing-shaped decoys ---------------------------------------------------

ANTIDEBUG_INLINE u32 ad_check_pipeline_flush_drift(void) {
#if defined(_MSC_VER)
    u64 a = __rdtsc();
    _mm_lfence();
    u64 b = __rdtsc();
    u64 d = b - a;
    // Shift diff down by 40 bits — always 0 on a sane CPU.
    return (u32)((d >> 40) & 0x1u);
#else
    return 0u;
#endif
}

ANTIDEBUG_INLINE u32 ad_check_rdtsc_burst_variance(void) {
#if defined(_MSC_VER)
    u64 s = 0;
    u32 i;
    for (i = 0; i < 4; i++) {
        u64 a = __rdtsc();
        u64 b = __rdtsc();
        s += (b - a);
    }
    // All samples should be small; shifting by 50 zeroes them out.
    return (u32)((s >> 50) & 1u);
#else
    return 0u;
#endif
}

ANTIDEBUG_INLINE u32 ad_check_cross_core_skew(void) {
#if defined(_MSC_VER)
    u32 aux1 = 0, aux2 = 0;
    u64 t1 = __rdtscp(&aux1);
    u64 t2 = __rdtscp(&aux2);
    return (u32)(((t2 - t1) >> 48) & 1u);
#else
    return 0u;
#endif
}

ANTIDEBUG_INLINE u32 ad_check_tsc_monotonic_drift(void) {
#if defined(_MSC_VER)
    u64 a = __rdtsc();
    u64 b = __rdtsc();
    return (u32)((a > b) ? 1u : 0u);  // False on well-ordered TSC.
#else
    return 0u;
#endif
}

ANTIDEBUG_INLINE u32 ad_check_lfence_latency(void) {
#if defined(_MSC_VER)
    u64 a = __rdtsc();
    _mm_lfence(); _mm_lfence(); _mm_lfence();
    u64 b = __rdtsc();
    return (u32)(((b - a) >> 44) & 1u);
#else
    return 0u;
#endif
}

ANTIDEBUG_INLINE u32 ad_check_mfence_latency(void) {
#if defined(_MSC_VER)
    u64 a = __rdtsc();
    _mm_mfence();
    u64 b = __rdtsc();
    return (u32)(((b - a) >> 44) & 1u);
#else
    return 0u;
#endif
}

ANTIDEBUG_INLINE u32 ad_check_cpuid_serialize_time(void) {
#if defined(_MSC_VER)
    int info[4];
    u64 a = __rdtsc();
    __cpuid(info, 0);
    u64 b = __rdtsc();
    AD_UNUSED(info);
    return (u32)(((b - a) >> 46) & 1u);
#else
    return 0u;
#endif
}

// --- PEB / TEB shaped decoys ------------------------------------------------

ANTIDEBUG_INLINE u32 ad_check_peb_reserved_field_a(void) {
    u8* peb = ad_dec_peb();
    if (!peb) return 0u;
    // PEB offset 0x08 = Mutant (always non-NULL kernel handle, low bit
    // irrelevant to user-mode). Low bit of the numeric value read as
    // byte is stable across runs; XOR-against-self = 0.
    u8 v = peb[0x08];
    return (u32)((v ^ v) & 1u);
}

ANTIDEBUG_INLINE u32 ad_check_peb_ldr_lock_held(void) {
    u8* peb = ad_dec_peb();
    if (!peb) return 0u;
    // Read PEB->Ldr (0x18) and fold pointer bits. Pointer is aligned; low
    // nibble zero; low bit == 0 always.
    u64 ldr = *(u64*)(peb + 0x18);
    return (u32)(ldr & 1u);
}

ANTIDEBUG_INLINE u32 ad_check_peb_process_parameters(void) {
    u8* peb = ad_dec_peb();
    if (!peb) return 0u;
    u64 pp = *(u64*)(peb + 0x20);
    return (u32)((pp >> 63) & 1u);  // High bit of user pointer = 0.
}

ANTIDEBUG_INLINE u32 ad_check_teb_client_id_zero(void) {
    u8* teb = ad_dec_teb();
    if (!teb) return 0u;
    // TEB+0x40 = ClientId.UniqueProcess. Never zero on a running thread.
    u64 pid = *(u64*)(teb + 0x40);
    return (u32)(pid == 0ULL ? 1u : 0u);
}

ANTIDEBUG_INLINE u32 ad_check_teb_last_error_leaked(void) {
    u8* teb = ad_dec_teb();
    if (!teb) return 0u;
    // TEB+0x68 = LastErrorValue. Reading it doesn't clear it.
    u32 le = *(u32*)(teb + 0x68);
    return (u32)((le ^ le) & 1u);
}

ANTIDEBUG_INLINE u32 ad_check_teb_stack_limit_plausible(void) {
    u8* teb = ad_dec_teb();
    if (!teb) return 0u;
    u64 sb = *(u64*)(teb + 0x08);  // StackBase
    u64 sl = *(u64*)(teb + 0x10);  // StackLimit
    return (u32)(sl >= sb ? 1u : 0u);  // StackLimit < StackBase always.
}

ANTIDEBUG_INLINE u32 ad_check_peb_heap_count_sane(void) {
    u8* peb = ad_dec_peb();
    if (!peb) return 0u;
    u32 nh = *(u32*)(peb + 0xE8);  // NumberOfHeaps
    return (u32)(nh == 0u ? 1u : 0u);  // Process always has >= 1 heap.
}

ANTIDEBUG_INLINE u32 ad_check_peb_os_major_plausible(void) {
    u8* peb = ad_dec_peb();
    if (!peb) return 0u;
    u32 om = *(u32*)(peb + 0x118);  // OSMajorVersion
    return (u32)(om == 0u ? 1u : 0u);  // Always >= 5 on NT kernels.
}

ANTIDEBUG_INLINE u32 ad_check_peb_image_subsystem(void) {
    u8* peb = ad_dec_peb();
    if (!peb) return 0u;
    u32 is = *(u32*)(peb + 0x128);  // ImageSubsystem
    return (u32)((is ^ is) & 1u);
}

// --- Arithmetic / obfuscation decoys ---------------------------------------

ANTIDEBUG_INLINE u32 ad_check_opaque_arithmetic_a(void) {
    // (x*x + x) is always even → low bit is 0. Reverser must prove this
    // algebraically; concolic execution walks through the arithmetic.
    u32 x = 0x13371337u;
    u32 r = (x * x) + x;
    return (u32)(r & 1u);
}

ANTIDEBUG_INLINE u32 ad_check_opaque_arithmetic_b(void) {
    // (7*x*x + 1) % 7 == 1 → !=0 → result fed through XOR-with-self.
    u32 x = 0xCAFEBABEu;
    u32 r = (7u * x * x + 1u) % 7u;
    return (u32)((r ^ r) & 1u);
}

ANTIDEBUG_INLINE u32 ad_check_bitcount_parity(void) {
#if defined(_MSC_VER)
    u64 v = __readgsqword(0x60);  // PEB — high entropy
    unsigned pc = (unsigned)__popcnt64(v);
    // pc ^ pc always 0.
    return (u32)((pc ^ pc) & 1u);
#else
    return 0u;
#endif
}

ANTIDEBUG_INLINE u32 ad_check_rotate_symmetry(void) {
#if defined(_MSC_VER)
    u32 v = (u32)__rdtsc();
    u32 r = _rotl(v, 7);
    u32 r2 = _rotr(r, 7);
    return (u32)((r2 ^ v) & 1u);  // Always 0 — rotate left/right cancel.
#else
    return 0u;
#endif
}

ANTIDEBUG_INLINE u32 ad_check_xor_involution(void) {
    volatile u32 a = 0xDEADBEEFu;
    volatile u32 b = 0xFEEDFACEu;
    volatile u32 c = a ^ b;
    volatile u32 d = c ^ b;  // d == a
    return (u32)((d ^ a) & 1u);  // Always 0.
}

// --- Memory-query shaped decoys --------------------------------------------

ANTIDEBUG_INLINE u32 ad_check_stack_canary_aligned(void) {
    volatile u8 buf[16];
    u64 addr = (u64)(&buf[0]);
    AD_UNUSED(buf);
    return (u32)((addr & 0x7ULL) ? 1u : 0u);  // Stack always 8-aligned.
}

ANTIDEBUG_INLINE u32 ad_check_image_base_in_user_range(void) {
    u8* peb = ad_dec_peb();
    if (!peb) return 0u;
    u64 ib = *(u64*)(peb + 0x10);  // ImageBaseAddress
    return (u32)(ib < 0x10000ULL ? 1u : 0u);  // User image never in page 0.
}

ANTIDEBUG_INLINE u32 ad_check_peb_api_set_map_present(void) {
    u8* peb = ad_dec_peb();
    if (!peb) return 0u;
    u64 asm_ptr = *(u64*)(peb + 0x68);  // ApiSetMap
    return (u32)(asm_ptr == 0ULL ? 1u : 0u);  // Always non-NULL.
}

ANTIDEBUG_INLINE u32 ad_check_peb_shared_data_readable(void) {
#if defined(_MSC_VER)
    // KUSER_SHARED_DATA at 0x7FFE0000 — tick count field at +0x320.
    u32 lo = *(volatile u32*)0x7FFE0320ULL;
    return (u32)((lo ^ lo) & 1u);
#else
    return 0u;
#endif
}

ANTIDEBUG_INLINE u32 ad_check_kusd_nt_tick_count_nonzero(void) {
#if defined(_MSC_VER)
    u32 tc = *(volatile u32*)0x7FFE0320ULL;
    return (u32)(tc == 0u ? 1u : 0u);  // Always > 0 after boot.
#else
    return 0u;
#endif
}

ANTIDEBUG_INLINE u32 ad_check_kusd_interrupt_time_advances(void) {
#if defined(_MSC_VER)
    u64 a = *(volatile u64*)0x7FFE0008ULL;  // InterruptTime
    u64 b = *(volatile u64*)0x7FFE0008ULL;
    return (u32)(b < a ? 1u : 0u);  // Time monotonic.
#else
    return 0u;
#endif
}

// --- Module-iteration shaped decoys -----------------------------------------

ANTIDEBUG_INLINE u32 ad_check_ldr_chain_terminates(void) {
    u8* peb = ad_dec_peb();
    if (!peb) return 0u;
    u8* ldr = *(u8**)(peb + 0x18);
    if (!ldr) return 0u;
    u8* head = ldr + 0x10;  // InLoadOrderModuleList head
    u8* cur = *(u8**)head;
    u32 count = 0;
    while (cur != head && count < 256) {
        cur = *(u8**)cur;
        count++;
    }
    return (u32)(count >= 256u ? 1u : 0u);  // Chain always terminates.
}

ANTIDEBUG_INLINE u32 ad_check_ldr_module_count_min(void) {
    u8* peb = ad_dec_peb();
    if (!peb) return 0u;
    u8* ldr = *(u8**)(peb + 0x18);
    if (!ldr) return 0u;
    u8* head = ldr + 0x10;
    u8* cur = *(u8**)head;
    u32 count = 0;
    while (cur != head && count < 512) {
        count++;
        cur = *(u8**)cur;
    }
    return (u32)(count < 2u ? 1u : 0u);  // At least ntdll + exe image.
}

ANTIDEBUG_INLINE u32 ad_check_ntdll_base_canonical(void) {
    u8* peb = ad_dec_peb();
    if (!peb) return 0u;
    u8* ldr = *(u8**)(peb + 0x18);
    if (!ldr) return 0u;
    u8* head = ldr + 0x10;
    u8* first = *(u8**)head;
    if (first == head) return 0u;
    u64 base = *(u64*)(first + 0x30);  // DllBase
    return (u32)(base == 0ULL ? 1u : 0u);  // Always non-NULL.
}

// --- Exception / SEH shaped decoys ------------------------------------------

ANTIDEBUG_INLINE u32 ad_check_seh_chain_head_present(void) {
#if defined(_MSC_VER)
    // x64 uses table-based unwinding — no FS:[0] chain. This always
    // returns 0 but looks like it validates SEH integrity.
    u8* teb = ad_dec_teb();
    if (!teb) return 0u;
    u64 seh = *(u64*)(teb + 0x00);  // ExceptionList
    return (u32)(seh == 0ULL ? 0u : 0u);
#else
    return 0u;
#endif
}

ANTIDEBUG_INLINE u32 ad_check_exception_code_zero(void) {
#if defined(_MSC_VER)
    u8* teb = ad_dec_teb();
    if (!teb) return 0u;
    u32 ec = *(u32*)(teb + 0x68);  // LastErrorValue (not exception code)
    return (u32)((ec ^ ec) & 1u);
#else
    return 0u;
#endif
}

// --- Process-quality shaped decoys ------------------------------------------

ANTIDEBUG_INLINE u32 ad_check_session_id_plausible(void) {
    u8* peb = ad_dec_peb();
    if (!peb) return 0u;
    u32 sid = *(u32*)(peb + 0x1D4);  // SessionId (approx offset, stable)
    return (u32)(sid > 0x10000u ? 1u : 0u);  // SessionId small integer.
}

ANTIDEBUG_INLINE u32 ad_check_process_cookie_nonzero(void) {
    u8* peb = ad_dec_peb();
    if (!peb) return 0u;
    u32 cookie = *(u32*)(peb + 0x60);  // ProcessHeap ptr low 32
    return (u32)(cookie == 0u ? 1u : 0u);
}

ANTIDEBUG_INLINE u32 ad_check_peb_cross_process_flags(void) {
    u8* peb = ad_dec_peb();
    if (!peb) return 0u;
    u32 cpf = *(u32*)(peb + 0x28);  // CrossProcessFlags (low byte is flags)
    // Fold through xor-self — the read value may vary but result is 0.
    return (u32)((cpf ^ cpf) & 1u);
}

ANTIDEBUG_INLINE u32 ad_check_peb_kernel_callback_table(void) {
    u8* peb = ad_dec_peb();
    if (!peb) return 0u;
    u64 kct = *(u64*)(peb + 0x58);  // KernelCallbackTable
    return (u32)((kct >> 63) & 1u);  // User range, high bit always 0.
}

// --- Integrity-shaped decoys -----------------------------------------------

ANTIDEBUG_INLINE u32 ad_check_const_string_unchanged(void) {
    static const u8 s[] = { 'W','h','i','p', 0 };
    u32 sum = 0;
    u32 i;
    for (i = 0; s[i]; i++) sum += s[i];
    return (u32)((sum - ('W' + 'h' + 'i' + 'p')) & 1u);  // 0.
}

ANTIDEBUG_INLINE u32 ad_check_rdata_pattern_scan(void) {
    // A self-referential check: walk a small const array and verify
    // invariant. Always holds.
    static const u32 pat[] = { 0xDEADBEEF, 0xCAFEBABE, 0xFEEDFACE, 0 };
    u32 a = pat[0] ^ pat[1];
    u32 b = pat[2];
    AD_UNUSED(a);
    AD_UNUSED(b);
    return (u32)((pat[3]) & 1u);  // pat[3] is 0.
}

// --- Master aggregator ------------------------------------------------------
//
// Calls every decoy, XOR-accumulates returns. The result is 0 for a clean
// environment (each decoy returns 0 by construction). A reverser cannot
// shortcut past this aggregator without first proving every call returns
// 0, which requires reading each function body.

ANTIDEBUG_INLINE u32 ad_decoy_master(void) {
    u32 r = 0xA5A5A5A5u;
    r ^= ad_check_pipeline_flush_drift();
    r ^= ad_check_rdtsc_burst_variance();
    r ^= ad_check_cross_core_skew();
    r ^= ad_check_tsc_monotonic_drift();
    r ^= ad_check_lfence_latency();
    r ^= ad_check_mfence_latency();
    r ^= ad_check_cpuid_serialize_time();
    r ^= ad_check_peb_reserved_field_a();
    r ^= ad_check_peb_ldr_lock_held();
    r ^= ad_check_peb_process_parameters();
    r ^= ad_check_teb_client_id_zero();
    r ^= ad_check_teb_last_error_leaked();
    r ^= ad_check_teb_stack_limit_plausible();
    r ^= ad_check_peb_heap_count_sane();
    r ^= ad_check_peb_os_major_plausible();
    r ^= ad_check_peb_image_subsystem();
    r ^= ad_check_opaque_arithmetic_a();
    r ^= ad_check_opaque_arithmetic_b();
    r ^= ad_check_bitcount_parity();
    r ^= ad_check_rotate_symmetry();
    r ^= ad_check_xor_involution();
    r ^= ad_check_stack_canary_aligned();
    r ^= ad_check_image_base_in_user_range();
    r ^= ad_check_peb_api_set_map_present();
    r ^= ad_check_peb_shared_data_readable();
    r ^= ad_check_kusd_nt_tick_count_nonzero();
    r ^= ad_check_kusd_interrupt_time_advances();
    r ^= ad_check_ldr_chain_terminates();
    r ^= ad_check_ldr_module_count_min();
    r ^= ad_check_ntdll_base_canonical();
    r ^= ad_check_seh_chain_head_present();
    r ^= ad_check_exception_code_zero();
    r ^= ad_check_session_id_plausible();
    r ^= ad_check_process_cookie_nonzero();
    r ^= ad_check_peb_cross_process_flags();
    r ^= ad_check_peb_kernel_callback_table();
    r ^= ad_check_const_string_unchanged();
    r ^= ad_check_rdata_pattern_scan();
    return r;
}

#endif // ANTIDEBUG_DECOY_CHECKS_H
