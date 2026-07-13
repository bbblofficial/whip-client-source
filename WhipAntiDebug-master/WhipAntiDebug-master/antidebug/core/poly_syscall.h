// ===== file: antidebug/core/poly_syscall.h =====
//
// Polymorphic Syscall Gadgets — defeat pattern-based hook of SyscallStub.
//
// Threat model
// ------------
// A reverser scans our image for `0F 05` (syscall opcode) or for a
// fingerprint of WhipSysCall's SyscallStub. Once located, a single hook
// intercepts every syscall we issue.
//
// Mitigations in this file
// ------------------------
// T1 — Per-instruction polymorphism (always on)
//    • 5 reg→reg moves each have 2 semantically-equivalent encodings
//      (MR vs RM form) chosen per gadget from a 32-bit seed.
//    • Each of the 7 stack-arg shifts picks its scratch register
//      independently from {r10, r11}. That gives 2^7 = 128 shift layouts.
//    • Multi-byte NOPs (lengths 1..9) of varying encoding are dispersed
//      between every real instruction so no byte run > 3 is stable.
//    • Random NOP sled before entry (0..45 bytes) — entry offset varies.
//    • Random junk suffix after `ret` — page fingerprint varies.
//
// T2 — Decoy pages (always on)
//    Additional pages are allocated and built with the same poly builder
//    but their entry points are NEVER exposed. `findallmem 0F05C3` yields
//    (count + decoy_count) hits; the analyst must execute each candidate
//    to find the real ones. Decoys also tolerate being hooked — breaking
//    them costs the attacker nothing.
//
// T3 — JIT opcode reveal (opt-in: AD_ENABLE_POLY_JIT)
//    At rest the two-byte `0F 05` is stored as `90 90` (nop nop). A
//    pattern scan for `0F 05` inside our gadget pages returns zero hits.
//    Before each real call we:
//       1. flip the target page to RW
//       2. patch `90 90` → `0F 05`
//       3. flip back to RX
//       4. execute
//       5. flip to RW, restore `90 90`
//       6. flip to RX
//    Cost: 4 extra syscalls per real syscall. A global spinlock
//    serializes prime/unprime across threads. The 4 support syscalls go
//    through SyscallStub (WhipSysCall) which still has its own `0F 05`,
//    so this shrinks the attack surface from N gadgets to one stub.
//
// T4 — Encrypted pointer dispatch (always on)
//    Gadget function pointers are stored XORed with a runtime key. Static
//    memory scans of our data segment cannot recover raw addresses
//    without also understanding the scheme and reading the key.
//
// Page layout (per real gadget and per decoy)
// -------------------------------------------
//   [offset 0x000] random NOP sled        (0..45 bytes)
//   [entry_off]    gadget prologue + shifts + syscall + ret
//   [...]          random junk tail
//   [offset 0xFF0] entry_off   (u32, little-endian)
//   [offset 0xFF4] syscall_off (u32) — offset of the `0F 05` (or `90 90`)
//
// The two u32 at 0xFF0/0xFF4 are metadata read by init/prime; they live
// in the page tail which is never executed.
//
#ifndef ANTIDEBUG_POLY_SYSCALL_H
#define ANTIDEBUG_POLY_SYSCALL_H

#include "types.h"
#include "macros.h"
#include "syscall_bridge.h"
#include "string_encrypt.h"

#if defined(_MSC_VER)

// ---------------------------------------------------------------------------
// Compile-time tunables
// ---------------------------------------------------------------------------
#ifndef AD_POLY_GADGET_COUNT
#  define AD_POLY_GADGET_COUNT    16u
#endif
#ifndef AD_POLY_DECOY_COUNT
#  define AD_POLY_DECOY_COUNT     32u
#endif
#ifndef AD_POLY_PAGE_SIZE
#  define AD_POLY_PAGE_SIZE       0x1000ULL
#endif

// T3 opt-in: JIT opcode reveal. Costs ~4 extra syscalls per real syscall.
// Undefine (or set to 0) for lower overhead; defined enables.
// #define AD_ENABLE_POLY_JIT

// T5 opt-in: transient per-call gadget. Allocates a fresh page for each
// syscall, executes, frees. New address every call → hook-by-address is
// impossible. Cost: 3 support syscalls/call (alloc + protect + free)
// which go through SyscallStub. Mutually redundant with T3.
// #define AD_ENABLE_POLY_TRANSIENT

// T6 — always on. Count of RW-only (non-executable) decoy pages that
// contain gadget-shaped bytes + many `0F 05 C3` sequences. A pattern
// scan hits them; a hook cannot attach since the pages aren't RX.
#ifndef AD_POLY_DATA_DECOY_COUNT
#  define AD_POLY_DATA_DECOY_COUNT 16u
#endif

// ---------------------------------------------------------------------------
// Metadata offsets inside each page (read-only at runtime)
// ---------------------------------------------------------------------------
#define AD_POLY_META_ENTRY    0xFF0u
#define AD_POLY_META_SYSOFF   0xFF4u

// ---------------------------------------------------------------------------
// Gadget call signature — identical to SyscallStub so call sites do not
// change when switching between direct and poly dispatch.
// ---------------------------------------------------------------------------
typedef void* (*ad_poly_gadget_fn)(
    u16   ssn,
    void* a1,  void* a2,  void* a3,  void* a4,
    void* a5,  void* a6,  void* a7,  void* a8,
    void* a9,  void* a10, void* a11
);

typedef struct {
    // Encrypted tables (T4) — XORed with g_poly.key.
    u64 pages_enc   [AD_POLY_GADGET_COUNT];
    u64 gadgets_enc [AD_POLY_GADGET_COUNT];
    u64 sysoff_enc  [AD_POLY_GADGET_COUNT];   // only used when AD_ENABLE_POLY_JIT
    u64 key;

    // Decoys — tracked for cleanup but never exposed for call.
    void* decoys[AD_POLY_DECOY_COUNT];
    u32   decoy_count;

    // Data-section decoys (T6). RW pages containing gadget-shaped bytes
    // with embedded `0F 05 C3` sequences. Tracked for cleanup only.
    void* data_decoys[AD_POLY_DATA_DECOY_COUNT];
    u32   data_decoy_count;

    // Cached SSNs for transient / JIT support paths.
    u16   ssn_alloc;
    u16   ssn_prot;
    u16   ssn_free;

    // Real gadget count (may be < AD_POLY_GADGET_COUNT if alloc failed).
    u32   count;

    // PRNG state.
    volatile u32 rng_state;

    // Global spinlock for JIT prime/unprime (T3). 0 = free, 1 = held.
    volatile long jit_lock;
} ad_poly_ctx_t;

static ad_poly_ctx_t g_poly = {0};

// ---------------------------------------------------------------------------
// xorshift32 PRNG
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE u32 ad_poly_rng(void) {
    u32 s = g_poly.rng_state;
    if (s == 0u) s = 0xA5A5A5A5u;
    s ^= s << 13; s ^= s >> 17; s ^= s << 5;
    g_poly.rng_state = s;
    return s;
}

// ---------------------------------------------------------------------------
// Multi-byte NOP emission. Produces a register-neutral, flag-neutral
// sequence of `min_len..max_len` bytes. All encodings below are Intel
// reserved multi-byte NOPs that explicitly do not access memory.
// Returns bytes written.
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE u32 ad_poly_emit_nop_run(u8* page, u32 off, u32 min_len, u32 max_len, u32 seed) {
    u32 written = 0u;
    u32 target  = min_len;
    if (max_len > min_len) {
        target = min_len + ((seed >> 3) % ((max_len - min_len) + 1u));
    }
    while (written < target) {
        u32 remaining = target - written;
        u32 pick = (seed ^ (written * 0x9E37u)) & 7u;
        // Map pick to NOP length in [1..9] but clamp to remaining bytes.
        static const u8 nop1[] = { 0x90 };
        static const u8 nop2[] = { 0x66, 0x90 };
        static const u8 nop3[] = { 0x0F, 0x1F, 0x00 };
        static const u8 nop4[] = { 0x0F, 0x1F, 0x40, 0x00 };
        static const u8 nop5[] = { 0x0F, 0x1F, 0x44, 0x00, 0x00 };
        static const u8 nop6[] = { 0x66, 0x0F, 0x1F, 0x44, 0x00, 0x00 };
        static const u8 nop7[] = { 0x0F, 0x1F, 0x80, 0x00, 0x00, 0x00, 0x00 };
        static const u8 nop8[] = { 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00 };
        static const u8 nop9[] = { 0x66, 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00 };

        const u8* src; u32 len;
        switch (pick) {
            case 0: src = nop1; len = 1; break;
            case 1: src = nop2; len = 2; break;
            case 2: src = nop3; len = 3; break;
            case 3: src = nop4; len = 4; break;
            case 4: src = nop5; len = 5; break;
            case 5: src = nop6; len = 6; break;
            case 6: src = nop7; len = 7; break;
            default: src = nop8; len = 8; break;
        }
        if (remaining >= 9u && pick == 7u) { src = nop9; len = 9; }
        // CRITICAL: never truncate a multi-byte NOP. The multi-byte NOP
        // encodings are { 0F 1F /r ... } with a ModRM/SIB/disp tail; cutting
        // them short leaves a partial-instruction prefix that the decoder
        // then completes with whatever bytes follow (subsequent emit, page
        // junk, or zero-padding). On unlucky seeds the truncated prefix
        // consumed real `mov` opcodes that came immediately after, so
        // RCX/RDX/etc were never set up and the gadget AV'd at the
        // syscall. If the chosen NOP doesn't fit the remaining slot, fall
        // back to single-byte 0x90s — always self-contained, never
        // misaligns the decoder.
        if (len > remaining) {
            u32 i;
            for (i = 0; i < remaining; i++) page[off + written + i] = 0x90;
            written += remaining;
            seed = (seed * 1103515245u) + 12345u;
            continue;
        }
        u32 i;
        for (i = 0; i < len; i++) page[off + written + i] = src[i];
        written += len;
        seed = (seed * 1103515245u) + 12345u;
    }
    return written;
}

// Emit a short junk run between real instructions — length 0..6 bytes.
ANTIDEBUG_INLINE u32 ad_poly_emit_junk(u8* page, u32 off, u32 seed) {
    u32 n = seed & 7u;              // 0..7 target length
    if (n > 6u) n = 6u;
    if (n == 0u) return 0u;
    return ad_poly_emit_nop_run(page, off, n, n, seed);
}

// ---------------------------------------------------------------------------
// Emit one of the five reg→reg moves with two encoding variants.
// Both variants produce identical semantics and identical byte length.
// mov_id selects the instruction; variant (0/1) selects the encoding.
// ---------------------------------------------------------------------------
// 0: mov eax, ecx      — 89 C8 | 8B C1            (2 bytes)
// 1: mov rcx, rdx      — 48 89 D1 | 48 8B CA      (3 bytes)
// 2: mov rdx, r8       — 4C 89 C2 | 49 8B D0      (3 bytes)
// 3: mov r8, r9        — 4D 89 C8 | 4D 8B C1      (3 bytes)
// 4: mov r10, rcx      — 49 89 CA | 4C 8B D1      (3 bytes)
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE u32 ad_poly_emit_mov(u8* page, u32 off, u32 mov_id, u32 variant) {
    variant &= 1u;
    switch (mov_id) {
        case 0: // mov eax, ecx
            if (variant == 0u) { page[off++] = 0x89; page[off++] = 0xC8; }
            else               { page[off++] = 0x8B; page[off++] = 0xC1; }
            return 2u;
        case 1: // mov rcx, rdx
            page[off++] = 0x48;
            if (variant == 0u) { page[off++] = 0x89; page[off++] = 0xD1; }
            else               { page[off++] = 0x8B; page[off++] = 0xCA; }
            return 3u;
        case 2: // mov rdx, r8
            if (variant == 0u) { page[off++] = 0x4C; page[off++] = 0x89; page[off++] = 0xC2; }
            else               { page[off++] = 0x49; page[off++] = 0x8B; page[off++] = 0xD0; }
            return 3u;
        case 3: // mov r8, r9
            page[off++] = 0x4D;
            if (variant == 0u) { page[off++] = 0x89; page[off++] = 0xC8; }
            else               { page[off++] = 0x8B; page[off++] = 0xC1; }
            return 3u;
        case 4: // mov r10, rcx
            if (variant == 0u) { page[off++] = 0x49; page[off++] = 0x89; page[off++] = 0xCA; }
            else               { page[off++] = 0x4C; page[off++] = 0x8B; page[off++] = 0xD1; }
            return 3u;
        default: return 0u;
    }
}

// Emit one stack-shift pair with chosen scratch register (r10 or r11).
// scratch = 0 → r10 (ModRM reg=010 → 0x54)
// scratch = 1 → r11 (ModRM reg=011 → 0x5C)
//
// mov scratch, [rsp + src_disp]
// mov [rsp + dst_disp], scratch
ANTIDEBUG_INLINE u32 ad_poly_emit_shift(u8* page, u32 off, u32 scratch, u8 src_disp, u8 dst_disp) {
    u8 modrm = (scratch & 1u) ? (u8)0x5C : (u8)0x54;
    // load: 4C 8B <modrm> 24 <disp8>
    page[off++] = 0x4C; page[off++] = 0x8B; page[off++] = modrm; page[off++] = 0x24; page[off++] = src_disp;
    // store: 4C 89 <modrm> 24 <disp8>
    page[off++] = 0x4C; page[off++] = 0x89; page[off++] = modrm; page[off++] = 0x24; page[off++] = dst_disp;
    return 10u;
}

// ---------------------------------------------------------------------------
// Build a full polymorphic gadget. jit_mode=1 stores `90 90` instead of
// `0F 05` at the syscall position (T3).
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE void ad_poly_build_gadget(u8* page, u32 seed, u32 jit_mode) {
    u32 off = 0;

    // Zero the metadata zone so stale data from a previous build cannot
    // mislead a subsequent prime.
    *(u32*)(page + AD_POLY_META_ENTRY)  = 0u;
    *(u32*)(page + AD_POLY_META_SYSOFF) = 0u;

    // ── Random NOP sled prefix: 0..45 bytes of varied multi-byte NOPs ──
    u32 sled_len = ((seed >> 4) & 0x3Fu);        // 0..63
    if (sled_len > 45u) sled_len = 45u;
    off += ad_poly_emit_nop_run(page, off, sled_len, sled_len, seed ^ 0xA1u);

    // Entry point for the callable gadget.
    u32 entry_off = off;

    // Variant selection — 5 one-bit variant flags + 7 scratch flags.
    u32 v = seed;
    u32 var_mov0 = (v >> 0) & 1u;
    u32 var_mov1 = (v >> 1) & 1u;
    u32 var_mov2 = (v >> 2) & 1u;
    u32 var_mov3 = (v >> 3) & 1u;
    u32 var_mov4 = (v >> 20) & 1u;
    u32 sc0 = (v >> 10) & 1u;
    u32 sc1 = (v >> 11) & 1u;
    u32 sc2 = (v >> 12) & 1u;
    u32 sc3 = (v >> 13) & 1u;
    u32 sc4 = (v >> 14) & 1u;
    u32 sc5 = (v >> 15) & 1u;
    u32 sc6 = (v >> 16) & 1u;

    // mov eax, ecx   (SSN from RCX)
    off += ad_poly_emit_mov(page, off, 0, var_mov0);
    off += ad_poly_emit_junk(page, off, seed ^ 0x11u);

    // mov rcx, rdx   (a1 → RCX). After this point RCX must NOT be
    // overwritten until the final `mov r10, rcx`.
    off += ad_poly_emit_mov(page, off, 1, var_mov1);
    off += ad_poly_emit_junk(page, off, seed ^ 0x22u);

    // mov rdx, r8    (a2 → RDX)
    off += ad_poly_emit_mov(page, off, 2, var_mov2);
    off += ad_poly_emit_junk(page, off, seed ^ 0x33u);

    // mov r8, r9     (a3 → R8)
    off += ad_poly_emit_mov(page, off, 3, var_mov3);
    off += ad_poly_emit_junk(page, off, seed ^ 0x44u);

    // mov r9, [rsp+0x28]  (a4 → R9). Single form: 4C 8B 4C 24 28.
    page[off++] = 0x4C; page[off++] = 0x8B; page[off++] = 0x4C;
    page[off++] = 0x24; page[off++] = 0x28;
    off += ad_poly_emit_junk(page, off, seed ^ 0x55u);

    // ── 7 stack-arg shifts. Each independently chooses r10 or r11 as
    // scratch. Junk inserted between pairs (never mid-pair) to preserve
    // the load/store ordering.
    off += ad_poly_emit_shift(page, off, sc0, 0x30, 0x28);
    off += ad_poly_emit_junk (page, off, seed ^ 0x61u);
    off += ad_poly_emit_shift(page, off, sc1, 0x38, 0x30);
    off += ad_poly_emit_junk (page, off, seed ^ 0x62u);
    off += ad_poly_emit_shift(page, off, sc2, 0x40, 0x38);
    off += ad_poly_emit_junk (page, off, seed ^ 0x63u);
    off += ad_poly_emit_shift(page, off, sc3, 0x48, 0x40);
    off += ad_poly_emit_junk (page, off, seed ^ 0x64u);
    off += ad_poly_emit_shift(page, off, sc4, 0x50, 0x48);
    off += ad_poly_emit_junk (page, off, seed ^ 0x65u);
    off += ad_poly_emit_shift(page, off, sc5, 0x58, 0x50);
    off += ad_poly_emit_junk (page, off, seed ^ 0x66u);
    off += ad_poly_emit_shift(page, off, sc6, 0x60, 0x58);
    off += ad_poly_emit_junk (page, off, seed ^ 0x67u);

    // mov r10, rcx — syscall ABI requires R10 == RCX.
    off += ad_poly_emit_mov(page, off, 4, var_mov4);

    // Record where the `syscall` bytes land. In JIT mode they are `90 90`
    // at rest and get patched to `0F 05` only during a live call.
    u32 syscall_off = off;
    if (jit_mode) {
        page[off++] = 0x90; page[off++] = 0x90;
    } else {
        page[off++] = 0x0F; page[off++] = 0x05;
    }
    page[off++] = 0xC3;  // ret

    // Random junk suffix — pad out to a random point in the page body so
    // the tail doesn't line up with other gadgets either.
    u32 tail_target = off + ((seed >> 6) & 0x7Fu);   // up to 127 extra bytes
    if (tail_target > AD_POLY_META_ENTRY - 8u) {
        tail_target = AD_POLY_META_ENTRY - 8u;
    }
    while (off < tail_target) {
        page[off] = (u8)((seed ^ (off * 0x6Bu)) & 0xFFu);
        off++;
    }

    // Metadata block — read by init (entry_off) and prime/unprime (syscall_off).
    *(u32*)(page + AD_POLY_META_ENTRY)  = entry_off;
    *(u32*)(page + AD_POLY_META_SYSOFF) = syscall_off;
}

// ---------------------------------------------------------------------------
// Allocate one RW page via NtAllocateVirtualMemory, build a gadget into
// it, flip to PAGE_EXECUTE_READ. On any failure the page is freed and
// (void*)0 is returned. Pages are never left in RWX state.
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE void* ad_poly_alloc_one(u16 ssn_alloc, u16 ssn_prot, u16 ssn_free,
                                        u32 seed, u32 jit_mode) {
    void* page = (void*)0;
    u64   size = AD_POLY_PAGE_SIZE;
    ad_ntstatus_t st = AD_SYSCALL6(ssn_alloc,
        AD_CURRENT_PROCESS, &page, (u64)0, &size,
        (u64)(0x1000UL | 0x2000UL),   // MEM_COMMIT | MEM_RESERVE
        (u64)0x04UL);                  // PAGE_READWRITE
    if (!AD_NT_SUCCESS(st) || !page) return (void*)0;

    ad_poly_build_gadget((u8*)page, seed, jit_mode);

    void* pb = page;
    u64   ps = AD_POLY_PAGE_SIZE;
    u32   old = 0;
    ad_ntstatus_t pst = AD_SYSCALL5(ssn_prot, AD_CURRENT_PROCESS, &pb, &ps,
        (u64)0x20UL, &old);            // PAGE_EXECUTE_READ
    if (!AD_NT_SUCCESS(pst)) {
        void* fb = page; u64 fs = 0;
        (void)AD_SYSCALL4(ssn_free, AD_CURRENT_PROCESS, &fb, &fs, (u64)0x8000UL);
        return (void*)0;
    }
    return page;
}

// ---------------------------------------------------------------------------
// T6 — Build a data-section decoy: a RW (non-executable) page containing
// gadget-shaped bytes with `0F 05 C3` sequences sprinkled at varying
// offsets. A pattern scan for the syscall+ret signature finds these
// pages, but since they are not PAGE_EXECUTE_* they cannot be hooked
// (a hook attempt would have to also change protection — itself a
// suspicious syscall the defender would flag).
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE void* ad_poly_alloc_data_decoy(u16 ssn_alloc, u16 ssn_free, u32 seed) {
    void* page = (void*)0;
    u64   size = AD_POLY_PAGE_SIZE;
    ad_ntstatus_t st = AD_SYSCALL6(ssn_alloc,
        AD_CURRENT_PROCESS, &page, (u64)0, &size,
        (u64)(0x1000UL | 0x2000UL),   // MEM_COMMIT | MEM_RESERVE
        (u64)0x04UL);                  // PAGE_READWRITE only (never executable)
    if (!AD_NT_SUCCESS(st) || !page) return (void*)0;
    AD_UNUSED(ssn_free);

    // Build a full polymorphic gadget into the page (same builder as real
    // ones) — this gives byte-level structural identity with real gadgets.
    ad_poly_build_gadget((u8*)page, seed, /*jit_mode=*/0u);

    // Sprinkle additional `0F 05 C3` triplets at several random offsets
    // in the page tail zone, so the page yields many more pattern hits
    // than a real gadget (a single gadget has exactly one real triplet).
    u8* p = (u8*)page;
    u32 extras = 4u + (seed & 7u);        // 4..11 extra triplets
    u32 i;
    for (i = 0; i < extras; i++) {
        u32 pos = 256u + ((seed >> (i & 15u)) * 37u + i * 113u) % 0xC00u;
        if (pos + 3u >= AD_POLY_META_ENTRY) continue;
        p[pos + 0] = 0x0F;
        p[pos + 1] = 0x05;
        p[pos + 2] = 0xC3;
    }
    return page;
}

// ---------------------------------------------------------------------------
// Initialize: build N real gadgets + M decoys. Decoys are identical in
// shape but never registered for call. Pointer table stored XOR-encrypted
// with a runtime-generated key.
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE b32 ad_poly_init(void) {
    if (g_poly.count > 0u) return 1;

    static u16 s_alloc = AD_SSN_UNRESOLVED;
    static u16 s_prot  = AD_SSN_UNRESOLVED;
    static u16 s_free  = AD_SSN_UNRESOLVED;
    AD_RESOLVE_SSN_ENC(s_alloc, NtAllocateVirtualMemory, 24);
    AD_RESOLVE_SSN_ENC(s_prot,  NtProtectVirtualMemory,  23);
    AD_RESOLVE_SSN_ENC(s_free,  NtFreeVirtualMemory,     20);
    if (s_alloc == AD_SSN_FAILED || s_prot == AD_SSN_FAILED) return 0;

    // Cache SSNs for transient (T5) and JIT (T3) hot paths.
    g_poly.ssn_alloc = s_alloc;
    g_poly.ssn_prot  = s_prot;
    g_poly.ssn_free  = s_free;

    // Seed PRNG and derive a runtime key for T4. TSC low is sufficient —
    // no crypto strength required, just non-predictability vs static scan.
    u64 tsc = __rdtsc();
    g_poly.rng_state = (u32)(tsc ^ 0xDEADBEEFu);
    g_poly.key       = tsc * 0x9E3779B97F4A7C15ULL;
    if (g_poly.key == 0ULL) g_poly.key = 0xA55A5AA5A5A55AA5ULL;

#if defined(AD_ENABLE_POLY_JIT)
    const u32 jit_mode = 1u;
#else
    const u32 jit_mode = 0u;
#endif

    u32 i;

    // Real gadgets.
    for (i = 0; i < AD_POLY_GADGET_COUNT; i++) {
        u32 seed = ad_poly_rng() ^ (i * 0x9E3779B9u);
        void* page = ad_poly_alloc_one(s_alloc, s_prot, s_free, seed, jit_mode);
        if (!page) continue;

        u32 entry_off = *(u32*)((u8*)page + AD_POLY_META_ENTRY);
        u32 sys_off   = *(u32*)((u8*)page + AD_POLY_META_SYSOFF);

        u64 fn = (u64)((u8*)page + entry_off);

        g_poly.pages_enc  [g_poly.count] = (u64)page ^ g_poly.key;
        g_poly.gadgets_enc[g_poly.count] = fn        ^ g_poly.key;
        g_poly.sysoff_enc [g_poly.count] = (u64)sys_off ^ g_poly.key;
        g_poly.count++;
    }

    // Decoys — built identically but never registered for dispatch.
    for (i = 0; i < AD_POLY_DECOY_COUNT; i++) {
        u32 seed = ad_poly_rng() ^ (i * 0x517CC1B7u) ^ 0xD0D0D0D0u;
        void* page = ad_poly_alloc_one(s_alloc, s_prot, s_free, seed, jit_mode);
        if (!page) continue;
        g_poly.decoys[g_poly.decoy_count++] = page;
    }

    // T6 — Data-section decoys (RW, non-executable). Pattern-scan
    // magnets with zero hook surface.
    for (i = 0; i < AD_POLY_DATA_DECOY_COUNT; i++) {
        u32 seed = ad_poly_rng() ^ (i * 0x7F4A7C15u) ^ 0xDA7ADA7Au;
        void* page = ad_poly_alloc_data_decoy(s_alloc, s_free, seed);
        if (!page) continue;
        g_poly.data_decoys[g_poly.data_decoy_count++] = page;
    }

    return (b32)(g_poly.count > 0u);
}

#if defined(AD_ENABLE_POLY_JIT)
// ---------------------------------------------------------------------------
// T3 — prime/unprime the `0F 05` bytes for a specific gadget. Serialized
// by a global spinlock so two threads don't race on the same page.
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE void ad_poly_jit_lock(void) {
    while (_InterlockedCompareExchange(&g_poly.jit_lock, 1, 0) != 0) {
        _mm_pause();
    }
}
ANTIDEBUG_INLINE void ad_poly_jit_unlock(void) {
    _InterlockedExchange(&g_poly.jit_lock, 0);
}

// Flip [page..page+PAGE_SIZE] to `new_prot`, return old prot via out param.
ANTIDEBUG_INLINE b32 ad_poly_flip(u16 ssn_prot, void* page, u64 new_prot, u32* out_old) {
    void* pb = page;
    u64   ps = AD_POLY_PAGE_SIZE;
    ad_ntstatus_t st = AD_SYSCALL5(ssn_prot, AD_CURRENT_PROCESS, &pb, &ps, new_prot, out_old);
    return AD_NT_SUCCESS(st);
}

// Patch the two syscall bytes in-place (page must be writable).
ANTIDEBUG_INLINE void ad_poly_patch_syscall(u8* page, u32 sys_off, u8 b0, u8 b1) {
    page[sys_off + 0] = b0;
    page[sys_off + 1] = b1;
}
#endif // AD_ENABLE_POLY_JIT

// ---------------------------------------------------------------------------
// Dispatch a syscall through a random gadget. Fallback to SyscallStub if
// no gadget was built.
// ---------------------------------------------------------------------------
__pragma(warning(push)) __pragma(warning(disable:4047))
ANTIDEBUG_INLINE void* ad_poly_call(
    u16   ssn,
    void* a1,  void* a2,  void* a3,  void* a4,
    void* a5,  void* a6,  void* a7,  void* a8,
    void* a9,  void* a10, void* a11
) {
    if (g_poly.count == 0u) {
        return SyscallStub(ssn, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11);
    }

#if defined(AD_ENABLE_POLY_TRANSIENT)
    // T5 — Transient per-call gadget. A fresh page at a fresh address,
    // built, called, freed. A hook attached to any previous gadget
    // address is never hit again.
    if (g_poly.ssn_alloc != AD_SSN_FAILED &&
        g_poly.ssn_prot  != AD_SSN_FAILED &&
        g_poly.ssn_free  != AD_SSN_FAILED) {
        u32   t_seed = ad_poly_rng();
        void* t_page = ad_poly_alloc_one(g_poly.ssn_alloc, g_poly.ssn_prot,
                                         g_poly.ssn_free, t_seed, /*jit_mode=*/0u);
        if (t_page) {
            u32 t_entry = *(u32*)((u8*)t_page + AD_POLY_META_ENTRY);
            ad_poly_gadget_fn t_fn = (ad_poly_gadget_fn)((u8*)t_page + t_entry);
            void* t_ret = t_fn(ssn, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11);
            // Release the page — next call will land at a different address.
            void* t_fb = t_page; u64 t_fs = 0;
            (void)AD_SYSCALL4(g_poly.ssn_free, AD_CURRENT_PROCESS, &t_fb, &t_fs,
                              (u64)0x8000UL);
            return t_ret;
        }
        // Alloc failed — fall through to stable dispatch below.
    }
#endif

    u32 idx = ad_poly_rng() % g_poly.count;

    // T4 — decrypt function pointer on use.
    u64 fn_enc = g_poly.gadgets_enc[idx];
    ad_poly_gadget_fn fn = (ad_poly_gadget_fn)(fn_enc ^ g_poly.key);

#if defined(AD_ENABLE_POLY_JIT)
    // T3 — prime the syscall bytes, execute, unprime. Serialized.
    static u16 s_prot = AD_SSN_UNRESOLVED;
    AD_RESOLVE_SSN_ENC(s_prot, NtProtectVirtualMemory, 23);
    if (s_prot == AD_SSN_FAILED) {
        return SyscallStub(ssn, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11);
    }

    u8* page    = (u8*)(g_poly.pages_enc [idx] ^ g_poly.key);
    u32 sys_off = (u32)(g_poly.sysoff_enc[idx] ^ g_poly.key);

    ad_poly_jit_lock();

    u32 old = 0;
    b32 ok = ad_poly_flip(s_prot, page, (u64)0x04UL, &old);   // PAGE_READWRITE
    if (!ok) {
        ad_poly_jit_unlock();
        return SyscallStub(ssn, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11);
    }
    ad_poly_patch_syscall(page, sys_off, 0x0F, 0x05);

    u32 old2 = 0;
    if (!ad_poly_flip(s_prot, page, (u64)0x20UL, &old2)) {    // PAGE_EXECUTE_READ
        ad_poly_patch_syscall(page, sys_off, 0x90, 0x90);
        (void)ad_poly_flip(s_prot, page, (u64)old, &old2);
        ad_poly_jit_unlock();
        return SyscallStub(ssn, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11);
    }

    void* ret = fn(ssn, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11);

    // Restore: RW → nop nop → RX.
    u32 old3 = 0;
    if (ad_poly_flip(s_prot, page, (u64)0x04UL, &old3)) {
        ad_poly_patch_syscall(page, sys_off, 0x90, 0x90);
        u32 old4 = 0;
        (void)ad_poly_flip(s_prot, page, (u64)0x20UL, &old4);
    }
    ad_poly_jit_unlock();
    return ret;
#else
    return fn(ssn, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11);
#endif
}
__pragma(warning(pop))

// ---------------------------------------------------------------------------
// Regenerate all gadgets at the same addresses. Defeats a persistent
// single-gadget hook that survives our init: the hooked bytes get
// overwritten with a fresh variant layout on the next regenerate.
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE void ad_poly_regenerate(void) {
    static u16 s_prot = AD_SSN_UNRESOLVED;
    AD_RESOLVE_SSN_ENC(s_prot, NtProtectVirtualMemory, 23);
    if (s_prot == AD_SSN_FAILED) return;

#if defined(AD_ENABLE_POLY_JIT)
    const u32 jit_mode = 1u;
#else
    const u32 jit_mode = 0u;
#endif

    // Rotate the encryption key as well so any stale static scan that
    // recovered the old key is invalidated.
    u64 new_key = g_poly.key ^ (__rdtsc() * 0xC2B2AE3D27D4EB4FULL);
    if (new_key == 0ULL) new_key = 0x5AA55AA55AA55AA5ULL;

    u32 i;
    for (i = 0; i < g_poly.count; i++) {
        void* page = (void*)(g_poly.pages_enc[i] ^ g_poly.key);
        if (!page) continue;

        // Flip to RW.
        void* pb = page; u64 ps = AD_POLY_PAGE_SIZE; u32 old = 0;
        ad_ntstatus_t st = AD_SYSCALL5(s_prot, AD_CURRENT_PROCESS, &pb, &ps,
            (u64)0x04UL, &old);
        if (!AD_NT_SUCCESS(st)) continue;

        u32 seed = ad_poly_rng() ^ (i * 0x517CC1B7u);
        ad_poly_build_gadget((u8*)page, seed, jit_mode);

        u32 entry_off = *(u32*)((u8*)page + AD_POLY_META_ENTRY);
        u32 sys_off   = *(u32*)((u8*)page + AD_POLY_META_SYSOFF);
        u64 fn        = (u64)((u8*)page + entry_off);

        // Re-encrypt with the new key.
        g_poly.pages_enc  [i] = (u64)page    ^ new_key;
        g_poly.gadgets_enc[i] = fn           ^ new_key;
        g_poly.sysoff_enc [i] = (u64)sys_off ^ new_key;

        // Flip back to RX.
        pb = page; ps = AD_POLY_PAGE_SIZE; old = 0;
        (void)AD_SYSCALL5(s_prot, AD_CURRENT_PROCESS, &pb, &ps,
            (u64)0x20UL, &old);
    }

    // Re-encrypt decoy entries implicitly by keeping their raw pages (we
    // never call decoys; only the real table needed a key swap).
    g_poly.key = new_key;
}

// ---------------------------------------------------------------------------
// Cleanup — free real gadget pages + decoy pages.
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// Diagnostics — expose internal counts for verification.
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE u32 ad_poly_count(void)       { return g_poly.count; }
ANTIDEBUG_INLINE u32 ad_poly_decoy_count(void) { return g_poly.decoy_count; }
ANTIDEBUG_INLINE u32 ad_poly_data_decoy_count(void) { return g_poly.data_decoy_count; }

ANTIDEBUG_INLINE void ad_poly_destroy(void) {
    static u16 s_free = AD_SSN_UNRESOLVED;
    AD_RESOLVE_SSN_ENC(s_free, NtFreeVirtualMemory, 20);
    if (s_free == AD_SSN_FAILED) return;

    u32 i;
    for (i = 0; i < g_poly.count; i++) {
        void* page = (void*)(g_poly.pages_enc[i] ^ g_poly.key);
        if (page) {
            void* fb = page; u64 fs = 0;
            (void)AD_SYSCALL4(s_free, AD_CURRENT_PROCESS, &fb, &fs, (u64)0x8000UL);
        }
        g_poly.pages_enc  [i] = 0;
        g_poly.gadgets_enc[i] = 0;
        g_poly.sysoff_enc [i] = 0;
    }
    g_poly.count = 0;

    for (i = 0; i < g_poly.decoy_count; i++) {
        if (g_poly.decoys[i]) {
            void* fb = g_poly.decoys[i]; u64 fs = 0;
            (void)AD_SYSCALL4(s_free, AD_CURRENT_PROCESS, &fb, &fs, (u64)0x8000UL);
            g_poly.decoys[i] = (void*)0;
        }
    }
    g_poly.decoy_count = 0;

    for (i = 0; i < g_poly.data_decoy_count; i++) {
        if (g_poly.data_decoys[i]) {
            void* fb = g_poly.data_decoys[i]; u64 fs = 0;
            (void)AD_SYSCALL4(s_free, AD_CURRENT_PROCESS, &fb, &fs, (u64)0x8000UL);
            g_poly.data_decoys[i] = (void*)0;
        }
    }
    g_poly.data_decoy_count = 0;
}

#else  // !_MSC_VER
ANTIDEBUG_INLINE b32   ad_poly_init(void)       { return 0; }
ANTIDEBUG_INLINE void  ad_poly_regenerate(void) {}
ANTIDEBUG_INLINE void  ad_poly_destroy(void)    {}
ANTIDEBUG_INLINE void* ad_poly_call(
    u16 ssn,
    void* a1, void* a2, void* a3, void* a4,
    void* a5, void* a6, void* a7, void* a8,
    void* a9, void* a10, void* a11)
{
    return (void*)0;
}
#endif // _MSC_VER

#endif // ANTIDEBUG_POLY_SYSCALL_H
