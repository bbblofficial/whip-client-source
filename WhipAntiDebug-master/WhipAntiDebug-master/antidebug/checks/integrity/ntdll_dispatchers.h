// ===== file: antidebug/checks/integrity/ntdll_dispatchers.h =====
//
// ntdll Multi-Point Integrity Check — "ultra-strong" hook surface scanner.
//
// Single check covering the 10 most-hooked entry points in ntdll. Any
// stealth tool (ScyllaHide, TitanHide, Detours, EasyHook, Frida-gadget,
// API Monitor, Intel Pin user-mode proxy, MSR-redirect unhookers…) that
// wants to intercept debug events, thread lifecycle, or syscall issuance
// must patch at least one of these. We fingerprint all ten at init and
// re-hash periodically, returning a bitmask of which slots mutated.
//
// Coverage:
//
//   Kernel→user dispatchers (exception / APC / callback paths)
//     [ 0]  KiUserExceptionDispatcher   — exception delivery
//     [ 1]  KiUserApcDispatcher         — user-mode APC delivery
//     [ 2]  KiUserCallbackDispatcher    — win32k callbacks to user
//
//   Thread lifecycle
//     [ 3]  LdrInitializeThunk           — thread entry from kernel
//     [ 4]  RtlUserThreadStart           — user-mode thread start
//
//   Syscall stubs (most-commonly-hooked NT APIs)
//     [ 5]  NtGetContextThread           — DR / context read
//     [ 6]  NtSetContextThread           — DR / context write
//     [ 7]  NtQueryInformationProcess    — DebugPort / DebugObjectHandle
//     [ 8]  NtContinue                   — resume from exception
//
//   Debug intrinsic
//     [ 9]  DbgBreakPoint                — __debugbreak target
//
// Each entry gets 16 bytes hashed via FNV-1a plus a signature sniffer
// for common hook prologues (jmp rel32, mov rax+jmp, jmp [rip+rel32],
// int3 hotpatch, short jmp).
//
// Output: 32-bit mask where bits 0-9 indicate which slot changed, and
// bits 16-31 indicate which signature type was sniffed. Zero = clean.
//
#ifndef ANTIDEBUG_NTDLL_DISPATCHERS_H
#define ANTIDEBUG_NTDLL_DISPATCHERS_H

#include "../../core/types.h"
#include "../../core/macros.h"
#include "../../core/api_hash.h"

#ifdef _MSC_VER

#define AD_NDT_COUNT          10u
#define AD_NDT_HASH_LEN       16u
#define AD_NDT_MAX_NAME       28u

// Per-entry state.
typedef struct {
    u32  name_hash;                       // FNV-1a of the ntdll export name
    void* addr;                           // resolved address
    u32  baseline_hash;                   // baseline FNV-1a of first 16 bytes
    u8   baseline_bytes[AD_NDT_HASH_LEN]; // for first-byte signature sniffing
    u8   present;                         // 1 if init resolved ok
} ad_ndt_entry_t;

typedef struct {
    u32             initialized;
    ad_ndt_entry_t  entries[AD_NDT_COUNT];
} ad_ndt_ctx_t;

// Helper: FNV-1a on bytes.
ANTIDEBUG_INLINE u32 ad_ndt_fnv1a_bytes(const u8* b, u32 n) {
    u32 h = 0x811C9DC5u;
    u32 i;
    for (i = 0; i < n; i++) { h ^= b[i]; h *= 0x01000193u; }
    return h;
}

// Helper: hash a stack-built ASCII name via ad_hash_str.
// Builds name[] char-by-char so no .rdata string exists.
#define AD_NDT_HASH_NAME(var, ...)                                          \
    static u32 var = 0u;                                                    \
    if (!var) {                                                             \
        char _b[AD_NDT_MAX_NAME];                                           \
        const char _chars[] = __VA_ARGS__;                                  \
        u32 _i;                                                             \
        for (_i = 0; _i < sizeof(_chars) && _i < AD_NDT_MAX_NAME; _i++)     \
            _b[_i] = _chars[_i];                                            \
        var = ad_hash_str(_b);                                              \
    }

// Returns 1 if the first bytes look like a hook prologue.
// Low 16 bits: which signature (see ad_xdp_sniff_hook_sig in XDP file).
// We duplicate the logic here to keep the header self-contained.
ANTIDEBUG_INLINE u32 ad_ndt_sniff_sig(const u8* b) {
    u32 m = 0u;
    if (b[0] == 0xE9)                                                 m |= 0x0001u;  // jmp rel32
    if (b[0] == 0x48 && b[1] == 0xB8 && b[10] == 0xFF && b[11] == 0xE0) m |= 0x0002u;  // mov rax,imm64 / jmp rax
    if (b[0] == 0xFF && b[1] == 0x25)                                 m |= 0x0004u;  // jmp [rip+rel32]
    if (b[0] == 0xCC)                                                 m |= 0x0008u;  // int3 hotpatch
    if (b[0] == 0xEB)                                                 m |= 0x0010u;  // short jmp
    // mov r10/r11 + jmp (some trampolines)
    if (b[0] == 0x49 && (b[1] == 0xBA || b[1] == 0xBB))               m |= 0x0020u;
    return m;
}

// Internal: populate an entry with addr + baseline bytes.
ANTIDEBUG_INLINE b32 ad_ndt_populate(ad_ndt_entry_t* e) {
    e->addr = ad_resolve_api(AD_HASH_NTDLL, e->name_hash);
    if (!e->addr) { e->present = 0u; return 0; }
    const volatile u8* p = (const volatile u8*)e->addr;
    u32 i;
    for (i = 0; i < AD_NDT_HASH_LEN; i++) e->baseline_bytes[i] = p[i];
    e->baseline_hash = ad_ndt_fnv1a_bytes(e->baseline_bytes, AD_NDT_HASH_LEN);
    e->present = 1u;
    return 1;
}

// Build the name hash for each entry, char-by-char on stack.
ANTIDEBUG_INLINE u32 ad_ndt_name_hash(int idx) {
    char b[AD_NDT_MAX_NAME];
    int n = 0;
#define AD_NDT_PUT(c) b[n++] = (char)(c)
    switch (idx) {
        case 0:  // KiUserExceptionDispatcher
            AD_NDT_PUT('K'); AD_NDT_PUT('i'); AD_NDT_PUT('U'); AD_NDT_PUT('s'); AD_NDT_PUT('e');
            AD_NDT_PUT('r'); AD_NDT_PUT('E'); AD_NDT_PUT('x'); AD_NDT_PUT('c'); AD_NDT_PUT('e');
            AD_NDT_PUT('p'); AD_NDT_PUT('t'); AD_NDT_PUT('i'); AD_NDT_PUT('o'); AD_NDT_PUT('n');
            AD_NDT_PUT('D'); AD_NDT_PUT('i'); AD_NDT_PUT('s'); AD_NDT_PUT('p'); AD_NDT_PUT('a');
            AD_NDT_PUT('t'); AD_NDT_PUT('c'); AD_NDT_PUT('h'); AD_NDT_PUT('e'); AD_NDT_PUT('r');
            break;
        case 1:  // KiUserApcDispatcher
            AD_NDT_PUT('K'); AD_NDT_PUT('i'); AD_NDT_PUT('U'); AD_NDT_PUT('s'); AD_NDT_PUT('e');
            AD_NDT_PUT('r'); AD_NDT_PUT('A'); AD_NDT_PUT('p'); AD_NDT_PUT('c'); AD_NDT_PUT('D');
            AD_NDT_PUT('i'); AD_NDT_PUT('s'); AD_NDT_PUT('p'); AD_NDT_PUT('a'); AD_NDT_PUT('t');
            AD_NDT_PUT('c'); AD_NDT_PUT('h'); AD_NDT_PUT('e'); AD_NDT_PUT('r');
            break;
        case 2:  // KiUserCallbackDispatcher
            AD_NDT_PUT('K'); AD_NDT_PUT('i'); AD_NDT_PUT('U'); AD_NDT_PUT('s'); AD_NDT_PUT('e');
            AD_NDT_PUT('r'); AD_NDT_PUT('C'); AD_NDT_PUT('a'); AD_NDT_PUT('l'); AD_NDT_PUT('l');
            AD_NDT_PUT('b'); AD_NDT_PUT('a'); AD_NDT_PUT('c'); AD_NDT_PUT('k'); AD_NDT_PUT('D');
            AD_NDT_PUT('i'); AD_NDT_PUT('s'); AD_NDT_PUT('p'); AD_NDT_PUT('a'); AD_NDT_PUT('t');
            AD_NDT_PUT('c'); AD_NDT_PUT('h'); AD_NDT_PUT('e'); AD_NDT_PUT('r');
            break;
        case 3:  // LdrInitializeThunk
            AD_NDT_PUT('L'); AD_NDT_PUT('d'); AD_NDT_PUT('r'); AD_NDT_PUT('I'); AD_NDT_PUT('n');
            AD_NDT_PUT('i'); AD_NDT_PUT('t'); AD_NDT_PUT('i'); AD_NDT_PUT('a'); AD_NDT_PUT('l');
            AD_NDT_PUT('i'); AD_NDT_PUT('z'); AD_NDT_PUT('e'); AD_NDT_PUT('T'); AD_NDT_PUT('h');
            AD_NDT_PUT('u'); AD_NDT_PUT('n'); AD_NDT_PUT('k');
            break;
        case 4:  // RtlUserThreadStart
            AD_NDT_PUT('R'); AD_NDT_PUT('t'); AD_NDT_PUT('l'); AD_NDT_PUT('U'); AD_NDT_PUT('s');
            AD_NDT_PUT('e'); AD_NDT_PUT('r'); AD_NDT_PUT('T'); AD_NDT_PUT('h'); AD_NDT_PUT('r');
            AD_NDT_PUT('e'); AD_NDT_PUT('a'); AD_NDT_PUT('d'); AD_NDT_PUT('S'); AD_NDT_PUT('t');
            AD_NDT_PUT('a'); AD_NDT_PUT('r'); AD_NDT_PUT('t');
            break;
        case 5:  // NtGetContextThread
            AD_NDT_PUT('N'); AD_NDT_PUT('t'); AD_NDT_PUT('G'); AD_NDT_PUT('e'); AD_NDT_PUT('t');
            AD_NDT_PUT('C'); AD_NDT_PUT('o'); AD_NDT_PUT('n'); AD_NDT_PUT('t'); AD_NDT_PUT('e');
            AD_NDT_PUT('x'); AD_NDT_PUT('t'); AD_NDT_PUT('T'); AD_NDT_PUT('h'); AD_NDT_PUT('r');
            AD_NDT_PUT('e'); AD_NDT_PUT('a'); AD_NDT_PUT('d');
            break;
        case 6:  // NtSetContextThread
            AD_NDT_PUT('N'); AD_NDT_PUT('t'); AD_NDT_PUT('S'); AD_NDT_PUT('e'); AD_NDT_PUT('t');
            AD_NDT_PUT('C'); AD_NDT_PUT('o'); AD_NDT_PUT('n'); AD_NDT_PUT('t'); AD_NDT_PUT('e');
            AD_NDT_PUT('x'); AD_NDT_PUT('t'); AD_NDT_PUT('T'); AD_NDT_PUT('h'); AD_NDT_PUT('r');
            AD_NDT_PUT('e'); AD_NDT_PUT('a'); AD_NDT_PUT('d');
            break;
        case 7:  // NtQueryInformationProcess
            AD_NDT_PUT('N'); AD_NDT_PUT('t'); AD_NDT_PUT('Q'); AD_NDT_PUT('u'); AD_NDT_PUT('e');
            AD_NDT_PUT('r'); AD_NDT_PUT('y'); AD_NDT_PUT('I'); AD_NDT_PUT('n'); AD_NDT_PUT('f');
            AD_NDT_PUT('o'); AD_NDT_PUT('r'); AD_NDT_PUT('m'); AD_NDT_PUT('a'); AD_NDT_PUT('t');
            AD_NDT_PUT('i'); AD_NDT_PUT('o'); AD_NDT_PUT('n'); AD_NDT_PUT('P'); AD_NDT_PUT('r');
            AD_NDT_PUT('o'); AD_NDT_PUT('c'); AD_NDT_PUT('e'); AD_NDT_PUT('s'); AD_NDT_PUT('s');
            break;
        case 8:  // NtContinue
            AD_NDT_PUT('N'); AD_NDT_PUT('t'); AD_NDT_PUT('C'); AD_NDT_PUT('o'); AD_NDT_PUT('n');
            AD_NDT_PUT('t'); AD_NDT_PUT('i'); AD_NDT_PUT('n'); AD_NDT_PUT('u'); AD_NDT_PUT('e');
            break;
        case 9:  // DbgBreakPoint
            AD_NDT_PUT('D'); AD_NDT_PUT('b'); AD_NDT_PUT('g'); AD_NDT_PUT('B'); AD_NDT_PUT('r');
            AD_NDT_PUT('e'); AD_NDT_PUT('a'); AD_NDT_PUT('k'); AD_NDT_PUT('P'); AD_NDT_PUT('o');
            AD_NDT_PUT('i'); AD_NDT_PUT('n'); AD_NDT_PUT('t');
            break;
        default: return 0u;
    }
#undef AD_NDT_PUT
    b[n] = 0;
    return ad_hash_str(b);
}

// Initialise — resolve all 10 and capture baselines.
ANTIDEBUG_INLINE b32 ad_ndt_init(ad_ndt_ctx_t* ctx) {
    if (!ctx) return 0;
    if (ctx->initialized) return 1;

    int i;
    u32 resolved = 0;
    for (i = 0; i < (int)AD_NDT_COUNT; i++) {
        ad_ndt_entry_t* e = &ctx->entries[i];
        e->name_hash = ad_ndt_name_hash(i);
        if (ad_ndt_populate(e)) resolved++;
    }
    ctx->initialized = 1u;
    return (b32)(resolved > 0u);
}

// Runtime check — returns bitmask.
//   bits  0-9  : which entry changed (1=patched, 0=clean)
//   bits 16-21 : which signature types were sniffed, ORed across all entries
//                (bit 16 = jmp rel32, bit 17 = mov rax+jmp, bit 18 = jmp [rip],
//                 bit 19 = int3 hotpatch, bit 20 = short jmp, bit 21 = mov r10/r11 trampoline)
ANTIDEBUG_INLINE u32 ad_ndt_check(const ad_ndt_ctx_t* ctx) {
    if (!ctx || !ctx->initialized) return 0u;

    u32 entry_mask = 0u;
    u32 sig_union  = 0u;

    int i;
    for (i = 0; i < (int)AD_NDT_COUNT; i++) {
        const ad_ndt_entry_t* e = &ctx->entries[i];
        if (!e->present) continue;

        const volatile u8* p = (const volatile u8*)e->addr;
        u8 cur[AD_NDT_HASH_LEN];
        u32 j;
        for (j = 0; j < AD_NDT_HASH_LEN; j++) cur[j] = p[j];

        u32 h = ad_ndt_fnv1a_bytes(cur, AD_NDT_HASH_LEN);
        if (h != e->baseline_hash) {
            // Only count signatures for entries that ACTUALLY changed.
            // Otherwise legitimate prologues that happen to start with
            // 0xCC (DbgBreakPoint) or 0xEB/0xE9 (tail-call exports) would
            // fire false positives.
            entry_mask |= (1u << (u32)i);
            sig_union  |= ad_ndt_sniff_sig(cur);
        }
    }

    return entry_mask | (sig_union << 16u);
}

// Convenience: returns count of patched entries (popcount of low 10 bits).
ANTIDEBUG_INLINE u32 ad_ndt_patched_count(const ad_ndt_ctx_t* ctx) {
    u32 m = ad_ndt_check(ctx) & 0x3FFu;
    u32 c = 0;
    while (m) { c += (m & 1u); m >>= 1u; }
    return c;
}

// Boolean wrapper — 1 if ANY entry is patched.
ANTIDEBUG_INLINE b32 ad_ndt_any_patched(const ad_ndt_ctx_t* ctx) {
    return (b32)((ad_ndt_check(ctx) & 0x3FFu) != 0u);
}

#else  // !_MSC_VER
typedef struct { int _unused; } ad_ndt_ctx_t;
ANTIDEBUG_INLINE b32 ad_ndt_init(ad_ndt_ctx_t* ctx) { (void)ctx; return 0; }
ANTIDEBUG_INLINE u32 ad_ndt_check(const ad_ndt_ctx_t* ctx) { (void)ctx; return 0; }
ANTIDEBUG_INLINE b32 ad_ndt_any_patched(const ad_ndt_ctx_t* ctx) { (void)ctx; return 0; }
#endif // _MSC_VER

#endif // ANTIDEBUG_NTDLL_DISPATCHERS_H
