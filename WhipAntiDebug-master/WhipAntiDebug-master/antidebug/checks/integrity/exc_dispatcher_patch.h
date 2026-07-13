// ===== file: antidebug/checks/integrity/exc_dispatcher_patch.h =====
//
// KiUserExceptionDispatcher Integrity Check — detects stealth hooks on
// the user-mode exception entry point.
//
// When the kernel delivers an exception to a user-mode process, control
// jumps to `ntdll!KiUserExceptionDispatcher`. This routine is the ONLY
// entry point through which hardware/software exceptions reach VEH/SEH
// chains. Advanced anti-anti-debug tooling can hook it to:
//
//   * intercept / rewrite exception records before they reach user SEH
//   * zero out DR registers inside delivered CONTEXT (what we suspect
//     defeated hardware_via_exc.h on Win10/11 — though that zeroing is
//     actually kernel-side)
//   * filter specific exception codes our checks rely on (STATUS_SINGLE_STEP,
//     STATUS_BREAKPOINT, STATUS_ACCESS_VIOLATION)
//   * transparently continue execution on exceptions we expect to be
//     caught, making SEH-based checks return 0
//
// Detection principle: at init, hash the first N bytes of
// `ntdll!KiUserExceptionDispatcher`. The dispatcher is a small, stable
// prologue — its bytes are identical across runs of a given Windows
// build. A hook (jmp/call rel32, mov rax+jmp, trampoline) overwrites
// the first 5-14 bytes with redirection code, producing a different
// hash. Re-hash periodically and compare against the init baseline.
//
// Bonus signal: also check that the bytes decode as "normal" prologue
// instructions (push/mov/sub patterns). A hook's first byte is usually
// 0xE9 (jmp rel32), 0x48 B8 (mov rax imm64), 0xFF 0x25 (jmp [rel32]),
// or 0xCC (int3 hotpatch). Detect these direct signatures too.
//
// Works on Windows 7 / 10 / 11. No CPU feature required.
//
#ifndef ANTIDEBUG_EXC_DISPATCHER_PATCH_H
#define ANTIDEBUG_EXC_DISPATCHER_PATCH_H

#include "../../core/types.h"
#include "../../core/macros.h"
#include "../../core/api_hash.h"

#ifdef _MSC_VER

#define AD_XDP_HASH_LEN        32u        // bytes to hash (safe below prologue)
#define AD_XDP_HOOK_SIG_LEN    14u        // first-bytes inspected for hook sigs

typedef struct {
    u32  initialized;
    u32  baseline_hash;
    u8   baseline_bytes[AD_XDP_HOOK_SIG_LEN];
    void* dispatcher_addr;
} ad_xdp_ctx_t;

// Build the "KiUserExceptionDispatcher" hash on stack, char-by-char —
// no .rdata string literal.
ANTIDEBUG_INLINE u32 ad_xdp_hash_dispatcher_name(void) {
    static u32 h = 0;
    if (!h) {
        char b[28];
        b[ 0]='K'; b[ 1]='i'; b[ 2]='U'; b[ 3]='s'; b[ 4]='e';
        b[ 5]='r'; b[ 6]='E'; b[ 7]='x'; b[ 8]='c'; b[ 9]='e';
        b[10]='p'; b[11]='t'; b[12]='i'; b[13]='o'; b[14]='n';
        b[15]='D'; b[16]='i'; b[17]='s'; b[18]='p'; b[19]='a';
        b[20]='t'; b[21]='c'; b[22]='h'; b[23]='e'; b[24]='r';
        b[25]=0;
        h = ad_hash_str(b);
    }
    return h;
}

// FNV-1a hash of a byte buffer (not case-folded).
ANTIDEBUG_INLINE u32 ad_xdp_fnv1a_bytes(const u8* buf, u32 n) {
    u32 h = 0x811C9DC5u;
    u32 i;
    for (i = 0; i < n; i++) {
        h ^= buf[i];
        h *= 0x01000193u;
    }
    return h;
}

// Initialise context — resolve dispatcher, snapshot bytes, compute baseline.
// Must be called once at program init, BEFORE any injection / hook could
// have happened. Returns 1 on success.
ANTIDEBUG_INLINE b32 ad_xdp_init(ad_xdp_ctx_t* ctx) {
    if (!ctx) return 0;
    if (ctx->initialized) return 1;

    void* addr = ad_resolve_api(AD_HASH_NTDLL, ad_xdp_hash_dispatcher_name());
    if (!addr) return 0;

    const volatile u8* p = (const volatile u8*)addr;
    u8 tmp[AD_XDP_HASH_LEN];
    u32 i;
    for (i = 0; i < AD_XDP_HASH_LEN; i++) tmp[i] = p[i];

    ctx->baseline_hash = ad_xdp_fnv1a_bytes(tmp, AD_XDP_HASH_LEN);
    for (i = 0; i < AD_XDP_HOOK_SIG_LEN; i++) ctx->baseline_bytes[i] = tmp[i];
    ctx->dispatcher_addr = addr;
    ctx->initialized = 1u;
    return 1;
}

// Known hook prologue signatures (first bytes of the dispatcher after a
// hook install). Returns bitmask:
//   bit 0: 0xE9 rel32          — direct jmp (5 bytes)
//   bit 1: 0x48 0xB8 ... 0xFF 0xE0 — mov rax,imm64 / jmp rax (12 bytes)
//   bit 2: 0xFF 0x25 rel32      — jmp [rip+rel32] (6 bytes)
//   bit 3: 0xCC                 — int3 hotpatch (1 byte, Microsoft /hotpatch)
//   bit 4: 0xEB short jmp       — (rare, 2 bytes)
ANTIDEBUG_INLINE u32 ad_xdp_sniff_hook_sig(const u8* b) {
    u32 m = 0u;
    if (b[0] == 0xE9) m |= 0x01u;
    if (b[0] == 0x48 && b[1] == 0xB8 && b[10] == 0xFF && b[11] == 0xE0)
        m |= 0x02u;
    if (b[0] == 0xFF && b[1] == 0x25) m |= 0x04u;
    if (b[0] == 0xCC) m |= 0x08u;
    if (b[0] == 0xEB) m |= 0x10u;
    return m;
}

// Runtime check — re-read dispatcher bytes, compare hash + sniff signatures.
// Returns bitmask:
//   bit 0 (0x1): hash mismatch — bytes changed since init
//   bit 1 (0x2): direct jmp rel32 detected
//   bit 2 (0x4): mov rax imm64 / jmp rax pattern
//   bit 3 (0x8): indirect jmp detected
//   bit 4 (0x10): int3 hotpatch
//   bit 5 (0x20): short jmp detected
ANTIDEBUG_INLINE u32 ad_xdp_check(const ad_xdp_ctx_t* ctx) {
    if (!ctx || !ctx->initialized) return 0u;

    const volatile u8* p = (const volatile u8*)ctx->dispatcher_addr;
    u8 current[AD_XDP_HASH_LEN];
    u32 i;
    for (i = 0; i < AD_XDP_HASH_LEN; i++) current[i] = p[i];

    u32 mask = 0u;

    u32 h = ad_xdp_fnv1a_bytes(current, AD_XDP_HASH_LEN);
    if (h != ctx->baseline_hash) mask |= 0x01u;

    u32 sig = ad_xdp_sniff_hook_sig(current);
    if (sig & 0x01u) mask |= 0x02u;
    if (sig & 0x02u) mask |= 0x04u;
    if (sig & 0x04u) mask |= 0x08u;
    if (sig & 0x08u) mask |= 0x10u;
    if (sig & 0x10u) mask |= 0x20u;

    return mask;
}

// Boolean wrapper — 1 if anything suspicious.
ANTIDEBUG_INLINE b32 ad_xdp_patched(const ad_xdp_ctx_t* ctx) {
    return (b32)(ad_xdp_check(ctx) != 0u);
}

#else  // !_MSC_VER
typedef struct { int _unused; } ad_xdp_ctx_t;
ANTIDEBUG_INLINE b32 ad_xdp_init(ad_xdp_ctx_t* ctx) { (void)ctx; return 0; }
ANTIDEBUG_INLINE u32 ad_xdp_check(const ad_xdp_ctx_t* ctx) { (void)ctx; return 0; }
ANTIDEBUG_INLINE b32 ad_xdp_patched(const ad_xdp_ctx_t* ctx) { (void)ctx; return 0; }
#endif // _MSC_VER

#endif // ANTIDEBUG_EXC_DISPATCHER_PATCH_H
