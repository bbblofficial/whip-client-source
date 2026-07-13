// ===== file: antidebug/checks/integrity/ntdll_full_text.h =====
//
// ntdll Full-.text Integrity Scan — the nuclear option.
//
// The ntdll_dispatchers.h check covers 10 specific entry points. This one
// is the complement: it hashes the ENTIRE .text section of ntdll into
// AD_NFT_CHUNK_COUNT equal-size chunks. At runtime, re-hash each chunk
// and report which ones changed (as a bitmask). Any single-byte patch
// anywhere in ntdll's executable code is caught — regardless of which
// function was hit.
//
// Tradeoffs vs. dispatchers:
//   + No guessing: every ntdll function is covered, not a curated list
//   + Detects hooks on rarely-used exports that attackers choose precisely
//     because defenders don't whitelist them
//   + Chunk-index output narrows down the patched region (~2-4 KB precision
//     for a typical ntdll with AD_NFT_CHUNK_COUNT=64)
//   − Larger init cost (~500 KB of FNV-1a) but still sub-millisecond
//   − Chunk-level location is coarser than function-level
//
// This check assumes ntdll's in-memory .text matches what the loader
// mapped from disk. If the OS or runtime has applied legitimate in-memory
// patches (hot-patching thunks, instrumentation callbacks installed by
// AV/EDR at system level), those will be visible at init and ignored as
// "baseline" — this check detects CHANGES after init, not deviation from
// disk.
//
#ifndef ANTIDEBUG_NTDLL_FULL_TEXT_H
#define ANTIDEBUG_NTDLL_FULL_TEXT_H

#include "../../core/types.h"
#include "../../core/macros.h"

#ifdef _MSC_VER

#ifndef AD_NFT_CHUNK_COUNT
#define AD_NFT_CHUNK_COUNT 64u        // bitmask bit per chunk — must be ≤ 64
#endif

typedef struct {
    u32  initialized;
    u8*  text_base;                          // in-memory .text base
    u32  text_size;                          // .text size in bytes
    u32  chunk_size;                         // bytes per chunk
    u32  chunk_hash[AD_NFT_CHUNK_COUNT];     // baseline FNV-1a per chunk
} ad_nft_ctx_t;

ANTIDEBUG_INLINE u32 ad_nft_fnv1a(const volatile u8* p, u32 n) {
    u32 h = 0x811C9DC5u;
    u32 i;
    for (i = 0; i < n; i++) { h ^= p[i]; h *= 0x01000193u; }
    return h;
}

// Locate ntdll's .text section via PEB→Ldr walk + PE header parse.
// Stores base + size in ctx on success. Returns 1 on success.
ANTIDEBUG_INLINE b32 ad_nft_find_ntdll_text(ad_nft_ctx_t* ctx) {
    u8* peb = (u8*)__readgsqword(0x60);
    if (!peb) return 0;
    u8* ldr = *(u8**)(peb + 0x18);
    if (!ldr) return 0;

    // InLoadOrderModuleList at Ldr+0x10
    u8* head  = ldr + 0x10;
    u8* entry = *(u8**)head;

    // Walk: usually [exe, ntdll, kernel32, ...]. Find ntdll by checking
    // the BaseDllName chars == "ntdll.dll" (case-insensitive).
    u32 visited = 0;
    u8* ntdll_base = 0;
    while (entry != head && visited < 256u) {
        visited++;
        u16  name_len_b = *(u16*)(entry + 0x58);
        u16* name_buf   = *(u16**)(entry + 0x60);
        u32  n_chars    = (u32)(name_len_b / 2u);

        // Quick match: ntdll.dll (9 chars)
        if (name_buf && n_chars == 9u) {
            static const u16 w_ntdll[] = {'n','t','d','l','l','.','d','l','l'};
            b32 match = 1;
            u32 i;
            for (i = 0; i < 9u; i++) {
                u16 c = name_buf[i];
                if (c >= 'A' && c <= 'Z') c = (u16)(c + 32u);
                if (c != w_ntdll[i]) { match = 0; break; }
            }
            if (match) {
                ntdll_base = *(u8**)(entry + 0x30);   // DllBase
                break;
            }
        }
        entry = *(u8**)entry;
    }
    if (!ntdll_base) return 0;
    if (*(u16*)ntdll_base != 0x5A4D) return 0;   // 'MZ'

    // Parse PE headers to locate .text.
    u32 pe_off = *(u32*)(ntdll_base + 0x3C);
    if (pe_off > 0x1000u) return 0;
    u8* pe = ntdll_base + pe_off;
    if (*(u32*)pe != 0x00004550u) return 0;       // 'PE\0\0'

    u16 n_sections = *(u16*)(pe + 6);
    u16 opt_size   = *(u16*)(pe + 20);
    u8* sections   = pe + 24 + opt_size;

    u32 text_rva = 0, text_vs = 0;
    u16 si;
    for (si = 0; si < n_sections; si++) {
        u8* sec = sections + (u32)si * 40u;
        if (sec[0] == '.' && sec[1] == 't' && sec[2] == 'e' &&
            sec[3] == 'x' && sec[4] == 't') {
            text_vs  = *(u32*)(sec + 8);    // Misc.VirtualSize
            text_rva = *(u32*)(sec + 12);   // VirtualAddress
            break;
        }
    }
    if (!text_rva || !text_vs) return 0;

    ctx->text_base = ntdll_base + text_rva;
    ctx->text_size = text_vs;
    return 1;
}

// Initialise — find ntdll.text, compute per-chunk baseline hashes.
ANTIDEBUG_INLINE b32 ad_nft_init(ad_nft_ctx_t* ctx) {
    if (!ctx) return 0;
    if (ctx->initialized) return 1;

    if (!ad_nft_find_ntdll_text(ctx)) return 0;

    ctx->chunk_size = ctx->text_size / AD_NFT_CHUNK_COUNT;
    if (ctx->chunk_size == 0u) return 0;

    u32 i;
    for (i = 0; i < AD_NFT_CHUNK_COUNT; i++) {
        const volatile u8* p = ctx->text_base + i * ctx->chunk_size;
        u32 len = ctx->chunk_size;
        // Last chunk absorbs any residual.
        if (i == AD_NFT_CHUNK_COUNT - 1u)
            len += ctx->text_size - AD_NFT_CHUNK_COUNT * ctx->chunk_size;
        ctx->chunk_hash[i] = ad_nft_fnv1a(p, len);
    }

    ctx->initialized = 1u;
    return 1;
}

// Runtime check — re-hash each chunk, return u64 bitmask of differing
// chunks (bit i = 1 if chunk i changed since init).
ANTIDEBUG_INLINE u64 ad_nft_check(const ad_nft_ctx_t* ctx) {
    if (!ctx || !ctx->initialized) return 0ULL;

    u64 mask = 0ULL;
    u32 i;
    for (i = 0; i < AD_NFT_CHUNK_COUNT; i++) {
        const volatile u8* p = ctx->text_base + i * ctx->chunk_size;
        u32 len = ctx->chunk_size;
        if (i == AD_NFT_CHUNK_COUNT - 1u)
            len += ctx->text_size - AD_NFT_CHUNK_COUNT * ctx->chunk_size;
        u32 h = ad_nft_fnv1a(p, len);
        if (h != ctx->chunk_hash[i]) mask |= (1ULL << i);
    }
    return mask;
}

// Popcount of differing chunks.
ANTIDEBUG_INLINE u32 ad_nft_changed_count(const ad_nft_ctx_t* ctx) {
    u64 m = ad_nft_check(ctx);
    u32 c = 0;
    while (m) { c += (u32)(m & 1ULL); m >>= 1ULL; }
    return c;
}

// Boolean wrapper — 1 if ANY chunk changed.
ANTIDEBUG_INLINE b32 ad_nft_patched(const ad_nft_ctx_t* ctx) {
    return (b32)(ad_nft_check(ctx) != 0ULL);
}

// Return the virtual address of the first byte of a given chunk —
// useful for pinpointing a hook after a mask bit fires.
ANTIDEBUG_INLINE void* ad_nft_chunk_addr(const ad_nft_ctx_t* ctx, u32 i) {
    if (!ctx || !ctx->initialized || i >= AD_NFT_CHUNK_COUNT) return 0;
    return (void*)(ctx->text_base + i * ctx->chunk_size);
}

#else  // !_MSC_VER
typedef struct { int _unused; } ad_nft_ctx_t;
ANTIDEBUG_INLINE b32 ad_nft_init(ad_nft_ctx_t* c) { (void)c; return 0; }
ANTIDEBUG_INLINE u64 ad_nft_check(const ad_nft_ctx_t* c) { (void)c; return 0ULL; }
ANTIDEBUG_INLINE b32 ad_nft_patched(const ad_nft_ctx_t* c) { (void)c; return 0; }
#endif // _MSC_VER

#endif // ANTIDEBUG_NTDLL_FULL_TEXT_H
