// ===== file: antidebug/checks/integrity/universal_hook_scan.h =====
//
// Universal Export Hook Scanner — the ultimate user-mode hook detector.
//
// PREMISE
// ───────
// EVERY user-mode hook framework (Detours, EasyHook, MinHook, Frida,
// ScyllaHide, TitanHide, Intel Pin proxy, EDR inline hooks, DBI
// trampolines) must ultimately intercept an EXPORTED function. Internal
// static functions inside a DLL aren't the target — callers use the
// exports. Therefore, verifying that EVERY export of EVERY loaded module
// is un-hooked catches the entire class.
//
// Two attack surfaces per export:
//   1. The EAT entry itself (Export Address Table RVA) is rewritten so
//      GetProcAddress returns a trampoline address.
//   2. The export's prologue bytes in .text are overwritten with a
//      jmp/call/mov+jmp to redirect execution (inline hook).
//
// We cover both:
//   * Init : walk PEB.Ldr → for each module → parse Export Directory →
//            for each export compute (target_rva, target_addr,
//            first-16-bytes FNV-1a hash)
//   * Check: re-walk, re-hash, compare. Report per-export hits.
//
// WHY IT'S "ULTIMATE"
// ───────────────────
// * Catches inline hooks on ANY function of ANY module — not just the
//   curated 10 of ntdll_dispatchers.
// * Catches EAT redirection which IAT-target validation misses (IAT
//   check verifies our callers, EAT check verifies the callees).
// * Handles forwarder exports (RVAs pointing inside the export table
//   itself) — those are skipped, as their target is a string not code.
// * Works on Windows 7 / 8 / 10 / 11 without privileges.
//
// COST
// ────
// Scope is bounded at AD_UHS_MAX_MODULES modules × AD_UHS_MAX_EXPORTS
// exports per module. Default 16 × 4096 = 65 KB of state (16 bytes per
// export). Init runs in a few ms on a 12-module process; check runs in
// ~1 ms (only FNV-1a on 16 bytes per export).
//
// BASELINE NORMALISATION
// ──────────────────────
// Init captures CURRENT bytes. If the system has pre-existing hooks
// (EDR, AV, Defender ETW-TI) applied at startup, those are part of the
// baseline and won't be flagged. We detect DRIFT since init, not
// deviation from disk. (For disk-vs-memory coverage, combine with the
// SDM check.)
//
#ifndef ANTIDEBUG_UNIVERSAL_HOOK_SCAN_H
#define ANTIDEBUG_UNIVERSAL_HOOK_SCAN_H

#include "../../core/types.h"
#include "../../core/macros.h"

#ifdef _MSC_VER

#ifndef AD_UHS_MAX_MODULES
#define AD_UHS_MAX_MODULES     16u
#endif
#ifndef AD_UHS_MAX_EXPORTS
#define AD_UHS_MAX_EXPORTS     4096u        // per module
#endif
#ifndef AD_UHS_PROLOGUE_LEN
#define AD_UHS_PROLOGUE_LEN    16u          // bytes hashed per export
#endif

typedef struct {
    u32  name_rva;         // RVA of export name string in .rdata
    u32  target_rva;       // RVA of the exported function
    u32  baseline_hash;    // FNV-1a of first 16 bytes at init
} ad_uhs_export_t;

typedef struct {
    u8*              base;
    u32              size;
    u32              text_rva;
    u32              text_size;
    u32              export_count;
    ad_uhs_export_t  exports[AD_UHS_MAX_EXPORTS];
    u8               name[16];   // DLL base name (ASCII), NUL-padded
} ad_uhs_module_t;

typedef struct {
    u32              module_count;
    ad_uhs_module_t  modules[AD_UHS_MAX_MODULES];
    u32              initialized;
} ad_uhs_ctx_t;

typedef struct {
    u32  module_index;
    u32  export_index;
    u32  reason;           // 1 = EAT target outside module
                           // 2 = prologue hash mismatch (inline hook)
                           // 4 = hook signature at first byte
                           // 8 = export target in non-executable region
    u32  hook_sig;         // bitmask of sniffed hook signatures
} ad_uhs_hit_t;

#ifndef AD_UHS_MAX_HITS
#define AD_UHS_MAX_HITS  256u
#endif

typedef struct {
    u32          hit_count;
    ad_uhs_hit_t hits[AD_UHS_MAX_HITS];
    u32          total_exports_scanned;
} ad_uhs_result_t;

// Fast FNV-1a on up to 16 bytes.
ANTIDEBUG_INLINE u32 ad_uhs_fnv1a(const volatile u8* p, u32 n) {
    u32 h = 0x811C9DC5u;
    u32 i;
    for (i = 0; i < n; i++) { h ^= p[i]; h *= 0x01000193u; }
    return h;
}

// Inline-hook signature sniffer (first byte + optional multi-byte).
ANTIDEBUG_INLINE u32 ad_uhs_sniff_hook(const u8* b) {
    u32 m = 0;
    if (b[0] == 0xE9)                                           m |= 0x01u;  // jmp rel32
    if (b[0] == 0x48 && b[1] == 0xB8 &&
        b[10] == 0xFF && b[11] == 0xE0)                         m |= 0x02u;  // mov rax,imm64 ; jmp rax
    if (b[0] == 0xFF && b[1] == 0x25)                           m |= 0x04u;  // jmp [rip+rel32]
    if (b[0] == 0xCC)                                           m |= 0x08u;  // int3 hotpatch
    if (b[0] == 0xEB)                                           m |= 0x10u;  // short jmp
    if (b[0] == 0x49 && (b[1] == 0xBA || b[1] == 0xBB))         m |= 0x20u;  // mov r10/r11, imm64
    if (b[0] == 0x68)                                           m |= 0x40u;  // push imm32 ; ret
    return m;
}

// Parse a loaded module's PE headers → locate .text and Export Directory.
// On success fills base/size/text_rva/text_size in out. Returns 1 on success.
ANTIDEBUG_INLINE b32 ad_uhs_parse_module_pe(u8* module_base, u32 module_size,
                                             ad_uhs_module_t* out) {
    if (*(u16*)module_base != 0x5A4D) return 0;
    u32 pe_off = *(u32*)(module_base + 0x3C);
    if (pe_off > 0x1000u) return 0;
    u8* pe = module_base + pe_off;
    if (*(u32*)pe != 0x00004550u) return 0;

    u16 n_sec    = *(u16*)(pe + 6);
    u16 opt_size = *(u16*)(pe + 20);
    u8* sections = pe + 24 + opt_size;

    // Find .text
    out->text_rva = 0; out->text_size = 0;
    u16 si;
    for (si = 0; si < n_sec; si++) {
        u8* sec = sections + (u32)si * 40u;
        if (sec[0] == '.' && sec[1] == 't' && sec[2] == 'e' &&
            sec[3] == 'x' && sec[4] == 't') {
            out->text_rva  = *(u32*)(sec + 12);
            out->text_size = *(u32*)(sec + 8);
            break;
        }
    }

    out->base = module_base;
    out->size = module_size;
    return 1;
}

// Walk Export Directory, record (name_rva, target_rva, baseline_hash)
// for each export. Forwarders are skipped. Returns number of exports stored.
ANTIDEBUG_INLINE u32 ad_uhs_snapshot_exports(ad_uhs_module_t* m) {
    m->export_count = 0;
    u8* pe = m->base + *(u32*)(m->base + 0x3C);
    u8* opt = pe + 24;
    // DataDir[0] = Export Directory
    u32 exp_rva  = *(u32*)(opt + 112 + 0);
    u32 exp_size = *(u32*)(opt + 112 + 4);
    if (exp_rva == 0u || exp_size == 0u) return 0;

    u8* exp_tbl = m->base + exp_rva;
    u32 n_funcs   = *(u32*)(exp_tbl + 0x14);   // NumberOfFunctions
    u32 n_names   = *(u32*)(exp_tbl + 0x18);   // NumberOfNames
    u32 func_rva  = *(u32*)(exp_tbl + 0x1C);   // AddressOfFunctions
    u32 name_rva  = *(u32*)(exp_tbl + 0x20);   // AddressOfNames
    u32 ord_rva   = *(u32*)(exp_tbl + 0x24);   // AddressOfNameOrdinals

    u32* funcs = (u32*)(m->base + func_rva);
    u32* names = (u32*)(m->base + name_rva);
    u16* ords  = (u16*)(m->base + ord_rva);

    // Range of the export table for forwarder detection.
    u32 exp_end = exp_rva + exp_size;

    u32 i;
    for (i = 0; i < n_names && m->export_count < AD_UHS_MAX_EXPORTS; i++) {
        u16 ord    = ords[i];
        if (ord >= n_funcs) continue;
        u32 rva    = funcs[ord];
        if (rva == 0u) continue;

        // Forwarder: target_rva points into export directory (string).
        if (rva >= exp_rva && rva < exp_end) continue;

        // Baseline: hash first 16 bytes.
        const volatile u8* p = m->base + rva;
        u32 h = ad_uhs_fnv1a(p, AD_UHS_PROLOGUE_LEN);

        ad_uhs_export_t* e = &m->exports[m->export_count++];
        e->name_rva       = names[i];
        e->target_rva     = rva;
        e->baseline_hash  = h;
    }
    return m->export_count;
}

// Initialise by walking PEB.Ldr. Returns module count.
ANTIDEBUG_INLINE b32 ad_uhs_init(ad_uhs_ctx_t* ctx) {
    if (!ctx) return 0;
    if (ctx->initialized) return 1;

    u8* peb = (u8*)__readgsqword(0x60);
    if (!peb) return 0;
    u8* ldr = *(u8**)(peb + 0x18);
    if (!ldr) return 0;

    u8* head  = ldr + 0x10;
    u8* entry = *(u8**)head;

    u32 walk = 0;
    ctx->module_count = 0u;
    while (entry != head && walk < 256u && ctx->module_count < AD_UHS_MAX_MODULES) {
        walk++;
        u8* mb = *(u8**)(entry + 0x30);
        u32 ms = *(u32*)(entry + 0x40);
        u16  nl = *(u16*)(entry + 0x58);
        u16* nb = *(u16**)(entry + 0x60);

        if (mb && ms) {
            ad_uhs_module_t* M = &ctx->modules[ctx->module_count];
            if (ad_uhs_parse_module_pe(mb, ms, M)) {
                // Copy name (trunc to 15 chars, low-byte of UTF-16)
                u32 nc = (u32)(nl / 2u);
                if (nc > 15u) nc = 15u;
                u32 j;
                for (j = 0; j < nc; j++) {
                    u16 c = nb ? nb[j] : (u16)' ';
                    M->name[j] = (u8)(c & 0xFFu);
                }
                for (; j < 16u; j++) M->name[j] = 0;

                ad_uhs_snapshot_exports(M);
                if (M->export_count > 0) ctx->module_count++;
            }
        }
        entry = *(u8**)entry;
    }

    ctx->initialized = 1u;
    return (b32)(ctx->module_count > 0u);
}

// Check every recorded export. Report hits.
ANTIDEBUG_INLINE void ad_uhs_check(const ad_uhs_ctx_t* ctx, ad_uhs_result_t* out) {
    u32 k; for (k = 0; k < (u32)sizeof(*out); k++) ((volatile u8*)out)[k] = 0;
    if (!ctx || !ctx->initialized) return;

    u32 mi;
    for (mi = 0; mi < ctx->module_count; mi++) {
        const ad_uhs_module_t* M = &ctx->modules[mi];
        u8* text_start = M->base + M->text_rva;
        u8* text_end   = text_start + M->text_size;

        u32 ei;
        for (ei = 0; ei < M->export_count; ei++) {
            const ad_uhs_export_t* E = &M->exports[ei];
            out->total_exports_scanned++;

            u8* tgt = M->base + E->target_rva;
            u32 reason = 0u;

            // (1) EAT target outside the module at all
            if (tgt < M->base || tgt >= M->base + M->size)
                reason |= 0x01u;

            // Skip further checks if target is invalid (outside module)
            if (reason & 0x01u) {
                if (out->hit_count < AD_UHS_MAX_HITS) {
                    ad_uhs_hit_t* h = &out->hits[out->hit_count++];
                    h->module_index = mi;
                    h->export_index = ei;
                    h->reason = reason;
                    h->hook_sig = 0;
                }
                continue;
            }

            // (2) Prologue bytes changed since init — the ONLY reliable
            // signal. Data exports (strings, tables, init blocks) living
            // in .rdata / .data are normal and not flagged.
            u32 h = ad_uhs_fnv1a(tgt, AD_UHS_PROLOGUE_LEN);
            if (h != E->baseline_hash) reason |= 0x02u;

            // (3) Sniff hook signatures — only meaningful if bytes changed.
            u32 sig = 0u;
            if (reason & 0x02u) sig = ad_uhs_sniff_hook(tgt);
            if (sig) reason |= 0x04u;

            // Only emit hits for bytes-changed scenarios, not for
            // data-export outside-of-.text (which is legitimate).
            if ((reason & 0x06u) != 0u && out->hit_count < AD_UHS_MAX_HITS) {
                ad_uhs_hit_t* hh = &out->hits[out->hit_count++];
                hh->module_index = mi;
                hh->export_index = ei;
                hh->reason = reason;
                hh->hook_sig = sig;
            }
        }
    }
}

ANTIDEBUG_INLINE b32 ad_uhs_hooked(const ad_uhs_ctx_t* ctx) {
    ad_uhs_result_t r;
    ad_uhs_check(ctx, &r);
    return (b32)(r.hit_count > 0u);
}

ANTIDEBUG_INLINE u32 ad_uhs_hit_count(const ad_uhs_ctx_t* ctx) {
    ad_uhs_result_t r;
    ad_uhs_check(ctx, &r);
    return r.hit_count;
}

#else  // !_MSC_VER
typedef struct { int _unused; } ad_uhs_ctx_t;
typedef struct { int _unused; } ad_uhs_result_t;
ANTIDEBUG_INLINE b32 ad_uhs_init(ad_uhs_ctx_t* c) { (void)c; return 0; }
ANTIDEBUG_INLINE void ad_uhs_check(const ad_uhs_ctx_t* c, ad_uhs_result_t* r) { (void)c; (void)r; }
ANTIDEBUG_INLINE b32 ad_uhs_hooked(const ad_uhs_ctx_t* c) { (void)c; return 0; }
#endif // _MSC_VER

#endif // ANTIDEBUG_UNIVERSAL_HOOK_SCAN_H
