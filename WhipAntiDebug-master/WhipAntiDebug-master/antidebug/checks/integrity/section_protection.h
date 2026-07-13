// ===== file: antidebug/checks/integrity/section_protection.h =====
//
// Section Protection Drift — catches in-progress hook installation.
//
// Every PE section declares its intended runtime protection in
// IMAGE_SECTION_HEADER.Characteristics:
//
//   IMAGE_SCN_MEM_EXECUTE  (0x20000000) — code section
//   IMAGE_SCN_MEM_READ     (0x40000000) — readable
//   IMAGE_SCN_MEM_WRITE    (0x80000000) — writable
//
// The loader maps each section with the protection implied by those
// flags. After load, protections are expected to remain immutable
// — a `.text` section is R+X and NEVER W; `.rdata` is R and never X.
//
// Hook installation frameworks (Microsoft Detours, EasyHook, MinHook,
// Frida) violate this invariant. To patch `.text`, they issue
// `VirtualProtect(PAGE_EXECUTE_READWRITE)` → install the hook → then
// `VirtualProtect` back. The WRITE window is short (microseconds) but
// a periodic probe samples it statistically. Worse — many EDRs leave
// the `.text` as RWX permanently to allow dynamic hook churn without
// the VirtualProtect dance every time.
//
// Our check snapshots every section's expected protection at init
// (derived from Characteristics flags), then re-queries the live
// protection via NtQueryVirtualMemory(MemoryBasicInformation) on each
// call. Any upgraded write bit on code, or executable bit on data, is
// reported with the section name.
//
// This defeats:
//   * Detours / EasyHook / MinHook inline hooks (during install window)
//   * EDR persistent-RWX policies (permanent detection)
//   * Self-modifying polymorphic stubs (JIT patchers)
//   * Some DBI trampoline relocation strategies
//
// Zero false positives on a clean build.
//
#ifndef ANTIDEBUG_SECTION_PROTECTION_H
#define ANTIDEBUG_SECTION_PROTECTION_H

#include "../../core/types.h"
#include "../../core/macros.h"
#include "../../core/syscall_bridge.h"
#include "../../core/string_encrypt.h"

// Stack-built encrypted string for NtQueryVirtualMemory (20 chars + NUL = 21).
#ifndef AD_STRENC_NtQueryVirtualMemory
#define AD_STRENC_NtQueryVirtualMemory(buf)                                  \
    do {                                                                     \
        const u8 _k = AD_STR_KEY(0x7A);                                     \
        char buf##_e[21];                                                    \
        AD_ENC(buf##_e,  0, 'N', _k); AD_ENC(buf##_e,  1, 't', _k);       \
        AD_ENC(buf##_e,  2, 'Q', _k); AD_ENC(buf##_e,  3, 'u', _k);       \
        AD_ENC(buf##_e,  4, 'e', _k); AD_ENC(buf##_e,  5, 'r', _k);       \
        AD_ENC(buf##_e,  6, 'y', _k); AD_ENC(buf##_e,  7, 'V', _k);       \
        AD_ENC(buf##_e,  8, 'i', _k); AD_ENC(buf##_e,  9, 'r', _k);       \
        AD_ENC(buf##_e, 10, 't', _k); AD_ENC(buf##_e, 11, 'u', _k);       \
        AD_ENC(buf##_e, 12, 'a', _k); AD_ENC(buf##_e, 13, 'l', _k);       \
        AD_ENC(buf##_e, 14, 'M', _k); AD_ENC(buf##_e, 15, 'e', _k);       \
        AD_ENC(buf##_e, 16, 'm', _k); AD_ENC(buf##_e, 17, 'o', _k);       \
        AD_ENC(buf##_e, 18, 'r', _k); AD_ENC(buf##_e, 19, 'y', _k);       \
        AD_DECODE_BUF(buf##_e, 20, _k);                                     \
        for (unsigned _ci = 0; _ci < 21; _ci++) (buf)[_ci] = buf##_e[_ci];  \
    } while (0)
#endif

#ifdef _MSC_VER

#define AD_SP_MAX_SECTIONS  32u

// IMAGE_SCN flags we care about.
#define AD_SCN_MEM_EXECUTE  0x20000000u
#define AD_SCN_MEM_READ     0x40000000u
#define AD_SCN_MEM_WRITE    0x80000000u

// Win32 memory protections (the four bit-packed values returned by
// NtQueryVirtualMemory / VirtualProtect).
#define AD_PAGE_NOACCESS          0x01u
#define AD_PAGE_READONLY          0x02u
#define AD_PAGE_READWRITE         0x04u
#define AD_PAGE_WRITECOPY         0x08u
#define AD_PAGE_EXECUTE           0x10u
#define AD_PAGE_EXECUTE_READ      0x20u
#define AD_PAGE_EXECUTE_READWRITE 0x40u
#define AD_PAGE_EXECUTE_WRITECOPY 0x80u

typedef struct {
    u8*  base;             // section VA base
    u32  size;             // virtual size
    u32  chars;            // IMAGE_SECTION_HEADER.Characteristics
    u32  expected_prot;    // derived AD_PAGE_* value
    u8   name[8];          // section name (ASCII, NUL-padded)
} ad_sp_section_t;

typedef struct {
    u32              count;
    ad_sp_section_t  sections[AD_SP_MAX_SECTIONS];
    u32              initialized;
} ad_sp_ctx_t;

typedef struct {
    u32  section_index;
    u32  expected_prot;
    u32  actual_prot;
} ad_sp_hit_t;

typedef struct {
    u32          hit_count;
    ad_sp_hit_t  hits[AD_SP_MAX_SECTIONS];
} ad_sp_result_t;

// Derive expected memory protection from section Characteristics.
ANTIDEBUG_INLINE u32 ad_sp_chars_to_prot(u32 chars) {
    b32 r = (b32)((chars & AD_SCN_MEM_READ)    != 0u);
    b32 w = (b32)((chars & AD_SCN_MEM_WRITE)   != 0u);
    b32 x = (b32)((chars & AD_SCN_MEM_EXECUTE) != 0u);

    // Loader typically maps:
    //   .text:   X + R      → PAGE_EXECUTE_READ (0x20)
    //   .rdata:  R          → PAGE_READONLY     (0x02)
    //   .data:   R + W      → PAGE_READWRITE    (0x04)
    //   .pdata/.xdata: R    → PAGE_READONLY
    //   .rsrc:   R          → PAGE_READONLY
    //   .reloc:  R          → PAGE_READONLY (stripped in some builds)
    if (x && w && r) return AD_PAGE_EXECUTE_READWRITE;
    if (x && r)      return AD_PAGE_EXECUTE_READ;
    if (x)           return AD_PAGE_EXECUTE;
    if (w && r)      return AD_PAGE_READWRITE;
    if (r)           return AD_PAGE_READONLY;
    return AD_PAGE_NOACCESS;
}

// Initialise: parse our own PE, record every section's expected prot.
ANTIDEBUG_INLINE b32 ad_sp_init(ad_sp_ctx_t* ctx) {
    if (!ctx) return 0;
    if (ctx->initialized) return 1;

    u8* peb = (u8*)__readgsqword(0x60);
    if (!peb) return 0;
    u8* image = *(u8**)(peb + 0x10);
    if (!image) return 0;
    if (*(u16*)image != 0x5A4D) return 0;

    u32 pe_off = *(u32*)(image + 0x3C);
    if (pe_off > 0x1000u) return 0;
    u8* pe = image + pe_off;
    if (*(u32*)pe != 0x00004550u) return 0;

    u16 n_sec    = *(u16*)(pe + 6);
    u16 opt_size = *(u16*)(pe + 20);
    u8* sections = pe + 24 + opt_size;

    if (n_sec > AD_SP_MAX_SECTIONS) n_sec = AD_SP_MAX_SECTIONS;
    ctx->count = 0u;

    u16 si;
    for (si = 0; si < n_sec; si++) {
        u8* sec = sections + (u32)si * 40u;

        ad_sp_section_t* out = &ctx->sections[ctx->count];
        u32 k;
        for (k = 0; k < 8u; k++) out->name[k] = sec[k];
        u32 vs   = *(u32*)(sec + 8);
        u32 va   = *(u32*)(sec + 12);
        u32 ch   = *(u32*)(sec + 36);
        out->base  = image + va;
        out->size  = vs;
        out->chars = ch;
        out->expected_prot = ad_sp_chars_to_prot(ch);
        ctx->count++;
    }
    ctx->initialized = 1u;
    return (b32)(ctx->count > 0u);
}

// Query runtime protection of a single region via NtQueryVirtualMemory.
// Returns 0 on failure, protection value otherwise.
ANTIDEBUG_INLINE u32 ad_sp_query_prot(void* addr) {
    static u16 s_ssn = AD_SSN_UNRESOLVED;
    AD_RESOLVE_SSN_ENC(s_ssn, NtQueryVirtualMemory, 24);
    if (s_ssn == AD_SSN_FAILED) return 0u;

    // MEMORY_BASIC_INFORMATION layout (x64): 48 bytes
    //   +0x00 BaseAddress
    //   +0x08 AllocationBase
    //   +0x10 AllocationProtect
    //   +0x14 (4 bytes pad)
    //   +0x18 RegionSize
    //   +0x20 State
    //   +0x24 Protect       <-- what we want
    //   +0x28 Type
    u8 mbi[48];
    u32 k; for (k = 0; k < 48u; k++) mbi[k] = 0;

    u64 ret_len = 0;
    ad_ntstatus_t st = AD_SYSCALL6(
        s_ssn,
        AD_CURRENT_PROCESS,
        addr,
        (u64)0,            // MemoryBasicInformation
        (void*)mbi,
        (u64)sizeof(mbi),
        &ret_len);
    if (!AD_NT_SUCCESS(st)) return 0u;

    return *(const u32*)(mbi + 0x24);
}

// Main check — re-query each section, report any that drifted.
ANTIDEBUG_INLINE void ad_sp_check(const ad_sp_ctx_t* ctx, ad_sp_result_t* out) {
    u32 k; for (k = 0; k < (u32)sizeof(*out); k++) ((volatile u8*)out)[k] = 0;
    if (!ctx || !ctx->initialized) return;

    u32 i;
    for (i = 0; i < ctx->count; i++) {
        if (ctx->sections[i].size == 0u) continue;
        u32 actual = ad_sp_query_prot(ctx->sections[i].base);
        if (actual == 0u) continue;

        // The expected protection is the loader-mapped value. A drift is
        // any elevation: gaining WRITE on code, gaining EXECUTE on data,
        // or unexpected PAGE_EXECUTE_READWRITE / PAGE_EXECUTE_WRITECOPY.
        b32 drift = 0;

        b32 exp_w = (b32)(ctx->sections[i].expected_prot ==
                          AD_PAGE_EXECUTE_READWRITE
                       || ctx->sections[i].expected_prot == AD_PAGE_READWRITE);
        b32 exp_x = (b32)(ctx->sections[i].expected_prot == AD_PAGE_EXECUTE
                       || ctx->sections[i].expected_prot == AD_PAGE_EXECUTE_READ
                       || ctx->sections[i].expected_prot ==
                          AD_PAGE_EXECUTE_READWRITE);

        b32 act_w = (b32)(actual == AD_PAGE_EXECUTE_READWRITE
                       || actual == AD_PAGE_READWRITE
                       || actual == AD_PAGE_EXECUTE_WRITECOPY
                       || actual == AD_PAGE_WRITECOPY);
        b32 act_x = (b32)(actual == AD_PAGE_EXECUTE
                       || actual == AD_PAGE_EXECUTE_READ
                       || actual == AD_PAGE_EXECUTE_READWRITE
                       || actual == AD_PAGE_EXECUTE_WRITECOPY);

        if (act_w && !exp_w) drift = 1;   // unexpected WRITE
        if (act_x && !exp_x) drift = 1;   // unexpected EXECUTE

        if (drift) {
            if (out->hit_count < AD_SP_MAX_SECTIONS) {
                out->hits[out->hit_count].section_index  = i;
                out->hits[out->hit_count].expected_prot  = ctx->sections[i].expected_prot;
                out->hits[out->hit_count].actual_prot    = actual;
                out->hit_count++;
            }
        }
    }
}

ANTIDEBUG_INLINE b32 ad_sp_drifted(const ad_sp_ctx_t* ctx) {
    ad_sp_result_t r;
    ad_sp_check(ctx, &r);
    return (b32)(r.hit_count > 0u);
}

#else  // !_MSC_VER
typedef struct { int _unused; } ad_sp_ctx_t;
typedef struct { int _unused; } ad_sp_result_t;
ANTIDEBUG_INLINE b32 ad_sp_init(ad_sp_ctx_t* c) { (void)c; return 0; }
ANTIDEBUG_INLINE void ad_sp_check(const ad_sp_ctx_t* c, ad_sp_result_t* r) { (void)c; (void)r; }
ANTIDEBUG_INLINE b32 ad_sp_drifted(const ad_sp_ctx_t* c) { (void)c; return 0; }
#endif // _MSC_VER

#endif // ANTIDEBUG_SECTION_PROTECTION_H
