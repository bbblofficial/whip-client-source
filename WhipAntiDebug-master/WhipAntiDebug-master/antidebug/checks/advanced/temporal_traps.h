// ===== file: antidebug/checks/advanced/temporal_traps.h =====
//
// Temporal Traps — plant state snapshots at T0 (during ad_init), verify
// at T+N (during ad_run_hardened). Creates a temporal bind: the reverser
// doesn't know WHEN verification will happen, so they can't temporarily
// patch and then unpatch without being caught.
//
#ifndef ANTIDEBUG_TEMPORAL_TRAPS_H
#define ANTIDEBUG_TEMPORAL_TRAPS_H

#include "../../core/types.h"
#include "../../core/macros.h"
#include "../../core/mem_encrypt.h"

#ifdef _MSC_VER
#include <intrin.h>
#endif

typedef struct {
    ad_vault_t planted_peb_debug;     // encrypted PEB.BeingDebugged at T0
    ad_vault_t planted_ntgflag;       // encrypted NtGlobalFlag at T0
    ad_vault_t planted_tsc;           // encrypted TSC at T0
    ad_vault_t planted_code_crc;      // encrypted CRC of first 64 bytes of .text
    u32        plant_count;
    b32        planted;
} ad_temporal_ctx_t;

// ---------------------------------------------------------------------------
// Plant: capture environment state at init time
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE void ad_temporal_trap_plant(ad_temporal_ctx_t* ctx,
                                              const ad_memkey_t* mk) {
#ifdef _MSC_VER
    AD_ZERO_BUF(ctx, sizeof(*ctx));

    u8* peb = (u8*)__readgsqword(0x60);
    u8 being_debugged = *(u8*)(peb + 2);
    u32 nt_global_flag = *(u32*)(peb + 0xBC);

    ad_vault_store(&ctx->planted_peb_debug, (u64)being_debugged, mk);
    ad_vault_store(&ctx->planted_ntgflag, (u64)nt_global_flag, mk);
    ad_vault_store(&ctx->planted_tsc, __rdtsc(), mk);

    // CRC of image base first 64 bytes (PE header)
    void* img = *(void**)(peb + 0x10);  // ImageBaseAddress
    if (img) {
        u32 crc = 0xFFFFFFFFu;
        const u8* p = (const u8*)img;
        u32 i;
        for (i = 0; i < 64u; i++) {
            crc ^= p[i];
            u32 bit;
            for (bit = 0; bit < 8u; bit++) {
                crc = (crc >> 1) ^ (0xEDB88320u & (-(s32)(crc & 1)));
            }
        }
        crc ^= 0xFFFFFFFFu;
        ad_vault_store(&ctx->planted_code_crc, (u64)crc, mk);
    }

    ctx->plant_count = 4;
    ctx->planted = 1;
#endif
}

// ---------------------------------------------------------------------------
// Verify: re-read the same values and compare with planted state.
// Returns 1 if divergence detected (environment changed between T0 and T+N).
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE b32 ad_temporal_trap_verify(ad_temporal_ctx_t* ctx,
                                              const ad_memkey_t* mk) {
#ifdef _MSC_VER
    if (!ctx->planted) return 0;

    u8* peb = (u8*)__readgsqword(0x60);
    u8 current_debug = *(u8*)(peb + 2);
    u32 current_ntgflag = *(u32*)(peb + 0xBC);

    u64 planted_debug = ad_vault_load(&ctx->planted_peb_debug, mk);
    u64 planted_ntgflag = ad_vault_load(&ctx->planted_ntgflag, mk);

    u32 suspicious = 0;

    // Case 1: PEB.BeingDebugged changed (debugger attached/detached)
    if ((u8)planted_debug != current_debug) suspicious++;

    // Case 2: NtGlobalFlag changed
    if ((u32)planted_ntgflag != current_ntgflag) suspicious++;

    // Case 3: Time elapsed is anomalous
    // If init was > 30 seconds ago AND score is 0, that's suspicious
    // (indicates single-stepping through the code)
    u64 planted_tsc = ad_vault_load(&ctx->planted_tsc, mk);
    u64 current_tsc = __rdtsc();
    u64 elapsed = current_tsc - planted_tsc;
    // ~3GHz * 30s = ~90 billion cycles
    if (elapsed > 90000000000ULL) suspicious++;

    // Case 4: PE header changed (anti-dump or patching)
    void* img = *(void**)(peb + 0x10);
    if (img) {
        u32 crc = 0xFFFFFFFFu;
        const u8* p = (const u8*)img;
        u32 i;
        for (i = 0; i < 64u; i++) {
            crc ^= p[i];
            u32 bit;
            for (bit = 0; bit < 8u; bit++) {
                crc = (crc >> 1) ^ (0xEDB88320u & (-(s32)(crc & 1)));
            }
        }
        crc ^= 0xFFFFFFFFu;
        u64 planted_crc = ad_vault_load(&ctx->planted_code_crc, mk);
        if ((u32)planted_crc != crc) suspicious++;
    }

    return (b32)(suspicious > 0u);
#else
    return 0;
#endif
}

#endif // ANTIDEBUG_TEMPORAL_TRAPS_H
