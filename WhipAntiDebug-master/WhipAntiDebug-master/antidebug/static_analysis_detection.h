// ===== file: antidebug/static_analysis_detection.h =====
//
// Anti-static analysis protections
// Détecte les modifications, patches, et analyse statique
//

#ifndef ANTIDEBUG_STATIC_ANALYSIS_DETECTION_H
#define ANTIDEBUG_STATIC_ANALYSIS_DETECTION_H

#include "core/types.h"
#include "core/macros.h"
#include <windows.h>
#include <intrin.h>

// =========================================================================
// PROTECTIONS ANTI-ANALYSE STATIQUE
// =========================================================================

#define EXPECTED_TEXT_CHECKSUM   0x8F4A2E1Du
#define EXPECTED_RDATA_CHECKSUM  0x3B8C9F2Au
#define EXPECTED_CODE_SIZE       0x28D000u

ANTIDEBUG_INLINE u32 ad_check_binary_integrity(void) {
    volatile u32 score = 0u;

    // EXPECTED_CODE_SIZE est un placeholder non calibré — on ne flag plus
    // sur le SizeOfImage. On garde uniquement la sanity-check des headers.
    HMODULE hMod = GetModuleHandleA(NULL);
    if (hMod) {
        IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)hMod;
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
            score += 30u;
            return score;
        }
        IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)((u8*)hMod + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) {
            score += 30u;
        }
    }

    return score;
}

ANTIDEBUG_INLINE u32 ad_detect_code_patches(void) {
    volatile u32 score = 0u;

    void* critical_addrs[] = {
        (void*)ad_detect_code_patches,
        (void*)ad_check_binary_integrity,
        NULL
    };

    for (int i = 0; critical_addrs[i]; i++) {
        u8* code = (u8*)critical_addrs[i];

        if (code[0] == 0x90 && code[1] == 0x90) {
            score += 20u;
        }
        if (code[0] == 0xCC) {
            score += 25u;
        }
        if (code[0] == 0xC3) {
            score += 18u;
        }
        if (code[0] == 0xE9) {
            score += 22u;
        }
    }

    return score;
}

ANTIDEBUG_INLINE u32 ad_detect_constant_tampering(void) {
    // Le checksum attendu (0xCAFE1337) ne correspond pas au XOR réel des
    // constantes — placeholder jamais calibré. Désactivé.
    return 0u;
}

// Code de confusion pour analyseurs statiques (x64-safe via intrinsics)
ANTIDEBUG_INLINE u32 ad_confuse_static_analysis(void) {
    volatile u32 score = 0u;

    // Quelques NOP/fence pour casser des patterns simples
    __nop();
    __nop();
    _ReadWriteBarrier();
    __nop();

    u8* current_func = (u8*)ad_confuse_static_analysis;
    u32 entropy = 0u;
    for (int i = 0; i < 64; i++) {
        entropy += current_func[i];
    }
    if (entropy < 3000u) {
        score += 12u;
    }

    return score;
}

ANTIDEBUG_INLINE u32 ad_verify_critical_sections(void) {
    // EXPECTED_TEXT_CHECKSUM est un placeholder non calibré → désactivé.
    // Le projet a déjà des CRC d'intégrité calibrés ailleurs (anti_tamper,
    // critical_scan).
    return 0u;
}

ANTIDEBUG_INLINE u32 ad_static_analysis_master(void) {
    volatile u32 total_score = 0u;

    __try {
        total_score += ad_check_binary_integrity();
        total_score += ad_detect_code_patches();
        total_score += ad_detect_constant_tampering();
        total_score += ad_confuse_static_analysis();
        total_score += ad_verify_critical_sections();
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        total_score += 100u;
    }

    return total_score;
}

// Honeypot statique : chaîne factice visible en désassemblage
ANTIDEBUG_INLINE void ad_analyzer_honeypot(void) {
    static const volatile char fake_flag[] =
        "FAKE{this_is_not_the_real_flag_static_analysis_detected}";
    static const volatile char fake_marker[] = "FLAG{fake}";
    (void)fake_flag;
    (void)fake_marker;
    __nop();
    __nop();
}

#endif // ANTIDEBUG_STATIC_ANALYSIS_DETECTION_H
