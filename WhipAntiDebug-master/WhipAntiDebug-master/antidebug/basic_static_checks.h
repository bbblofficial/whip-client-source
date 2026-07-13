// ===== file: antidebug/basic_static_checks.h =====
//
// Checks basiques anti-analyse statique
// Détections simples mais efficaces
//

#ifndef ANTIDEBUG_BASIC_STATIC_CHECKS_H
#define ANTIDEBUG_BASIC_STATIC_CHECKS_H

#include "core/types.h"
#include "core/macros.h"

// =========================================================================
// CHECKS BASIQUES ANTI-ANALYSE STATIQUE
// =========================================================================

// --- Vérification de l'entropie du code ---
ANTIDEBUG_INLINE u32 ad_check_code_entropy(void) {
    volatile u32 score = 0u;

    HMODULE hMod = GetModuleHandleA(NULL);
    if (!hMod) return 10u;

    // Calculer l'entropie de la section .text
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)hMod;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)((u8*)hMod + dos->e_lfanew);
    IMAGE_SECTION_HEADER* sections = IMAGE_FIRST_SECTION(nt);

    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (memcmp(sections[i].Name, ".text\0\0\0", 8) == 0) {
            u8* text_start = (u8*)hMod + sections[i].VirtualAddress;
            u32 text_size = sections[i].Misc.VirtualSize;

            // Compter les fréquences d'octets
            u32 freq[256] = {0};
            for (u32 j = 0; j < text_size && j < 10000; j++) {  // Sample limité
                freq[text_start[j]]++;
            }

            // NOTE : MSVC remplit l'inter-fonctions avec 0xCC (INT3) en
            // padding normal — `freq[0xCC] > 0` flagait toujours. On exige
            // une densité anormale (>5%) pour un vrai signal d'INT3 injecté.
            if (freq[0x90] > text_size / 50) {   // >2% NOPs (padding hot-patch)
                score += 15u;
            }
            if (freq[0xCC] > text_size / 20) {   // >5% INT3 = vraiment anormal
                score += 20u;
            }
            // RET (0xC3) est aussi très fréquent dans le code normal ; seuil
            // relevé pour ne flag que sur du code visiblement émasculé.
            if (freq[0xC3] > text_size / 100) {  // >1% RET = beaucoup
                score += 12u;
            }

            break;
        }
    }

    return score;
}

// --- Détection de modifications simples ---
ANTIDEBUG_INLINE u32 ad_check_simple_patches(void) {
    volatile u32 score = 0u;

    // Vérifier des zones critiques connues
    void* critical_functions[] = {
        (void*)ad_check_simple_patches,
        (void*)GetModuleHandleA,
        (void*)GetProcAddress,
        NULL
    };

    for (int i = 0; critical_functions[i]; i++) {
        u8* func = (u8*)critical_functions[i];

        __try {
            // Patterns de patching courants
            if (func[0] == 0x90 && func[1] == 0x90 && func[2] == 0x90) {
                score += 25u;  // Triple NOP suspect
            }

            // Hook pattern: MOV EAX, imm32 + JMP
            if (func[0] == 0xB8 && func[5] == 0xE9) {
                score += 30u;  // Hook pattern détecté
            }

            // Patch pattern: XOR EAX,EAX + RET
            if (func[0] == 0x31 && func[1] == 0xC0 && func[2] == 0xC3) {
                score += 20u;  // Fonction neutralisée
            }
        }
        __except(EXCEPTION_EXECUTE_HANDLER) {
            score += 10u;  // Accès protégé suspect
        }
    }

    return score;
}

// --- Vérification des imports suspects ---
ANTIDEBUG_INLINE u32 ad_check_suspicious_imports(void) {
    volatile u32 score = 0u;

    HMODULE hMod = GetModuleHandleA(NULL);
    if (!hMod) return 5u;

    // NOTE : retiré dbghelp/imagehlp/psapi — ces DLLs sont chargées par
    // beaucoup de processus normaux (Windows EDR, Defender, Telemetry, et
    // par psapi.lib lui-même via ce binaire). On ne garde que symsrv qui
    // est plus spécifique au debugging de symboles.
    const char* suspicious_dlls[] = {
        "symsrv.dll",
        NULL
    };

    for (int i = 0; suspicious_dlls[i]; i++) {
        if (GetModuleHandleA(suspicious_dlls[i])) {
            score += 10u;  // DLL de débogage chargée
        }
    }

    // Vérifier des fonctions de débogage
    HMODULE kernel32 = GetModuleHandleA("kernel32.dll");
    if (kernel32) {
        const char* debug_functions[] = {
            "IsDebuggerPresent",
            "CheckRemoteDebuggerPresent",
            "OutputDebugStringA",
            NULL
        };

        for (int i = 0; debug_functions[i]; i++) {
            void* func = GetProcAddress(kernel32, debug_functions[i]);
            if (func) {
                u8* code = (u8*)func;
                // Vérifier si la fonction a été hookée
                if (code[0] == 0xE9 || code[0] == 0xEB) {  // JMP
                    score += 15u;
                }
            }
        }
    }

    return score;
}

// --- Détection de sections ajoutées ---
ANTIDEBUG_INLINE u32 ad_check_extra_sections(void) {
    volatile u32 score = 0u;

    HMODULE hMod = GetModuleHandleA(NULL);
    if (!hMod) return 5u;

    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)hMod;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)((u8*)hMod + dos->e_lfanew);

    // NOTE : "expected_sections=7" ne reflète pas la réalité de ce binaire
    // (qui a légitimement plus de sections : .text, .rdata, .data, .pdata,
    // .rsrc, .reloc, .ainotic, ...). On ne flag que les noms de sections
    // explicitement suspects (cf. boucle ci-dessous).

    // Vérifier les noms de sections suspects
    IMAGE_SECTION_HEADER* sections = IMAGE_FIRST_SECTION(nt);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        char section_name[9] = {0};
        memcpy(section_name, sections[i].Name, 8);

        // Sections ajoutées par des outils de modification
        if (strcmp(section_name, ".patch") == 0 ||
            strcmp(section_name, ".hook") == 0 ||
            strcmp(section_name, ".new") == 0 ||
            strcmp(section_name, ".add") == 0) {
            score += 35u;
        }

        // Sections avec caractéristiques suspectes
        if (sections[i].Characteristics & IMAGE_SCN_CNT_CODE &&
            sections[i].Characteristics & IMAGE_SCN_MEM_WRITE) {
            score += 20u;  // Section code modifiable
        }
    }

    return score;
}

// --- Vérification du PE header ---
ANTIDEBUG_INLINE u32 ad_check_pe_header_integrity(void) {
    volatile u32 score = 0u;

    HMODULE hMod = GetModuleHandleA(NULL);
    if (!hMod) return 10u;

    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)hMod;

    // Vérifier la signature DOS
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        score += 50u;  // Header corrompu
    }

    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)((u8*)hMod + dos->e_lfanew);

    // Vérifier la signature PE
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        score += 50u;  // Header PE corrompu
    }

    // NOTE : retiré le check "DEBUG_STRIPPED non positionné" et "binaire <24h" —
    // chaque build dev a ces deux propriétés et déclenchait +20 systématique.
    return score;
}

// --- Check de cohérence générale ---
// NOTE : la détection HW-breakpoints (DR0-DR7) a été retirée d'ici — le
// projet manipule lui-même les debug registers pour ses propres détections
// (cf. hardware_via_exc, BTB triangulation), ce qui était un auto-FP.
// La détection HW-bp légitime est faite ailleurs dans le projet.
ANTIDEBUG_INLINE u32 ad_general_consistency_check(void) {
    volatile u32 score = 0u;
    if (GetModuleHandleA == NULL || GetProcAddress == NULL) {
        score += 100u;
    }
    return score;
}

// --- Master function pour tous les checks basiques ---
ANTIDEBUG_INLINE u32 ad_basic_static_checks_master(void) {
    volatile u32 total_score = 0u;

    __try {
        total_score += ad_check_code_entropy();
        total_score += ad_check_simple_patches();
        total_score += ad_check_suspicious_imports();
        total_score += ad_check_extra_sections();
        total_score += ad_check_pe_header_integrity();
        total_score += ad_general_consistency_check();
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        total_score += 50u;  // Exception durant les checks
    }

    return total_score;
}

#endif // ANTIDEBUG_BASIC_STATIC_CHECKS_H