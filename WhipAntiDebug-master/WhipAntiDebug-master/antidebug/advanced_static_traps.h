// ===== file: antidebug/advanced_static_traps.h =====
//
// Pièges avancés anti-analyse statique
// Techniques sournoise pour détecter et tromper les reversers
//

#ifndef ANTIDEBUG_ADVANCED_STATIC_TRAPS_H
#define ANTIDEBUG_ADVANCED_STATIC_TRAPS_H

#include "core/types.h"
#include "core/macros.h"
#include <windows.h>
#include <tlhelp32.h>
#include <string.h>

// =========================================================================
// PIÈGES ANTI-REVERSE ENGINEERING AVANCÉS
// =========================================================================

// --- Détection de modification de timestamps ---
// NOTE : "modifié <24h" est un faux positif systématique sur tout build dev.
// On flag uniquement si le timestamp d'écriture est postérieur au timestamp
// de création (= patch après release).
ANTIDEBUG_INLINE u32 ad_check_file_timestamps(void) {
    volatile u32 score = 0u;

    char module_path[MAX_PATH];
    if (GetModuleFileNameA(NULL, module_path, MAX_PATH)) {
        HANDLE hFile = CreateFileA(module_path, GENERIC_READ,
                                  FILE_SHARE_READ, NULL, OPEN_EXISTING,
                                  FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile != INVALID_HANDLE_VALUE) {
            FILETIME creation, lastAccess, lastWrite;
            if (GetFileTime(hFile, &creation, &lastAccess, &lastWrite)) {
                ULARGE_INTEGER c, w;
                c.LowPart = creation.dwLowDateTime;
                c.HighPart = creation.dwHighDateTime;
                w.LowPart = lastWrite.dwLowDateTime;
                w.HighPart = lastWrite.dwHighDateTime;
                // > 30 jours d'écart création/dernière écriture = patch tardif.
                // 1h était trop strict — un build CMake normal écrit le binaire
                // (lastWrite) après la création initiale, le delta dépassant
                // souvent plusieurs heures sur des incrementals.
                // FILETIME unit = 100ns. 30 jours = 30 * 86400 * 1e7 ≈ 2.59e13.
                if (w.QuadPart > c.QuadPart + 25920000000000ULL) {
                    score += 25u;
                }
            }
            CloseHandle(hFile);
        }
    }

    return score;
}

// --- Piège à base de faux exports ---
ANTIDEBUG_INLINE u32 ad_fake_export_trap(void) {
    volatile u32 score = 0u;

    // Créer de fausses références qui apparaissent importantes en analyse statique
    volatile void* fake_important_functions[] = {
        (void*)(uintptr_t)0xDEADBEEFull,  // GetFlagDecryptionKey
        (void*)(uintptr_t)0xCAFEBABEull,  // DecryptSecretFlag
        (void*)(uintptr_t)0x13371337ull,  // ValidateLicense
        (void*)(uintptr_t)0xFEEDFACEull   // CheckProtection
    };

    // Code qui ne s'exécute jamais mais trompe l'analyse
    if (GetModuleHandleA("definitely_not_a_real_module.dll")) {
        for (int i = 0; i < 4; i++) {
            if (fake_important_functions[i]) {
                score += 1000u;  // Ne devrait jamais arriver
            }
        }
    }

    return score;
}

// --- Détection d'outils d'analyse statique par fenêtres ---
ANTIDEBUG_INLINE u32 ad_detect_analysis_tools(void) {
    volatile u32 score = 0u;

    // Liste d'outils d'analyse statique populaires
    const char* analysis_tools[] = {
        "IDA Pro",
        "Ghidra",
        "x64dbg",
        "Radare2",
        "Binary Ninja",
        "HxD",
        "010 Editor",
        "PE Explorer",
        "CFF Explorer",
        "Detect It Easy",
        NULL
    };

    for (int i = 0; analysis_tools[i]; i++) {
        if (FindWindowA(NULL, analysis_tools[i])) {
            score += 50u;  // Outil d'analyse détecté
        }
    }

    // Vérifier les processus suspects
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);

        if (Process32First(hSnapshot, &pe32)) {
            do {
                // Convertir en lowercase pour comparaison
                char lower_name[MAX_PATH];
                strcpy_s(lower_name, MAX_PATH, pe32.szExeFile);
                _strlwr_s(lower_name, MAX_PATH);

                // NOTE : "ida" en substring matche "nvidia.exe", "Idle.exe"
                // (en lowercase: "idle" non, mais "nvidia" contient "ida"!),
                // beaucoup d'autres. On utilise des matches exacts ou des
                // noms binaires complets pour éviter les faux positifs.
                static const char* const exact_names[] = {
                    "ida.exe", "ida64.exe", "idaq.exe", "idaq64.exe",
                    "idaw.exe", "idaw64.exe",
                    "ghidra.exe", "ghidrarun.bat",
                    "x64dbg.exe", "x32dbg.exe", "x96dbg.exe",
                    "radare2.exe", "r2.exe", "rizin.exe",
                    "hxd.exe", "hxd32.exe",
                    "cff explorer.exe", "cffexplorer.exe",
                    "pe-bear.exe", "pebear.exe",
                    NULL
                };
                for (int k = 0; exact_names[k]; k++) {
                    if (_stricmp(pe32.szExeFile, exact_names[k]) == 0) {
                        score += 30u;
                        break;
                    }
                }
            } while (Process32Next(hSnapshot, &pe32));
        }
        CloseHandle(hSnapshot);
    }

    return score;
}

// --- Protection par code auto-vérificateur ---
// NOTE : la valeur "expected" était un placeholder jamais calibré → +40
// systématique. On désactive cette heuristique tant qu'elle n'est pas
// calibrée par le pipeline de build.
ANTIDEBUG_INLINE u32 ad_self_verifying_code(void) {
    return 0u;
}

// --- Piège de faux algorithme de déchiffrement ---
ANTIDEBUG_INLINE void ad_fake_decryption_algorithm(void) {
    // Algorithme factice qui ressemble au vrai déchiffrement
    // Pour tromper l'analyse statique

    char fake_encrypted_flag[] = {
        0x41, 0x44, 0x43, 0x54, 0x46, 0x7B,  // "ADCTF{"
        0x66, 0x61, 0x6B, 0x65, 0x5F,        // "fake_"
        0x73, 0x74, 0x61, 0x74, 0x69, 0x63,  // "static"
        0x5F, 0x61, 0x6E, 0x61, 0x6C, 0x79, 0x73, 0x69, 0x73,  // "_analysis"
        0x7D, 0x00  // "}\0"
    };

    // Faux déchiffrement XOR
    for (int i = 0; i < sizeof(fake_encrypted_flag); i++) {
        fake_encrypted_flag[i] ^= 0x13;  // Fausse clé
    }

    // Cette chaîne ne sera jamais utilisée mais apparaît en analyse
    volatile char* fake_result = fake_encrypted_flag;
    AD_UNUSED(fake_result);
}

// --- Détection de breakpoints software cachés ---
// NOTE : un scan brut de 0xCC sur le code génère des milliers de faux positifs
// — MSVC remplit les marges entre fonctions avec 0xCC. On désactive le scan
// massif et on ne flag que la présence d'INT3 sur le 1er byte de fonctions
// critiques (ce qui est réellement anormal).
ANTIDEBUG_INLINE u32 ad_detect_hidden_breakpoints(void) {
    volatile u32 score = 0u;

    void* fns[] = {
        (void*)GetModuleHandleA,
        (void*)GetProcAddress,
        (void*)CreateFileA,
        NULL
    };
    for (int i = 0; fns[i]; i++) {
        __try {
            if (((u8*)fns[i])[0] == 0xCC) {
                score += 30u;  // INT3 sur l'entrée d'une API critique
            }
        } __except(EXCEPTION_EXECUTE_HANDLER) {}
    }

    return score;
}

// --- Anti-pattern recognition pour confondre l'IA ---
// NOTE : le pattern attendu n'est jamais réellement émis par le compilateur
// à l'offset +50 → 88 points de FP par run. Désactivé.
ANTIDEBUG_INLINE u32 ad_confuse_ai_analysis(void) {
    return 0u;
}

// --- Master function pour toutes les protections avancées ---
ANTIDEBUG_INLINE u32 ad_advanced_static_traps_master(void) {
    volatile u32 total_score = 0u;

    // Appeler tous les pièges dans un ordre aléatoire
    u32 checks[] = {
        ad_check_file_timestamps(),
        ad_fake_export_trap(),
        ad_detect_analysis_tools(),
        ad_self_verifying_code(),
        ad_detect_hidden_breakpoints(),
        ad_confuse_ai_analysis()
    };

    // Mélanger l'ordre d'exécution
    for (int i = 0; i < 6; i++) {
        total_score += checks[i];
    }

    // Appel de la fonction factice
    ad_fake_decryption_algorithm();

    return total_score;
}

#endif // ANTIDEBUG_ADVANCED_STATIC_TRAPS_H