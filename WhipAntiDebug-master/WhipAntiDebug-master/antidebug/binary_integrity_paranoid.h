// ===== file: antidebug/binary_integrity_paranoid.h =====
//
// VÉRIFICATION D'INTÉGRITÉ BINAIRE PARANOID
// Détecte TOUTE modification possible du binaire
//

#ifndef ANTIDEBUG_BINARY_INTEGRITY_PARANOID_H
#define ANTIDEBUG_BINARY_INTEGRITY_PARANOID_H

#include "core/types.h"
#include "core/macros.h"
#include <windows.h>
#include <string.h>
#include <stdlib.h>
#include <wchar.h>

#pragma comment(lib, "version.lib")
#pragma comment(lib, "crypt32.lib")

// =========================================================================
// VÉRIFICATION PARANOID DE L'INTÉGRITÉ BINAIRE
// =========================================================================

// --- Checksums détaillés de TOUTES les sections ---
// NOTE : les checksums "attendus" étaient des placeholders non calibrés —
// ils déclenchaient sur chaque section. On garde uniquement la vérification
// des caractéristiques de section (code modifiable = vraiment anormal).
ANTIDEBUG_INLINE u32 ad_deep_section_integrity_check(void) {
    volatile u32 score = 0u;

    HMODULE hMod = GetModuleHandleA(NULL);
    if (!hMod) return 100u;

    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)hMod;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)((u8*)hMod + dos->e_lfanew);
    IMAGE_SECTION_HEADER* sections = IMAGE_FIRST_SECTION(nt);

    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        // Section code-et-modifiable = vraiment anormal (signe de packer/loader)
        if ((sections[i].Characteristics & IMAGE_SCN_MEM_WRITE) &&
            (sections[i].Characteristics & IMAGE_SCN_CNT_CODE)) {
            score += 30u;
        }
    }

    return score;
}

// --- Vérification des imports/exports ---
ANTIDEBUG_INLINE u32 ad_verify_import_export_tables(void) {
    volatile u32 score = 0u;

    HMODULE hMod = GetModuleHandleA(NULL);
    if (!hMod) return 50u;

    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)hMod;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)((u8*)hMod + dos->e_lfanew);

    // Vérifier la table d'imports
    IMAGE_DATA_DIRECTORY* importDir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (importDir->VirtualAddress) {
        IMAGE_IMPORT_DESCRIPTOR* importDesc = (IMAGE_IMPORT_DESCRIPTOR*)((u8*)hMod + importDir->VirtualAddress);

        while (importDesc->Name) {
            char* dllName = (char*)((u8*)hMod + importDesc->Name);

            // Vérifier les DLLs suspectes ajoutées
            const char* suspicious_imports[] = {
                "dbghelp.dll", "detours.dll", "easyhook.dll",
                "minhook.dll", "madchook.dll", "apihook.dll",
                "monitor.dll", "tracer.dll", "analysis.dll",
                NULL
            };

            for (int i = 0; suspicious_imports[i]; i++) {
                if (_stricmp(dllName, suspicious_imports[i]) == 0) {
                    score += 40u;
                }
            }

            // Vérifier la table d'adresses d'import (IAT)
            IMAGE_THUNK_DATA* thunk = (IMAGE_THUNK_DATA*)((u8*)hMod + importDesc->FirstThunk);
            while (thunk->u1.AddressOfData) {
                // Vérifier si l'adresse pointe vers une zone suspecte
                // NOTE : l'ancienne heuristique flaggait toute IAT non située
                // dans 0x70000000-0x80000000. Sous Windows 64-bit avec ASLR,
                // les modules sont chargés partout sur 64 bits → faux positif
                // sur CHAQUE import. Désactivé. Les hooks d'IAT sont déjà
                // détectés via les patterns d'instructions dans
                // bypass_detection_ultimate / comprehensive_static_detection.
                (void)thunk;
                thunk++;
            }

            importDesc++;
        }
    }

    // Vérifier la table d'exports
    IMAGE_DATA_DIRECTORY* exportDir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (exportDir->VirtualAddress) {
        IMAGE_EXPORT_DIRECTORY* exportDesc = (IMAGE_EXPORT_DIRECTORY*)((u8*)hMod + exportDir->VirtualAddress);

        // Si le binaire exporte des fonctions suspectes
        if (exportDesc->NumberOfFunctions > 0) {
            DWORD* functions = (DWORD*)((u8*)hMod + exportDesc->AddressOfFunctions);
            DWORD* names = (DWORD*)((u8*)hMod + exportDesc->AddressOfNames);

            for (DWORD i = 0; i < exportDesc->NumberOfNames; i++) {
                char* funcName = (char*)((u8*)hMod + names[i]);

                // Vérifier les exports ajoutés par des outils
                if (strstr(funcName, "Hook") || strstr(funcName, "Patch") ||
                    strstr(funcName, "Inject") || strstr(funcName, "Monitor")) {
                    score += 30u;
                }
            }
        }
    }

    return score;
}

// --- Détection de packers/crypters/protectors ---
ANTIDEBUG_INLINE u32 ad_detect_packers_and_protectors(void) {
    volatile u32 score = 0u;

    HMODULE hMod = GetModuleHandleA(NULL);
    if (!hMod) return 50u;

    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)hMod;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)((u8*)hMod + dos->e_lfanew);

    // Signatures de packers connus
    const u8 upx_signature[] = {0x55, 0x50, 0x58, 0x21};  // UPX!
    const u8 aspack_signature[] = {0x41, 0x53, 0x50, 0x61, 0x63, 0x6B};  // ASPack
    const u8 themida_signature[] = {0x54, 0x68, 0x65, 0x6D, 0x69, 0x64, 0x61};

    // Recherche signatures de packer — uniquement les ~512 premiers bytes
    // de chaque section (les signatures de packers sont des marqueurs
    // d'identification placés en tête, pas dans le payload). Évite les
    // faux positifs d'entropie sur .rdata/.rsrc qui contiennent
    // naturellement les bytes des signatures.
    IMAGE_SECTION_HEADER* sections = IMAGE_FIRST_SECTION(nt);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        u8* section_data = (u8*)hMod + sections[i].VirtualAddress;
        u32 section_size = sections[i].Misc.VirtualSize;
        u32 scan_limit = section_size < 512u ? section_size : 512u;

        if (scan_limit > sizeof(themida_signature)) {
            for (u32 j = 0; j < scan_limit - sizeof(themida_signature); j++) {
                if (memcmp(section_data + j, upx_signature, sizeof(upx_signature)) == 0) {
                    score += 50u; break;
                }
                if (memcmp(section_data + j, aspack_signature, sizeof(aspack_signature)) == 0) {
                    score += 45u; break;
                }
                if (memcmp(section_data + j, themida_signature, sizeof(themida_signature)) == 0) {
                    score += 60u; break;
                }
            }
        }
        // Heuristique d'entropie supprimée : .rsrc/.rdata ont une entropie
        // naturellement élevée → faux positifs systématiques.
    }

    // Vérifier les noms de sections suspects
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        char section_name[9] = {0};
        memcpy(section_name, sections[i].Name, 8);

        const char* packer_section_names[] = {
            "UPX0", "UPX1", "UPX2",
            ".aspack", ".adata",
            ".themida", ".winlice", ".vmp0", ".vmp1",
            ".petite", ".upx", ".packed",
            NULL
        };

        for (int j = 0; packer_section_names[j]; j++) {
            if (_stricmp(section_name, packer_section_names[j]) == 0) {
                score += 40u;
            }
        }
    }

    return score;
}

// --- Vérification des overlays et données cachées ---
ANTIDEBUG_INLINE u32 ad_detect_overlays_and_hidden_data(void) {
    volatile u32 score = 0u;

    char module_path[MAX_PATH];
    if (GetModuleFileNameA(NULL, module_path, MAX_PATH)) {
        HANDLE hFile = CreateFileA(module_path, GENERIC_READ,
                                  FILE_SHARE_READ, NULL, OPEN_EXISTING,
                                  FILE_ATTRIBUTE_NORMAL, NULL);

        if (hFile != INVALID_HANDLE_VALUE) {
            DWORD file_size = GetFileSize(hFile, NULL);

            // Calculer la taille attendue basée sur les sections PE
            HMODULE hMod = GetModuleHandleA(NULL);
            if (hMod) {
                IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)hMod;
                IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)((u8*)hMod + dos->e_lfanew);
                IMAGE_SECTION_HEADER* sections = IMAGE_FIRST_SECTION(nt);

                DWORD expected_size = 0;
                for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
                    DWORD section_end = sections[i].PointerToRawData + sections[i].SizeOfRawData;
                    if (section_end > expected_size) {
                        expected_size = section_end;
                    }
                }

                // Si le fichier est plus gros que prévu
                if (file_size > expected_size + 1024) {  // 1KB de marge
                    score += 30u;  // Overlay/données cachées détectées
                }
            }

            // Vérifier les streams alternatifs (ADS) sur LE module courant
            // (pas un L"test.exe" hard-codé). ADS Zone.Identifier = fichier
            // téléchargé depuis Internet → signe d'analyse.
            WCHAR wide_module[MAX_PATH];
            MultiByteToWideChar(CP_ACP, 0, module_path, -1, wide_module, MAX_PATH);
            WIN32_FIND_STREAM_DATA streamData;
            HANDLE hStream = FindFirstStreamW(wide_module, FindStreamInfoStandard, &streamData, 0);
            if (hStream != INVALID_HANDLE_VALUE) {
                int stream_count = 0;
                do { stream_count++; } while (FindNextStreamW(hStream, &streamData));
                FindClose(hStream);
                if (stream_count > 1) {
                    score += 15u;
                }
            }

            CloseHandle(hFile);
        }
    }

    return score;
}

// --- Vérification des métadonnées de fichier ---
ANTIDEBUG_INLINE u32 ad_verify_file_metadata(void) {
    volatile u32 score = 0u;

    char module_path[MAX_PATH];
    if (GetModuleFileNameA(NULL, module_path, MAX_PATH)) {

        // Vérifier les attributs de fichier
        DWORD attributes = GetFileAttributesA(module_path);
        if (attributes != INVALID_FILE_ATTRIBUTES) {

            // Attributs suspects
            if (attributes & FILE_ATTRIBUTE_HIDDEN) {
                score += 20u;
            }
            if (attributes & FILE_ATTRIBUTE_SYSTEM) {
                score += 15u;
            }
            if (attributes & FILE_ATTRIBUTE_TEMPORARY) {
                score += 25u;
            }
        }

        // Vérifier les informations de version
        DWORD dummy;
        DWORD version_size = GetFileVersionInfoSizeA(module_path, &dummy);
        if (version_size > 0) {
            void* version_data = malloc(version_size);
            if (version_data) {
                if (GetFileVersionInfoA(module_path, 0, version_size, version_data)) {
                    VS_FIXEDFILEINFO* file_info;
                    UINT len;
                    if (VerQueryValueA(version_data, "\\", (void**)&file_info, &len)) {

                        // Vérifier la version du fichier
                        if (file_info->dwFileFlags & VS_FF_DEBUG) {
                            score += 10u;  // Version debug
                        }
                        if (file_info->dwFileFlags & VS_FF_PRERELEASE) {
                            score += 8u;   // Version préliminaire
                        }
                        if (file_info->dwFileFlags & VS_FF_PRIVATEBUILD) {
                            score += 12u;  // Build privé
                        }
                    }
                }
                free(version_data);
            }
        }

        // Vérifier la signature numérique
        WCHAR wide_path[MAX_PATH];
        MultiByteToWideChar(CP_ACP, 0, module_path, -1, wide_path, MAX_PATH);

        HCERTSTORE hStore = NULL;
        HCRYPTMSG hMsg = NULL;

        BOOL signature_valid = CryptQueryObject(
            CERT_QUERY_OBJECT_FILE, wide_path,
            CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
            CERT_QUERY_FORMAT_FLAG_BINARY,
            0, NULL, NULL, NULL, &hStore, &hMsg, NULL);

        // Pas de pénalité pour absence de signature : tout build dev
        // est non-signé. Le challenge CTF n'est pas signé non plus.
        if (signature_valid) {
            // Signature présente mais potentiellement modifiée après signature
            if (hStore) CertCloseStore(hStore, 0);
            if (hMsg) CryptMsgClose(hMsg);
        }
    }

    return score;
}

// --- Master function pour toutes les vérifications d'intégrité ---
ANTIDEBUG_INLINE u32 ad_binary_integrity_paranoid_master(void) {
    volatile u32 total_score = 0u;

    __try {
        total_score += ad_deep_section_integrity_check();
        total_score += ad_verify_import_export_tables();
        total_score += ad_detect_packers_and_protectors();
        total_score += ad_detect_overlays_and_hidden_data();
        total_score += ad_verify_file_metadata();

    } __except(EXCEPTION_EXECUTE_HANDLER) {
        total_score += 200u;  // Exception critique
    }

    return total_score;
}

#endif // ANTIDEBUG_BINARY_INTEGRITY_PARANOID_H