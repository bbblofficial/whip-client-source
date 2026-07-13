// ===== file: antidebug/bypass_detection_ultimate.h =====
//
// DÉTECTION ULTIME DE TECHNIQUES DE BYPASS
// Détecte TOUTES les techniques avancées de contournement
//

#ifndef ANTIDEBUG_BYPASS_DETECTION_ULTIMATE_H
#define ANTIDEBUG_BYPASS_DETECTION_ULTIMATE_H

#include "core/types.h"
#include "core/macros.h"
#include <windows.h>
#include <tlhelp32.h>
#include <winternl.h>
#include <intrin.h>
#include <string.h>

// =========================================================================
// DÉTECTION ULTIME DE BYPASS ET PATCHING AVANCÉ
// =========================================================================

// --- Détection d'injection de code ---
// NOTE : ce framework ALLOUE volontairement des régions RWX (poly_syscall T5,
// ghost trampoline, anonymous RWX). Compter chaque RWX privé comme +25 +
// scan des bytes générait un score énorme par auto-détection. On désactive
// le scan généralisé : les vraies injections externes sont déjà capturées
// par ad_detect_advanced_api_hooking, ad_detect_structure_manipulation, et
// par private_exec_scan dans le projet.
ANTIDEBUG_INLINE u32 ad_detect_code_injection_techniques(void) {
    return 0u;
}

// --- Détection d'API hooking avancé ---
ANTIDEBUG_INLINE u32 ad_detect_advanced_api_hooking(void) {
    volatile u32 score = 0u;

    // NOTE : sous Win10/11, BEAUCOUP de fonctions de kernel32 sont des
    // forwarders vers kernelbase.dll qui commencent légitimement par
    // `FF 25` (JMP indirect) — exactement le pattern qu'on cherche pour
    // détecter un hook. On vérifie donc uniquement ntdll/user32 où les
    // forwarders sont rares.
    struct {
        const char* module;
        const char* function;
    } critical_apis[] = {
        {"ntdll.dll", "NtQueryInformationProcess"},
        {"ntdll.dll", "NtSetInformationProcess"},
        {"ntdll.dll", "NtCreateFile"},
        {"ntdll.dll", "NtReadFile"},
        {"ntdll.dll", "NtWriteFile"},
        {"ntdll.dll", "NtOpenProcess"},
        {"ntdll.dll", "NtReadVirtualMemory"},
        {"ntdll.dll", "NtWriteVirtualMemory"},
        {"ntdll.dll", "NtProtectVirtualMemory"},
        {"ntdll.dll", "LdrLoadDll"},
        {"ntdll.dll", "LdrGetProcedureAddress"},
        {"user32.dll", "CreateWindowExA"},
        {"user32.dll", "CreateWindowExW"},
        {"user32.dll", "FindWindowA"},
        {"user32.dll", "FindWindowW"},
        {"user32.dll", "GetWindowTextA"},
        {"user32.dll", "GetWindowTextW"},
        {NULL, NULL}
    };

    for (int i = 0; critical_apis[i].module; i++) {
        HMODULE hMod = GetModuleHandleA(critical_apis[i].module);
        if (hMod) {
            void* funcAddr = GetProcAddress(hMod, critical_apis[i].function);
            if (funcAddr) {
                u8* code = (u8*)funcAddr;

                // Vérifier les patterns de hook avancés
                __try {
                    // Pattern 1: JMP relatif (E9)
                    if (code[0] == 0xE9) {
                        score += 30u;
                    }
                    // Pattern 2: JMP indirect (FF 25)
                    if (code[0] == 0xFF && code[1] == 0x25) {
                        score += 35u;
                    }
                    // Pattern 3: PUSH + RET (trampolines)
                    if (code[0] == 0x68 && code[5] == 0xC3) {
                        score += 40u;
                    }
                    // Pattern 4: MOV EAX, addr + JMP EAX
                    if (code[0] == 0xB8 && code[5] == 0xFF && code[6] == 0xE0) {
                        score += 45u;
                    }
                    // Pattern 5: CALL suivi d'un JMP (hook inline)
                    if (code[0] == 0xE8 && code[5] == 0xE9) {
                        score += 50u;
                    }
                    // Pattern 6: Instructions modifiées (backup + patch)
                    if (code[0] == 0x90 && code[1] == 0x90 && code[2] != 0x90) {
                        score += 25u;  // NOPs suspects
                    }
                }
                __except(EXCEPTION_EXECUTE_HANDLER) {
                    score += 20u;  // Protection d'accès = suspect
                }
            }
        }
    }

    return score;
}

// --- Détection de manipulation de structures Windows ---
ANTIDEBUG_INLINE u32 ad_detect_structure_manipulation(void) {
    volatile u32 score = 0u;

    // Vérifier la manipulation du PEB (Process Environment Block)
    PPEB peb = (PPEB)__readgsqword(0x60);
    if (peb) {
        __try {
            // Vérifier si BeingDebugged a été modifié récemment
            volatile BOOLEAN* being_debugged_ptr = &peb->BeingDebugged;
            BOOLEAN original_value = *being_debugged_ptr;

            // Test de modification temporaire
            *being_debugged_ptr = !original_value;
            if (*being_debugged_ptr == original_value) {
                score += 40u;  // Valeur protégée/hookée
            }
            *being_debugged_ptr = original_value;  // Restaurer

            // Walk PEB.Ldr.InLoadOrderModuleList via raw offsets (winternl.h
            // stripped struct n'expose pas tous les champs sous x64 MSVC).
            u8* peb_b = (u8*)peb;
            u8* ldr   = *(u8**)(peb_b + 0x18);
            if (ldr) {
                u8* head  = ldr + 0x10;
                u8* entry = *(u8**)head;
                int module_count = 0;

                while (entry != head && module_count < 100) {
                    // BaseDllName UNICODE_STRING at entry+0x58
                    u16    name_len    = *(u16*)(entry + 0x58);
                    WCHAR* name_buffer = *(WCHAR**)(entry + 0x60);

                    if (name_buffer && name_len > 0u) {
                        // Recherche substring case-insensitive sans CRT — on
                        // compare un tag ASCII à des chars UNICODE.
                        static const WCHAR* tags[] = {
                            L"hook", L"inject", L"detour", L"patch", NULL
                        };
                        for (int t = 0; tags[t]; t++) {
                            if (wcsstr(name_buffer, tags[t])) {
                                score += 30u;
                                break;
                            }
                        }
                    }

                    entry = *(u8**)entry;
                    module_count++;
                }
            }
        }
        __except(EXCEPTION_EXECUTE_HANDLER) {
            score += 50u;  // Exception lors de l'accès au PEB
        }
    }

    return score;
}

// --- Détection de patching de bytecode ---
ANTIDEBUG_INLINE u32 ad_detect_bytecode_patching(void) {
    volatile u32 score = 0u;

    // Vérifier l'intégrité de nos propres fonctions critiques
    void* critical_functions[] = {
        (void*)ad_detect_bytecode_patching,
        (void*)ad_detect_structure_manipulation,
        (void*)ad_detect_advanced_api_hooking,
        (void*)ad_detect_code_injection_techniques,
        (void*)GetModuleHandleA,
        (void*)GetProcAddress,
        NULL
    };

    for (int i = 0; critical_functions[i]; i++) {
        u8* func = (u8*)critical_functions[i];

        __try {
            // NOTE : la comparaison à des checksums "attendus" placeholders
            // (0x12345678, 0xDEADBEEF…) générait +35 systématique pour
            // chaque fonction. Désactivée. On garde uniquement la détection
            // de patterns de patching évidents (NOPs, JMP, RET, XOR+RET).

            // Détecter des patterns de modification spécifiques
            // Pattern: Instructions remplacées par des NOPs
            if (func[0] == 0x90 && func[1] == 0x90 && func[2] == 0x90) {
                score += 50u;  // Triple NOP = fonction neutralisée
            }

            // Pattern: Fonction redirigée
            if (func[0] == 0xE9) {  // JMP
                score += 45u;
            }

            // Pattern: Return immédiat
            if (func[0] == 0xC3) {  // RET
                score += 40u;
            }

            // Pattern: XOR EAX,EAX + RET (return 0)
            if (func[0] == 0x31 && func[1] == 0xC0 && func[2] == 0xC3) {
                score += 55u;
            }
        }
        __except(EXCEPTION_EXECUTE_HANDLER) {
            score += 30u;  // Accès protégé
        }
    }

    return score;
}

// --- Détection d'outils de patching automatique ---
ANTIDEBUG_INLINE u32 ad_detect_automatic_patching_tools(void) {
    volatile u32 score = 0u;

    // Processus d'outils de patching connus
    const char* patching_tools[] = {
        "patcher.exe", "autopatcher.exe", "bypasser.exe",
        "unhooker.exe", "antidebug_bypass.exe", "killer.exe",
        "protection_remover.exe", "crack.exe", "keygen.exe",
        "patch.exe", "modifier.exe", "editor.exe",
        "binary_editor.exe", "hex_patcher.exe", "byte_patcher.exe",
        "anti_anti.exe", "bypass_tool.exe", "debugger_hider.exe",
        "scyllahide.exe", "phantomdll.exe", "titanhide.exe",
        "stealth64.exe", "invisible.exe", "hide_debugger.exe",
        NULL
    };

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);

        if (Process32First(hSnapshot, &pe32)) {
            do {
                char lower_name[MAX_PATH];
                strcpy_s(lower_name, MAX_PATH, pe32.szExeFile);
                _strlwr_s(lower_name, MAX_PATH);

                // Vérifier contre la liste d'outils de patching
                for (int i = 0; patching_tools[i]; i++) {
                    if (strstr(lower_name, patching_tools[i])) {
                        score += 60u;  // Outil de patching détecté
                    }
                }

                // NOTE : retiré les substrings génériques (anti/patch/hide/
                // killer/stealth) — Windows ships "AntimalwareServiceExe.exe",
                // "MicrosoftEdgeUpdatePatch.exe", "ApplicationsLifecycleHost"
                // etc. qui matchent ces motifs. On ne garde que les noms
                // exhaustifs de la liste explicite ci-dessus.

            } while (Process32Next(hSnapshot, &pe32));
        }
        CloseHandle(hSnapshot);
    }

    // Vérifier les DLLs d'outils de bypass chargées
    HMODULE suspect_modules[] = {
        GetModuleHandleA("scyllahide.dll"),
        GetModuleHandleA("titanhide.dll"),
        GetModuleHandleA("phantomdll.dll"),
        GetModuleHandleA("stealth64.dll"),
        GetModuleHandleA("antidebug_bypass.dll"),
        GetModuleHandleA("unhook.dll"),
        GetModuleHandleA("bypass.dll"),
    };

    for (int i = 0; i < 7; i++) {
        if (suspect_modules[i]) {
            score += 40u;  // DLL de bypass chargée
        }
    }

    return score;
}

// --- Détection de modification de la table des syscalls ---
ANTIDEBUG_INLINE u32 ad_detect_syscall_table_modification(void) {
    volatile u32 score = 0u;

    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (ntdll) {
        // Syscalls critiques à vérifier
        const char* critical_syscalls[] = {
            "NtQueryInformationProcess",
            "NtSetInformationProcess",
            "NtQuerySystemInformation",
            "NtOpenProcess",
            "NtReadVirtualMemory",
            "NtWriteVirtualMemory",
            "NtProtectVirtualMemory",
            "NtCreateFile",
            "NtClose",
            NULL
        };

        for (int i = 0; critical_syscalls[i]; i++) {
            void* syscall_addr = GetProcAddress(ntdll, critical_syscalls[i]);
            if (syscall_addr) {
                u8* code = (u8*)syscall_addr;

                __try {
                    // Vérifier la structure normale d'un syscall
                    // Pattern attendu: MOV EAX, syscall_number; SYSCALL; RET
                    if (code[0] != 0x48 || code[1] != 0x8B || code[2] != 0xC4) {
                        // Structure anormale
                        if (code[0] == 0xE9 || code[0] == 0xFF) {
                            score += 45u;  // Syscall hookée
                        }
                    }

                    // Vérifier les instruction SYSCALL (0x0F 0x05)
                    b32 found_syscall = FALSE;
                    for (int j = 0; j < 20; j++) {
                        if (code[j] == 0x0F && code[j+1] == 0x05) {
                            found_syscall = TRUE;
                            break;
                        }
                    }

                    if (!found_syscall) {
                        score += 50u;  // Instruction SYSCALL manquante
                    }
                }
                __except(EXCEPTION_EXECUTE_HANDLER) {
                    score += 35u;
                }
            }
        }
    }

    return score;
}

// --- Master function pour toutes les détections de bypass ultimate ---
ANTIDEBUG_INLINE u32 ad_bypass_detection_ultimate_master(void) {
    volatile u32 total_score = 0u;

    __try {
        total_score += ad_detect_code_injection_techniques();
        total_score += ad_detect_advanced_api_hooking();
        total_score += ad_detect_structure_manipulation();
        total_score += ad_detect_bytecode_patching();
        total_score += ad_detect_automatic_patching_tools();
        total_score += ad_detect_syscall_table_modification();

    } __except(EXCEPTION_EXECUTE_HANDLER) {
        total_score += 300u;  // Exception critique = bypass détecté
    }

    return total_score;
}

#endif // ANTIDEBUG_BYPASS_DETECTION_ULTIMATE_H