// ===== file: antidebug/comprehensive_static_detection.h =====
//
// DÉTECTION EXHAUSTIVE ANTI-ANALYSE STATIQUE
// Couvre ABSOLUMENT TOUT de A à Z
//

#ifndef ANTIDEBUG_COMPREHENSIVE_STATIC_DETECTION_H
#define ANTIDEBUG_COMPREHENSIVE_STATIC_DETECTION_H

#include "core/types.h"
#include "core/macros.h"
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <winternl.h>
#include <string.h>
#include <ctype.h>

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "advapi32.lib")

// =========================================================================
// DÉTECTION TOTALE D'ENVIRONNEMENT D'ANALYSE
// =========================================================================

// --- Variables d'environnement suspectes ---
ANTIDEBUG_INLINE u32 ad_detect_analysis_environment_vars(void) {
    volatile u32 score = 0u;

    const char* suspicious_env_vars[] = {
        "IDA_CFG_PATH", "IDAUSR", "IDALOG",
        "GHIDRA_INSTALL_DIR", "GHIDRA_PROJECT",
        "X64DBG_PATH", "X32DBG_PATH",
        "RADARE2_HOME", "R2_HOMEDIR",
        "HEX_EDITOR", "BINARY_ANALYSIS",
        "_NT_SYMBOL_PATH", "DBGHELP_HOMEDIR",
        "REVERSE_ENGINEERING", "STATIC_ANALYSIS",
        "DISASSEMBLER", "HEXEDIT_MODE",
        "OLLYDBG", "IMMUNITY_PATH",
        "CHEAT_ENGINE", "CE_PATH",
        "HIEW_PATH", "SOFTICE_PATH",
        "DETOURS_PATH", "API_MONITOR",
        "PROCESS_HACKER", "SYSINTERNALS",
        NULL
    };

    for (int i = 0; suspicious_env_vars[i]; i++) {
        char buffer[512];
        if (GetEnvironmentVariableA(suspicious_env_vars[i], buffer, sizeof(buffer)) > 0) {
            score += 25u;  // Variable d'outil d'analyse détectée
        }
    }

    // Variables Windows suspectes
    if (GetEnvironmentVariableA("PROCESSOR_ARCHITECTURE", NULL, 0) == 0) {
        score += 10u;  // Environnement anormal
    }

    return score;
}

// --- Registres Windows suspects ---
ANTIDEBUG_INLINE u32 ad_detect_registry_traces(void) {
    volatile u32 score = 0u;

    // NOTE : retiré "Sysinternals" et "Microsoft\\Debugging Tools" — ce sont
    // des outils légitimes installés par défaut sur les postes admin/dev.
    const char* registry_paths[] = {
        "SOFTWARE\\Hex-Rays\\IDA Pro",
        "SOFTWARE\\National Security Agency\\Ghidra",
        "SOFTWARE\\x64dbg",
        "SOFTWARE\\radare\\radare2",
        "SOFTWARE\\Cheat Engine",
        "SOFTWARE\\Ollydbg",
        "SOFTWARE\\Immunity Inc",
        "SOFTWARE\\SoftICE",
        "SOFTWARE\\HxD",
        "SOFTWARE\\010 Editor",
        "SOFTWARE\\PE Explorer",
        "SOFTWARE\\CFF Explorer",
        NULL
    };

    for (int i = 0; registry_paths[i]; i++) {
        HKEY hKey;
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, registry_paths[i], 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            score += 20u;
            RegCloseKey(hKey);
        }
        if (RegOpenKeyExA(HKEY_CURRENT_USER, registry_paths[i], 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            score += 15u;
            RegCloseKey(hKey);
        }
    }

    return score;
}

// --- Fichiers temporaires et résidus d'outils ---
ANTIDEBUG_INLINE u32 ad_detect_analysis_file_traces(void) {
    volatile u32 score = 0u;

    const char* temp_patterns[] = {
        "C:\\temp\\*.idb", "C:\\temp\\*.i64",
        "C:\\temp\\*.ghidra", "C:\\temp\\*.gpr",
        "C:\\temp\\*.x64dbg", "C:\\temp\\*.x32dbg",
        "C:\\temp\\*.r2", "C:\\temp\\*.radare",
        "C:\\temp\\*.ce", "C:\\temp\\*.ct",
        "C:\\temp\\*.od", "C:\\temp\\*.udd",
        "C:\\Users\\*\\AppData\\Local\\IDA\\*",
        "C:\\Users\\*\\AppData\\Roaming\\Ghidra\\*",
        "C:\\Users\\*\\AppData\\Local\\x64dbg\\*",
        "C:\\Users\\*\\AppData\\Roaming\\radare2\\*",
        NULL
    };

    // Vérifier la présence de fichiers d'analyse récents
    WIN32_FIND_DATAA findData;
    for (int i = 0; temp_patterns[i]; i++) {
        HANDLE hFind = FindFirstFileA(temp_patterns[i], &findData);
        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                // Vérifier si le fichier est récent (moins de 7 jours)
                SYSTEMTIME now;
                GetSystemTime(&now);
                FILETIME nowFt;
                SystemTimeToFileTime(&now, &nowFt);

                ULARGE_INTEGER nowUl, fileUl;
                nowUl.LowPart = nowFt.dwLowDateTime;
                nowUl.HighPart = nowFt.dwHighDateTime;
                fileUl.LowPart = findData.ftLastWriteTime.dwLowDateTime;
                fileUl.HighPart = findData.ftLastWriteTime.dwHighDateTime;

                if ((nowUl.QuadPart - fileUl.QuadPart) < 6048000000000ULL) { // 7 jours
                    score += 15u;
                }
            } while (FindNextFileA(hFind, &findData));
            FindClose(hFind);
        }
    }

    return score;
}

// --- Services de debugging suspects ---
ANTIDEBUG_INLINE u32 ad_detect_debugging_services(void) {
    volatile u32 score = 0u;

    const char* suspicious_services[] = {
        "DbgSvc", "DebugService", "WinDbg",
        "SoftICE", "Detours", "ApiMonitor",
        "ProcessHacker", "Sysinternals",
        "CheatEngine", "x64dbg", "OllyDbg",
        NULL
    };

    SC_HANDLE scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    if (scm) {
        for (int i = 0; suspicious_services[i]; i++) {
            SC_HANDLE service = OpenServiceA(scm, suspicious_services[i], SERVICE_QUERY_STATUS);
            if (service) {
                SERVICE_STATUS status;
                if (QueryServiceStatus(service, &status)) {
                    if (status.dwCurrentState != SERVICE_STOPPED) {
                        score += 30u;  // Service de debug actif
                    }
                }
                CloseServiceHandle(service);
            }
        }
        CloseServiceHandle(scm);
    }

    return score;
}

// --- DLLs suspectes chargées ---
ANTIDEBUG_INLINE u32 ad_detect_analysis_dlls(void) {
    volatile u32 score = 0u;

    // NOTE : retiré dbghelp/imagehlp/symsrv (chargées par EDR/Windows
    // Defender), monitor/tracer/logger (substrings trop génériques —
    // "logger.dll" matche WinHttpLogger, ETW, etc.), ce.dll (matche n'importe
    // quel suffixe terminant par "ce" — "office.dll", "service.dll").
    const char* suspicious_dlls[] = {
        "detours.dll", "detoured.dll", "minhook.dll",
        "easyhook.dll", "apihook.dll", "madchook.dll",
        "injectdll.dll", "hookdll.dll", "interceptor.dll",
        "scyllahide.dll", "titanhide.dll", "phantomdll.dll",
        "ida.dll", "ghidra.dll", "x64dbg.dll",
        "ollydbg.dll", "immunity.dll", "softice.dll",
        "cheatengine.dll", "ceserver.dll",
        NULL
    };

    HANDLE hProcess = GetCurrentProcess();
    HMODULE hModules[256];
    DWORD cbNeeded;

    if (EnumProcessModules(hProcess, hModules, sizeof(hModules), &cbNeeded)) {
        DWORD cModules = cbNeeded / sizeof(HMODULE);

        for (DWORD i = 0; i < cModules; i++) {
            char moduleName[MAX_PATH];
            if (GetModuleBaseNameA(hProcess, hModules[i], moduleName, sizeof(moduleName))) {

                // Convertir en lowercase
                for (char* p = moduleName; *p; p++) {
                    *p = tolower(*p);
                }

                // Vérifier contre la liste
                for (int j = 0; suspicious_dlls[j]; j++) {
                    if (strstr(moduleName, suspicious_dlls[j])) {
                        score += 25u;
                    }
                }
            }
        }
    }

    return score;
}

// --- Détection de hooks système ---
// NOTE : kernel32 contient des forwarders vers kernelbase qui commencent
// légitimement par `FF 25` — on inspecte uniquement ntdll (vrai entry point
// des syscalls). On ignore aussi `FF 25` car certaines exports ntdll x64
// modernes l'utilisent comme thunk vers d'autres modules (ApiSet).
ANTIDEBUG_INLINE u32 ad_detect_system_hooks(void) {
    volatile u32 score = 0u;

    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (ntdll) {
        const char* critical_apis[] = {
            "NtQueryInformationProcess", "NtSetInformationProcess",
            "NtCreateFile", "NtReadFile", "NtWriteFile",
            "NtOpenProcess", "NtReadVirtualMemory", "NtWriteVirtualMemory",
            "NtProtectVirtualMemory", "NtClose",
            NULL
        };

        for (int i = 0; critical_apis[i]; i++) {
            void* func = GetProcAddress(ntdll, critical_apis[i]);
            if (func) {
                u8* code = (u8*)func;
                // Patterns de hook les plus distinctifs (E9 = JMP relatif)
                if (code[0] == 0xE9) {
                    score += 20u;
                }
                if (code[0] == 0x68 && code[5] == 0xC3) {
                    score += 25u;
                }
                if (code[0] == 0xB8 && code[5] == 0xFF && code[6] == 0xE0) {
                    score += 30u;
                }
            }
        }
    }

    return score;
}

// --- Détection de processus d'analyse en arrière-plan ---
ANTIDEBUG_INLINE u32 ad_detect_background_analysis_processes(void) {
    volatile u32 score = 0u;

    // Liste exhaustive de processus d'analyse
    const char* analysis_processes[] = {
        "ida.exe", "ida64.exe", "idag.exe", "idag64.exe",
        "idaw.exe", "idaw64.exe", "idaq.exe", "idaq64.exe",
        "ghidrarun", "ghidra.exe", "analyzeheadless",
        "x64dbg.exe", "x32dbg.exe", "x96dbg.exe",
        "ollydbg.exe", "odbg110.exe", "odbgscript.exe",
        "radare2.exe", "r2.exe", "rabin2.exe", "rahash2.exe",
        "rizin.exe", "rz-bin.exe", "rz-ax.exe",
        "hiew32.exe", "hiew64.exe", "hiew.exe",
        "hexworkshop.exe", "hxd.exe", "010editor.exe",
        "pe-bear.exe", "peid.exe", "peview.exe", "pestudio.exe",
        "cff explorer.exe", "cffexplorer.exe", "exeinfope.exe",
        "die.exe", "detect.exe", "bintext.exe", "strings.exe",
        "cheatengine-x86_64.exe", "cheatengine.exe",
        "processhacker.exe", "procexp.exe", "procexp64.exe",
        "apimonitor-x86.exe", "apimonitor-x64.exe",
        "detours.exe", "rohitab.exe", "depends.exe",
        "resource hacker.exe", "reshacker.exe", "restorator.exe",
        "sysinternals.exe", "autoruns.exe", "procmon.exe",
        "windbg.exe", "kd.exe", "cdb.exe", "ntsd.exe",
        "softice.exe", "winice.exe", "iceext.exe",
        "immunity.exe", "immdbg.exe", "immunitydebugger.exe",
        "binaryninja.exe", "hopper.exe", "jeb.exe",
        "capstone.exe", "keystone.exe", "unicorn.exe",
        "dnspy.exe", "ilspy.exe", "reflexil.exe",
        "fiddler.exe", "wireshark.exe", "tcpdump.exe",
        // NOTE : retiré vmware.exe / virtualbox.exe / qemu.exe — ce sont
        // les UIs de virtualisation côté HOST, beaucoup de devs en lancent
        // pour des raisons légitimes. La détection "on tourne dans une VM
        // d'analyse" est faite par sandbox_analysis_detection (CPUID +
        // artefacts in-VM). Garde uniquement sandboxie qui est plus
        // spécifique à l'analyse de malware.
        "sandboxie.exe",
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

                // Vérifier contre la liste exhaustive
                for (int i = 0; analysis_processes[i]; i++) {
                    if (strstr(lower_name, analysis_processes[i])) {
                        score += 35u;
                    }
                }

                // NOTE : retiré le scoring sur substrings génériques
                // ("debug", "monitor", "patch"...). Trop de processus
                // légitimes (Windows Defender ATP "monitor", "patch tuesday"
                // updates, "DebugAssistant", etc.) finissaient flaggés.

            } while (Process32Next(hSnapshot, &pe32));
        }
        CloseHandle(hSnapshot);
    }

    return score;
}

// --- Master function pour toutes les détections exhaustives ---
ANTIDEBUG_INLINE u32 ad_comprehensive_static_detection_master(void) {
    volatile u32 total_score = 0u;

    __try {
        // Environnement
        total_score += ad_detect_analysis_environment_vars();
        total_score += ad_detect_registry_traces();
        total_score += ad_detect_analysis_file_traces();

        // Processus et services
        total_score += ad_detect_debugging_services();
        total_score += ad_detect_background_analysis_processes();

        // Code et hooks
        total_score += ad_detect_analysis_dlls();
        total_score += ad_detect_system_hooks();

    } __except(EXCEPTION_EXECUTE_HANDLER) {
        total_score += 100u;  // Exception durant la détection
    }

    return total_score;
}

#endif // ANTIDEBUG_COMPREHENSIVE_STATIC_DETECTION_H