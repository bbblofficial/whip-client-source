// ===== file: antidebug/sandbox_analysis_detection.h =====
//
// DÉTECTION DE SANDBOX ET ENVIRONNEMENTS D'ANALYSE
// Détecte tous les environnements automatisés d'analyse
//

#ifndef ANTIDEBUG_SANDBOX_ANALYSIS_DETECTION_H
#define ANTIDEBUG_SANDBOX_ANALYSIS_DETECTION_H

#include "core/types.h"
#include "core/macros.h"
#include <windows.h>
#include <tlhelp32.h>
#include <intrin.h>
#include <string.h>

// =========================================================================
// DÉTECTION DE SANDBOX ET ENVIRONNEMENTS D'ANALYSE
// =========================================================================

// --- Détection de VM et sandbox par hardware ---
ANTIDEBUG_INLINE u32 ad_detect_virtualization_hardware(void) {
    volatile u32 score = 0u;

    // CPUID pour détecter l'hyperviseur
    int cpuid_info[4];
    __cpuid(cpuid_info, 1);

    // NOTE : sous Windows 10/11, le bit 31 d'ECX ("hyperviseur présent") est
    // souvent positionné sur du matériel HOST quand Virtualization-Based
    // Security (VBS), HVCI, WSL2, Windows Sandbox ou Hyper-V est activé.
    // → +40 FP systématique. On ne flag que sur les vendor-id de VMs
    // typiquement utilisées pour l'analyse (VMware/VBox/KVM/Xen).
    if (cpuid_info[2] & (1 << 31)) {
        __cpuid(cpuid_info, 0x40000000);
        char vendor[13];
        memcpy(vendor, &cpuid_info[1], 4);
        memcpy(vendor + 4, &cpuid_info[2], 4);
        memcpy(vendor + 8, &cpuid_info[3], 4);
        vendor[12] = '\0';

        if (strcmp(vendor, "VMwareVMware") == 0) score += 30u;
        if (strcmp(vendor, "KVMKVMKVM") == 0)    score += 35u;
        if (strcmp(vendor, "XenVMMXenVMM") == 0) score += 30u;
        if (strcmp(vendor, "VBoxVBoxVBox") == 0) score += 45u;
        // "Microsoft Hv" volontairement ignoré : trop courant sur host Win11
    }

    // NOTE : RDMSR en ring 3 lève normalement #GP. Mais sous HyperV/WSL2
    // sur host Win11, certaines lectures peuvent réussir → FP. La détection
    // d'hyperviseur est déjà couverte par CPUID ci-dessus, on retire le
    // double-check MSR.

    return score;
}

// --- Détection par artefacts système ---
ANTIDEBUG_INLINE u32 ad_detect_vm_artifacts(void) {
    volatile u32 score = 0u;

    // Fichiers et dossiers spécifiques aux VMs
    const char* vm_files[] = {
        "C:\\windows\\system32\\drivers\\vmmouse.sys",
        "C:\\windows\\system32\\drivers\\vmhgfs.sys",
        "C:\\windows\\system32\\drivers\\VBoxMouse.sys",
        "C:\\windows\\system32\\drivers\\VBoxGuest.sys",
        "C:\\windows\\system32\\drivers\\VBoxSF.sys",
        "C:\\windows\\system32\\VBoxService.exe",
        "C:\\windows\\system32\\VBoxTray.exe",
        "C:\\windows\\system32\\vmtoolsd.exe",
        "C:\\windows\\system32\\vmwaretray.exe",
        "C:\\windows\\system32\\vmwareuser.exe",
        "C:\\program files\\vmware\\vmware tools\\",
        "C:\\program files\\oracle\\virtualbox guest additions\\",
        NULL
    };

    for (int i = 0; vm_files[i]; i++) {
        DWORD attributes = GetFileAttributesA(vm_files[i]);
        if (attributes != INVALID_FILE_ATTRIBUTES) {
            score += 25u;
        }
    }

    // Services VM
    const char* vm_services[] = {
        "VBoxService", "VBoxSF", "VBoxMouse",
        "VMTools", "vmhgfs", "vmmouse", "vmmemctl",
        "vmware-usbarbitrator64", "vmware-converter",
        "VMwareHostOpen",
        NULL
    };

    SC_HANDLE scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    if (scm) {
        for (int i = 0; vm_services[i]; i++) {
            SC_HANDLE service = OpenServiceA(scm, vm_services[i], SERVICE_QUERY_STATUS);
            if (service) {
                score += 20u;
                CloseServiceHandle(service);
            }
        }
        CloseServiceHandle(scm);
    }

    return score;
}

// --- Détection de sandbox par comportement temporel ---
ANTIDEBUG_INLINE u32 ad_detect_sandbox_timing(void) {
    volatile u32 score = 0u;

    // Test de vitesse d'exécution
    LARGE_INTEGER start, end, freq;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&start);

    // Opération simple qui devrait être rapide
    volatile int dummy = 0;
    for (int i = 0; i < 10000; i++) {
        dummy += i;
    }

    QueryPerformanceCounter(&end);

    // Calculer le temps écoulé en millisecondes
    double elapsed = (double)(end.QuadPart - start.QuadPart) * 1000.0 / freq.QuadPart;

    // Si l'exécution est anormalement lente (sandbox avec overhead)
    if (elapsed > 50.0) {  // Plus de 50ms pour 10k opérations
        score += 30u;
    }

    // Test de cohérence temporelle
    DWORD tick1 = GetTickCount();
    Sleep(100);  // Attendre 100ms
    DWORD tick2 = GetTickCount();
    DWORD actual_sleep = tick2 - tick1;

    // Si le sleep ne correspond pas au temps réel (sandbox accélérée)
    if (actual_sleep < 90 || actual_sleep > 150) {
        score += 25u;
    }

    return score;
}

// --- Détection de sandbox par ressources limitées ---
ANTIDEBUG_INLINE u32 ad_detect_sandbox_resources(void) {
    volatile u32 score = 0u;

    // Vérifier la mémoire disponible
    MEMORYSTATUSEX memStatus;
    memStatus.dwLength = sizeof(memStatus);
    if (GlobalMemoryStatusEx(&memStatus)) {
        // Moins de 2GB de RAM physique = probablement une sandbox
        if (memStatus.ullTotalPhys < 2ULL * 1024 * 1024 * 1024) {
            score += 20u;
        }
    }

    // Vérifier l'espace disque
    ULARGE_INTEGER freeBytesAvailable, totalNumberOfBytes;
    if (GetDiskFreeSpaceExA("C:\\", &freeBytesAvailable, &totalNumberOfBytes, NULL)) {
        // Moins de 50GB = probablement une sandbox
        if (totalNumberOfBytes.QuadPart < 50ULL * 1024 * 1024 * 1024) {
            score += 15u;
        }
    }

    // Vérifier le nombre de processeurs
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    if (sysInfo.dwNumberOfProcessors < 2) {
        score += 25u;  // Moins de 2 CPU = suspect
    }

    return score;
}

// --- Détection de sandbox par noms d'utilisateur/machine ---
ANTIDEBUG_INLINE u32 ad_detect_sandbox_names(void) {
    volatile u32 score = 0u;

    // Noms d'utilisateur suspects (mots forts uniquement — "admin", "user",
    // "test" sont trop courants pour être discriminants).
    char username[256];
    DWORD username_size = sizeof(username);
    if (GetUserNameA(username, &username_size)) {
        const char* sandbox_users[] = {
            "sandbox", "malware", "maltest", "cuckoo",
            "currentuser", "fortinet", "wilbert", "abby",
            NULL
        };
        for (int i = 0; sandbox_users[i]; i++) {
            if (_stricmp(username, sandbox_users[i]) == 0) {
                score += 30u;
            }
        }
    }

    // Nom de l'ordinateur — seulement les marqueurs très spécifiques.
    // "DESKTOP-" / "WIN-" sont les NOMS PAR DÉFAUT de Windows 10/11
    // → faux positifs systématiques. Supprimés.
    char computer_name[256];
    DWORD computer_name_size = sizeof(computer_name);
    if (GetComputerNameA(computer_name, &computer_name_size)) {
        const char* sandbox_computers[] = {
            "SANDBOX", "MALWARE", "CUCKOO", "FORTINET",
            NULL
        };
        _strupr_s(computer_name, sizeof(computer_name));
        for (int i = 0; sandbox_computers[i]; i++) {
            if (strstr(computer_name, sandbox_computers[i])) {
                score += 25u;
            }
        }
    }

    return score;
}

// --- Détection de debuggers et outils d'analyse en ligne ---
// NOTE : la résolution DNS active (gethostbyname / WSAStartup) est volontairement
// évitée — elle est trop bruyante et dépend de winsock. On se rabat sur la
// présence du fichier hosts personnalisé ou de proxies d'analyse connus.
ANTIDEBUG_INLINE u32 ad_detect_online_analysis_tools(void) {
    volatile u32 score = 0u;

    const char* analysis_artifacts[] = {
        "C:\\Program Files\\Cuckoo\\",
        "C:\\Program Files\\AnyRun\\",
        "C:\\Program Files\\JoeSandbox\\",
        "C:\\Program Files\\VMRay\\",
        "C:\\cuckoo\\",
        "C:\\analysis\\",
        NULL
    };

    for (int i = 0; analysis_artifacts[i]; i++) {
        DWORD attr = GetFileAttributesA(analysis_artifacts[i]);
        if (attr != INVALID_FILE_ATTRIBUTES) {
            score += 15u;
        }
    }

    return score;
}

// --- Détection d'environnement CI/CD et build automatisé ---
ANTIDEBUG_INLINE u32 ad_detect_automated_build_environment(void) {
    volatile u32 score = 0u;

    // Variables d'environnement CI/CD (uniquement marqueurs forts —
    // "CI" tout court est trop courant en local).
    const char* ci_env_vars[] = {
        "JENKINS_URL", "TRAVIS", "APPVEYOR", "GITLAB_CI",
        "GITHUB_ACTIONS", "TEAMCITY_VERSION",
        "BAMBOO_BUILD_KEY", "CIRCLECI", "CODEBUILD_BUILD_ID",
        NULL
    };

    for (int i = 0; ci_env_vars[i]; i++) {
        char buffer[256];
        if (GetEnvironmentVariableA(ci_env_vars[i], buffer, sizeof(buffer)) > 0) {
            score += 15u;
        }
    }

    // NOTE : la détection de processus de build (msbuild, cmake, ninja…) a
    // été retirée — ces processus sont normaux sur poste de développement et
    // ne sont pas représentatifs d'un environnement d'attaque.

    return score;
}

// --- Master function pour toutes les détections de sandbox ---
ANTIDEBUG_INLINE u32 ad_sandbox_analysis_detection_master(void) {
    volatile u32 total_score = 0u;

    __try {
        total_score += ad_detect_virtualization_hardware();
        total_score += ad_detect_vm_artifacts();
        total_score += ad_detect_sandbox_timing();
        total_score += ad_detect_sandbox_resources();
        total_score += ad_detect_sandbox_names();
        total_score += ad_detect_online_analysis_tools();
        total_score += ad_detect_automated_build_environment();

    } __except(EXCEPTION_EXECUTE_HANDLER) {
        total_score += 150u;  // Exception = environnement suspect
    }

    return total_score;
}

#endif // ANTIDEBUG_SANDBOX_ANALYSIS_DETECTION_H