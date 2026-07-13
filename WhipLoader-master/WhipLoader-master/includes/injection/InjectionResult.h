#pragma once

#include "../util/Types.h"
#include <string>
#include <cstdint>

enum class InjectionStatus {
    Success,            // Injection réussie
    ProcessNotFound,    // Process cible non trouvé
    AccessDenied,       // Accès refusé au process
    AllocationFailed,   // Échec allocation mémoire
    WriteFailed,        // Échec écriture mémoire
    MappingFailed,      // Échec mapping sections
    ImportsFailed,      // Échec résolution imports
    RelocationsFailed,  // Échec relocations
    TlsCallbackFailed,  // Échec TLS callbacks
    EntryPointFailed,   // Échec appel DllMain
    Timeout,            // Timeout
    Unknown             // Erreur inconnue
};

struct InjectionResult {
    InjectionStatus status = InjectionStatus::Unknown;

    // Process cible
    uint32_t processId = 0;
    std::string processName;

    // Adresses
    uintptr_t baseAddress = 0;      // Adresse base de la DLL injectée
    uintptr_t entryPoint = 0;       // Adresse DllMain

    // Timing
    Timestamp startTime;
    Timestamp endTime;
    Duration duration;

    // Erreur détaillée
    uint32_t lastError = 0;         // GetLastError()
    std::string errorMessage;

    // Méthodes
    [[nodiscard]] bool isSuccess() const noexcept {
        return status == InjectionStatus::Success;
    }

    [[nodiscard]] std::string statusString() const {
        switch (status) {
            case InjectionStatus::Success: return "Success";
            case InjectionStatus::ProcessNotFound: return "Process not found";
            case InjectionStatus::AccessDenied: return "Access denied";
            case InjectionStatus::AllocationFailed: return "Memory allocation failed";
            case InjectionStatus::WriteFailed: return "Memory write failed";
            case InjectionStatus::MappingFailed: return "Section mapping failed";
            case InjectionStatus::ImportsFailed: return "Import resolution failed";
            case InjectionStatus::RelocationsFailed: return "Relocation failed";
            case InjectionStatus::TlsCallbackFailed: return "TLS callback failed";
            case InjectionStatus::EntryPointFailed: return "Entry point call failed";
            case InjectionStatus::Timeout: return "Timeout";
            default: return "Unknown error";
        }
    }
};

struct ProcessInfo {
    uint32_t processId = 0;
    std::string name;
    std::string path;
    std::string commandLine;
    uintptr_t baseAddress = 0;
    bool is64Bit = true;
    Timestamp startTime;

    [[nodiscard]] bool isValid() const noexcept {
        return processId != 0 && !name.empty();
    }
};