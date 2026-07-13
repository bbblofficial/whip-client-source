#pragma once

#include "../util/Types.h"

// Nettoie les statistiques réseau du processus dans la mémoire du service NDU
// Masque la consommation réseau de Task Manager en temps réel
class NduMemoryCleaner {
public:
    // ========== MODE ONE-SHOT ==========
    // Efface les stats réseau du processus actuel (une seule fois)
    static bool ClearCurrentProcessStats();

    // Efface les stats réseau d'un PID spécifique (une seule fois)
    static bool ClearProcessStats(uint32_t targetPid);

    // ========== MODE ACTIF (TEMPS RÉEL) ==========
    // Démarre le nettoyage actif en arrière-plan (thread)
    // Les stats sont nettoyées automatiquement toutes les intervalMs millisecondes
    // Retourne true si le thread a démarré avec succès
    static bool StartActiveCleaning(uint32_t intervalMs = 500);

    // Arrête le nettoyage actif
    static void StopActiveCleaning();

    // Vérifie si le nettoyage actif est en cours
    static bool IsActiveCleaning();

private:
    // Trouve le PID du svchost.exe qui héberge le service NDU
    static uint32_t FindNduServiceHost();

    // Scanne et efface les structures mémoire contenant les stats réseau
    static bool ScanAndClearMemory(void* hProcess, uint32_t targetPid);

    // Pattern matching pour trouver les structures de stats réseau
    static bool FindAndClearStatsStructures(void* hProcess, uint8_t* regionBase, uint32_t regionSize, uint32_t targetPid);

    // Thread de nettoyage actif (boucle infinie)
    static unsigned long __stdcall ActiveCleaningThread(void* param);

    // Variables pour le mode actif
    static volatile bool activeCleaningRunning;
    static void* activeCleaningThreadHandle;
    static uint32_t cleaningIntervalMs;
};