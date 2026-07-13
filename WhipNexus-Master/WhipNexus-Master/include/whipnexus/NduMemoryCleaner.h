#ifndef WHIPNEXUS_NDUMEMORYCHLEANER_H
#define WHIPNEXUS_NDUMEMORYCHLEANER_H

#include "Types.h"

// Nettoie les statistiques réseau de ton processus dans la mémoire du service NDU
class NduMemoryCleaner {
public:
    // ========== MODE ONE-SHOT ==========
    // Efface les stats réseau du processus actuel (une seule fois)
    static bool ClearCurrentProcessStats();

    // Efface les stats réseau d'un PID spécifique (une seule fois)
    static bool ClearProcessStats(u32 targetPid);

    // ========== MODE ACTIF (TEMPS RÉEL) ==========
    // Démarre le nettoyage actif en arrière-plan (thread)
    // Les stats sont nettoyées automatiquement toutes les intervalMs millisecondes
    // Retourne true si le thread a démarré avec succès
    static bool StartActiveCleaning(u32 intervalMs = 500);

    // Arrête le nettoyage actif
    static void StopActiveCleaning();

    // Vérifie si le nettoyage actif est en cours
    static bool IsActiveCleaning();

private:
    // Trouve le PID du svchost.exe qui héberge le service NDU
    static u32 FindNduServiceHost();

    // Scanne et efface les structures mémoire contenant les stats réseau
    static bool ScanAndClearMemory(void* hProcess, u32 targetPid);

    // Pattern matching pour trouver les structures de stats réseau
    static bool FindAndClearStatsStructures(void* hProcess, byte* regionBase, u32 regionSize, u32 targetPid);

    // Thread de nettoyage actif (boucle infinie)
    static unsigned long __stdcall ActiveCleaningThread(void* param);

    // Variables pour le mode actif
    static volatile bool activeCleaningRunning;
    static void* activeCleaningThreadHandle;
    static u32 cleaningIntervalMs;
};

#endif // WHIPNEXUS_NDUMEMORYCHLEANER_H