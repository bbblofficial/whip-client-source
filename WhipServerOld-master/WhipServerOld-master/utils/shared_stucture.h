#pragma once

// =============================================
// DÉFINITIONS PARTAGÉES POUR LES STRUCTURES
// =============================================

#include <cstdint>
#include <cstring>

// IMPORTANT: Définir la structure avec un alignement strict de 1 byte
// sans padding entre les champs
#pragma pack(push, 1)

struct ConfigResponse {
    uint8_t status;     // Code de statut (0=succès, autres=erreurs)
    uint32_t dataSize;  // Taille des données après cette structure

    // Constructeur par défaut pour initialiser les champs
    ConfigResponse() : status(0), dataSize(0) {}
};

// Remettre l'alignement par défaut
#pragma pack(pop)

// Fonction utilitaire pour créer une réponse sécurisée
inline char* createSafeResponse(const ConfigResponse& response, const void* data = nullptr, size_t dataSize = 0) {
    // Allouer la mémoire pour la réponse
    size_t totalSize = sizeof(ConfigResponse) + (data ? dataSize : 0);
    char* buffer = new char[totalSize];

    // Copier l'en-tête de réponse
    memcpy(buffer, &response, sizeof(ConfigResponse));

    // Copier les données si présentes
    if (data && dataSize > 0) {
        memcpy(buffer + sizeof(ConfigResponse), data, dataSize);
    }

    return buffer;
}