#pragma once
#include <string>

// Fonction pour échapper les caractères spéciaux JSON
std::string EscapeJsonString(const std::string& input);

// Fonction pour nettoyer un UUID (enlever les tirets)
std::string CleanUUID(const std::string& uuid);

// Fonction simple pour envoyer un webhook Discord (version avec image)
bool SendDiscordWebhookWithImage(
    const char* webhookUrl,
    const char* title,
    const char* message,
    bool isSuccess,
    const char* username,
    const char* avatarUrl,
    const char* imageUrl
);

// Version standard
bool SendDiscordWebhook(
    const char* webhookUrl,
    const char* title,
    const char* message,
    bool isSuccess,
    const char* username = nullptr,
    const char* avatarUrl = nullptr
);

// Dans SimpleWebhook.h
bool SendAccessDeniedWebhook(
    const char* hwid,
    const char* ip,
    const char* version,
    const char* product = nullptr
);

// Fonction pour envoyer une notification de connexion client (version avec UUID)
bool SendClientConnectedWebhook(
    const char* username,
    const char* hwid,
    const char* sessionId,
    const char* ip,
    const char* minecraftVersion,
    const char* uuid
);

// Fonction pour envoyer une notification de connexion client (version sans UUID pour compatibilité)
bool SendClientConnectedWebhook(
    const char* username,
    const char* hwid,
    const char* sessionId,
    const char* ip,
    const char* minecraftVersion
);

// Fonction pour envoyer des alertes de sécurité
bool SendSecurityAlertWebhook(
    const char* alertType,
    const char* username,
    const char* hwid,
    const char* sessionId,
    const char* ip,
    const char* screenshotPath = nullptr
);

// Fonction de test simple
bool TestWebhook();