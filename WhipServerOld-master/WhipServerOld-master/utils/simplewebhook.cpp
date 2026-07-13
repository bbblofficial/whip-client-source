#include "SimpleWebhook.h"
#include "Discord.h"
#include <iostream>
#include <sstream>
#include <algorithm>
#include "time_utils.h"
#include "safe_string.h"

#ifdef _WIN32
    #include <windows.h>
    #include <wininet.h>
    #pragma comment(lib, "wininet.lib")
#else
    #include "native_http.h"
    #include <cstring>
#endif

// Fonction pour vérifier si l'HWID doit être filtré
bool shouldSkipWebhookForHWID(const char* hwid) {
    // HWID à filtrer
    const char* filteredHWID = "568f13de60c11baab3fc14b11e18868cb880e83d881071322b8dfcd2be2482e5";

    // Si l'HWID est NULL ou vide, ne pas filtrer
    if (!hwid || hwid[0] == '\0' || strcmp(hwid, "n/a") == 0) {
        return false;
    }

    // Vérifier si l'HWID correspond à celui que nous voulons filtrer
    return (strcmp(hwid, filteredHWID) == 0);
}

// Fonction pour échapper les caractères spéciaux JSON
std::string EscapeJsonString(const std::string& input) {
    std::stringstream ss;
    for (auto c : input) {
        switch (c) {
        case '\"': ss << "\\\""; break;
        case '\\': ss << "\\\\"; break;
        case '\b': ss << "\\b"; break;
        case '\f': ss << "\\f"; break;
        case '\n': ss << "\\n"; break;
        case '\r': ss << "\\r"; break;
        case '\t': ss << "\\t"; break;
        default:
            if ('\x00' <= c && c <= '\x1f') {
                char buf[7];
                if (SAFE_SPRINTF(buf, "\\u%04x", (int)c) >= 0) {
                    ss << buf;
                } else {
                    ss << "\\u0000"; // Fallback sécurisé
                }
            }
            else {
                ss << c;
            }
        }
    }
    return ss.str();
}

// Fonction pour nettoyer un UUID (enlever les tirets)
std::string CleanUUID(const std::string& uuid) {
    std::string clean_uuid = uuid;
    clean_uuid.erase(std::remove(clean_uuid.begin(), clean_uuid.end(), '-'), clean_uuid.end());
    return clean_uuid;
}

// Fonction pour envoyer un webhook Discord (version avec image)
bool SendDiscordWebhookWithImage(
    const char* webhookUrl,
    const char* title,
    const char* message,
    bool isSuccess,
    const char* username,
    const char* avatarUrl,
    const char* imageUrl)
{
    try {
        DiscordWebhook webhook(webhookUrl);

        // Configurer les options de base du webhook
        if (username && *username) {
            webhook.setUsername(username);
        }

        if (avatarUrl && *avatarUrl) {
            webhook.setAvatarUrl(avatarUrl);
        }

        // Créer un embed avec les informations fournies
        DiscordEmbed embed(title, message);

        // Définir la couleur (vert pour le succès, rouge pour l'échec)
        embed.setColor(isSuccess ? 0x00FF00 : 0xFF0000);

        // Ajouter un timestamp
        embed.setTimestamp();

        // Ajouter l'image si fournie
        if (imageUrl && *imageUrl) {
            embed.setImage(imageUrl);
        }

        // Ajouter l'embed au webhook
        webhook.addEmbed(embed);

        // Exécuter l'envoi
        webhook.execute();

        std::cout << "[Discord] Webhook with image sent successfully!" << std::endl;
        return true;
    }
    catch (const std::exception& e) {
        std::cerr << "[Discord] Error sending webhook with image: " << e.what() << std::endl;
        return false;
    }
}

// Version standard sans image
bool SendDiscordWebhook(
    const char* webhookUrl,
    const char* title,
    const char* message,
    bool isSuccess,
    const char* username,
    const char* avatarUrl)
{
    return SendDiscordWebhookWithImage(webhookUrl, title, message, isSuccess, username, avatarUrl, nullptr);
}

// Fonction pour envoyer une notification de connexion client
bool SendClientConnectedWebhook(
    const char* username,
    const char* hwid,
    const char* sessionId,
    const char* ip,
    const char* minecraftVersion,
    const char* uuid)
{
    // Vérifier si nous devons filtrer ce message basé sur l'HWID
    if (shouldSkipWebhookForHWID(hwid)) {
        std::cout << "[Discord] Webhook skipped for filtered HWID" << std::endl;
        return true; // Retourner true pour simuler un envoi réussi
    }

    // URL du webhook Discord - Utilise la même URL que dans le code existant
    const char* webhookUrl = "https://discord.com/api/webhooks/1345771990774190143/zjjphYPJR8ZS_NPU3Tu7s5GXdUJxWNZA2edBnE_WMB2OXhMkJGv2uWCCO6kTetcvfizq";

    try {
        DiscordWebhook webhook(webhookUrl);

        // Configurer le webhook
        webhook.setUsername("Security");

        // Titre du message
        std::string title = "New connection";

        // Créer un message détaillé
        std::ostringstream message;
        message << "**Player:** " << (username && *username ? username : "n/a");

        if (uuid && *uuid && strcmp(uuid, "n/a") != 0) {
            message << " (`" << uuid << "`)";
        }

        message << "\n**HWID:** `" << (hwid && *hwid ? hwid : "n/a") << "`"
            << "\n**Session:** `" << (sessionId && *sessionId ? sessionId : "n/a") << "`"
            << "\n**IP:** `" << (ip && *ip ? ip : "n/a") << "`"
            << "\n**Version:** " << (minecraftVersion && *minecraftVersion ? minecraftVersion : "n/a");

        // Créer un embed avec les informations fournies
        DiscordEmbed embed(title, message.str());

        // Définir la couleur (vert pour une connexion réussie)
        embed.setColor(0x00FF00);

        // Ajouter un timestamp
        embed.setTimestamp();

        // Ajouter l'embed au webhook
        webhook.addEmbed(embed);

        // Exécuter l'envoi
        webhook.execute();

        std::cout << "[Discord] Client connection webhook sent successfully!" << std::endl;
        return true;
    }
    catch (const std::exception& e) {
        std::cerr << "[Discord] Error sending client connection webhook: " << e.what() << std::endl;
        return false;
    }
}

// Surcharge pour compatibilité avec la version sans UUID
bool SendClientConnectedWebhook(
    const char* username,
    const char* hwid,
    const char* sessionId,
    const char* ip,
    const char* minecraftVersion)
{
    return SendClientConnectedWebhook(username, hwid, sessionId, ip, minecraftVersion, "n/a");
}

bool SendSecurityAlertWebhook(
    const char* alertType,
    const char* username,
    const char* hwid,
    const char* sessionToken,
    const char* clientIp,
    const char* screenshotPath)  // Ce paramètre sera toujours nullptr
{
    // Vérifier si nous devons filtrer ce message basé sur l'HWID
    if (shouldSkipWebhookForHWID(hwid)) {
        std::cout << "[Discord] Security alert webhook skipped for filtered HWID" << std::endl;
        return true; // Retourner true pour simuler un envoi réussi
    }

    try {
        // URL du webhook Discord
        const char* webhookUrl = "https://discord.com/api/webhooks/1349115993137348700/woJWeA8QoLnob3XOiZaoTLXjW6gpxvnmcdyBYk5LErGgfXX_QcRh6Zks4ttfEjokXRe-";
        DiscordWebhook webhook(webhookUrl);
        webhook.setUsername("Security Alert");

        // Ajouter un message principal avec @everyone pour garantir la notification
        webhook.setContent("@everyone SECURITY ALERTE");

        // Titre du message de l'embed
        std::string title = "SECURITY ALERTE";

        // Message détaillé dans l'embed
        std::ostringstream message;
        message << "**An attacker has ben found!**\n\n"
            << "**alerte type:** " << (alertType && *alertType ? alertType : "unknown") << "\n"
            << "**user:** " << (username && *username ? username : "n/a") << "\n"
            << "**hwid:** `" << (hwid && *hwid ? hwid : "n/a") << "`\n"
            << "**Session ID:** `" << (sessionToken && *sessionToken ? sessionToken : "n/a") << "`\n"
            << "**Adresse IP:** `" << (clientIp && *clientIp ? clientIp : "n/a") << "`\n";

        // Créer un embed avec les informations
        DiscordEmbed embed(title, message.str());
        embed.setColor(0xFF0000);  // Rouge pour alerte
        embed.setTimestamp();
        embed.setFooter("Security System");

        webhook.addEmbed(embed);
        webhook.execute();

        std::cout << "[Discord] Security alert webhook sent successfully!" << std::endl;
        return true;
    }
    catch (const std::exception& e) {
        std::cerr << "[Discord] Error sending security alert webhook: " << e.what() << std::endl;
        return false;
    }
}

bool SendAccessDeniedWebhook(
    const char* hwid,
    const char* ip,
    const char* version,
    const char* product)
{
    // Vérifier si nous devons filtrer ce message basé sur l'HWID
    if (shouldSkipWebhookForHWID(hwid)) {
        std::cout << "[Discord] Access denied webhook skipped for filtered HWID" << std::endl;
        return true; // Retourner true pour simuler un envoi réussi
    }

    // URL du webhook Discord
    const char* webhookUrl = "https://discord.com/api/webhooks/1349115993137348700/woJWeA8QoLnob3XOiZaoTLXjW6gpxvnmcdyBYk5LErGgfXX_QcRh6Zks4ttfEjokXRe-";

    try {
        DiscordWebhook webhook(webhookUrl);

        // Configuration du webhook
        webhook.setUsername("Security Alert");
        webhook.setContent("@everyone illegal acces");

        // Titre descriptif
        std::string title = "! ACCES REFUSED - HWID UNALLOWED !";

        // Message détaillé
        std::ostringstream message;
        message << "**AN UNALLOWED HWID HAS BEEN DETECTED**\n\n"
            << "**HWID:** `" << (hwid && *hwid ? hwid : "n/a") << "`\n"
            << "**IP:** `" << (ip && *ip ? ip : "n/a") << "`\n"
            << "**Version:** " << (version && *version ? version : "n/a");

        // Ajouter le produit si fourni
        if (product && *product) {
            message << "\n**PRODUCT:** " << product;
        }

        message << "\n\n**TIME:** " << TimeUtils::getUnixTimestamp();

        // Créer un embed avec les informations
        DiscordEmbed embed(title, message.str());
        embed.setColor(0xFF0000);  // Rouge pour alerte
        embed.setFooter("Security System");

        webhook.addEmbed(embed);
        webhook.execute();

        std::cout << "[Security] Webhook d'alerte d'accès refusé envoyé avec succès!" << std::endl;
        return true;
    }
    catch (const std::exception& e) {
        std::cerr << "[Security] Erreur lors de l'envoi du webhook d'alerte d'accès refusé: " << e.what() << std::endl;
        return false;
    }
}

bool TestWebhook() {
    // URL du webhook Discord
    const char* webhookUrl = "https://discord.com/api/webhooks/1370748900809637988/Dh2XLADjQHS18JjL7Fm5dV-2ieFeZb_gvLt2yuzqNzM4dnRZwdheDu5SBAAfUNHGZsCR";

    try {
        DiscordWebhook webhook(webhookUrl);

        // Utiliser uniquement les fonctionnalités de base pour éviter les problèmes potentiels
        webhook.setUsername("Server");

        // Utiliser des caractères ASCII simples pour éviter les problèmes d'encodage
        webhook.setContent("Server started.");

        // Si vous voulez quand même utiliser un embed, utilisez des caractères simples
        DiscordEmbed embed("Serveur starting", "Le serveur started and working");
        embed.setColor(0x3498DB); // Bleu
        embed.setTimestamp();

        // Ajout de champs simples
        embed.addField("Version", "1.0.0", true);
        embed.addField("Mode", "Release", true);

        // Ajouter un pied de page
        embed.setFooter("Authentication Server");

        // Ajouter l'embed au webhook
        webhook.addEmbed(embed);

        // Exécuter l'envoi
        webhook.execute();

        std::cout << "[Discord] Test webhook sent successfully!" << std::endl;
        return true;
    }
    catch (const std::exception& e) {
        std::cerr << "[Discord] Error sending test webhook: " << e.what() << std::endl;
        return false;
    }
}