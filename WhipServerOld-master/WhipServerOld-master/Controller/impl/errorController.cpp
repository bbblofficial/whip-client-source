#include "errorController.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include "../../utils/encryption_utils.h"
#include "../../utils/string_utils.h"
#include "../../utils/time_utils.h"
#include "../../utils/SimpleWebhook.h"

#ifdef _WIN32
#include <fileapi.h>
#else
#include <unistd.h>
#include <sys/stat.h>
#endif

ErrorController::ErrorController() {
    std::cout << "[ErrorController] Initialized" << std::endl;
}

const char* ErrorController::getErrorTypeString(uint8_t errorType, const char* debuggerName) {
    static std::string result;

    switch (static_cast<ErrorType>(errorType)) {
    case ErrorType::DEBUGGER_DETECTED:
        if (debuggerName && debuggerName[0] != '\0') {
            result = std::string("Debugger detecte (") + debuggerName + ")";
        }
        else {
            result = "Debugger detecte";
        }
        return result.c_str();
    case ErrorType::HOOK_DETECTED:
        return "Hook detecte";
    case ErrorType::VM_DETECTED:
        return "Machine virtuelle detectee";
    default:
        return "Erreur inconnue";
    }
}

const char* ErrorController::getUserByHwid(const char* hwid) {
    static std::string result;

    // Lire le fichier users.txt
    std::ifstream file("users.txt");
    if (!file.is_open()) {
        std::cerr << "[ErrorController] Impossible d'ouvrir users.txt" << std::endl;
        return "Utilisateur inconnu";
    }

    std::string line;
    while (std::getline(file, line)) {
        if (line.empty()) continue;

        // Chercher le HWID dans la ligne
        if (line.find(hwid) != std::string::npos) {
            std::vector<const char*> parts = StringUtils::split(line.c_str(), ";");
            if (parts.size() >= 1) {
                result = parts[0]; // Nom d'utilisateur
                std::cout << "[ErrorController] Utilisateur trouvÃ©: " << result << std::endl;
                return result.c_str();
            }
        }
    }

    std::cout << "[ErrorController] Aucun utilisateur trouvÃ© pour HWID: " << hwid << std::endl;
    return "Utilisateur inconnu";
}

bool ErrorController::removeUserByHwid(const char* hwid) {
    // Lire le fichier users.txt et crÃ©er un nouveau contenu sans l'utilisateur
    std::ifstream inFile("users.txt");
    if (!inFile.is_open()) {
        std::cerr << "[ErrorController] Impossible d'ouvrir users.txt pour suppression" << std::endl;
        return false;
    }

    std::vector<std::string> lines;
    std::string line;
    bool userFound = false;

    while (std::getline(inFile, line)) {
        if (line.empty()) {
            lines.push_back(line);  // Garder les lignes vides
            continue;
        }

        // Si la ligne contient le HWID, ne pas l'ajouter (= supprimer)
        if (line.find(hwid) != std::string::npos) {
            std::cout << "[ErrorController] Ligne Ã  supprimer trouvÃ©e: " << line << std::endl;
            userFound = true;
        }
        else {
            lines.push_back(line);  // Garder toutes les autres lignes
        }
    }

    inFile.close();

    // Si aucun utilisateur trouvÃ©, ne rien faire
    if (!userFound) {
        std::cout << "[ErrorController] Aucun utilisateur avec HWID " << hwid << " trouvÃ© pour suppression" << std::endl;
        return false;
    }

    // Ã‰crire le nouveau contenu dans le fichier
    std::ofstream outFile("users.txt");
    if (!outFile.is_open()) {
        std::cerr << "[ErrorController] Impossible d'ouvrir users.txt pour Ã©criture" << std::endl;
        return false;
    }

    for (const auto& l : lines) {
        outFile << l << std::endl;
    }

    outFile.close();
    std::cout << "[ErrorController] Utilisateur avec HWID " << hwid << " supprimÃ© avec succÃ¨s" << std::endl;
    return true;
}

bool ErrorController::sendErrorWebhook(const char* username, const char* hwid, const char* sessionId,
    const char* clientIp, uint8_t errorType, const char* screenshotPath, const char* debuggerName) {

    // Obtenir le type d'erreur avec le nom du débogueur si disponible
    const char* errorTypeStr = getErrorTypeString(errorType, debuggerName);

    // Utilisation de la fonction amÃ©liorÃ©e SendSecurityAlertWebhook
    return SendSecurityAlertWebhook(
        errorTypeStr,
        username,
        hwid,
        clientIp,
        nullptr  // Toujours nullptr pour indiquer pas de capture d'Ã©cran
    );
}

const char* ErrorController::handleRequest(const char* payload, const char* clientIp) {
    static std::string resultStr;

    try {
        std::cout << "[ErrorController] Traitement d'une requÃªte d'erreur" << std::endl;

        // DÃ©sÃ©rialiser le payload
        ErrorPayload errorPayload;
        std::memcpy(&errorPayload, payload, sizeof(ErrorPayload));

        std::cout << "[ErrorController] Type d'erreur: " << (int)errorPayload.errorType << std::endl;
        std::cout << "[ErrorController] Timestamp: " << errorPayload.timestamp << std::endl;
        std::cout << "[ErrorController] Taille capture d'Ã©cran: " << errorPayload.screenshotSize << std::endl;

        // Vérifier si nous avons un nom de débogueur dans les champs réservés
        char debuggerName[24] = { 0 }; // Taille +1 pour s'assurer du terminateur nul
        if (errorPayload.errorType == static_cast<uint8_t>(ErrorType::DEBUGGER_DETECTED) &&
            errorPayload.reserved[0] != '\0') {
            // Copier le nom du débogueur depuis les données réservées
            strncpy(debuggerName, reinterpret_cast<const char*>(errorPayload.reserved), sizeof(debuggerName) - 1);
            debuggerName[sizeof(debuggerName) - 1] = '\0'; // S'assurer de la terminaison
            std::cout << "[ErrorController] Nom du débogueur détecté: " << debuggerName << std::endl;
        }

        // Essayer d'extraire le HWID depuis sessionToken (nouvelle approche simplifiée)
        const char* sessionContent = errorPayload.sessionToken;
        static std::string hwidStr = "Unknown HWID";
        static std::string timestampStr = "0";
        const char* hwid = hwidStr.c_str();
        const char* timestamp = timestampStr.c_str();
        
        // Vérifier si le sessionToken contient des données
        if (sessionContent[0] != '\0') {
            try {
                // SÃ©parer les parties chiffrÃ©es
                std::vector<const char*> parts = StringUtils::split(sessionContent, "-|e");
                if (parts.size() == 3) {
                    // DÃ©chiffrer avec XOR dans l'ordre appropriÃ©
                    char randomKeyBuffer[64];
                    strcpy(randomKeyBuffer, EncryptionUtils::decryptXor(parts[2], "errorsecret"));
                    const char* randomKey = randomKeyBuffer;

                    char timestampBuffer[64];
                    strcpy(timestampBuffer, EncryptionUtils::decryptXor(parts[0], randomKey));
                    timestampStr = timestampBuffer;
                    timestamp = timestampStr.c_str();

                    char hwidBuffer[256];
                    strcpy(hwidBuffer, EncryptionUtils::decryptXor(parts[1], timestampBuffer));
                    hwidStr = hwidBuffer;
                    hwid = hwidStr.c_str();
                } else {
                    std::cout << "[ErrorController] SessionToken format invalide, utilisation HWID par défaut" << std::endl;
                }
            } catch (const std::exception& e) {
                std::cout << "[ErrorController] Erreur déchiffrement sessionToken: " << e.what() << std::endl;
            }
        }

        std::cout << "[ErrorController] Valeurs dÃ©chiffrÃ©es:" << std::endl;
        std::cout << "  Timestamp: " << timestamp << std::endl;
        std::cout << "  HWID: " << hwid << std::endl;

        // Recherche d'un utilisateur existant par HWID
        const char* username = getUserByHwid(hwid);

        // Si aucun utilisateur n'est trouvÃ©, utiliser une valeur par dÃ©faut
        if (!username || strcmp(username, "Utilisateur inconnu") == 0) {
            username = "Utilisateur non identifiÃ©";
            std::cout << "[ErrorController] Aucun utilisateur trouvÃ© pour HWID: " << hwid << std::endl;
        }
        else {
            std::cout << "[ErrorController] Utilisateur trouvÃ©: " << username << std::endl;

            // Supprimer l'utilisateur du fichier users.txt
            bool removalSuccess = removeUserByHwid(hwid);
            std::cout << "[ErrorController] Suppression de l'utilisateur "
                << (removalSuccess ? "rÃ©ussie" : "Ã©chouÃ©e") << std::endl;
        }

        // Pour la compatibilitÃ© avec les webhooks existants, utiliser "no-session" comme ID de session par dÃ©faut
        const char* sessionId = "no-session";

        std::cout << "[ErrorController] Using session ID: " << sessionId << std::endl;

        // Envoyer l'alerte via webhook (avec nom du débogueur si disponible)
        bool webhookSuccess = sendErrorWebhook(
            username,
            hwid,
            sessionId,
            clientIp,
            errorPayload.errorType,
            nullptr,  // Pas de capture d'Ã©cran
            debuggerName[0] != '\0' ? debuggerName : nullptr  // Passer le nom du débogueur s'il est disponible
        );

        std::cout << "[ErrorController] Webhook " << (webhookSuccess ? "envoyÃ© avec succÃ¨s" : "Ã©chec d'envoi") << std::endl;

        // PrÃ©parer la rÃ©ponse
        ErrorResponse response{};
        response.status = webhookSuccess ? 0 : 3; // 0 = succÃ¨s, 3 = Ã©chec webhook
        resultStr = std::string(reinterpret_cast<const char*>(&response), sizeof(response));

        return resultStr.c_str();
    }
    catch (const std::exception& e) {
        std::cerr << "[ErrorController] Erreur: " << e.what() << std::endl;

        // Retourner une rÃ©ponse d'erreur
        ErrorResponse response{};
        response.status = 4; // Erreur gÃ©nÃ©rale
        resultStr = std::string(reinterpret_cast<const char*>(&response), sizeof(response));
        return resultStr.c_str();
    }
}