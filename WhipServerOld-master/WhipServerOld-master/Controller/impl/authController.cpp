#include "authController.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <bits/this_thread_sleep.h>

#include "../../utils/time_utils.h"
#include "../../utils/SimpleWebhook.h"
#include "../../utils/Thread/ThreadSafeBuffer.h"
#include "../../utils/safe_string.h"
#include "../../utils/json/nlohmann/json.hpp"
#include "../../utils/aes.h"

// Fonction utilitaire pour calculer la longueur sans dépendre de null terminator
namespace {
    size_t safe_string_length(const char *str, size_t max_len) {
        if (!str) return 0;
        size_t len = 0;
        for (size_t i = 0; i < max_len && str[i] != '\0'; i++) {
            len++;
        }
        return len;
    }
}

AuthController::AuthController() {
    versionToMappingsFile = {
        {"0", "mappings/Lunar-1.7.10.json"},
        {"1", "mappings/Lunar-1.8.9.json"},
        {"2", "mappings/Badlion-1.8.9.json"}
    };
}

std::vector<const char *> AuthController::readUsersFile() {
    std::vector<const char *> users;
    std::ifstream file("users.txt");
    std::string line;
    std::vector<std::string> stringLines;

    while (std::getline(file, line)) {
        if (!line.empty()) {
            stringLines.push_back(line);
            users.push_back(stringLines.back().c_str());
        }
    }

    return users;
}

const char *AuthController::vectorToString(const std::vector<uint8_t> &data) {
    static std::string result;
    result = std::string(reinterpret_cast<const char *>(data.data()), data.size());
    return result.c_str();
}

bool AuthController::validateHWID(const char *hwid) {
    if (!hwid) return false;

    size_t hwid_len = 0;
    for (size_t i = 0; i < 512 && hwid[i] != '\0'; i++) {
        hwid_len++;
    }

    if (hwid_len < 8 || hwid_len > 64) {
        return false;
    }

    for (size_t i = 0; i < hwid_len; i++) {
        char c = hwid[i];
        if (!std::isalnum(c) && c != '-' && c != '_') {
            return false;
        }
    }

    return true;
}

bool AuthController::validateVersion(const char *version) {
    for (const auto &pair: versionToMappingsFile) {
        if (strcmp(pair.first, version) == 0) {
            return true;
        }
    }
    return false;
}

bool AuthController::validateProduct(const char *product) {
    if (!product || product[0] == '\0') return false;

    size_t len = 0;
    for (size_t i = 0; i < 32 && product[i] != '\0'; i++) {
        len++;
    }

    return len <= 32;
}

const char *AuthController::getUserByHwid(const std::vector<const char *> &users, const char *hwid) {
    static std::string result;

    std::cout << "[AuthController] Recherche utilisateur avec HWID: " << hwid << std::endl;
    std::cout << "[AuthController] Nombre d'utilisateurs dans la base: " << users.size() << std::endl;

    for (const auto &user: users) {
        std::cout << "Le pseudo hwid: " << user << std::endl;

        std::vector<const char *> parts = StringUtils::split(user, ";");

        if (parts.size() < 3) {
            return nullptr;
        }

        if (parts[1] == hwid) {
            return user;
        }

        return nullptr;
    }

    std::cout << "[AuthController] [ACCESS DENIED] Aucun utilisateur trouvé pour HWID: " << hwid << std::endl;
    return nullptr;
}

AuthPart1Response AuthController::createPart1SuccessResponse(const char *hwid, const char *versionsContent) {
    AuthPart1Response response{};
    response.status = AuthStatus::SUCCESS;
    
    // Auth Part 1 envoie les versions comme contenu textuel (JSON)
    size_t versionsSize = 0;
    if (versionsContent) {
        versionsSize = strlen(versionsContent);
    }
    response.messageSize = static_cast<uint32_t>(versionsSize);
    
    // versionsDataSize n'est plus utilisé pour les données binaires
    response.versionsDataSize = 0;
    
    std::cout << "[AuthController] Auth Part 1 - messageSize: " << response.messageSize << " (versions JSON)" << std::endl;
    std::cout << "[AuthController] Auth Part 1 - versionsDataSize: " << response.versionsDataSize << " (unused)" << std::endl;
    
    strncpy(response.hwid, hwid, sizeof(response.hwid) - 1);
    return response;
}

AuthPart2Response AuthController::createPart2SuccessResponse(const char *username, const char *uuid, const char *mappingContent) {
    AuthPart2Response response{};
    response.status = AuthStatus::SUCCESS;
    size_t contentSize = 0;
    if (mappingContent) {
        contentSize = strlen(mappingContent);
        std::cout << "[AuthController] createPart2SuccessResponse - mappingContent length: " << contentSize << std::endl;
    }
    response.messageSize = static_cast<uint32_t>(contentSize);
    // Pour AUTH_PART2, on n'utilise pas username/uuid - laissé vide
    memset(response.username, 0, sizeof(response.username));
    memset(response.uuid, 0, sizeof(response.uuid));
    return response;
}

AuthPart1Response AuthController::createPart1ErrorResponse(const char *message) {
    AuthPart1Response response{};
    response.status = AuthStatus::ERRORR;
    size_t msgSize = 0;
    if (message) {
        for (size_t i = 0; i < 256 && message[i] != '\0'; i++) {
            msgSize++;
        }
    }
    response.messageSize = static_cast<uint32_t>(msgSize);
    return response;
}

AuthPart2Response AuthController::createPart2ErrorResponse(const char *message) {
    AuthPart2Response response{};
    response.status = AuthStatus::ERRORR;
    size_t msgSize = 0;
    if (message) {
        for (size_t i = 0; i < 256 && message[i] != '\0'; i++) {
            msgSize++;
        }
    }
    response.messageSize = static_cast<uint32_t>(msgSize);
    return response;
}

const char *AuthController::getMappingContent(const char *version) {
    static std::string content;

    const char *filename = nullptr;
    for (const auto &pair: versionToMappingsFile) {
        if (strcmp(pair.first, version) == 0) {
            filename = pair.second;
            break;
        }
    }

    if (filename == nullptr) {
        return nullptr;
    }

    std::ifstream mappingFile(filename);
    if (!mappingFile.is_open()) {
        return nullptr;
    }

    std::stringstream buffer;
    buffer << mappingFile.rdbuf();
    content = buffer.str();
    return content.c_str();
}

unsigned char* AuthController::fromBase64(const char* input, size_t* output_len) {
    if (!input || !output_len) {
        return nullptr;
    }

    static const char base64_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            "abcdefghijklmnopqrstuvwxyz"
            "0123456789+/";
    
    size_t input_len = 0;
    while (input[input_len] != '\0') {
        char c = input[input_len];
        if (strchr(base64_chars, c) == nullptr && c != '=') {
            break;
        }
        input_len++;
    }

    size_t max_output_size = (input_len * 3) / 4 + 1;
    unsigned char *decoded = new unsigned char[max_output_size];

    uint32_t bit_stream = 0;
    size_t counter = 0;
    size_t offset = 0;
    size_t out_pos = 0;

    for (size_t i = 0; i < input_len; i++) {
        char c = input[i];
        
        const char *pos = strchr(base64_chars, c);
        if (pos) {
            size_t num_val = pos - base64_chars;
            offset = 18 - (counter % 4) * 6;
            bit_stream += num_val << offset;

            if (offset == 12) {
                decoded[out_pos++] = (bit_stream >> 16) & 0xFF;
            }
            if (offset == 6) {
                decoded[out_pos++] = (bit_stream >> 8) & 0xFF;
            }
            if (offset == 0 && counter != 4) {
                decoded[out_pos++] = bit_stream & 0xFF;
                bit_stream = 0;
            }
            counter++;
        } else if (c != '=') {
            delete[] decoded;
            *output_len = 0;
            return nullptr;
        }
    }

    *output_len = out_pos;
    return decoded;
}

const char* AuthController::aesDecrypt(const char* input, const char* key) {
    try {
        size_t input_len = 0;
        for (input_len = 0; input[input_len] != '\0'; input_len++);

        size_t decoded_len = 0;
        unsigned char *decoded = fromBase64(input, &decoded_len);

        if (!decoded || decoded_len < 8 + AES_BLOCKLEN) {
            if (decoded) delete[] decoded;
            return nullptr;
        }

        uint32_t magic;
        memcpy(&magic, decoded, 4);
        if (magic != 0xAECBDAEF) {
            delete[] decoded;
            return nullptr;
        }

        uint32_t original_len;
        memcpy(&original_len, decoded + 4, 4);

        size_t encrypted_data_len = decoded_len - 8 - AES_BLOCKLEN;
        if (original_len > 1000000 || original_len > encrypted_data_len) {
            if (encrypted_data_len > AES_BLOCKLEN) {
                original_len = encrypted_data_len - (encrypted_data_len % AES_BLOCKLEN);
                original_len -= AES_BLOCKLEN;
            } else {
                delete[] decoded;
                return nullptr;
            }
        }

        unsigned char iv[AES_BLOCKLEN];
        memcpy(iv, decoded + 8, AES_BLOCKLEN);

        unsigned char *encrypted_data = new unsigned char[encrypted_data_len];
        memcpy(encrypted_data, decoded + 8 + AES_BLOCKLEN, encrypted_data_len);

        delete[] decoded;

        size_t key_len = 0;
        for (key_len = 0; key_len < 128 && key[key_len] != '\0'; key_len++);

        unsigned char derived_key[AES_KEYLEN];
        for (size_t i = 0; i < AES_KEYLEN; i++) {
            derived_key[i] = key[i % key_len] ^ (i * 13);
        }

        AES_ctx ctx;
        AES_init_ctx_iv(&ctx, derived_key, iv);
        AES_CBC_decrypt_buffer(&ctx, encrypted_data, encrypted_data_len);

        if (original_len > encrypted_data_len) {
            delete[] encrypted_data;
            return nullptr;
        }

        static std::string result;
        result = std::string(reinterpret_cast<const char*>(encrypted_data), original_len);
        delete[] encrypted_data;
        return result.c_str();
    } catch (const std::exception &e) {
        return nullptr;
    }
}

std::vector<std::string> AuthController::splitEncryptedPayload(const char* payload, const char* delimiter) {
    std::vector<std::string> result;
    if (!payload || !delimiter) return result;
    
    std::string payloadStr(payload);
    std::string delimiterStr(delimiter);
    
    size_t start = 0;
    size_t end = 0;
    
    while ((end = payloadStr.find(delimiterStr, start)) != std::string::npos) {
        result.push_back(payloadStr.substr(start, end - start));
        start = end + delimiterStr.length();
    }
    result.push_back(payloadStr.substr(start));
    
    return result;
}

const char* AuthController::getVersionsContent() {
    static std::string content;
    
    try {
        // Load versions from JSON file and return as string (like mappings)
        std::ifstream file("versions/versions.json");
        if (!file.is_open()) {
            std::cout << "[AuthController] ERROR: Failed to open versions/versions.json" << std::endl;
            return nullptr;
        }
        
        std::stringstream buffer;
        buffer << file.rdbuf();
        content = buffer.str();
        file.close();
        
        std::cout << "[AuthController] Loaded versions JSON content, size: " << content.size() << " bytes" << std::endl;
        return content.c_str();
        
    } catch (const std::exception& e) {
        std::cout << "[AuthController] ERROR: Exception loading versions JSON: " << e.what() << std::endl;
        return nullptr;
    }
}

const char *AuthController::handleAuthPart1(const char *payload, const char *clientIp) {
    static char binaryResponseBuffer[MAX_MAPPING_SIZE + 512];
    static size_t binaryResponseSize = 0;
    
    std::cout << "[AuthController] ===== HANDLE AUTH PART 1 START =====" << std::endl;
    std::cout << "[AuthController] Payload: " << (payload ? payload : "null") << std::endl;
    
    try {
        // Parser le payload (format: "hwid:version:product:clientIp")
        std::vector<const char *> parts = StringUtils::split(payload, ":");

        if (parts.size() < 3) {
            AuthPart1Response response = createPart1ErrorResponse("Format invalide");
            std::vector<uint8_t> finalPayload = BinaryProtocol::pack(response);

            const char *errorMsg = "Format invalide";
            size_t errorMsgLen = safe_string_length(errorMsg, 256);
            finalPayload.insert(finalPayload.end(),
                                reinterpret_cast<const uint8_t *>(errorMsg),
                                reinterpret_cast<const uint8_t *>(errorMsg + errorMsgLen));

            binaryResponseSize = finalPayload.size();
            if (binaryResponseSize > sizeof(binaryResponseBuffer)) {
                binaryResponseSize = sizeof(binaryResponseBuffer);
            }
            memcpy(binaryResponseBuffer, finalPayload.data(), binaryResponseSize);
            return binaryResponseBuffer;
        }

        const char *hwid = parts[0];
        const char *version = parts[1];
        const char *product = parts[2];

        std::cout << "[AuthController] Processing Auth Part 1:" << std::endl;
        std::cout << "  HWID: " << hwid << std::endl;
        std::cout << "  Version: " << version << std::endl;
        std::cout << "  Product: " << product << std::endl;

        // Valider les données
        if (!validateHWID(hwid) || !validateVersion(version) || !validateProduct(product)) {
            const char *errorMsg = "Données invalides";
            AuthPart1Response response = createPart1ErrorResponse(errorMsg);
            std::vector<uint8_t> finalPayload = BinaryProtocol::pack(response);

            size_t errorMsgLen = safe_string_length(errorMsg, 256);
            finalPayload.insert(finalPayload.end(),
                                reinterpret_cast<const uint8_t *>(errorMsg),
                                reinterpret_cast<const uint8_t *>(errorMsg + errorMsgLen));

            binaryResponseSize = finalPayload.size();
            if (binaryResponseSize > sizeof(binaryResponseBuffer)) {
                binaryResponseSize = sizeof(binaryResponseBuffer);
            }
            memcpy(binaryResponseBuffer, finalPayload.data(), binaryResponseSize);
            return binaryResponseBuffer;
        }

        // Vérifier utilisateur
        auto users = readUsersFile();
        const char *user = getUserByHwid(users, hwid);

        if (user == nullptr || *user == '\0') {
            const char *errorMsg = "HWID non autorisé";
            AuthPart1Response response = createPart1ErrorResponse(errorMsg);
            std::vector<uint8_t> finalPayload = BinaryProtocol::pack(response);

            size_t errorMsgLen = safe_string_length(errorMsg, 256);
            finalPayload.insert(finalPayload.end(),
                                reinterpret_cast<const uint8_t *>(errorMsg),
                                reinterpret_cast<const uint8_t *>(errorMsg + errorMsgLen));

            binaryResponseSize = finalPayload.size();
            if (binaryResponseSize > sizeof(binaryResponseBuffer)) {
                binaryResponseSize = sizeof(binaryResponseBuffer);
            }
            memcpy(binaryResponseBuffer, finalPayload.data(), binaryResponseSize);
            return binaryResponseBuffer;
        }

        if (!StringUtils::endsWith(user, product)) {
            const char *errorMsg = "Produit invalide";
            AuthPart1Response response = createPart1ErrorResponse(errorMsg);
            std::vector<uint8_t> finalPayload = BinaryProtocol::pack(response);

            size_t errorMsgLen = safe_string_length(errorMsg, 256);
            finalPayload.insert(finalPayload.end(),
                                reinterpret_cast<const uint8_t *>(errorMsg),
                                reinterpret_cast<const uint8_t *>(errorMsg + errorMsgLen));

            binaryResponseSize = finalPayload.size();
            if (binaryResponseSize > sizeof(binaryResponseBuffer)) {
                binaryResponseSize = sizeof(binaryResponseBuffer);
            }
            memcpy(binaryResponseBuffer, finalPayload.data(), binaryResponseSize);
            return binaryResponseBuffer;
        }

        // Charger le mapping
        const char *mappingContent = getMappingContent(version);
        if (mappingContent == nullptr || mappingContent[0] == '\0') {
            const char *errorMsg = "Erreur de mapping";
            AuthPart1Response response = createPart1ErrorResponse(errorMsg);
            std::vector<uint8_t> finalPayload = BinaryProtocol::pack(response);

            size_t errorMsgLen = safe_string_length(errorMsg, 256);
            finalPayload.insert(finalPayload.end(),
                                reinterpret_cast<const uint8_t *>(errorMsg),
                                reinterpret_cast<const uint8_t *>(errorMsg + errorMsgLen));

            binaryResponseSize = finalPayload.size();
            if (binaryResponseSize > sizeof(binaryResponseBuffer)) {
                binaryResponseSize = sizeof(binaryResponseBuffer);
            }
            memcpy(binaryResponseBuffer, finalPayload.data(), binaryResponseSize);
            return binaryResponseBuffer;
        }

        std::cout << "[AuthController] Auth Part 1 successful for HWID: " << hwid << std::endl;

        // Obtenir le contenu des versions (JSON)
        const char* versionsContent = getVersionsContent();
        if (!versionsContent) {
            const char *errorMsg = "Erreur de versions";
            AuthPart1Response response = createPart1ErrorResponse(errorMsg);
            std::vector<uint8_t> finalPayload = BinaryProtocol::pack(response);

            size_t errorMsgLen = safe_string_length(errorMsg, 256);
            finalPayload.insert(finalPayload.end(),
                                reinterpret_cast<const uint8_t *>(errorMsg),
                                reinterpret_cast<const uint8_t *>(errorMsg + errorMsgLen));

            binaryResponseSize = finalPayload.size();
            if (binaryResponseSize > sizeof(binaryResponseBuffer)) {
                binaryResponseSize = sizeof(binaryResponseBuffer);
            }
            memcpy(binaryResponseBuffer, finalPayload.data(), binaryResponseSize);
            return binaryResponseBuffer;
        }

        // Créer la réponse de succès pour Auth Part 1 avec les versions
        AuthPart1Response response = createPart1SuccessResponse(hwid, versionsContent);
        std::vector<uint8_t> finalPayload = BinaryProtocol::pack(response);

        // Ajouter le contenu JSON des versions (comme pour les mappings)
        size_t versionsLen = strlen(versionsContent);
        if (versionsLen > 0) {
            finalPayload.insert(finalPayload.end(),
                                reinterpret_cast<const uint8_t *>(versionsContent),
                                reinterpret_cast<const uint8_t *>(versionsContent + versionsLen));
        }

        binaryResponseSize = finalPayload.size();
        if (binaryResponseSize > sizeof(binaryResponseBuffer)) {
            binaryResponseSize = sizeof(binaryResponseBuffer);
        }
        memcpy(binaryResponseBuffer, finalPayload.data(), binaryResponseSize);

        return binaryResponseBuffer;

    } catch (const std::exception &e) {
        std::cerr << "[AuthController] Auth Part 1 Error: " << e.what() << std::endl;
        const char *errorMsg = "Erreur interne";
        AuthPart1Response response = createPart1ErrorResponse(errorMsg);
        std::vector<uint8_t> finalPayload = BinaryProtocol::pack(response);

        finalPayload.insert(finalPayload.end(),
                            reinterpret_cast<const uint8_t *>(errorMsg),
                            reinterpret_cast<const uint8_t *>(errorMsg + strlen(errorMsg)));

        binaryResponseSize = finalPayload.size();
        if (binaryResponseSize > sizeof(binaryResponseBuffer)) {
            binaryResponseSize = sizeof(binaryResponseBuffer);
        }
        memcpy(binaryResponseBuffer, finalPayload.data(), binaryResponseSize);

        return binaryResponseBuffer;
    }
}

const char *AuthController::handleAuthPart2(const char *payload, const char *clientIp) {
    static char binaryResponseBuffer[MAX_MAPPING_SIZE + 512];
    static size_t binaryResponseSize = 0;
    
    std::cout << "[AuthController] ===== HANDLE AUTH PART 2 START =====" << std::endl;
    std::cout << "[AuthController] Payload: " << (payload ? payload : "null") << std::endl;
    
    try {
        const char *mappingContent = nullptr;
        
        // Vérifier si c'est un payload chiffré AES (contient "-|x" delimiter)
        if (payload && strstr(payload, "-|x") != nullptr) {
            std::cout << "[AuthController] Detected AES encrypted payload, proceeding with decryption" << std::endl;
            
            // Décrypter le payload AES (format: "hwidProtected-|xdetectedVersionKeyProtected-|xtimestampProtected-|xrandomKeyProtected")
            std::vector<std::string> encryptedParts = splitEncryptedPayload(payload, "-|x");
            std::cout << "[AuthController] Found " << encryptedParts.size() << " encrypted parts" << std::endl;

            if (encryptedParts.size() < 4) {
                std::cout << "[AuthController] ERROR: Invalid number of encrypted parts: " << encryptedParts.size() << std::endl;
                AuthPart2Response response = createPart2ErrorResponse("Format invalide");
                std::vector<uint8_t> finalPayload = BinaryProtocol::pack(response);

                const char *errorMsg = "Format invalide";
                size_t errorMsgLen = safe_string_length(errorMsg, 256);
                finalPayload.insert(finalPayload.end(),
                                    reinterpret_cast<const uint8_t *>(errorMsg),
                                    reinterpret_cast<const uint8_t *>(errorMsg + errorMsgLen));

                binaryResponseSize = finalPayload.size();
                if (binaryResponseSize > sizeof(binaryResponseBuffer)) {
                    binaryResponseSize = sizeof(binaryResponseBuffer);
                }
                memcpy(binaryResponseBuffer, finalPayload.data(), binaryResponseSize);
                return binaryResponseBuffer;
            }

            // Décrypter randomKey d'abord (avec clé fixe "loginpart2key")
            const char* randomKey = aesDecrypt(encryptedParts[3].c_str(), "loginpart2key");
            if (!randomKey) {
                std::cout << "[AuthController] ERROR: Failed to decrypt random key" << std::endl;
                const char *errorMsg = "Erreur de décryption";
                AuthPart2Response response = createPart2ErrorResponse(errorMsg);
                std::vector<uint8_t> finalPayload = BinaryProtocol::pack(response);

                size_t errorMsgLen = safe_string_length(errorMsg, 256);
                finalPayload.insert(finalPayload.end(),
                                    reinterpret_cast<const uint8_t *>(errorMsg),
                                    reinterpret_cast<const uint8_t *>(errorMsg + errorMsgLen));

                binaryResponseSize = finalPayload.size();
                if (binaryResponseSize > sizeof(binaryResponseBuffer)) {
                    binaryResponseSize = sizeof(binaryResponseBuffer);
                }
                memcpy(binaryResponseBuffer, finalPayload.data(), binaryResponseSize);
                return binaryResponseBuffer;
            }

            std::cout << "[AuthController] Decrypted random key: " << randomKey << std::endl;

             // Décrypter les autres données avec la randomKey
            const char* hwid = aesDecrypt(encryptedParts[0].c_str(), randomKey);
            const char* detectedVersionKey = aesDecrypt(encryptedParts[1].c_str(), randomKey);
            const char* timestamp = aesDecrypt(encryptedParts[2].c_str(), randomKey);

            if (!hwid || !detectedVersionKey || !timestamp) {
                std::cout << "[AuthController] ERROR: Failed to decrypt payload data" << std::endl;
                auto errorMsg = "Erreur de décryption des données";
                AuthPart2Response response = createPart2ErrorResponse(errorMsg);
                std::vector<uint8_t> finalPayload = BinaryProtocol::pack(response);

                size_t errorMsgLen = safe_string_length(errorMsg, 256);
                finalPayload.insert(finalPayload.end(),
                                    reinterpret_cast<const uint8_t *>(errorMsg),
                                    reinterpret_cast<const uint8_t *>(errorMsg + errorMsgLen));

                binaryResponseSize = finalPayload.size();
                if (binaryResponseSize > sizeof(binaryResponseBuffer)) {
                    binaryResponseSize = sizeof(binaryResponseBuffer);
                }
                memcpy(binaryResponseBuffer, finalPayload.data(), binaryResponseSize);
                return binaryResponseBuffer;
            }

            std::cout << "[AuthController] Processing Auth Part 2:" << std::endl;
            std::cout << "  Timestamp: " << timestamp << std::endl;
            std::cout << "  HWID: " << hwid << std::endl;
            std::cout << "  Detected Version Key: " << detectedVersionKey << std::endl;

            // Vérifier que le HWID est toujours valide
            auto users = readUsersFile();
            const char *user = getUserByHwid(users, hwid);

            if (user == nullptr || *user == '\0') {
                const char *errorMsg = "HWID non autorisé";
                AuthPart2Response response = createPart2ErrorResponse(errorMsg);
                std::vector<uint8_t> finalPayload = BinaryProtocol::pack(response);

                size_t errorMsgLen = safe_string_length(errorMsg, 256);
                finalPayload.insert(finalPayload.end(),
                                    reinterpret_cast<const uint8_t *>(errorMsg),
                                    reinterpret_cast<const uint8_t *>(errorMsg + errorMsgLen));

                binaryResponseSize = finalPayload.size();
                if (binaryResponseSize > sizeof(binaryResponseBuffer)) {
                    binaryResponseSize = sizeof(binaryResponseBuffer);
                }
                memcpy(binaryResponseBuffer, finalPayload.data(), binaryResponseSize);
                return binaryResponseBuffer;
            }

            std::cout << "[AuthController] Auth Part 2 successful for HWID: " << hwid << std::endl;

            // Pour AUTH_PART2, pas d'infos joueur encore (viendront dans PLAYER_INFO_REQUEST)
            // notifyPlayerSession sera appelé dans PLAYER_INFO_REQUEST

            // Obtenir le mapping basé sur la version détectée
            int versionKey = atoi(detectedVersionKey);
            char versionStr[8];
            sprintf(versionStr, "%d", versionKey);
            mappingContent = getMappingContent(versionStr);
            
            if (!mappingContent) {
                std::cout << "[AuthController] Warning: No mapping found for detected version " << versionKey << std::endl;
                mappingContent = "";
            }

        } else {
            // Format legacy non-chiffré (format: "timestamp:hwid:detectedVersionKey")
            std::cout << "[AuthController] Detected legacy unencrypted payload, using old parsing" << std::endl;
            
            std::vector<const char *> parts = StringUtils::split(payload, ":");

            if (parts.size() < 3) {
                AuthPart2Response response = createPart2ErrorResponse("Format invalide");
                std::vector<uint8_t> finalPayload = BinaryProtocol::pack(response);

                const char *errorMsg = "Format invalide";
                size_t errorMsgLen = safe_string_length(errorMsg, 256);
                finalPayload.insert(finalPayload.end(),
                                    reinterpret_cast<const uint8_t *>(errorMsg),
                                    reinterpret_cast<const uint8_t *>(errorMsg + errorMsgLen));

                binaryResponseSize = finalPayload.size();
                if (binaryResponseSize > sizeof(binaryResponseBuffer)) {
                    binaryResponseSize = sizeof(binaryResponseBuffer);
                }
                memcpy(binaryResponseBuffer, finalPayload.data(), binaryResponseSize);
                return binaryResponseBuffer;
            }

            const char *hwid = parts[0];
            const char *detectedVersionKey = parts[1];
            const char *timestamp = parts[2];

            long long timestampValue = std::stoll(timestamp);
            long long currentTimeStamp = TimeUtils::currentTimeMillis();
            if (currentTimeStamp - timestampValue > 10000) {
                std::cout << "[ALERT] ERROR: Timestamp not valid: " << timestampValue << " | " << currentTimeStamp <<std::endl;
            }

            std::cout << "[AuthController] Processing Auth Part 2:" << std::endl;
            std::cout << "  Timestamp: " << timestamp << std::endl;
            std::cout << "  HWID: " << hwid << std::endl;
            std::cout << "  Detected Version Key: " << detectedVersionKey << std::endl;

            // Vérifier que le HWID est toujours valide
            auto users = readUsersFile();

            const char *user = getUserByHwid(users, hwid);

            if (user == nullptr || *user == '\0') {
                const char *errorMsg = "HWID non autorisé";
                AuthPart2Response response = createPart2ErrorResponse(errorMsg);
                std::vector<uint8_t> finalPayload = BinaryProtocol::pack(response);

                size_t errorMsgLen = safe_string_length(errorMsg, 256);
                finalPayload.insert(finalPayload.end(),
                                    reinterpret_cast<const uint8_t *>(errorMsg),
                                    reinterpret_cast<const uint8_t *>(errorMsg + errorMsgLen));

                binaryResponseSize = finalPayload.size();
                if (binaryResponseSize > sizeof(binaryResponseBuffer)) {
                    binaryResponseSize = sizeof(binaryResponseBuffer);
                }
                memcpy(binaryResponseBuffer, finalPayload.data(), binaryResponseSize);
                return binaryResponseBuffer;
            }

            std::cout << "[AuthController] Auth Part 2 successful for HWID: " << hwid << std::endl;

            // Obtenir le mapping basé sur la version détectée
            int versionKey = atoi(detectedVersionKey);
            char versionStr[8];
            sprintf(versionStr, "%d", versionKey);
            mappingContent = getMappingContent(versionStr);
            
            if (!mappingContent) {
                std::cout << "[AuthController] Warning: No mapping found for detected version " << versionKey << std::endl;
                mappingContent = "";
            }
        }

        // Créer la réponse de succès (commun aux deux formats)
        AuthPart2Response response = createPart2SuccessResponse("auth_part2", "success", mappingContent);
        std::vector<uint8_t> finalPayload = BinaryProtocol::pack(response);

        // Ajouter le mapping content si présent
        size_t mappingLen = strlen(mappingContent);
        if (mappingLen > 0) {
            std::cout << "[AuthController] Adding mapping content, length: " << mappingLen << std::endl;
            std::cout << "[AuthController] First 200 chars of mapping: " << std::string(mappingContent, std::min(mappingLen, (size_t)200)) << std::endl;
            std::cout << "[AuthController] Last 200 chars of mapping: " << std::string(mappingContent + std::max(0, (int)mappingLen - 200), std::min(mappingLen, (size_t)200)) << std::endl;
            
            // Vérifier que le JSON est valide en testant les premiers et derniers caractères
            if (mappingContent[0] != '{') {
                std::cout << "[ERROR] Mapping does not start with '{', first char: " << (int)mappingContent[0] << std::endl;
            }
            if (mappingContent[mappingLen-1] != '}') {
                std::cout << "[ERROR] Mapping does not end with '}', last char: " << (int)mappingContent[mappingLen-1] << std::endl;
            }
            
            finalPayload.insert(finalPayload.end(),
                                reinterpret_cast<const uint8_t *>(mappingContent),
                                reinterpret_cast<const uint8_t *>(mappingContent + mappingLen));
        }

        binaryResponseSize = finalPayload.size();
        if (binaryResponseSize > sizeof(binaryResponseBuffer)) {
            binaryResponseSize = sizeof(binaryResponseBuffer);
        }
        memcpy(binaryResponseBuffer, finalPayload.data(), binaryResponseSize);

        // Debug: Afficher le début et la fin du payload final
        std::cout << "[AuthController] Final payload size: " << finalPayload.size() << std::endl;
        std::cout << "[AuthController] Final payload first 50 bytes: ";
        for (size_t i = 0; i < std::min(finalPayload.size(), (size_t)50); i++) {
            printf("%02x ", finalPayload[i]);
        }
        std::cout << std::endl;
        
        // Chercher où commence le JSON dans le payload (chercher le premier '{')
        for (size_t i = 0; i < finalPayload.size(); i++) {
            if (finalPayload[i] == '{') {
                std::cout << "[AuthController] JSON starts at offset: " << i << std::endl;
                // Afficher les 100 premiers chars du JSON
                std::string jsonStart(reinterpret_cast<const char*>(finalPayload.data() + i), std::min(finalPayload.size() - i, (size_t)100));
                std::cout << "[AuthController] JSON beginning: " << jsonStart << std::endl;
                break;
            }
        }

        return binaryResponseBuffer;

    } catch (const std::exception &e) {
        std::cerr << "[AuthController] Auth Part 2 Error: " << e.what() << std::endl;
        const char *errorMsg = "Erreur interne";
        AuthPart2Response response = createPart2ErrorResponse(errorMsg);
        std::vector<uint8_t> finalPayload = BinaryProtocol::pack(response);

        finalPayload.insert(finalPayload.end(),
                            reinterpret_cast<const uint8_t *>(errorMsg),
                            reinterpret_cast<const uint8_t *>(errorMsg + strlen(errorMsg)));

        binaryResponseSize = finalPayload.size();
        if (binaryResponseSize > sizeof(binaryResponseBuffer)) {
            binaryResponseSize = sizeof(binaryResponseBuffer);
        }
        memcpy(binaryResponseBuffer, finalPayload.data(), binaryResponseSize);

        return binaryResponseBuffer;
    }
}

// Variable statique globale pour la taille de la dernière réponse
static size_t lastPlayerInfoResponseSize = 0;

const char *AuthController::handlePlayerInfoRequest(const char *payload, const char *clientIp) {
    static char binaryResponseBuffer[MAX_MAPPING_SIZE + 512];
    static size_t binaryResponseSize = 0;
    
    std::cout << "[AuthController] ===== HANDLE PLAYER INFO REQUEST START =====" << std::endl;
    std::cout << "[AuthController] Encrypted Payload: " << (payload ? payload : "null") << std::endl;
    
    try {
        // Décrypter le payload AES (format: "hwidProtected-|xusernameProtected-|xuuidProtected-|xtimestampProtected-|xrandomKeyProtected")
        std::vector<std::string> encryptedParts = splitEncryptedPayload(payload, "-|x");

        if (encryptedParts.size() < 5) {
            PlayerInfoResponse response{};
            response.status = AuthStatus::ERRORR;
            response.dataSize = 0;
            memset(response.username, 0, sizeof(response.username));
            memset(response.uuid, 0, sizeof(response.uuid));
            memset(response.sessionId, 0, sizeof(response.sessionId));
            
            std::vector<uint8_t> finalPayload = BinaryProtocol::pack(response);

            const char *errorMsg = "Format invalide";
            size_t errorMsgLen = safe_string_length(errorMsg, 256);
            finalPayload.insert(finalPayload.end(),
                                reinterpret_cast<const uint8_t *>(errorMsg),
                                reinterpret_cast<const uint8_t *>(errorMsg + errorMsgLen));

            binaryResponseSize = finalPayload.size();
            if (binaryResponseSize > sizeof(binaryResponseBuffer)) {
                binaryResponseSize = sizeof(binaryResponseBuffer);
            }
            memcpy(binaryResponseBuffer, finalPayload.data(), binaryResponseSize);
            return binaryResponseBuffer;
        }

        // Décrypter randomKey d'abord (avec clé fixe "playerinfokey")
        const char* randomKey = aesDecrypt(encryptedParts[4].c_str(), "playerinfokey");
        if (!randomKey) {
            std::cout << "[AuthController] ERROR: Failed to decrypt random key" << std::endl;
            PlayerInfoResponse response{};
            response.status = AuthStatus::ERRORR;
            response.dataSize = 0;
            memset(response.username, 0, sizeof(response.username));
            memset(response.uuid, 0, sizeof(response.uuid));
            memset(response.sessionId, 0, sizeof(response.sessionId));
            
            std::vector<uint8_t> finalPayload = BinaryProtocol::pack(response);
            
            const char *errorMsg = "Erreur de décryption";
            size_t errorMsgLen = safe_string_length(errorMsg, 256);
            finalPayload.insert(finalPayload.end(),
                                reinterpret_cast<const uint8_t *>(errorMsg),
                                reinterpret_cast<const uint8_t *>(errorMsg + errorMsgLen));

            binaryResponseSize = finalPayload.size();
            if (binaryResponseSize > sizeof(binaryResponseBuffer)) {
                binaryResponseSize = sizeof(binaryResponseBuffer);
            }
            memcpy(binaryResponseBuffer, finalPayload.data(), binaryResponseSize);
            return binaryResponseBuffer;
        }

        std::cout << "[AuthController] Decrypted random key: " << randomKey << std::endl;

        // Décrypter les autres données avec la randomKey
        const char* hwid = aesDecrypt(encryptedParts[0].c_str(), randomKey);
        const char* username = aesDecrypt(encryptedParts[1].c_str(), randomKey);
        const char* uuid = aesDecrypt(encryptedParts[2].c_str(), randomKey);
        const char* timestamp = aesDecrypt(encryptedParts[3].c_str(), randomKey);

        if (!hwid || !username || !uuid || !timestamp) {
            std::cout << "[AuthController] ERROR: Failed to decrypt payload data" << std::endl;
            PlayerInfoResponse response{};
            response.status = AuthStatus::ERRORR;
            response.dataSize = 0;
            memset(response.username, 0, sizeof(response.username));
            memset(response.uuid, 0, sizeof(response.uuid));
            memset(response.sessionId, 0, sizeof(response.sessionId));
            
            std::vector<uint8_t> finalPayload = BinaryProtocol::pack(response);
            
            const char *errorMsg = "Erreur de décryption des données";
            size_t errorMsgLen = safe_string_length(errorMsg, 256);
            finalPayload.insert(finalPayload.end(),
                                reinterpret_cast<const uint8_t *>(errorMsg),
                                reinterpret_cast<const uint8_t *>(errorMsg + errorMsgLen));

            binaryResponseSize = finalPayload.size();
            if (binaryResponseSize > sizeof(binaryResponseBuffer)) {
                binaryResponseSize = sizeof(binaryResponseBuffer);
            }
            memcpy(binaryResponseBuffer, finalPayload.data(), binaryResponseSize);
            return binaryResponseBuffer;
        }

        std::cout << "[AuthController] Processing Player Info Request:" << std::endl;
        std::cout << "  HWID: " << hwid << std::endl;
        std::cout << "  Username: " << username << std::endl;
        std::cout << "  UUID: " << uuid << std::endl;
        std::cout << "  Timestamp: " << timestamp << std::endl;

        // Vérifier que le HWID est toujours valide
        auto users = readUsersFile();
        const char *user = getUserByHwid(users, hwid);

        if (user == nullptr || *user == '\0') {
            std::cout << "[AuthController] ERROR: HWID not authorized for player info" << std::endl;
            PlayerInfoResponse response{};
            response.status = AuthStatus::ERRORR;
            response.dataSize = 0;
            memset(response.username, 0, sizeof(response.username));
            memset(response.uuid, 0, sizeof(response.uuid));
            memset(response.sessionId, 0, sizeof(response.sessionId));
            
            std::vector<uint8_t> finalPayload = BinaryProtocol::pack(response);
            
            const char *errorMsg = "HWID non autorisé";
            size_t errorMsgLen = safe_string_length(errorMsg, 256);
            finalPayload.insert(finalPayload.end(),
                                reinterpret_cast<const uint8_t *>(errorMsg),
                                reinterpret_cast<const uint8_t *>(errorMsg + errorMsgLen));

            binaryResponseSize = finalPayload.size();
            if (binaryResponseSize > sizeof(binaryResponseBuffer)) {
                binaryResponseSize = sizeof(binaryResponseBuffer);
            }
            memcpy(binaryResponseBuffer, finalPayload.data(), binaryResponseSize);
            return binaryResponseBuffer;
        }

        // Créer la réponse de succès
        PlayerInfoResponse response{};
        response.status = AuthStatus::SUCCESS;
        response.dataSize = 0;
        
        strncpy(response.username, username, sizeof(response.username) - 1);
        strncpy(response.uuid, uuid, sizeof(response.uuid) - 1);
        
        // Générer un sessionId basé sur username et timestamp
        char sessionId[64];
        sprintf(sessionId, "%s_%s", username, timestamp);
        strncpy(response.sessionId, sessionId, sizeof(response.sessionId) - 1);

        std::cout << "[AuthController] Player Info Request successful for user: " << username << std::endl;
        
        // Notifier la session Discord
        notifyPlayerSession(username, uuid, hwid, clientIp);

        std::vector<uint8_t> finalPayload = BinaryProtocol::pack(response);

        binaryResponseSize = finalPayload.size();
        if (binaryResponseSize > sizeof(binaryResponseBuffer)) {
            binaryResponseSize = sizeof(binaryResponseBuffer);
        }
        memcpy(binaryResponseBuffer, finalPayload.data(), binaryResponseSize);
        
        // Mettre à jour la taille globale pour le serveur TLS
        lastPlayerInfoResponseSize = binaryResponseSize;

        return binaryResponseBuffer;

    } catch (const std::exception &e) {
        std::cerr << "[AuthController] Player Info Request Error: " << e.what() << std::endl;
        PlayerInfoResponse response{};
        response.status = AuthStatus::ERRORR;
        response.dataSize = 0;
        memset(response.username, 0, sizeof(response.username));
        memset(response.uuid, 0, sizeof(response.uuid));
        memset(response.sessionId, 0, sizeof(response.sessionId));
        
        std::vector<uint8_t> finalPayload = BinaryProtocol::pack(response);

        const char *errorMsg = "Erreur interne";
        finalPayload.insert(finalPayload.end(),
                            reinterpret_cast<const uint8_t *>(errorMsg),
                            reinterpret_cast<const uint8_t *>(errorMsg + strlen(errorMsg)));

        binaryResponseSize = finalPayload.size();
        if (binaryResponseSize > sizeof(binaryResponseBuffer)) {
            binaryResponseSize = sizeof(binaryResponseBuffer);
        }
        memcpy(binaryResponseBuffer, finalPayload.data(), binaryResponseSize);

        return binaryResponseBuffer;
    }
}

const char *AuthController::handleRequest(const char *payload, const char *clientIp) {
    // Log du payload reçu pour debug
    std::cout << "[AuthController] handleRequest called with payload: \"" << (payload ? payload : "null") << "\"" << std::endl;
    
    // Vérifier si c'est un payload chiffré AES (contient "-|x" delimiter)
    if (payload && strstr(payload, "-|x") != nullptr) {
        std::cout << "[AuthController] Detected encrypted AES payload (contains -|x delimiter)" << std::endl;
        
        // Compter le nombre de parties chiffrées
        std::vector<std::string> encryptedParts = splitEncryptedPayload(payload, "-|x");
        std::cout << "[AuthController] Found " << encryptedParts.size() << " encrypted parts" << std::endl;
        
        if (encryptedParts.size() == 4) {
            // Format AUTH_PART2: "hwidProtected-|xdetectedVersionKeyProtected-|xtimestampProtected-|xrandomKeyProtected"
            std::cout << "[AuthController] Detected encrypted AUTH_PART2 format (4 parts)" << std::endl;
            return handleAuthPart2(payload, clientIp);
        } else if (encryptedParts.size() == 5) {
            // Format PLAYER_INFO_REQUEST: "hwidProtected-|xusernameProtected-|xuuidProtected-|xtimestampProtected-|xrandomKeyProtected"
            std::cout << "[AuthController] Detected encrypted PLAYER_INFO_REQUEST format (5 parts)" << std::endl;
            return handlePlayerInfoRequest(payload, clientIp);
        } else {
            std::cout << "[AuthController] Invalid number of encrypted parts: " << encryptedParts.size() << std::endl;
            static char errorBuffer[256];
            strcpy(errorBuffer, "Format de payload chiffré invalide");
            return errorBuffer;
        }
    }
    
    // Sinon, traiter comme un payload non chiffré (legacy pour AUTH_PART1)
    std::cout << "[AuthController] Processing as unencrypted payload" << std::endl;
    
    // Déterminer si c'est la partie 1 ou 2 basé sur le format du payload
    std::vector<const char *> parts = StringUtils::split(payload, ":");
    
    std::cout << "[AuthController] Split result: " << parts.size() << " parts" << std::endl;
    for (size_t i = 0; i < parts.size(); i++) {
        std::cout << "[AuthController] Part " << i << ": \"" << parts[i] << "\"" << std::endl;
    }
    
    if (parts.size() == 4) {
        // Vérifier si c'est un format partie 1 ou partie 2
        // Partie 1: "hwid:version:product:clientIp" - version est un chiffre simple (0, 1, 2)
        // Partie 2: "username:uuid:timestamp:hwid" - timestamp est un nombre long (10+ chiffres)
        
        // Si la troisième partie est un timestamp long (10+ chiffres), c'est une partie 2
        const char* thirdPart = parts[2];
        size_t thirdPartLen = 0;
        bool isAllDigits = true;
        
        for (thirdPartLen = 0; thirdPart[thirdPartLen] != '\0'; thirdPartLen++) {
            if (thirdPart[thirdPartLen] < '0' || thirdPart[thirdPartLen] > '9') {
                isAllDigits = false;
                break;
            }
        }
        
        if (isAllDigits && thirdPartLen >= 10) {
            // Format partie 2: "username:uuid:timestamp:hwid"
            return handleAuthPart2(payload, clientIp);
        } else {
            // Format partie 1: "hwid:version:product:clientIp"
            return handleAuthPart1(payload, clientIp);
        }
    } else if (parts.size() == 3) {
        // Différencier entre AUTH_PART1 et AUTH_PART2 avec 3 parties
        // AUTH_PART1: "hwid:version:product" - premier élément est un long HWID (64 caractères)
        // AUTH_PART2: "timestamp:hwid:detectedVersionKey" - premier élément est un timestamp (10 chiffres)
        
        const char* firstPart = parts[0];
        size_t firstPartLen = 0;
        bool isAllDigits = true;
        
        // Debug: log first part analysis
        std::cout << "[AuthController] Analyzing first part: \"" << firstPart << "\"" << std::endl;
        
        for (firstPartLen = 0; firstPart[firstPartLen] != '\0'; firstPartLen++) {
            if (firstPart[firstPartLen] < '0' || firstPart[firstPartLen] > '9') {
                isAllDigits = false;
                break;
            }
        }
        
        std::cout << "[AuthController] First part length: " << firstPartLen << ", isAllDigits: " << (isAllDigits ? "true" : "false") << std::endl;
        
        std::cout << "[AuthController] DECISION: isAllDigits=" << (isAllDigits ? "true" : "false") 
                  << ", firstPartLen=" << firstPartLen << std::endl;
        
        if (isAllDigits && firstPartLen == 10) {
            // Format AUTH_PART2: "timestamp:hwid:detectedVersionKey" (timestamp = 10 chiffres)
            std::cout << "[AuthController] Detected AUTH_PART2 format (3 parts, timestamp=" << firstPart << ")" << std::endl;
            return handleAuthPart2(payload, clientIp);
        } else {
            // Format AUTH_PART1: "hwid:version:product" (hwid = long hexadécimal)
            std::cout << "[AuthController] Detected AUTH_PART1 format (3 parts, hwid=" << firstPart << ")" << std::endl;
            return handleAuthPart1(payload, clientIp);
        }
    } else {
        // Format invalide
        static char errorBuffer[256];
        strcpy(errorBuffer, "Format de requête invalide");
        return errorBuffer;
    }
}

// Fonction globale pour obtenir la taille de la dernière réponse PlayerInfo
extern size_t getLastPlayerInfoResponseSize() {
    extern size_t lastPlayerInfoResponseSize;
    return lastPlayerInfoResponseSize;
}

size_t AuthController::getLastBinaryResponseSize() {
    return 0;
}

const char *AuthController::getMinecraftVersionString(const char *version) {
    static std::string result;

    if (version == nullptr || version[0] == '\0') {
        return "n/a";
    }

    if (strcmp(version, "0") == 0) {
        result = "Lunar Client 1.7.10";
    } else if (strcmp(version, "1") == 0) {
        result = "Lunar Client 1.8.9";
    } else if (strcmp(version, "2") == 0) {
        result = "Badlion Client 1.8.9";
    } else {
        result = "Unknown Version (";
        result += version;
        result += ")";
    }

    return result.c_str();
}

const char *AuthController::parseUsername(const char *userString) {
    static std::string result;

    if (userString == nullptr || userString[0] == '\0') {
        return "n/a";
    }

    std::vector<const char *> parts = StringUtils::split(userString, ";");
    if (parts.size() >= 1) {
        result = parts[0];
        return result.c_str();
    }

    return "n/a";
}

const char *AuthController::parseUUID(const char *userString) {
    static std::string result;

    if (userString == nullptr || userString[0] == '\0') {
        return "n/a";
    }

    return "n/a";
}

void AuthController::notifyPlayerSession(const char *username, const char *uuid, const char *hwid, const char *clientIp) {
    SendClientConnectedWebhook(
        username && username[0] != '\0' ? username : "n/a",
        hwid && hwid[0] != '\0' ? hwid : "n/a",
        "n/a", // plus de session token
        clientIp && clientIp[0] != '\0' ? clientIp : "n/a",
        "Unknown",
        uuid && uuid[0] != '\0' ? uuid : "n/a"
    );
}