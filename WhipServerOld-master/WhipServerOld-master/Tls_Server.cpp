#include "Tls_Server.h"
#include <iostream>
#include <cinttypes>
#include <cstring>
#include <cstddef>  // Pour offsetof
#include "controller/impl/authController.h"
// Removed controllers: heartbeat, shutdown, destroySession
#include "controller/impl/errorController.h"
#include "utils/encryption_utils.h"
#include "Controller/impl/ConfigController.h"
#include "utils/safe_string.h"
#include "utils/Protocol/protocol.h"

#ifndef _WIN32
#include <strings.h>  // Pour strcasecmp et strncasecmp
#endif

Server *Server::instance = nullptr;

Server *Server::getInstance() {
    if (!instance) {
        instance = new Server();
    }
    return instance;
}

Server::Server() : serverSocket(1323, "6!NYRYP$xcJ7gYTLnMn4g?eLY7fX&tqyyQG@j9sf"), isRunning(false), PORT(1323) {
    try {
        std::cout << "\n=== Server Initialization ===" << std::endl;
        loadControllers();
    } catch (const std::exception &e) {
        std::cerr << "\n=== FATAL ERROR ===" << std::endl;
        std::cerr << "Message: " << e.what() << std::endl;
        throw;
    }
}

void Server::loadControllers() {
    controllers["auth"] = std::make_unique<AuthController>();
    controllers["error"] = std::make_unique<ErrorController>();
    controllers["config"] = std::make_unique<ConfigController>();

    for (const auto &controller: controllers) {
        std::cout << "[Server] Registered controller for route: " << controller.first << std::endl;
    }
}

const char *Server::getClientAddress(SOCKET clientSocket) {
    static char clientIp[INET_ADDRSTRLEN];
    sockaddr_in clientAddr;
#ifdef _WIN32
    int addrLen = sizeof(clientAddr);
#else
    socklen_t addrLen = sizeof(clientAddr);
#endif
    getpeername(clientSocket, (sockaddr *) &clientAddr, &addrLen);
    inet_ntop(AF_INET, &clientAddr.sin_addr, clientIp, INET_ADDRSTRLEN);
    return clientIp;
}

bool Server::sendResponse(SOCKET clientSocket, MessageType type, const std::vector<uint8_t> &payload) {
    return serverSocket.sendBinaryMessage(clientSocket, type, payload);
}

bool Server::sendErrorResponse(SOCKET clientSocket, ProtocolError error) {
    std::vector<uint8_t> errorPayload = BinaryProtocol::pack(error);
    return serverSocket.sendBinaryMessage(clientSocket, MessageType::ERRORR, errorPayload);
}

void Server::start() {
    if (!serverSocket.start()) {
        throw std::runtime_error("Failed to start server");
    }

    isRunning = true;
    char portBuffer[32];
    if (SAFE_SPRINTF(portBuffer, "[Server] Started on port %d", PORT) < 0) {
        std::cout << "[Server] Started on port " << PORT << std::endl;
    } else {
        std::cout << portBuffer << std::endl;
    }

    while (isRunning) {
        SOCKET clientSocket = serverSocket.acceptClient();
        if (clientSocket == INVALID_SOCKET) {
            if (isRunning) {
                std::cerr << "[Server] Failed to accept client" << std::endl;
            }
            continue;
        }

        std::thread([this, clientSocket]() {
            handleClient(clientSocket);
        }).detach();
    }
}

void Server::stop() {
    isRunning = false;
    serverSocket.stop();
}

Server::~Server() {
    stop();
}

void Server::handleClient(SOCKET clientSocket) {
    const char *clientIp = getClientAddress(clientSocket);
    char logBuffer[256];

    if (SAFE_SPRINTF(logBuffer, "New client connection") >= 0) {
        logMessage(logBuffer, clientIp);
    } else {
        logMessage("New client connection", clientIp);
    }

    try {
        BinaryMessageHeader header;
        std::vector<uint8_t> payload;

        // Log avant r�ception
        logMessage("Attempting to receive message...", clientIp);

        if (!serverSocket.receiveBinaryMessage(clientSocket, header, payload)) {
            logError("Failed to receive message", clientIp);
            serverSocket.sendErrorResponse(clientSocket, ProtocolError::INVALID_MAGIC);
            return;
        }

        // Log apr�s r�ception r�ussie
        sprintf(logBuffer, "Received message - Type: %d, Size: %zu", header.type, payload.size());
        logMessage(logBuffer, clientIp);

        // Traiter selon le type de message
        switch (static_cast<MessageType>(header.type)) {
            case MessageType::AUTH_PART1:
                handleAuthRequest(clientSocket, header, payload);
                break;
            case MessageType::AUTH_PART2:
                handleAuthPart2Request(clientSocket, header, payload);
                break;
            case MessageType::PLAYER_INFO_REQUEST:
                handlePlayerInfoRequest(clientSocket, header, payload);
                break;
            case MessageType::ERRORR:
                handleErrorRequest(clientSocket, header, payload);
                break;
            case MessageType::CONFIG_OPERATION:
                handleConfigRequest(clientSocket, header, payload);
                break;
            default:
                logError("Invalid message type", clientIp);
                serverSocket.sendErrorResponse(clientSocket, ProtocolError::INVALID_TYPE);
                break;
        }
    } catch (const std::exception &e) {
        char errorMsg[256];
        sprintf(errorMsg, "Error handling client: %s", e.what());
        logError(errorMsg, clientIp);
        serverSocket.sendErrorResponse(clientSocket, ProtocolError::INVALID_TYPE);
    }

    serverSocket.closeClient(clientSocket);
    logMessage("Connection closed", clientIp);
}

// Mise � jour de la m�thode Server::handleConfigRequest pour mieux traiter les messages binaires

void Server::handleConfigRequest(SOCKET clientSocket, const BinaryMessageHeader &header,
                                 const std::vector<uint8_t> &payload) {
    const char *clientIp = getClientAddress(clientSocket);
    logMessage("Processing config request", clientIp);

    try {
        // V�rifier la taille minimale du payload
        if (payload.empty()) {
            throw std::runtime_error("Empty config payload");
        }

        char logBuffer[256];
        sprintf(logBuffer, "Config payload size: %zu bytes", payload.size());
        logMessage(logBuffer, clientIp);

        // V�rifier si le payload est suffisamment grand pour contenir l'en-t�te de requ�te
        if (payload.size() < sizeof(ConfigRequest)) {
            sprintf(logBuffer, "Config payload too small: %zu bytes, expected at least %zu bytes",
                    payload.size(), sizeof(ConfigRequest));
            logError(logBuffer, clientIp);
            throw std::runtime_error("Invalid config payload size");
        }

        // Extraire la requ�te
        ConfigRequest configRequest;
        memcpy(&configRequest, payload.data(), sizeof(ConfigRequest));

        // Log d�taill� pour le d�bogage
        sprintf(logBuffer, "Config operation: %d, Config name: %s, Data size: %u",
                static_cast<int>(configRequest.operation), configRequest.configName, configRequest.dataSize);
        logMessage(logBuffer, clientIp);

        // V�rifier que la taille du payload correspond � l'en-t�te + donn�es additionnelles
        if (sizeof(ConfigRequest) + configRequest.dataSize > payload.size()) {
            sprintf(logBuffer, "Payload size mismatch: expected %zu, got %zu",
                    sizeof(ConfigRequest) + configRequest.dataSize, payload.size());
            logError(logBuffer, clientIp);
            throw std::runtime_error("Payload size mismatch");
        }

        // Trouver le contr�leur de configuration
        auto controller = controllers.find("config");
        if (controller == controllers.end()) {
            throw std::runtime_error("Config controller not found");
        }

        // Pr�parer le payload pour le controller
        // Cr�er une copie exacte du payload binaire
        std::vector<uint8_t> controllerPayloadVec = payload;

        // Allouer un buffer pour la r�ponse du controller
        const char *controllerResponse = controller->second->handleRequest(
            reinterpret_cast<const char *>(controllerPayloadVec.data()),
            clientIp
        );

        // V�rifier la r�ponse
        if (!controllerResponse) {
            throw std::runtime_error("Null response from controller");
        }

        // CORRECTION: Utiliser une copie de la structure avec le bon alignement
        ConfigResponse respHeader;
        memcpy(&respHeader, controllerResponse, sizeof(ConfigResponse));

        // Journal pour d�bogage
        sprintf(logBuffer, "Response header - Status: %d, DataSize: %u",
                (int) respHeader.status, respHeader.dataSize);
        logMessage(logBuffer, clientIp);

        // V�rification de s�curit�
        if (respHeader.status > 100) {
            logError("Invalid response status detected (>100), possible corruption", clientIp);
            respHeader.status = 5; // Server error
            respHeader.dataSize = 0;
        }

        // Limiter la taille de la r�ponse
        const size_t MAX_RESPONSE_SIZE = 10 * 1024 * 1024; // 10 MB
        if (respHeader.dataSize > MAX_RESPONSE_SIZE) {
            sprintf(logBuffer, "Response size too large: %u bytes, capping at %zu bytes",
                    respHeader.dataSize, MAX_RESPONSE_SIZE);
            logError(logBuffer, clientIp);

            // Cr�er une r�ponse d'erreur
            ConfigResponse errorResponse;
            errorResponse.status = 9; // Trop grand
            errorResponse.dataSize = 0;

            std::vector<uint8_t> responseData(reinterpret_cast<uint8_t *>(&errorResponse),
                                              reinterpret_cast<uint8_t *>(&errorResponse) + sizeof(errorResponse));

            serverSocket.sendBinaryMessage(clientSocket, MessageType::CONFIG_RESPONSE, responseData);
            return;
        }

        // Calculer la taille totale
        size_t responseSize = sizeof(ConfigResponse) + respHeader.dataSize;

        sprintf(logBuffer, "Preparing response: total size=%zu bytes (header=%zu, data=%u)",
                responseSize, sizeof(ConfigResponse), respHeader.dataSize);
        logMessage(logBuffer, clientIp);

        // Copier les donn�es dans un vecteur pour l'envoi
        std::vector<uint8_t> responseData(controllerResponse, controllerResponse + responseSize);

        // Message de d�bogage final
        sprintf(logBuffer, "Sending response vector of size %zu bytes", responseData.size());
        logMessage(logBuffer, clientIp);

        if (!serverSocket.sendBinaryMessage(clientSocket, MessageType::CONFIG_RESPONSE, responseData)) {
            throw std::runtime_error("Failed to send config response");
        }

        logMessage("Config response sent successfully", clientIp);
    } catch (const std::exception &e) {
        char errorBuffer[256];
        sprintf(errorBuffer, "Config error: %s", e.what());
        logError(errorBuffer, clientIp);

        // Envoyer une r�ponse d'erreur
        ConfigResponse errorResponse;
        memset(&errorResponse, 0, sizeof(errorResponse));
        errorResponse.status = 99; // Code d'erreur g�n�rique
        errorResponse.dataSize = 0;

        std::vector<uint8_t> responseData(reinterpret_cast<uint8_t *>(&errorResponse),
                                          reinterpret_cast<uint8_t *>(&errorResponse) + sizeof(errorResponse));

        serverSocket.sendBinaryMessage(clientSocket, MessageType::CONFIG_RESPONSE, responseData);
    }
}

void Server::handleAuthRequest(SOCKET clientSocket, const BinaryMessageHeader &header,
                               const std::vector<uint8_t> &payload) {
    const char *clientIp = getClientAddress(clientSocket);
    logMessage("Processing auth request", clientIp);

    try {
        // Process auth payload directly without using deprecated AuthPayload struct
        if (payload.empty()) {
            throw std::runtime_error("Empty auth payload");
        }

        // Extract base64 payload from raw data
        std::string payloadStr(payload.begin(), payload.end());
        const char *base64Payload = payloadStr.c_str();

        size_t payloadLength = payloadStr.length();

        char logPayloadBuffer[128];
        if (payloadLength > 100) {
            SAFE_SPRINTF(logPayloadBuffer, "Received base64 payload: %.*s...(truncated)", 100, base64Payload);
        } else {
            SAFE_SPRINTF(logPayloadBuffer, "Received base64 payload: %s", base64Payload);
        }
        logMessage(logPayloadBuffer, clientIp);

        // D�coder et v�rifier les parties chiffr�es
        std::vector<const char *> parts = StringUtils::split(base64Payload, "-|x");
        if (parts.size() != 5) {
            throw std::runtime_error("Invalid number of encrypted parts");
        }

        char randomKeyBuffer[64] = {0};
        char timestampBuffer[64] = {0};
        char hwidBuffer[256] = {0};
        char versionBuffer[16] = {0};
        char productBuffer[64] = {0};

        const char *randomKeyProtected = parts[4];
        size_t decryptedKeyLen = 0;
        const char *randomKey = EncryptionUtils::aesDecrypt(randomKeyProtected, "lucprime", &decryptedKeyLen);

        printf("RandomKey: %s | Decrypt: %llu | RandomkeyBuffer: %llu\n", randomKey, decryptedKeyLen,
               sizeof(randomKeyBuffer));

        if (!randomKey || decryptedKeyLen >= sizeof(randomKeyBuffer)) {
            throw std::runtime_error("Invalid random key size");
        }

        SAFE_MEMCPY(randomKeyBuffer, randomKey, decryptedKeyLen);
        randomKeyBuffer[decryptedKeyLen] = '\0';

        std::cout << "[Server] Decrypted random key: " << randomKeyBuffer << std::endl;

        // 2. D�crypter le timestamp avec la cl� random
        const char *timestampProtected = parts[3];
        size_t timestampLen = 0;
        const char *timestamp = EncryptionUtils::aesDecrypt(timestampProtected, randomKeyBuffer, &timestampLen);

        if (!timestamp || timestampLen >= sizeof(timestampBuffer)) {
            throw std::runtime_error("Invalid timestamp size");
        }
        memcpy(timestampBuffer, timestamp, timestampLen);
        timestampBuffer[timestampLen] = '\0';

        // 3. D�crypter les autres parties avec le timestamp
        size_t hwidLen = 0, versionLen = 0, productLen = 0;
        const char *hwid = EncryptionUtils::aesDecrypt(parts[0], timestampBuffer, &hwidLen);
        const char *version = EncryptionUtils::aesDecrypt(parts[1], timestampBuffer, &versionLen);
        const char *product = EncryptionUtils::aesDecrypt(parts[2], timestampBuffer, &productLen);

        if (!hwid || hwidLen >= sizeof(hwidBuffer) ||
            !version || versionLen >= sizeof(versionBuffer) ||
            !product || productLen >= sizeof(productBuffer)) {
            throw std::runtime_error("Invalid decrypted data size");
        }

        memcpy(hwidBuffer, hwid, hwidLen);
        memcpy(versionBuffer, version, versionLen);
        memcpy(productBuffer, product, productLen);
        hwidBuffer[hwidLen] = '\0';
        versionBuffer[versionLen] = '\0';
        productBuffer[productLen] = '\0';

        logMessage("Decrypted values:", clientIp);
        char hwidLogBuffer[300], versionLogBuffer[100], productLogBuffer[100];
        sprintf(hwidLogBuffer, "HWID: %s", hwidBuffer);
        sprintf(versionLogBuffer, "Version: %s", versionBuffer);
        sprintf(productLogBuffer, "Product: %s", productBuffer);

        logMessage(hwidLogBuffer, clientIp);
        logMessage(versionLogBuffer, clientIp);
        logMessage(productLogBuffer, clientIp);

        // Valider avec AuthController
        auto controller = controllers.find("auth");
        if (controller == controllers.end()) {
            throw std::runtime_error("Auth controller not found");
        }

        // Prepare direct response without session management

        char controllerPayload[512];
        std::cout << "[Server] Adding client IP to controller payload: " << clientIp << std::endl;
        snprintf(controllerPayload, sizeof(controllerPayload), "%s:%s:%s:%s",
                 hwidBuffer, versionBuffer, productBuffer, clientIp);
        std::cout << "[Server] Controller payload: " << controllerPayload << std::endl;

        // Obtenir le mapping depuis le controller - IMPORTANT: Passage de l'IP client
        const char *mapping = controller->second->handleRequest(controllerPayload, clientIp);
        
        // Calculate response size based on controller type
        size_t mappingSize = 0;
        
        if (controller->first == "auth") {
            // For auth controller, determine response size from AuthPart1Response or AuthPart2Response
            if (mapping != nullptr) {
                // Nouvelle AuthPart1Response: status(1) + hwid(64) + messageSize(4) + versionsDataSize(4) + reserved(28) = 101 bytes
                // AuthPart2Response: status(1) + username(64) + uuid(37) + messageSize(4) + reserved(32) = 138 bytes
                
                // Read messageSize from offset 65 (après status(1) + hwid(64))
                const uint32_t *messageSizePtr = reinterpret_cast<const uint32_t*>(mapping + 65);
                uint32_t contentSize = *messageSizePtr;
                
                // Read versionsDataSize from offset 69 (après status(1) + hwid(64) + messageSize(4))
                const uint32_t *versionsDataSizePtr = reinterpret_cast<const uint32_t*>(mapping + 69);
                uint32_t versionsDataSize = *versionsDataSizePtr;
                
                mappingSize = sizeof(AuthPart1Response) + contentSize + versionsDataSize; // AuthPart1Response header + content + versions
                
                std::cout << "[Server] Auth response detected, contentSize: " << contentSize << std::endl;
                std::cout << "[Server] Auth response detected, versionsDataSize: " << versionsDataSize << std::endl;
                std::cout << "[Server] Total auth response size: " << mappingSize << std::endl;
                
                // Debug: show first bytes
                std::cout << "[Server] First 32 bytes of auth response: ";
                for (size_t i = 0; i < std::min(mappingSize, (size_t)32); i++) {
                    printf("%02x ", (unsigned char)mapping[i]);
                }
                std::cout << std::endl;
            }
        } else {
            mappingSize = strlen(mapping);
        }
        
        char mappingLogBuffer[128];
        sprintf(mappingLogBuffer, "Controller response (mapping) size: %zu", mappingSize);
        logMessage(mappingLogBuffer, clientIp);

        // Pr�parer la cl� de chiffrement
        uint64_t timestampValue = strtoull(timestampBuffer, nullptr, 10);
        timestampValue += 1;
        char adjustedTimestampBuffer[32];
        if (SAFE_SPRINTF(adjustedTimestampBuffer, "%" PRIu64, timestampValue) < 0) {
            logError("Failed to format timestamp", clientIp);
            return;
        }

        // Construction de la cl� combin�e
        char combinedKey[512];
        if (SAFE_SPRINTF(combinedKey, "%s:%s", adjustedTimestampBuffer, randomKeyBuffer) < 0) {
            logError("Failed to create combined key", clientIp);
            return;
        }

        std::cout << "[Server] Combined key for encryption: " << combinedKey << std::endl;

        // Utiliser XChaCha20 pour chiffrer le mapping (plus performant pour les gros volumes de donn�es)
        //const char* encryptedMapping = XChaCha20::encrypt(mapping, mappingSize, combinedKey);

        std::cout << "[Server] Encrypted mapping with XChaCha20, length: " << mappingSize << std::endl;

        // D�terminer la taille du r�sultat chiffr�
        size_t encryptedSize = mappingSize;
        std::cout << "[Server] Final encrypted size: " << encryptedSize << std::endl;

        // Use the controller response directly without session management

        // Pr�parer la r�ponse finale
        std::vector<uint8_t> responseData;
        responseData.reserve(encryptedSize);

        // Insert controller response data directly
        responseData.insert(responseData.end(),
                            reinterpret_cast<const uint8_t *>(mapping),
                            reinterpret_cast<const uint8_t *>(mapping) + encryptedSize);

        // Response data already inserted above

        std::cout << "[Server] Total response size: " << responseData.size() << std::endl;

        if (!serverSocket.sendBinaryMessage(clientSocket, MessageType::AUTH_PART2, responseData)) {
            throw std::runtime_error("Failed to send response");
        }

        logMessage("Response sent successfully", clientIp);
    } catch (const std::exception &e) {
        char errorBuffer[256];
        sprintf(errorBuffer, "Auth error: %s", e.what());
        logError(errorBuffer, clientIp);
        sendErrorResponse(clientSocket, ProtocolError::INVALID_TYPE);
    }
}

void Server::handleAuthPart2Request(SOCKET clientSocket, const BinaryMessageHeader &header,
                                   const std::vector<uint8_t> &payload) {
    const char *clientIp = getClientAddress(clientSocket);
    logMessage("Processing auth part 2 request", clientIp);

    try {
        // Process auth part 2 payload directly as string
        if (payload.empty()) {
            throw std::runtime_error("Empty auth part 2 payload");
        }

        // Extract string payload from raw data
        std::string payloadStr(payload.begin(), payload.end());
        const char *stringPayload = payloadStr.c_str();

        char logPayloadBuffer[128];
        size_t payloadLength = payloadStr.length();
        if (payloadLength > 100) {
            SAFE_SPRINTF(logPayloadBuffer, "Received part 2 payload: %.*s...(truncated)", 100, stringPayload);
        } else {
            SAFE_SPRINTF(logPayloadBuffer, "Received part 2 payload: %s", stringPayload);
        }
        logMessage(logPayloadBuffer, clientIp);

        // Find auth controller
        auto controller = controllers.find("auth");
        if (controller == controllers.end()) {
            throw std::runtime_error("Auth controller not found");
        }

        const char *mapping = nullptr;

        // Check if payload contains AES encrypted data (delimited by "-|x")
        std::vector<const char *> parts = StringUtils::split(stringPayload, "-|x");
        std::cout << "Part size " << parts.size() << std::endl;


        if (parts.size() == 4) {
            // AES encrypted payload detected - decrypt it like in handleAuthRequest
            logMessage("AES encrypted payload detected for part 2", clientIp);
            
            char randomKeyBuffer[64] = {0};
            char timestampBuffer[64] = {0};
            char hwidBuffer[256] = {0};
            char detectedVersionKeyBuffer[32] = {0};
            
            // 1. Decrypt the random key (last part) with "loginpart2key"
            logMessage(parts[3], clientIp);
            const char *randomKeyProtected = parts[3];
            size_t decryptedKeyLen = 0;
            const char *randomKey = EncryptionUtils::aesDecrypt(randomKeyProtected, "loginpart2key", &decryptedKeyLen);
            
            if (!randomKey || decryptedKeyLen >= sizeof(randomKeyBuffer)) {
                throw std::runtime_error("Invalid random key size for part 2");
            }
            
            SAFE_MEMCPY(randomKeyBuffer, randomKey, decryptedKeyLen);
            randomKeyBuffer[decryptedKeyLen] = '\0';
            
            std::cout << "[Server] Decrypted random key for part 2: " << randomKeyBuffer << std::endl;
            
            // 2. Decrypt the timestamp with the random key

            logMessage(randomKeyBuffer, clientIp);

            const char *timestampProtected = parts[2];
            size_t timestampLen = 0;
            const char *timestamp = EncryptionUtils::aesDecrypt(timestampProtected, randomKeyBuffer, &timestampLen);
            
            if (!timestamp || timestampLen >= sizeof(timestampBuffer)) {
                throw std::runtime_error("Invalid timestamp size for part 2");
            }
            memcpy(timestampBuffer, timestamp, timestampLen);
            timestampBuffer[timestampLen] = '\0';
            
            // 3. Decrypt HWID and detectedVersionKey with the timestamp
            size_t hwidLen = 0, versionKeyLen = 0;
            const char *hwid = EncryptionUtils::aesDecrypt(parts[0], randomKeyBuffer, &hwidLen);
            logMessage(hwid, clientIp);
            const char *detectedVersionKey = EncryptionUtils::aesDecrypt(parts[1], randomKeyBuffer, &versionKeyLen);
            logMessage(detectedVersionKey, clientIp);
            
            if (!hwid || hwidLen >= sizeof(hwidBuffer) ||
                !detectedVersionKey || versionKeyLen >= sizeof(detectedVersionKeyBuffer)) {
                throw std::runtime_error("Invalid decrypted data size for part 2");
            }
            
            memcpy(hwidBuffer, hwid, hwidLen);
            memcpy(detectedVersionKeyBuffer, detectedVersionKey, versionKeyLen);
            hwidBuffer[hwidLen] = '\0';
            detectedVersionKeyBuffer[versionKeyLen] = '\0';
            
            logMessage("Decrypted values for part 2:", clientIp);
            char hwidLogBuffer[300], versionKeyLogBuffer[100];
            sprintf(hwidLogBuffer, "HWID: %s", hwidBuffer);
            sprintf(versionKeyLogBuffer, "DetectedVersionKey: %s", detectedVersionKeyBuffer);
            
            logMessage(hwidLogBuffer, clientIp);
            logMessage(versionKeyLogBuffer, clientIp);
            
            // Construct decrypted payload for AuthController
            char decryptedPayload[512];
            snprintf(decryptedPayload, sizeof(decryptedPayload), "%s:%s:%s:%s",
                     hwidBuffer, detectedVersionKeyBuffer, timestampBuffer, clientIp);
            
            // Call AuthController with decrypted payload
            std::cout << "[Server] About to call AuthController::handleAuthPart2 with decrypted payload: " << decryptedPayload << std::endl;
            AuthController* authController = static_cast<AuthController*>(controller->second.get());
            mapping = authController->handleAuthPart2(decryptedPayload, clientIp);
            std::cout << "[Server] AuthController::handleAuthPart2 returned, processing response..." << std::endl;
        } else {
            // Fallback for non-encrypted payloads
            logMessage("Non-encrypted payload detected for part 2, using fallback", clientIp);

            // Use AuthController::handleRequest for proper routing
            std::cout << "[Server] About to call AuthController::handleRequest with payload: " << std::string(stringPayload, 0, 100) << "..." << std::endl;
            AuthController* authController = static_cast<AuthController*>(controller->second.get());
            mapping = authController->handleRequest(stringPayload, clientIp);
            std::cout << "[Server] AuthController::handleRequest returned, processing response..." << std::endl;
        }
        
        // Calculate response size
        size_t mappingSize = 0;
        
        if (controller->first == "auth") {
            std::cout << "[DEBUG] Entering auth controller processing" << std::endl;
            std::cout << "[DEBUG] Mapping pointer: " << (void*)mapping << std::endl;
            // For auth controller part 2, determine response size from AuthPart2Response
            if (mapping != nullptr) {
                std::cout << "[DEBUG] Mapping is not null, proceeding with analysis" << std::endl;
                // DEBUG: Print first 16 bytes of mapping data
                std::cout << "[DEBUG] Mapping data first 16 bytes: ";
                for (size_t i = 0; i < 16; i++) {
                    printf("%02x ", (unsigned char)mapping[i]);
                }
                std::cout << std::endl;
                
                // DEBUG: Check structure size and alignment
                std::cout << "[DEBUG] AuthPart2Response structure size: " << sizeof(AuthPart2Response) << std::endl;
                std::cout << "[DEBUG] Expected messageSize offset GROD FDP: " << offsetof(AuthPart2Response, messageSize) << std::endl;
                
                // The response is created by BinaryProtocol::pack(), so we need to unpack it first
                std::cout << "[DEBUG] About to unpack AuthPart2Response from binary data" << std::endl;
                
                // Create a vector from the binary data for unpacking
                size_t responseHeaderSize = sizeof(AuthPart2Response);
                std::vector<uint8_t> responseData(mapping, mapping + responseHeaderSize);
                
                std::cout << "[DEBUG] Created vector of size: " << responseData.size() << std::endl;
                
                // Unpack the AuthPart2Response structure
                AuthPart2Response response = BinaryProtocol::unpack<AuthPart2Response>(responseData);
                uint32_t contentSize = response.messageSize;
                
                std::cout << "[DEBUG] Successfully unpacked and read messageSize: " << contentSize << std::endl;
                
                // DEBUG: Print structure fields
                std::cout << "[DEBUG] Response status: " << (int)response.status << std::endl;
                std::cout << "[DEBUG] Response username: " << std::string(response.username, std::min(10, 64)) << "..." << std::endl;
                std::cout << "[DEBUG] Response uuid: " << std::string(response.uuid, std::min(10, 37)) << "..." << std::endl;
                std::cout << "[DEBUG] Raw messageSize value: " << contentSize << std::endl;
                
                // Validate contentSize to prevent huge allocations
                if (contentSize > 10 * 1024 * 1024) { // 10MB limit
                    std::cout << "[ERROR] contentSize too large: " << contentSize << " bytes, setting to 0" << std::endl;
                    contentSize = 0;
                }
                
                mappingSize = sizeof(AuthPart2Response) + contentSize;
                
                std::cout << "[Server] Auth Part 2 response detected, contentSize: " << contentSize << std::endl;
                std::cout << "[Server] Total auth part 2 response size: " << mappingSize << std::endl;
            }
        } else {
            mappingSize = strlen(mapping);
        }
        
        char mappingLogBuffer[128];
        sprintf(mappingLogBuffer, "Controller part 2 response size: %zu", mappingSize);
        logMessage(mappingLogBuffer, clientIp);

        // Prepare final response
        std::vector<uint8_t> responseData;
        responseData.reserve(mappingSize);

        // Insert controller response data directly
        responseData.insert(responseData.end(),
                            reinterpret_cast<const uint8_t *>(mapping),
                            reinterpret_cast<const uint8_t *>(mapping) + mappingSize);

        std::cout << "[Server] Total part 2 response size: " << responseData.size() << std::endl;

        if (!serverSocket.sendBinaryMessage(clientSocket, MessageType::AUTH_PART2, responseData)) {
            throw std::runtime_error("Failed to send part 2 response");
        }

        logMessage("Part 2 response sent successfully", clientIp);
    } catch (const std::exception &e) {
        char errorBuffer[256];
        sprintf(errorBuffer, "Auth part 2 error: %s", e.what());
        logError(errorBuffer, clientIp);
        sendErrorResponse(clientSocket, ProtocolError::INVALID_TYPE);
    }
}

void Server::handlePlayerInfoRequest(SOCKET clientSocket, const BinaryMessageHeader &header,
                                     const std::vector<uint8_t> &payload) {
    const char *clientIp = getClientAddress(clientSocket);
    logMessage("Processing encrypted player info request", clientIp);

    try {
        // 1. Convert payload to string for AES decryption
        if (payload.empty()) {
            throw std::runtime_error("Empty player info payload");
        }

        std::string payloadStr(payload.begin(), payload.end());
        const char *encryptedPayload = payloadStr.c_str();

        char logBuffer[256];
        sprintf(logBuffer, "Encrypted player info payload: %.100s...", encryptedPayload);
        logMessage(logBuffer, clientIp);

        // Check if payload contains AES encrypted data (delimited by "-|x")
        std::vector<const char *> parts = StringUtils::split(encryptedPayload, "-|x");
        if (parts.size() == 5) {
            // AES encrypted payload detected - decrypt it
            logMessage("AES encrypted payload detected for player info", clientIp);
            
            char randomKeyBuffer[64] = {0};
            char timestampBuffer[64] = {0};
            char hwidBuffer[256] = {0};
            char usernameBuffer[128] = {0};
            char uuidBuffer[64] = {0};
            
            // 1. Decrypt the random key (last part) with "playerinfokey"
            const char *randomKeyProtected = parts[4];
            size_t decryptedKeyLen = 0;
            const char *randomKey = EncryptionUtils::aesDecrypt(randomKeyProtected, "playerinfokey", &decryptedKeyLen);
            
            if (!randomKey || decryptedKeyLen >= sizeof(randomKeyBuffer)) {
                throw std::runtime_error("Invalid random key size for player info");
            }
            
            SAFE_MEMCPY(randomKeyBuffer, randomKey, decryptedKeyLen);
            randomKeyBuffer[decryptedKeyLen] = '\0';
            
            std::cout << "[Server] Decrypted random key for player info: " << randomKeyBuffer << std::endl;
            
            // 2. Decrypt the timestamp with the random key
            const char *timestampProtected = parts[3];
            size_t timestampLen = 0;
            const char *timestamp = EncryptionUtils::aesDecrypt(timestampProtected, randomKeyBuffer, &timestampLen);
            
            if (!timestamp || timestampLen >= sizeof(timestampBuffer)) {
                throw std::runtime_error("Invalid timestamp size for player info");
            }
            memcpy(timestampBuffer, timestamp, timestampLen);
            timestampBuffer[timestampLen] = '\0';
            
            // 3. Decrypt HWID, username, and UUID with the timestamp
            size_t hwidLen = 0, usernameLen = 0, uuidLen = 0;
            const char *hwid = EncryptionUtils::aesDecrypt(parts[0], timestampBuffer, &hwidLen);
            const char *username = EncryptionUtils::aesDecrypt(parts[1], timestampBuffer, &usernameLen);
            const char *uuid = EncryptionUtils::aesDecrypt(parts[2], timestampBuffer, &uuidLen);
            
            if (!hwid || hwidLen >= sizeof(hwidBuffer) ||
                !username || usernameLen >= sizeof(usernameBuffer) ||
                !uuid || uuidLen >= sizeof(uuidBuffer)) {
                throw std::runtime_error("Invalid decrypted data size for player info");
            }
            
            memcpy(hwidBuffer, hwid, hwidLen);
            memcpy(usernameBuffer, username, usernameLen);
            memcpy(uuidBuffer, uuid, uuidLen);
            hwidBuffer[hwidLen] = '\0';
            usernameBuffer[usernameLen] = '\0';
            uuidBuffer[uuidLen] = '\0';
            
            logMessage("Decrypted values for player info:", clientIp);
            char hwidLogBuffer[300], usernameLogBuffer[150], uuidLogBuffer[100];
            sprintf(hwidLogBuffer, "HWID: %s", hwidBuffer);
            sprintf(usernameLogBuffer, "Username: %s", usernameBuffer);
            sprintf(uuidLogBuffer, "UUID: %s", uuidBuffer);
            
            logMessage(hwidLogBuffer, clientIp);
            logMessage(usernameLogBuffer, clientIp);
            logMessage(uuidLogBuffer, clientIp);
            
            // Construct decrypted payload for AuthController
            char decryptedPayload[512];
            snprintf(decryptedPayload, sizeof(decryptedPayload), "%s:%s:%s:%s:%s",
                     hwidBuffer, usernameBuffer, uuidBuffer, timestampBuffer, clientIp);
            
            // 2. Use AuthController to handle decrypted payload
            AuthController authController;
            const char* binaryResponse = authController.handlePlayerInfoRequest(decryptedPayload, clientIp);
            
            if (!binaryResponse) {
                throw std::runtime_error("Failed to process player info request");
            }

            // 3. The AuthController returns a binary response buffer
            // Get the actual size from the global function
            extern size_t getLastPlayerInfoResponseSize();
            size_t responseSize = getLastPlayerInfoResponseSize();
            
            if (responseSize == 0 || !binaryResponse) {
                throw std::runtime_error("Invalid response from auth controller");
            }
            
            // Create vector from the binary response with correct size
            const uint8_t* binaryPtr = reinterpret_cast<const uint8_t*>(binaryResponse);
            std::vector<uint8_t> responseData(binaryPtr, binaryPtr + responseSize);

            // 4. Send the response back to client
            if (!serverSocket.sendBinaryMessage(clientSocket, MessageType::PLAYER_INFO_RESPONSE, responseData)) {
                throw std::runtime_error("Failed to send player info response");
            }

            logMessage("Encrypted player info response sent successfully", clientIp);
        } else {
            // Fallback for non-encrypted payloads
            AuthController authController;
            const char* binaryResponse = authController.handlePlayerInfoRequest(encryptedPayload, clientIp);
            
            if (!binaryResponse) {
                throw std::runtime_error("Failed to process player info request");
            }

            extern size_t getLastPlayerInfoResponseSize();
            size_t responseSize = getLastPlayerInfoResponseSize();
            
            if (responseSize == 0 || !binaryResponse) {
                throw std::runtime_error("Invalid response from auth controller");
            }
            
            const uint8_t* binaryPtr = reinterpret_cast<const uint8_t*>(binaryResponse);
            std::vector<uint8_t> responseData(binaryPtr, binaryPtr + responseSize);

            if (!serverSocket.sendBinaryMessage(clientSocket, MessageType::PLAYER_INFO_RESPONSE, responseData)) {
                throw std::runtime_error("Failed to send player info response");
            }

            logMessage("Player info response sent successfully", clientIp);
        }

    } catch (const std::exception &e) {
        e.what();
        // Error handling
        char errorBuffer[256];
        sprintf(errorBuffer, "Player info request error: %s", e.what());
        logError(errorBuffer, clientIp);
        
        // Send error response
        PlayerInfoResponse errorResponse = {};
        errorResponse.status = AuthStatus::ERRORR;
        strcpy(errorResponse.username, "error");
        strcpy(errorResponse.uuid, "00000000-0000-0000-0000-000000000000");
        strcpy(errorResponse.sessionId, "error");
        errorResponse.dataSize = 0;
        
        std::vector<uint8_t> errorData = BinaryProtocol::pack(errorResponse);
        serverSocket.sendBinaryMessage(clientSocket, MessageType::PLAYER_INFO_RESPONSE, errorData);
    }
}

// Session validation removed - using direct controller authentication

void Server::cleanupProtectedCopies(char *timestamp, char *hwid, char *token, char *randomKey, char *username,
                                    char *uuid) {
    if (timestamp) delete[] timestamp;
    if (hwid) delete[] hwid;
    if (token) delete[] token;
    if (randomKey) delete[] randomKey;
    if (username) delete[] username;
    if (uuid) delete[] uuid;
}

void Server::handleErrorRequest(SOCKET clientSocket, const BinaryMessageHeader &header,
                                const std::vector<uint8_t> &payload) {
    const char *clientIp = getClientAddress(clientSocket);
    logMessage("Processing error request", clientIp);

    try {
        // V�rifier la taille minimale du payload
        if (payload.size() < sizeof(ErrorPayload)) {
            throw std::runtime_error("Invalid error payload size");
        }

        // Log du payload pour debug
        ErrorPayload *errorHeader = (ErrorPayload *) payload.data();
        char logBuffer[256];
        sprintf(logBuffer, "Error payload - Type: %d, Screenshot size: %u",
                errorHeader->errorType, errorHeader->screenshotSize);
        logMessage(logBuffer, clientIp);

        // V�rifier que la taille du payload est coh�rente avec la taille de capture d'�cran d�clar�e
        size_t expectedSize = sizeof(ErrorPayload) + errorHeader->screenshotSize;
        if (payload.size() < expectedSize) {
            sprintf(logBuffer, "Error payload too small - Expected: %zu, Got: %zu",
                    expectedSize, payload.size());
            logError(logBuffer, clientIp);
            throw std::runtime_error("Screenshot data incomplete");
        }

        // Utiliser le contr�leur d'erreur
        auto controller = controllers.find("error");
        if (controller == controllers.end()) {
            throw std::runtime_error("Error controller not found");
        }

        // Copier le payload complet pour le contr�leur
        char *payloadCopy = new char[payload.size()];
        memcpy(payloadCopy, payload.data(), payload.size());

        // Appeler le contr�leur avec l'adresse IP du client
        const char *response = controller->second->handleRequest(payloadCopy, clientIp);

        // Lib�rer la m�moire
        delete[] payloadCopy;

        // Envoyer la r�ponse
        std::vector<uint8_t> responseData(response, response + sizeof(ErrorResponse));
        if (!serverSocket.sendBinaryMessage(clientSocket, MessageType::ERRORR, responseData)) {
            throw std::runtime_error("Failed to send error response");
        }

        logMessage("Error response sent successfully", clientIp);
    } catch (const std::exception &e) {
        char errorBuffer[256];
        sprintf(errorBuffer, "Error processing error request: %s", e.what());
        logError(errorBuffer, clientIp);
        serverSocket.sendErrorResponse(clientSocket, ProtocolError::INVALID_TYPE);
    }
}

// Removed deprecated handleHeartbeatRequest and handleCloseClientRequest functions
// These functions handled deprecated MessageType values that no longer exist
