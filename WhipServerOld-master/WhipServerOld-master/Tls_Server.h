#pragma once

#ifdef _WIN32
    #define _CRT_SECURE_NO_WARNINGS
    #define _WINSOCK_DEPRECATED_NO_WARNINGS
    #pragma comment(lib, "ws2_32.lib")
    #pragma comment(lib, "iphlpapi.lib")
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #include "utils/Socket/SecureSocket.h"
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <signal.h>
#include "utils/Socket/LinuxSecureSocket.h"
typedef int SOCKET;
#define INVALID_SOCKET -1
#endif

#include <string>
#include <memory>
#include <map>
#include <thread>
#include "controller/controller.h"
#include <iostream>
#include "utils/xchacha20/xchacha20.h"

#pragma pack(push, 1)
// Structures pour messages binaires internes si n�cessaire
#pragma pack(pop)

class Server {
private:
    static Server *instance;
    ServerSecureSocket serverSocket;
    std::map<std::string, std::unique_ptr<Controller> > controllers;
    bool isRunning;
    const int PORT;

    Server();

    void loadControllers();

    void handleClient(SOCKET clientSocket);

    void handleAuthRequest(SOCKET clientSocket, const BinaryMessageHeader &header, const std::vector<uint8_t> &payload);
    
    void handleAuthPart2Request(SOCKET clientSocket, const BinaryMessageHeader &header, const std::vector<uint8_t> &payload);
    
    void handlePlayerInfoRequest(SOCKET clientSocket, const BinaryMessageHeader &header, const std::vector<uint8_t> &payload);

    // Removed deprecated handleHeartbeatRequest and handleCloseClientRequest declarations

    void handleErrorRequest(SOCKET clientSocket, const BinaryMessageHeader &header,
                            const std::vector<uint8_t> &payload); // Nouveau handler
    void handleConfigRequest(SOCKET clientSocket, const BinaryMessageHeader &header,
                             const std::vector<uint8_t> &payload);

    // Utilitaires
    bool sendResponse(SOCKET clientSocket, MessageType type, const std::vector<uint8_t> &payload);

    bool sendErrorResponse(SOCKET clientSocket, ProtocolError error);

    const char *getClientAddress(SOCKET clientSocket);

    // Session validation removed - using direct controller authentication

    void cleanupProtectedCopies(char *timestamp, char *hwid, char *token, char *randomKey,
                                char *username, char *uuid);

#ifndef _WIN32
    static void signalHandler(int signum);
#endif

    // Log s�curis�
    void logMessage(const char *message, const char *clientIp) const {
        std::cout << "[Server] [" << clientIp << "] " << message << std::endl;
    }

    void log(const char *message) const {
        std::cout << "[Server] [" << message << "] " << std::endl;
    }

    void logError(const char *error, const char *clientIp) const {
        std::cerr << "[Server] [" << clientIp << "] ERROR: " << error << std::endl;
    }

    void sendDiscordWebhook(bool success,
                            const char *username,
                            const char *uuid,
                            const char *timestamp,
                            const char *hwid,
                            const char *session_id,
                            const char *pc_name,
                            const char *ip,
                            const char *minecraft_version,
                            const char *error_message = nullptr);

    const char *getMinecraftVersionString(uint8_t version);

public:
    static Server *getInstance();

    ~Server();

    void start();

    void stop();

    bool getIsRunning() const { return isRunning; }

    // Emp�cher la copie et l'assignation
    Server(const Server &) = delete;

    Server &operator=(const Server &) = delete;

    Server(Server &&) = delete;

    Server &operator=(Server &&) = delete;
};
