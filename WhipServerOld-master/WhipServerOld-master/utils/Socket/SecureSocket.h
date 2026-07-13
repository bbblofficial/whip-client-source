#pragma once
#include <winsock2.h>
#include <ws2tcpip.h>
#include <vector>
#include <iostream>
#include "../Protocol/protocol.h"

class ServerSecureSocket {
private:
    SOCKET serverSocket;
    bool isRunning;
    const int PORT;
    static constexpr size_t BUFFER_SIZE = 8192;

    char encryptionKey[64];

    bool receiveAll(SOCKET clientSocket, uint8_t* buffer, size_t length) {
        std::cout << "[ServerSocket] Starting to receive " << length << " bytes" << std::endl;
        size_t totalReceived = 0;

        while (totalReceived < length) {
            int received = recv(clientSocket,
                reinterpret_cast<char*>(buffer + totalReceived),
                length - totalReceived, 0);

            std::cout << "[ServerSocket] Received " << received << " bytes" << std::endl;

            if (received <= 0) {
                std::cout << "[ServerSocket] Receive error: " << WSAGetLastError()
                    << " after receiving " << totalReceived << "/" << length << " bytes" << std::endl;
                return false;
            }
            totalReceived += received;
            std::cout << "[ServerSocket] Total received: " << totalReceived << "/" << length << " bytes" << std::endl;
        }
        std::cout << "[ServerSocket] Completed receiving " << totalReceived << " bytes" << std::endl;
        return true;
    }

    bool sendAll(SOCKET clientSocket, const uint8_t* data, size_t length) {
        size_t totalSent = 0;
        while (totalSent < length) {
            int sent = send(clientSocket,
                reinterpret_cast<const char*>(data + totalSent),
                length - totalSent, 0);
            if (sent == SOCKET_ERROR) {
                std::cout << "[ServerSocket] Send error: " << WSAGetLastError() << "\n";
                return false;
            }
            totalSent += sent;
        }
        return true;
    }

public:
    ServerSecureSocket(int port = 1335, const char* key = "pg9g8N5DRxrgKJRQnhFi!eD6$d@hEi&4HahALiTF") :
        serverSocket(INVALID_SOCKET),
        isRunning(false),
        PORT(port) {
        strncpy(encryptionKey, key, sizeof(encryptionKey) - 1);
        encryptionKey[sizeof(encryptionKey) - 1] = '\0';
    }

    ~ServerSecureSocket() {
        stop();
    }

    bool start() {
        WSADATA wsaData;
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
            std::cout << "[ServerSocket] WSAStartup failed\n";
            return false;
        }

        serverSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (serverSocket == INVALID_SOCKET) {
            std::cout << "[ServerSocket] Failed to create socket\n";
            return false;
        }

        sockaddr_in serverAddr;
        serverAddr.sin_family = AF_INET;
        serverAddr.sin_port = htons(PORT);
        serverAddr.sin_addr.s_addr = INADDR_ANY;

        if (bind(serverSocket, reinterpret_cast<sockaddr*>(&serverAddr),
            sizeof(serverAddr)) == SOCKET_ERROR) {
            std::cout << "[ServerSocket] Bind failed\n";
            closesocket(serverSocket);
            return false;
        }

        if (listen(serverSocket, SOMAXCONN) == SOCKET_ERROR) {
            std::cout << "[ServerSocket] Listen failed\n";
            closesocket(serverSocket);
            return false;
        }

        isRunning = true;
        std::cout << "[ServerSocket] Server started on port " << PORT << "\n";
        return true;
    }

    SOCKET acceptClient() {
        if (!isRunning) return INVALID_SOCKET;

        sockaddr_in clientAddr;
        int clientAddrSize = sizeof(clientAddr);

        SOCKET clientSocket = accept(serverSocket,
            reinterpret_cast<sockaddr*>(&clientAddr),
            &clientAddrSize);

        if (clientSocket != INVALID_SOCKET) {
            char clientIP[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &clientAddr.sin_addr, clientIP, INET_ADDRSTRLEN);
            std::cout << "[ServerSocket] Client connected from " << clientIP << "\n";
        }

        return clientSocket;
    }

    bool receiveBinaryMessage(SOCKET clientSocket, BinaryMessageHeader& header, std::vector<uint8_t>& payload) {
        std::cout << "[ServerSocket] Starting to receive encrypted message..." << std::endl;

        try {
            // Read first 8 bytes (magic + size)
            uint8_t initialHeader[8];
            if (!receiveAll(clientSocket, initialHeader, sizeof(initialHeader))) {
                std::cout << "[ServerSocket] Failed to receive initial header" << std::endl;
                return false;
            }

            uint32_t magic = *reinterpret_cast<uint32_t*>(initialHeader);
            uint32_t totalSize = *reinterpret_cast<uint32_t*>(initialHeader + 4);
            std::cout << "[ServerSocket] Received header magic: 0x" << std::hex << magic
                << ", total size: " << std::dec << totalSize << std::endl;

            // Verify encrypted header signature
            if (magic != ENCRYPTED_HEADER_MAGIC) {
                std::cout << "[ServerSocket] Invalid encrypted header magic: 0x"
                    << std::hex << magic << std::dec << std::endl;
                return false;
            }

            // Verify size
            if (totalSize < sizeof(EncryptedHeader) || totalSize > 10 * 1024 * 1024) {
                std::cout << "[ServerSocket] Invalid encrypted message size: " << totalSize << std::endl;
                return false;
            }

            // Read the rest of the message
            std::vector<uint8_t> encryptedData(totalSize);
            memcpy(encryptedData.data(), initialHeader, sizeof(initialHeader));

            size_t remainingBytes = totalSize - sizeof(initialHeader);
            std::cout << "[ServerSocket] Reading remaining " << remainingBytes << " bytes..." << std::endl;

            if (!receiveAll(clientSocket, encryptedData.data() + sizeof(initialHeader), remainingBytes)) {
                std::cout << "[ServerSocket] Failed to receive encrypted data" << std::endl;
                return false;
            }

            std::cout << "[ServerSocket] Received complete encrypted data of size: "
                << encryptedData.size() << std::endl;

            // Decrypt using XOR and Base64
            if (!BinaryProtocol::decryptWithXorAndBase64(encryptedData, header, payload, encryptionKey)) {
                std::cout << "[ServerSocket] Failed to decrypt message" << std::endl;
                return false;
            }

            std::cout << "[ServerSocket] Message decrypted successfully" << std::endl;
            return true;
        }
        catch (const std::exception& e) {
            std::cout << "[ServerSocket] Exception during message reception: " << e.what() << std::endl;
            return false;
        }
    }

    bool sendBinaryMessage(SOCKET clientSocket, MessageType type, const std::vector<uint8_t>& payload) {
        try {
            // Create normal header
            auto header = BinaryProtocol::createHeader(type, payload.size());
            header.checksum = BinaryProtocol::calculateCRC32(payload.data(), payload.size());

            std::cout << "[ServerSocket] Sending message - Type: "
                << static_cast<int>(type) << ", Size: "
                << payload.size() << std::endl;

            // Encrypt using XOR and Base64
            std::vector<uint8_t> encryptedData =
                BinaryProtocol::encryptWithXorAndBase64(header, payload, encryptionKey);

            // Ensure minimum size for small messages
            if (encryptedData.size() < 64) {
                size_t paddingNeeded = 64 - encryptedData.size();
                encryptedData.resize(encryptedData.size() + paddingNeeded, 0);

                // Update total size in header
                EncryptedHeader* encHeader = reinterpret_cast<EncryptedHeader*>(encryptedData.data());
                encHeader->totalSize = static_cast<uint32_t>(encryptedData.size());

                std::cout << "[ServerSocket] Added " << paddingNeeded << " bytes of padding to ensure minimum message size" << std::endl;
            }

            std::cout << "[ServerSocket] Sending encrypted message - Type: "
                << static_cast<int>(type) << ", Original size: "
                << payload.size() << ", Encrypted size: "
                << encryptedData.size() << std::endl;

            // Send the encrypted data
            if (!sendAll(clientSocket, encryptedData.data(), encryptedData.size())) {
                std::cout << "[ServerSocket] Failed to send encrypted data" << std::endl;
                return false;
            }

            std::cout << "[ServerSocket] Encrypted message sent successfully" << std::endl;
            return true;
        }
        catch (const std::exception& e) {
            std::cout << "[ServerSocket] Exception during encryption: " << e.what() << std::endl;
            return false;
        }
    }

    void closeClient(SOCKET clientSocket) {
        if (clientSocket != INVALID_SOCKET) {
            closesocket(clientSocket);
        }
    }

    void stop() {
        isRunning = false;
        if (serverSocket != INVALID_SOCKET) {
            closesocket(serverSocket);
            serverSocket = INVALID_SOCKET;
        }
        WSACleanup();
    }

    bool getIsRunning() const {
        return isRunning;
    }

    bool sendErrorResponse(SOCKET clientSocket, ProtocolError error) {
        std::vector<uint8_t> errorPayload = BinaryProtocol::pack(error);
        return sendBinaryMessage(clientSocket, MessageType::ERRORR, errorPayload);
    }
};