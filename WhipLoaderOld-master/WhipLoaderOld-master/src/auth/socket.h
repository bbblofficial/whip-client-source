#pragma once
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <chrono>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <string.h>
#include <cstdint>
#include <iostream>
#include <thread>
#include <ctime>
#include <iomanip>

#include "protocol/protocol.h"

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

#ifdef Themida
#include "SecureEngineMacros.h"
#pragma optimize("", off)
#endif

class SecureSocket {
private:
    SOCKET sock;
    bool connected;
    bool initialized;
    WSADATA wsaData;
    char encryptionKey[64];

public:
    SecureSocket(const char* key = "6!NYRYP$xcJ7gYTLnMn4g?eLY7fX&tqyyQG@j9sf")
        : sock(INVALID_SOCKET), connected(false), initialized(false) {
        strncpy(encryptionKey, key, sizeof(encryptionKey) - 1);
        encryptionKey[sizeof(encryptionKey) - 1] = '\0';
    }

    ~SecureSocket() {
        cleanup();
    }

    bool sendAll(const uint8_t* data, size_t length) {
        size_t totalSent = 0;

        while (totalSent < length) {
            int sent = send(sock, reinterpret_cast<const char*>(data + totalSent),
                            length - totalSent, 0);
            if (sent == SOCKET_ERROR) {
                return false;
            }
            totalSent += sent;
        }

        return true;
    }

    bool receiveAll(uint8_t* buffer, size_t length) {
        size_t totalReceived = 0;

        while (totalReceived < length) {
            int received = recv(sock, reinterpret_cast<char*>(buffer + totalReceived),
                                length - totalReceived, 0);

            if (received <= 0) {
                return false;
            }

            totalReceived += received;
        }

        return totalReceived == length;
    }

    bool connect(const char* host, int port) {
#ifdef Themida
        VM_EAGLE_BLACK_START
#endif

        if (!initialized) {
            if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
                return false;
            }
            initialized = true;
        }

        sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sock == INVALID_SOCKET) {
            return false;
        }

        sockaddr_in serverAddr{};
        serverAddr.sin_family = AF_INET;
        serverAddr.sin_port = htons(port);
        serverAddr.sin_addr.s_addr = inet_addr(host);

        if (::connect(sock, reinterpret_cast<sockaddr*>(&serverAddr),
                      sizeof(serverAddr)) == SOCKET_ERROR) {
            closesocket(sock);
            sock = INVALID_SOCKET;
            return false;
        }

        connected = true;
        return true;
#ifdef Themida
        VM_EAGLE_BLACK_END
#endif
    }

    bool sendMessage(MessageType type, const uint8_t* payload, size_t payloadSize) {
#ifdef Themida
        VM_TIGER_RED_START
#endif

        if (!connected) {
            return false;
        }

        try {
            return sendLoaderMessage(type, payload, payloadSize);
        } catch (const std::exception& e) {
            return false;
        }

#ifdef Themida
        VM_TIGER_RED_END
#endif
    }

    bool sendLoaderMessage(MessageType type, const uint8_t* payload, size_t payloadSize) {
#ifdef Themida
        VM_LION_WHITE_START
#endif

        try {
            BinaryMessageHeader header = BinaryProtocol::createLoaderHeader(
                type,
                static_cast<uint32_t>(payloadSize)
            );

            size_t completeMessageSize = sizeof(BinaryMessageHeader) + payloadSize;
            uint8_t* completeMessage = new uint8_t[completeMessageSize];

            memcpy(completeMessage, &header, sizeof(BinaryMessageHeader));
            memcpy(completeMessage + sizeof(BinaryMessageHeader), payload, payloadSize);

#ifdef Themida
        VM_LION_WHITE_END
#endif

#ifdef Themida
        VM_EAGLE_RED_START
#endif

            uint8_t* encryptedPayload = nullptr;
            size_t encryptedSize = 0;

            if (!BinaryProtocol::encryptWithChaCha20Poly1305(
                completeMessage, completeMessageSize,
                encryptionKey,
                &encryptedPayload, &encryptedSize)) {
                delete[] completeMessage;
                return false;
            }

            delete[] completeMessage;

            if (!encryptedPayload || encryptedSize == 0) {
                if (encryptedPayload) delete[] encryptedPayload;
                return false;
            }

#ifdef Themida
        VM_EAGLE_RED_END
#endif

#ifdef Themida
        VM_SHARK_BLACK_START
#endif

            uint32_t totalSize = 8 + static_cast<uint32_t>(encryptedSize);
            uint8_t* loaderData = new uint8_t[totalSize];

            memcpy(loaderData, &totalSize, 4);
            uint32_t magic = LOADER_ENCRYPTED_MAGIC;
            memcpy(loaderData + 4, &magic, 4);
            memcpy(loaderData + 8, encryptedPayload, encryptedSize);

            delete[] encryptedPayload;

#ifdef Themida
        VM_SHARK_BLACK_END
#endif

#ifdef Themida
        VM_DOLPHIN_WHITE_START
#endif

            bool sendResult = sendAll(loaderData, totalSize);
            delete[] loaderData;

            if (!sendResult) {
                return false;
            }

#ifdef Themida
        VM_DOLPHIN_WHITE_END
#endif

            return true;
        }
        catch (const std::exception& e) {
            return false;
        }
    }

    bool receiveMessage(BinaryMessageHeader& header, uint8_t** payload, size_t* payloadSize) {
#ifdef Themida
        VM_DOLPHIN_RED_START
#endif

        try {
            uint8_t initialHeader[8];
            if (!receiveAll(initialHeader, sizeof(initialHeader))) {
                return false;
            }

            uint32_t magic = *reinterpret_cast<uint32_t*>(initialHeader);
            uint32_t totalSize = *reinterpret_cast<uint32_t*>(initialHeader + 4);

            if (magic == LOADER_ENCRYPTED_MAGIC) {
                return receiveLoaderMessage(header, payload, payloadSize, initialHeader, totalSize);
            }
            else {
                return false;
            }
        } catch (const std::exception& e) {
            return false;
        }

#ifdef Themida
        VM_DOLPHIN_RED_END
#endif
    }

    bool receiveLoaderMessage(BinaryMessageHeader& header, uint8_t** payload, size_t* payloadSize,
                     const uint8_t* initialHeader, uint32_t totalSize) {
#ifdef Themida
        VM_TIGER_BLACK_START
#endif

        try {
            uint32_t magic = *reinterpret_cast<const uint32_t*>(initialHeader);
            uint32_t size = *reinterpret_cast<const uint32_t*>(initialHeader + 4);

            if (magic != LOADER_ENCRYPTED_MAGIC) {
                return false;
            }

            if (size < 8 || size > 100 * 1024 * 1024) {
                return false;
            }

#ifdef Themida
        VM_TIGER_BLACK_END
#endif

#ifdef Themida
        VM_LION_RED_START
#endif

            uint8_t* loaderData = new uint8_t[size];
            memcpy(loaderData, initialHeader, 8);

            size_t remainingBytes = size - 8;

            if (!receiveAll(loaderData + 8, remainingBytes)) {
                delete[] loaderData;
                return false;
            }

            bool result = decryptLoaderResponse(loaderData, size, header, payload, payloadSize);
            delete[] loaderData;
            return result;
        }
        catch (const std::exception& e) {
            return false;
        }

#ifdef Themida
        VM_LION_RED_END
#endif
    }

    bool decryptLoaderResponse(const uint8_t* loaderData, size_t loaderDataSize,
                              BinaryMessageHeader& header, uint8_t** payload, size_t* payloadSize) {
#ifdef Themida
        VM_EAGLE_WHITE_START
#endif

        if (loaderDataSize < 8) {
            return false;
        }

        const uint8_t* encryptedPayload = loaderData + 8;
        size_t encryptedSize = loaderDataSize - 8;

#ifdef Themida
        VM_EAGLE_WHITE_END
#endif

        uint8_t* decryptedPayload = nullptr;
        size_t decryptedSize = 0;

        if (!BinaryProtocol::decryptWithChaCha20Poly1305(
            encryptedPayload, encryptedSize,
            encryptionKey,
            &decryptedPayload, &decryptedSize)) {
            return false;
        }

#ifdef Themida
        VM_SHARK_RED_START
#endif

        if (!decryptedPayload || decryptedSize == 0) {
            if (decryptedPayload) delete[] decryptedPayload;
            return false;
        }

        header = BinaryProtocol::createLoaderHeader(
            MessageType::LOADER_AUTH_RESPONSE,
            static_cast<uint32_t>(decryptedSize)
        );

        *payload = decryptedPayload;
        *payloadSize = decryptedSize;

        return true;

#ifdef Themida
        VM_SHARK_RED_END
#endif
    }

    bool isConnected() const {
        return connected;
    }

    void disconnect() {
#ifdef Themida
        VM_MUTATE_ONLY_START
#endif
        if (sock != INVALID_SOCKET) {
            closesocket(sock);
            sock = INVALID_SOCKET;
        }
        connected = false;
#ifdef Themida
        VM_MUTATE_ONLY_END
#endif
    }

    void cleanup() {
#ifdef Themida
        VM_TIGER_WHITE_START
#endif
        disconnect();
        if (initialized) {
            WSACleanup();
            initialized = false;
        }
#ifdef Themida
        VM_TIGER_WHITE_END
#endif
    }
};