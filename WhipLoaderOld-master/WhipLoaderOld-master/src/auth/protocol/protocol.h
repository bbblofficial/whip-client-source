#ifndef _PROTOCOL_H_
#define _PROTOCOL_H_

#pragma once
#include <cstdint>

#ifdef Themida
#include "SecureEngineMacros.h"
#pragma optimize("", off)
#endif

constexpr uint32_t LOADER_PROTOCOL_MAGIC = 0x42505054;
constexpr uint32_t LOADER_ENCRYPTED_MAGIC = 0x57484950;
constexpr uint16_t PROTOCOL_VERSION = 0x0002;

enum class MessageType : uint16_t {
    LOADER_AUTH = 8,
    LOADER_AUTH_RESPONSE = 9,
    SECURITY_ALERT = 11
};

#pragma pack(push, 1)
struct BinaryMessageHeader {
    uint32_t magic;
    uint16_t version;
    uint16_t type;
    uint32_t timestamp;
    uint32_t payload_size;
    uint32_t mapping_size;
    uint32_t checksum;
};
#pragma pack(pop)

enum class AuthStatus : uint8_t {
    SUCCESS = 0,
    INVALID_HWID = 1,
    INVALID_VERSION = 2,
    INVALID_PRODUCT = 3,
    SESSION_EXPIRED = 4,
    ERRORR = 255
};

#pragma pack(push, 1)
struct LoaderAuthResponse {
    AuthStatus status;
    uint8_t padding[3];
    uint32_t messageSize;
};
#pragma pack(pop)

class BinaryProtocol {
public:
    static bool encryptWithChaCha20Poly1305(const uint8_t* data, size_t dataSize, const char* key, uint8_t** outData, size_t* outSize);
    static bool decryptWithChaCha20Poly1305(const uint8_t* encryptedData, size_t encryptedSize, const char* key, uint8_t** outData, size_t* outSize);

    static BinaryMessageHeader createLoaderHeader(MessageType type, uint32_t payloadSize);

    template<typename T>
    static void pack(const T& data, uint8_t* buffer) {
        memcpy(buffer, &data, sizeof(T));
    }

    template<typename T>
    static void unpack(const uint8_t* buffer, T& data) {
        memcpy(&data, buffer, sizeof(T));
    }

private:
    static const uint32_t crc_table[256];
};

#endif