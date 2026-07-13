#ifndef _PROTOCOL_H_
#define _PROTOCOL_H_

#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <memory>
#include <cstring>
#include <ctime>

#pragma pack(push, 1)

constexpr uint32_t PROTOCOL_MAGIC = 0x42505054;
constexpr uint16_t PROTOCOL_VERSION = 0x0001;
constexpr uint32_t MAX_PAYLOAD_SIZE = 2048 * 2048; 
constexpr uint32_t MAX_MAPPING_SIZE = 64 * 1024;
constexpr uint16_t HEADER_SIZE = 24;
constexpr uint32_t ENCRYPTED_HEADER_MAGIC = 0x58435354;

// Message types
enum class MessageType : uint16_t {
    AUTH_PART1 = 1,
    AUTH_PART2 = 2,
    PLAYER_INFO_REQUEST = 3,
    PLAYER_INFO_RESPONSE = 4,
    CONFIG_OPERATION = 6,
    CONFIG_RESPONSE = 7,
    ERRORR = 0xFFFF
};

// Error codes
enum class ProtocolError : uint16_t {
    NONE = 0,
    INVALID_MAGIC = 1,
    INVALID_VERSION = 2,
    INVALID_TYPE = 3,
    INVALID_SIZE = 4,
    INVALID_CHECKSUM = 5,
    INVALID_SESSION = 6,
    TIMESTAMP_OUT_OF_SYNC = 7
};

// Binary message header
struct BinaryMessageHeader {
    uint32_t magic;
    uint16_t version;
    uint16_t type;
    uint32_t timestamp;
    uint32_t payload_size;
    uint32_t mapping_size;
    uint32_t checksum;
};

struct EncryptedHeader {
    uint32_t magic;
    uint32_t totalSize;
    char encryptedData[];
};

// Auth structures
enum class AuthStatus : uint8_t {
    SUCCESS = 0,
    INVALID_HWID = 1,
    INVALID_VERSION = 2,
    INVALID_PRODUCT = 3,
    SESSION_EXPIRED = 4,
    ERRORR = 255
};

struct AuthPart1Payload {
    char hwid[512];
    uint8_t version;
    char product[32];
    uint32_t timestamp;
    uint8_t reserved[27];
    uint8_t checksum;
};

struct AuthPart2Payload {
    char hwid[512];
    char username[64];
    char uuid[37];
    uint32_t timestamp;
    uint8_t reserved[27];
    uint8_t checksum;
};

struct AuthPart1Response {
    AuthStatus status;
    char hwid[64];
    uint32_t messageSize;
    uint32_t versionsDataSize;  // Taille des données de versions
    uint8_t reserved[28];
};

struct AuthPart2Response {
    AuthStatus status;
    char username[64];
    char uuid[37];
    uint32_t messageSize;
    uint8_t reserved[32];
};

struct MessageData {
    AuthPart1Response base;
    std::vector<uint8_t> message;
};

struct PlayerInfoRequest {
    char hwid[512];
    char sessionToken[64];
    uint32_t timestamp;
    uint8_t reserved[32];
};

struct PlayerInfoResponse {
    AuthStatus status;
    char username[64];
    char uuid[37];
    char sessionId[64];
    uint32_t dataSize;
    uint8_t reserved[32];
};






struct PublicConfigInfo {
    char name[32];
    char description[128];
    char creator[32];
    char date[32];
    char share_code[16];
    int likes;
    int dislikes;
    int downloads;
};

// Type d'op�ration de configuration
enum class ConfigOperation : uint8_t {
    SAVE = 1,
    LOAD = 2,
    MODIFY = 3,
    LIST = 4,
    DELETEE = 5
};

// Structure pour les requ�tes de configuration
struct ConfigRequest {
    ConfigOperation operation;
    char configName[32];   // Nom de la configuration
    char hwid[64];         // HWID de l'utilisateur
    uint32_t dataSize;     // Taille des donn�es additionnelles
    uint8_t reserved[24];  // R�serv� pour extensions futures
};

// Structure pour les r�ponses de configuration
struct ConfigResponse {
    uint8_t status;        // 0 = succ�s, autres = codes d'erreur
    uint32_t dataSize;     // Taille des donn�es de r�ponse
    uint8_t reserved[27];  // R�serv� pour extensions futures
};

// Structure pour les m�tadonn�es de configuration
struct ConfigMetadata {
    char name[32];        // Nom de la configuration
    char description[128]; // Description
    uint32_t timestamp;   // Date de cr�ation/modification
    uint32_t size;        // Taille des donn�es
};

#pragma pack(pop)

// Forward declaration for Auth class
class Auth;

// Binary protocol implementation
class BinaryProtocol {
public:
    static uint32_t calculateCRC32(const uint8_t* data, size_t length);
    static BinaryMessageHeader createHeader(MessageType type, uint32_t payloadSize);
    static bool validateHeader(const BinaryMessageHeader& header);
    static uint8_t calculateAuthChecksum(const AuthPart1Payload& payload);
    static uint8_t calculateAuthChecksum(const AuthPart2Payload& payload);

    // M�thodes pour la gestion des en-t�tes chiffr�s
    static std::vector<uint8_t> encryptWithAes(
        const BinaryMessageHeader& header,
        const std::vector<uint8_t>& payload,
        const char* key);

    static bool decryptWithAes(
        const std::vector<uint8_t>& encryptedData,
        BinaryMessageHeader& outHeader,
        std::vector<uint8_t>& outPayload,
        const char* key);

    static std::vector<uint8_t> encryptWithXorAndBase64(
        const BinaryMessageHeader& header,
        const std::vector<uint8_t>& payload,
        const char* key);

    static bool decryptWithXorAndBase64(
        const std::vector<uint8_t>& encryptedData,
        BinaryMessageHeader& outHeader,
        std::vector<uint8_t>& outPayload,
        const char* key);

    template<typename T>
    static std::vector<uint8_t> pack(const T& data) {
        std::vector<uint8_t> buffer(sizeof(T));
        memcpy(buffer.data(), &data, sizeof(T));
        return buffer;
    }

    template<typename T>
    static T unpack(const std::vector<uint8_t>& buffer) {
        T data{};
        if (buffer.size() >= sizeof(T)) {
            memcpy(&data, buffer.data(), sizeof(T));
        }
        return data;
    }

private:
    static const uint32_t crc_table[256];  // D�claration seulement, pas d'initialisation

    // Fonctions adaptateurs qui utilisent Auth
    static const char* adaptAesEncrypt(const char* input, const char* key);
    static const char* adaptAesDecrypt(const char* input, const char* key);

    static const char* adaptXorString(const char* input, const char* key);
    static const char* adaptFromXorString(const char* input, const char* key);
};

#endif // _PROTOCOL_H_ 