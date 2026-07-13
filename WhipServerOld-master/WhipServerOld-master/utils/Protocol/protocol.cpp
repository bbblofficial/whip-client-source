#include "protocol.h"
#include <cstring>
#include <ctime>
#include <stdexcept>
#include <string>
#include "../native_crypto.h"
#include "../xchacha20/xchacha20.h"
#include <iostream>

const uint32_t BinaryProtocol::crc_table[256] = {
    0x00000000, 0x77073096, 0xEE0E612C, 0x990951BA, 0x076DC419, 0x706AF48F, 0xE963A535, 0x9E6495A3,
    0x0EDB8832, 0x79DCB8A4, 0xE0D5E91E, 0x97D2D988, 0x09B64C2B, 0x7EB17CBD, 0xE7B82D07, 0x90BF1D91,
    0x1DB71064, 0x6AB020F2, 0xF3B97148, 0x84BE41DE, 0x1ADAD47D, 0x6DDDE4EB, 0xF4D4B551, 0x83D385C7,
    0x136C9856, 0x646BA8C0, 0xFD62F97A, 0x8A65C9EC, 0x14015C4F, 0x63066CD9, 0xFA0F3D63, 0x8D080DF5,
    0x3B6E20C8, 0x4C69105E, 0xD56041E4, 0xA2677172, 0x3C03E4D1, 0x4B04D447, 0xD20D85FD, 0xA50AB56B,
    0x35B5A8FA, 0x42B2986C, 0xDBBBC9D6, 0xACBCF940, 0x32D86CE3, 0x45DF5C75, 0xDCD60DCF, 0xABD13D59,
    0x26D930AC, 0x51DE003A, 0xC8D75180, 0xBFD06116, 0x21B4F4B5, 0x56B3C423, 0xCFBA9599, 0xB8BDA50F,
    0x2802B89E, 0x5F058808, 0xC60CD9B2, 0xB10BE924, 0x2F6F7C87, 0x58684C11, 0xC1611DAB, 0xB6662D3D,
    0x76DC4190, 0x01DB7106, 0x98D220BC, 0xEFD5102A, 0x71B18589, 0x06B6B51F, 0x9FBFE4A5, 0xE8B8D433,
    0x7807C9A2, 0x0F00F934, 0x9609A88E, 0xE10E9818, 0x7F6A0DBB, 0x086D3D2D, 0x91646C97, 0xE6635C01,
    0x6B6B51F4, 0x1C6C6162, 0x856530D8, 0xF262004E, 0x6C0695ED, 0x1B01A57B, 0x8208F4C1, 0xF50FC457,
    0x65B0D9C6, 0x12B7E950, 0x8BBEB8EA, 0xFCB9887C, 0x62DD1DDF, 0x15DA2D49, 0x8CD37CF3, 0xFBD44C65,
    0x4DB26158, 0x3AB551CE, 0xA3BC0074, 0xD4BB30E2, 0x4ADFA541, 0x3DD895D7, 0xA4D1C46D, 0xD3D6F4FB,
    0x4369E96A, 0x346ED9FC, 0xAD678846, 0xDA60B8D0, 0x44042D73, 0x33031DE5, 0xAA0A4C5F, 0xDD0D7CC9,
    0x5005713C, 0x270241AA, 0xBE0B1010, 0xC90C2086, 0x5768B525, 0x206F85B3, 0xB966D409, 0xCE61E49F,
    0x5EDEF90E, 0x29D9C998, 0xB0D09822, 0xC7D7A8B4, 0x59B33D17, 0x2EB40D81, 0xB7BD5C3B, 0xC0BA6CAD,
    0xEDB88320, 0x9ABFB3B6, 0x03B6E20C, 0x74B1D29A, 0xEAD54739, 0x9DD277AF, 0x04DB2615, 0x73DC1683,
    0xE3630B12, 0x94643B84, 0x0D6D6A3E, 0x7A6A5AA8, 0xE40ECF0B, 0x93EBCF9D, 0x0A9E701D, 0x7D9EF58B,
    0xF00F9344, 0x8708A3D2, 0x1E01F268, 0x6906C2FE, 0xF762575D, 0x806567CB, 0x196C3671, 0x6E6B06E7,
    0xFED41B76, 0x89D32BE0, 0x10DA7A5A, 0x67DD4ACC, 0xF9B9DF6F, 0x8EBEEFF9, 0x17B7BE43, 0x60B08ED5,
    0xD6D6A3E8, 0xA1D1937E, 0x38D8C2C4, 0x4FDFF252, 0xD1BB67F1, 0xA6BC5767, 0x3FB506DD, 0x48B2364B,
    0xD80D2BDA, 0xAF0A1B4C, 0x36034AF6, 0x41047A60, 0xDF60EFC3, 0xA867DF55, 0x316E8EEF, 0x4669BE79,
    0xCB61B38C, 0xBC66831A, 0x256FD2A0, 0x5268E236, 0xCC0C7795, 0xBB0B4703, 0x220216B9, 0x5505262F,
    0xC5BA3BBE, 0xB2BD0B28, 0x2BB45A92, 0x5CB36A04, 0xC2D7FFA7, 0xB5D0CF31, 0x2CD99E8B, 0x5BDEAE1D,
    0x9B64C2B0, 0xEC63F226, 0x756AA39C, 0x026D930A, 0x9C0906A9, 0xEB0E363F, 0x72076785, 0x05005713,
    0x95BF4A82, 0xE2B87A14, 0x7BB12BAE, 0x0CB61B38, 0x92D28E9B, 0xE5D5BE0D, 0x7CDCEFB7, 0x0BDBDF21,
    0x86D3D2D4, 0xF1D4E242, 0x68DDB3F8, 0x1FDA836E, 0x81BE16CD, 0xF6B9265B, 0x6FB077E1, 0x18B74777,
    0x88085AE6, 0xFF0F6A70, 0x66063BCA, 0x11010B5C, 0x8F659EFF, 0xF862AE69, 0x616BFFD3, 0x166CCF45,
    0xA00AE278, 0xD70DD2EE, 0x4E048354, 0x3903B3C2, 0xA7672661, 0xD06016F7, 0x4969474D, 0x3E6E77DB,
    0xAED16A4A, 0xD9D65ADC, 0x40DF0B66, 0x37D83BF0, 0xA9BCAE53, 0xDEBB9EC5, 0x47B2CF7F, 0x30B5FFE9,
    0xBDBDF21C, 0xCABAC28A, 0x53B39330, 0x24B4A3A6, 0xBAD03605, 0xCDD70693, 0x54DE5729, 0x23D967BF,
    0xB3667A2E, 0xC4614AB8, 0x5D681B02, 0x2A6F2B94, 0xB40BBE37, 0xC30C8EA1, 0x5A05DF1B, 0x2D02EF8D
};

uint32_t BinaryProtocol::calculateCRC32(const uint8_t *data, size_t length) {
    uint32_t crc = 0xFFFFFFFF;

    for (size_t i = 0; i < length; i++) {
        crc = (crc >> 8) ^ crc_table[(crc & 0xFF) ^ data[i]];
    }

    return crc ^ 0xFFFFFFFF;
}

BinaryMessageHeader BinaryProtocol::createHeader(MessageType type, uint32_t payloadSize) {
    if (payloadSize > MAX_PAYLOAD_SIZE) {
        throw std::runtime_error("Payload size exceeds maximum allowed");
    }

    BinaryMessageHeader header{};
    header.magic = PROTOCOL_MAGIC;
    header.version = PROTOCOL_VERSION;
    header.type = static_cast<uint16_t>(type);
    header.timestamp = static_cast<uint32_t>(time(nullptr));
    header.payload_size = payloadSize;
    header.checksum = 0; // Sera calcul� apr�s pr�paration du payload

    return header;
}

bool BinaryProtocol::validateHeader(const BinaryMessageHeader &header) {
    // V�rifier la signature magique
    if (header.magic != PROTOCOL_MAGIC) {
        std::cerr << "[Protocol] Invalid magic: 0x" << std::hex << header.magic
                << " (expected 0x" << PROTOCOL_MAGIC << ")" << std::dec << std::endl;
        return false;
    }

    // V�rifier la version du protocole
    if (header.version != PROTOCOL_VERSION) {
        std::cerr << "[Protocol] Invalid version: " << header.version
                << " (expected " << PROTOCOL_VERSION << ")" << std::endl;
        return false;
    }

    // V�rifier la taille du payload
    if (header.payload_size > MAX_PAYLOAD_SIZE) {
        std::cerr << "[Protocol] Payload size exceeds maximum: " << header.payload_size
                << " > " << MAX_PAYLOAD_SIZE << std::endl;
        return false;
    }

    // V�rifier le timestamp (dans une fen�tre de 10 secondes)
    uint32_t currentTime = static_cast<uint32_t>(time(nullptr));
    if (abs(static_cast<int64_t>(currentTime) - header.timestamp) > 10) {
        std::cerr << "[Protocol] Timestamp out of sync: " << header.timestamp
                << " (current: " << currentTime << ")" << std::endl;
        return false;
    }

    // V�rifier le type de message
    switch (static_cast<MessageType>(header.type)) {
        case MessageType::AUTH_PART1:
        case MessageType::AUTH_PART2:
        case MessageType::PLAYER_INFO_REQUEST:
        case MessageType::PLAYER_INFO_RESPONSE:
        case MessageType::CONFIG_OPERATION:
        case MessageType::CONFIG_RESPONSE:
        case MessageType::ERRORR:
            break;
        default:
            std::cerr << "[Protocol] Invalid message type: " << header.type << std::endl;
            return false;
    }

    return true;
}

uint8_t BinaryProtocol::calculateAuthChecksum(const AuthPart1Payload &payload) {
    uint8_t checksum = 0;
    const uint8_t *data = reinterpret_cast<const uint8_t *>(&payload);
    size_t checksumOffset = offsetof(AuthPart1Payload, checksum);

    for (size_t i = 0; i < checksumOffset; i++) {
        checksum ^= data[i];
    }
    return checksum;
}

uint8_t BinaryProtocol::calculateAuthChecksum(const AuthPart2Payload &payload) {
    uint8_t checksum = 0;
    const uint8_t *data = reinterpret_cast<const uint8_t *>(&payload);
    size_t checksumOffset = offsetof(AuthPart2Payload, checksum);

    for (size_t i = 0; i < checksumOffset; i++) {
        checksum ^= data[i];
    }
    return checksum;
}

// Modification des adaptateurs dans BinaryProtocol
const char *BinaryProtocol::adaptAesEncrypt(const char *input, const char *key) {
    // ATTENTION: Cette fonction ne doit pas être utilisée pour des données binaires
    // Elle est maintenue pour compatibilité avec du code existant uniquement
    // Calculer la longueur manuellement pour éviter strnlen avec données binaires
    size_t input_len = 0;
    if (input) {
        for (size_t i = 0; i < MAX_PAYLOAD_SIZE && input[i] != '\0'; i++) {
            input_len++;
        }
    }
    return EncryptionUtils::aesEncrypt(input, input_len, key);
}

const char *BinaryProtocol::adaptAesDecrypt(const char *input, const char *key) {
    return EncryptionUtils::aesDecrypt(input, key);
}

const char *BinaryProtocol::adaptXorString(const char *input, const char *key) {
    size_t input_len = 0;
    for (input_len = 0; input[input_len] != '\0'; input_len++);
    return EncryptionUtils::encryptXor(input, input_len, key);
}

const char *BinaryProtocol::adaptFromXorString(const char *input, const char *key) {
    return EncryptionUtils::decryptXor(input, key);
}

std::vector<uint8_t> BinaryProtocol::encryptWithAes(
    const BinaryMessageHeader &header,
    const std::vector<uint8_t> &payload,
    const char *key) {
    try {
        std::cout << "[Protocol] encryptWithXorString: Starting encryption" << std::endl;
        std::cout << "[Protocol] Header size: " << sizeof(BinaryMessageHeader)
                << ", Payload size: " << payload.size() << std::endl;

        // 1. S�rialiser l'en-t�te et le payload ensemble
        std::vector<uint8_t> combined;
        combined.reserve(sizeof(BinaryMessageHeader) + payload.size());

        // Ajouter l'en-t�te
        const uint8_t *headerBytes = reinterpret_cast<const uint8_t *>(&header);
        combined.insert(combined.end(), headerBytes, headerBytes + sizeof(BinaryMessageHeader));

        // Ajouter le payload
        combined.insert(combined.end(), payload.begin(), payload.end());

        std::cout << "[Protocol] Combined data size: " << combined.size() << std::endl;

        // 2. Chiffrer avec xorString (passer la taille explicitement)
        const char *encryptedStr = EncryptionUtils::aesEncrypt(
            reinterpret_cast<const char *>(combined.data()),
            combined.size(),
            key);

        if (!encryptedStr) {
            throw std::runtime_error("Encryption failed - NULL result");
        }

        // Calculer la taille du r�sultat avec une limite de s�curit�
        size_t encryptedSize = 0;
        for (encryptedSize = 0; encryptedStr[encryptedSize] != '\0' && encryptedSize < 1000000; encryptedSize++);

        std::cout << "[Protocol] Encrypted string size: " << encryptedSize << std::endl;

        // V�rification de s�curit�
        if (encryptedSize < 10) {
            std::cout << "[Protocol] WARNING: Encrypted result too small, likely corrupted. First bytes: ";
            for (size_t i = 0; i < encryptedSize; i++) {
                printf("%02x ", (unsigned char) encryptedStr[i]);
            }
            std::cout << std::endl;
            throw std::runtime_error("Encrypted result too small, likely corrupted");
        }

        // 3. Calculer la taille totale du message chiffr�
        size_t headerSize = sizeof(EncryptedHeader);
        size_t totalSize = headerSize + encryptedSize;

        // 4. Construire le message final avec l'en-t�te
        std::vector<uint8_t> result(totalSize);
        EncryptedHeader *encrypted_header = reinterpret_cast<EncryptedHeader *>(result.data());
        encrypted_header->magic = ENCRYPTED_HEADER_MAGIC;
        encrypted_header->totalSize = static_cast<uint32_t>(totalSize);

        // 5. Copier les donn�es chiffr�es
        memcpy(encrypted_header->encryptedData, encryptedStr, encryptedSize);

        std::cout << "[Protocol] Final encrypted message size: " << result.size() << std::endl;
        return result;
    } catch (const std::exception &e) {
        std::cerr << "[Protocol] encryptWithXorString error: " << e.what() << std::endl;
        throw;
    }
}

bool BinaryProtocol::decryptWithAes(
    const std::vector<uint8_t> &encryptedData,
    BinaryMessageHeader &outHeader,
    std::vector<uint8_t> &outPayload,
    const char *key) {
    try {
        std::cout << "[Protocol] decryptWithXorString: Starting decryption" << std::endl;
        std::cout << "[Protocol] Encrypted data size: " << encryptedData.size() << std::endl;

        // 1. V�rifier la taille minimale
        if (encryptedData.size() < sizeof(EncryptedHeader)) {
            std::cerr << "[Protocol] Encrypted data too small" << std::endl;
            return false;
        }

        // 2. Extraire l'en-t�te chiffr�
        const EncryptedHeader *encrypted_header =
                reinterpret_cast<const EncryptedHeader *>(encryptedData.data());

        // 3. V�rifier la signature magique
        if (encrypted_header->magic != ENCRYPTED_HEADER_MAGIC) {
            std::cerr << "[Protocol] Invalid encrypted header magic" << std::endl;
            return false;
        }

        // 4. Extraire la partie chiffr�e
        size_t encryptedPartSize = encryptedData.size() - sizeof(EncryptedHeader);
        std::cout << "[Protocol] Encrypted part size: " << encryptedPartSize << std::endl;

        // Copier les donn�es chiffr�es en incluant un octet nul � la fin
        char *encryptedPart = new char[encryptedPartSize + 1];
        memcpy(encryptedPart, encrypted_header->encryptedData, encryptedPartSize);
        encryptedPart[encryptedPartSize] = '\0'; // N�cessaire pour base64

        // 5. D�chiffrer avec taille explicite
        size_t decryptedSize = 0;
        const char *decryptedData = nullptr;

        try {
            decryptedData = EncryptionUtils::aesDecrypt(encryptedPart, key, &decryptedSize);
            delete[] encryptedPart;

            if (!decryptedData || decryptedSize < sizeof(BinaryMessageHeader)) {
                std::cerr << "[Protocol] Decryption failed or invalid size" << std::endl;
                return false;
            }

            // 6. Extraire l'en-t�te du protocole
            memcpy(&outHeader, decryptedData, sizeof(BinaryMessageHeader));

            // Log de l'en-t�te pour le d�bogage
            std::cout << "[Protocol] Decrypted header magic: 0x" << std::hex << outHeader.magic << std::dec <<
                    std::endl;

            // V�rifier si c'est un magic number valide
            if (outHeader.magic == PROTOCOL_MAGIC) {
                // Extraire le payload
                size_t payloadSize = outHeader.payload_size;
                if (payloadSize > 0 && sizeof(BinaryMessageHeader) + payloadSize <= decryptedSize) {
                    outPayload.resize(payloadSize);
                    memcpy(outPayload.data(),
                           decryptedData + sizeof(BinaryMessageHeader),
                           payloadSize);
                    std::cout << "[Protocol] Extracted payload of size: " << payloadSize << " bytes" << std::endl;
                } else {
                    outPayload.clear();
                    std::cout << "[Protocol] No payload data or invalid size" << std::endl;
                }

                return true;
            }

            // Si le magic number n'est pas valide, cr�er un en-t�te artificiel
            std::cout << "[Protocol] Invalid magic number, creating artificial header" << std::endl;

            // Cr�er un header artificiel pour AUTH
            outHeader.magic = PROTOCOL_MAGIC;
            outHeader.version = PROTOCOL_VERSION;
            outHeader.type = static_cast<uint16_t>(MessageType::AUTH_PART1);
            outHeader.timestamp = static_cast<uint32_t>(time(nullptr));
            outHeader.payload_size = decryptedSize;
            outHeader.checksum = 0;

            // Copier toutes les donn�es d�chiffr�es comme payload
            outPayload.resize(decryptedSize);
            memcpy(outPayload.data(), decryptedData, decryptedSize);

            std::cout << "[Protocol] Created artificial header for AUTH" << std::endl;
            return true;
        } catch (const std::exception &e) {
            delete[] encryptedPart;
            std::cerr << "[Protocol] fromXorString error: " << e.what() << std::endl;
            return false;
        }
    } catch (const std::exception &e) {
        std::cerr << "[Protocol] decryptWithXorString error: " << e.what() << std::endl;
        return false;
    }
}

std::vector<uint8_t> BinaryProtocol::encryptWithXorAndBase64(
    const BinaryMessageHeader &header,
    const std::vector<uint8_t> &payload,
    const char *key) {
    try {
        std::cout << "[Protocol] encryptWithXorAndXChaCha20: Starting encryption" << std::endl;
        std::cout << "[Protocol] Header size: " << sizeof(BinaryMessageHeader)
                << ", Payload size: " << payload.size() << std::endl;

        // 1. Serialize header and payload together
        std::vector<uint8_t> combined;
        combined.reserve(sizeof(BinaryMessageHeader) + payload.size());

        // Add header
        const uint8_t *headerBytes = reinterpret_cast<const uint8_t *>(&header);
        combined.insert(combined.end(), headerBytes, headerBytes + sizeof(BinaryMessageHeader));

        // Add payload
        combined.insert(combined.end(), payload.begin(), payload.end());

        std::cout << "[Protocol] Combined data size: " << combined.size() << std::endl;

        size_t keyLen = 0;
        for (keyLen = 0; key[keyLen] != '\0'; keyLen++);

        std::vector<uint8_t> xorEncrypted(combined.size());
        for (size_t i = 0; i < combined.size(); i++) {
            xorEncrypted[i] = combined[i] ^ key[i % keyLen] ^ ((i * 13) & 0xFF);
        }

        const char *xchachaResult = XChaCha20::encrypt(
            reinterpret_cast<const char *>(xorEncrypted.data()),
            xorEncrypted.size(),
            key);

        if (!xchachaResult) {
            throw std::runtime_error("XChaCha20 encryption failed - NULL result");
        }

        // Get the hex string length
        size_t encodedSize = strlen(xchachaResult);
        std::cout << "[Protocol] XChaCha20 encrypted size: " << encodedSize << std::endl;

        // 4. Create the final message with encrypted header
        size_t headerSize = sizeof(EncryptedHeader);
        size_t totalSize = headerSize + encodedSize;

        std::vector<uint8_t> result(totalSize);
        EncryptedHeader *encrypted_header = reinterpret_cast<EncryptedHeader *>(result.data());
        encrypted_header->magic = ENCRYPTED_HEADER_MAGIC;
        encrypted_header->totalSize = static_cast<uint32_t>(totalSize);

        // 5. Copy the encrypted data
        memcpy(encrypted_header->encryptedData, xchachaResult, encodedSize);

        std::cout << "[Protocol] Final encrypted message size: " << result.size() << std::endl;
        return result;
    } catch (const std::exception &e) {
        std::cerr << "[Protocol] encryptWithXorAndBase64 error: " << e.what() << std::endl;
        throw;
    }
}

bool BinaryProtocol::decryptWithXorAndBase64(
    const std::vector<uint8_t> &encryptedData,
    BinaryMessageHeader &outHeader,
    std::vector<uint8_t> &outPayload,
    const char *key) {
    try {
        std::cout << "[Protocol] decryptWithXorAndXChaCha20: Starting decryption" << std::endl;
        std::cout << "[Protocol] Encrypted data size: " << encryptedData.size() << std::endl;

        // 1. Check minimum size
        if (encryptedData.size() < sizeof(EncryptedHeader)) {
            std::cerr << "[Protocol] Encrypted data too small" << std::endl;
            return false;
        }

        // 2. Extract encrypted header
        const EncryptedHeader *encrypted_header =
                reinterpret_cast<const EncryptedHeader *>(encryptedData.data());

        // 3. Verify magic number
        if (encrypted_header->magic != ENCRYPTED_HEADER_MAGIC) {
            std::cerr << "[Protocol] Invalid encrypted header magic" << std::endl;
            return false;
        }

        // 4. Extract the encrypted part
        size_t encryptedPartSize = encryptedData.size() - sizeof(EncryptedHeader);
        std::cout << "[Protocol] Encrypted part size: " << encryptedPartSize << std::endl;

        // Copy encrypted data
        char *xchachaData = new char[encryptedPartSize];
        memcpy(xchachaData, encrypted_header->encryptedData, encryptedPartSize);

        // 5. Decrypt with XChaCha20
        // XChaCha20 expects hex string input (data is already in hex format)
        std::string hexInput(xchachaData, encryptedPartSize);
        
        std::cout << "[Protocol] XChaCha20 hex input size: " << hexInput.size() << std::endl;
        std::cout << "[Protocol] XChaCha20 hex input (first 32 chars): " << hexInput.substr(0, 32) << std::endl;

        size_t decodedSize = 0;
        const char *decodedData = XChaCha20::decrypt(hexInput.c_str(), key, &decodedSize);

        delete[] xchachaData;

        if (!decodedData || decodedSize == 0) {
            std::cerr << "[Protocol] XChaCha20 decryption failed" << std::endl;
            return false;
        }

        std::cout << "[Protocol] Decoded size: " << decodedSize << std::endl;

        // 6. Decrypt with XOR
        size_t keyLen = 0;
        for (keyLen = 0; key[keyLen] != '\0'; keyLen++);

        std::vector<uint8_t> xorDecrypted(decodedSize);
        for (size_t i = 0; i < decodedSize; i++) {
            xorDecrypted[i] = decodedData[i] ^ key[i % keyLen] ^ ((i * 13) & 0xFF);
        }

        // 7. Extract binary message header
        if (xorDecrypted.size() < sizeof(BinaryMessageHeader)) {
            std::cerr << "[Protocol] Decrypted data too small for header" << std::endl;
            return false;
        }

        memcpy(&outHeader, xorDecrypted.data(), sizeof(BinaryMessageHeader));

        // 8. Verify protocol magic
        if (outHeader.magic != PROTOCOL_MAGIC) {
            std::cerr << "[Protocol] Invalid protocol magic in decrypted header: 0x"
                    << std::hex << outHeader.magic << std::dec << std::endl;
            return false;
        }

        // 9. Extract payload
        if (outHeader.payload_size > 0) {
            size_t headerSize = sizeof(BinaryMessageHeader);
            if (headerSize + outHeader.payload_size <= xorDecrypted.size()) {
                outPayload.resize(outHeader.payload_size);
                memcpy(outPayload.data(),
                       xorDecrypted.data() + headerSize,
                       outHeader.payload_size);
                std::cout << "[Protocol] Extracted payload of size: " << outHeader.payload_size << " bytes" <<
                        std::endl;
            } else {
                std::cerr << "[Protocol] Invalid payload size" << std::endl;
                return false;
            }
        } else {
            outPayload.clear();
        }

        return true;
    } catch (const std::exception &e) {
        std::cerr << "[Protocol] Error: " << e.what() << std::endl;
        return false;
    }
}
