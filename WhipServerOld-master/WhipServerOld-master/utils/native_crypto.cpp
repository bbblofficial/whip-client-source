#include "native_crypto.h"
#include <iostream>
#include <algorithm>
#include <random>

#include "aes.h"

// Tables AES S-box
const uint8_t NativeCrypto::sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

const uint8_t NativeCrypto::inv_sbox[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

const uint32_t NativeCrypto::rcon[11] = {
    0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};

const std::string NativeCrypto::base64Chars = 
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789+/";

const std::vector<unsigned char> NativeCrypto::FIXED_SALT = {
    0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef
};

uint8_t NativeCrypto::gmul(uint8_t a, uint8_t b) {
    uint8_t p = 0;
    for (int i = 0; i < 8; i++) {
        if (b & 1) p ^= a;
        bool hi_bit = a & 0x80;
        a <<= 1;
        if (hi_bit) a ^= 0x1b;
        b >>= 1;
    }
    return p;
}

void NativeCrypto::keyExpansion(const uint8_t* key, uint32_t* roundKeys) {
    for (int i = 0; i < 8; i++) {
        roundKeys[i] = ((uint32_t)key[4*i] << 24) |
                       ((uint32_t)key[4*i+1] << 16) |
                       ((uint32_t)key[4*i+2] << 8) |
                       ((uint32_t)key[4*i+3]);
    }

    for (int i = 8; i < 60; i++) {
        uint32_t temp = roundKeys[i-1];
        if (i % 8 == 0) {
            temp = ((uint32_t)sbox[(temp >> 16) & 0xff] << 24) |
                   ((uint32_t)sbox[(temp >> 8) & 0xff] << 16) |
                   ((uint32_t)sbox[temp & 0xff] << 8) |
                   ((uint32_t)sbox[(temp >> 24) & 0xff]);
            temp ^= rcon[i/8];
        } else if (i % 8 == 4) {
            temp = ((uint32_t)sbox[(temp >> 24) & 0xff] << 24) |
                   ((uint32_t)sbox[(temp >> 16) & 0xff] << 16) |
                   ((uint32_t)sbox[(temp >> 8) & 0xff] << 8) |
                   ((uint32_t)sbox[temp & 0xff]);
        }
        roundKeys[i] = roundKeys[i-8] ^ temp;
    }
}

void NativeCrypto::addRoundKey(uint8_t* state, const uint32_t* roundKey) {
    for (int i = 0; i < 4; i++) {
        uint32_t k = roundKey[i];
        state[4*i] ^= (k >> 24) & 0xff;
        state[4*i+1] ^= (k >> 16) & 0xff;
        state[4*i+2] ^= (k >> 8) & 0xff;
        state[4*i+3] ^= k & 0xff;
    }
}

void NativeCrypto::subBytes(uint8_t* state) {
    for (int i = 0; i < 16; i++) {
        state[i] = sbox[state[i]];
    }
}

void NativeCrypto::invSubBytes(uint8_t* state) {
    for (int i = 0; i < 16; i++) {
        state[i] = inv_sbox[state[i]];
    }
}

void NativeCrypto::shiftRows(uint8_t* state) {
    uint8_t temp;
    // Row 1
    temp = state[1]; state[1] = state[5]; state[5] = state[9]; state[9] = state[13]; state[13] = temp;
    // Row 2
    temp = state[2]; state[2] = state[10]; state[10] = temp;
    temp = state[6]; state[6] = state[14]; state[14] = temp;
    // Row 3
    temp = state[3]; state[3] = state[15]; state[15] = state[11]; state[11] = state[7]; state[7] = temp;
}

void NativeCrypto::invShiftRows(uint8_t* state) {
    uint8_t temp;
    // Row 1
    temp = state[13]; state[13] = state[9]; state[9] = state[5]; state[5] = state[1]; state[1] = temp;
    // Row 2
    temp = state[2]; state[2] = state[10]; state[10] = temp;
    temp = state[6]; state[6] = state[14]; state[14] = temp;
    // Row 3
    temp = state[7]; state[7] = state[11]; state[11] = state[15]; state[15] = state[3]; state[3] = temp;
}

void NativeCrypto::mixColumns(uint8_t* state) {
    for (int i = 0; i < 4; i++) {
        uint8_t a = state[4*i], b = state[4*i+1], c = state[4*i+2], d = state[4*i+3];
        state[4*i] = gmul(a, 2) ^ gmul(b, 3) ^ c ^ d;
        state[4*i+1] = a ^ gmul(b, 2) ^ gmul(c, 3) ^ d;
        state[4*i+2] = a ^ b ^ gmul(c, 2) ^ gmul(d, 3);
        state[4*i+3] = gmul(a, 3) ^ b ^ c ^ gmul(d, 2);
    }
}

void NativeCrypto::invMixColumns(uint8_t* state) {
    for (int i = 0; i < 4; i++) {
        uint8_t a = state[4*i], b = state[4*i+1], c = state[4*i+2], d = state[4*i+3];
        state[4*i] = gmul(a, 14) ^ gmul(b, 11) ^ gmul(c, 13) ^ gmul(d, 9);
        state[4*i+1] = gmul(a, 9) ^ gmul(b, 14) ^ gmul(c, 11) ^ gmul(d, 13);
        state[4*i+2] = gmul(a, 13) ^ gmul(b, 9) ^ gmul(c, 14) ^ gmul(d, 11);
        state[4*i+3] = gmul(a, 11) ^ gmul(b, 13) ^ gmul(c, 9) ^ gmul(d, 14);
    }
}

void NativeCrypto::aesEncryptBlock(const uint8_t* input, uint8_t* output, const uint32_t* roundKeys) {
    memcpy(output, input, 16);
    
    addRoundKey(output, &roundKeys[0]);
    
    for (int round = 1; round < 14; round++) {
        subBytes(output);
        shiftRows(output);
        mixColumns(output);
        addRoundKey(output, &roundKeys[4*round]);
    }
    
    subBytes(output);
    shiftRows(output);
    addRoundKey(output, &roundKeys[56]);
}

void NativeCrypto::aesDecryptBlock(const uint8_t* input, uint8_t* output, const uint32_t* roundKeys) {
    memcpy(output, input, 16);
    
    addRoundKey(output, &roundKeys[56]);
    
    for (int round = 13; round > 0; round--) {
        invShiftRows(output);
        invSubBytes(output);
        addRoundKey(output, &roundKeys[4*round]);
        invMixColumns(output);
    }
    
    invShiftRows(output);
    invSubBytes(output);
    addRoundKey(output, &roundKeys[0]);
}

void NativeCrypto::pkcs7Pad(std::vector<uint8_t>& data, size_t blockSize) {
    size_t padding = blockSize - (data.size() % blockSize);
    for (size_t i = 0; i < padding; i++) {
        data.push_back(static_cast<uint8_t>(padding));
    }
}

bool NativeCrypto::pkcs7Unpad(std::vector<uint8_t>& data) {
    if (data.empty()) return false;
    
    uint8_t paddingLength = data.back();
    if (paddingLength == 0 || paddingLength > 16 || paddingLength > data.size()) {
        return false;
    }
    
    for (size_t i = data.size() - paddingLength; i < data.size(); i++) {
        if (data[i] != paddingLength) {
            return false;
        }
    }
    
    data.resize(data.size() - paddingLength);
    return true;
}

const char* NativeCrypto::aesEncrypt(const char* input, size_t input_len, const char* key) {
    try {
        // Préparer la clé AES-256 (32 bytes)
        uint8_t aesKey[32];
        memset(aesKey, 0, 32);
        // Calculer la longueur de la clé sans dépendre de null terminator
        size_t keyLen = 0;
        if (key) {
            for (size_t i = 0; i < 64 && key[i] != '\0'; i++) {
                keyLen++;
            }
        }
        memcpy(aesKey, key, std::min(keyLen, (size_t)32));
        
        // Expansion de clé
        uint32_t roundKeys[60];
        keyExpansion(aesKey, roundKeys);
        
        // Préparer les données avec padding
        std::vector<uint8_t> data(input, input + input_len);
        pkcs7Pad(data, 16);
        
        // Génération d'un IV aléatoire
        std::vector<uint8_t> iv(16);
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, 255);
        for (int i = 0; i < 16; i++) {
            iv[i] = dis(gen);
        }
        
        // Chiffrement en mode CBC
        std::vector<uint8_t> encrypted;
        encrypted.reserve(16 + data.size()); // IV + données chiffrées
        
        // Ajouter l'IV en début
        encrypted.insert(encrypted.end(), iv.begin(), iv.end());
        
        std::vector<uint8_t> prevBlock = iv;
        for (size_t i = 0; i < data.size(); i += 16) {
            uint8_t block[16];
            memcpy(block, &data[i], 16);
            
            // XOR avec le bloc précédent (CBC)
            for (int j = 0; j < 16; j++) {
                block[j] ^= prevBlock[j];
            }
            
            uint8_t encryptedBlock[16];
            aesEncryptBlock(block, encryptedBlock, roundKeys);
            
            encrypted.insert(encrypted.end(), encryptedBlock, encryptedBlock + 16);
            memcpy(prevBlock.data(), encryptedBlock, 16);
        }
        
        // Convertir en Base64
        return toBase64(reinterpret_cast<const char*>(encrypted.data()), encrypted.size());
        
    } catch (const std::exception& e) {
        std::cerr << "[NativeCrypto] AES encryption error: " << e.what() << std::endl;
        return nullptr;
    }
}

const char* NativeCrypto::aesDecrypt(const char* input, const char* key, size_t* output_len) {
    try {
        std::cout << "\n[FromXorString] === Starting Decryption ===\n";
        std::cout << "[FromXorString] Input: '" << input << "'" << std::endl;
        std::cout << "[FromXorString] Key: '" << key << "'" << std::endl;

        // Calculer la longueur de la chaîne base64 d'entrée EXACTEMENT comme le client
        size_t input_len = 0;
        for (input_len = 0; input[input_len] != '\0'; input_len++);

        std::cout << "[FromXorString] Input base64 length: " << input_len << std::endl;

        // Décoder base64 EXACTEMENT comme le client
        size_t decoded_len = 0;
        unsigned char* decoded = fromBase64(input, &decoded_len);

        if (!decoded || decoded_len < 8 + AES_BLOCKLEN) {
            if (decoded) delete[] decoded;
            throw std::runtime_error("Input too short or base64 decode failed");
        }

        std::cout << "[fromBase64] Decoded " << input_len << " bytes to " << decoded_len << " bytes" << std::endl;

        // Vérifier le magic number EXACTEMENT comme le client
        uint32_t magic = 0;
        memcpy(&magic, decoded, 4);
        if (magic != 0xAECBDAEF) {
            delete[] decoded;
            std::cout << "[FromXorString] Invalid magic: 0x" << std::hex << magic << std::dec << std::endl;
            throw std::runtime_error("Invalid magic number");
        }

        // Extraire la longueur originale EXACTEMENT comme le client
        uint32_t original_len = 0;
        memcpy(&original_len, decoded + 4, 4);
        std::cout << "[FromXorString] Original data length: " << original_len << std::endl;

        // VALIDATION STRICTE comme le client
        size_t encrypted_data_len = decoded_len - 8 - AES_BLOCKLEN;

        // REPRODUCTION EXACTE de la logique client pour original_len
        if (original_len > 1000000 || original_len > encrypted_data_len) {
            std::cout << "[FromXorString] WARNING: original_len seems invalid (" << original_len
                << "), using client-compatible recovery" << std::endl;

            // Utiliser EXACTEMENT la même logique que le client
            if (encrypted_data_len > AES_BLOCKLEN) {
                original_len = encrypted_data_len - (encrypted_data_len % AES_BLOCKLEN);
                // Réduire d'un bloc pour tenir compte du padding (comme le client)
                original_len -= AES_BLOCKLEN;
                std::cout << "[FromXorString] Adjusted original_len to: " << original_len << std::endl;
            }
            else {
                delete[] decoded;
                throw std::runtime_error("Invalid data size for recovery");
            }
        }

        // Extraire l'IV
        unsigned char iv[AES_BLOCKLEN];
        memcpy(iv, decoded + 8, AES_BLOCKLEN);

        // Extraire les données chiffrées
        unsigned char* encrypted_data = new unsigned char[encrypted_data_len];
        memcpy(encrypted_data, decoded + 8 + AES_BLOCKLEN, encrypted_data_len);

        delete[] decoded;

        std::cout << "[FromXorString] IV (hex): ";
        for (int i = 0; i < AES_BLOCKLEN; i++)
            printf("%02x", iv[i]);
        std::cout << std::endl;

        // Dériver la clé EXACTEMENT comme le client
        size_t key_len = 0;
        for (key_len = 0; key_len < 128 && key[key_len] != '\0'; key_len++);

        std::cout << "[FromXorString] Key length: " << key_len << std::endl;

        unsigned char derived_key[AES_KEYLEN];
        for (size_t i = 0; i < AES_KEYLEN; i++) {
            derived_key[i] = key[i % key_len] ^ (i * 13);
        }

        std::cout << "[FromXorString] Derived key (hex): ";
        for (size_t i = 0; i < AES_KEYLEN; i++)
            printf("%02x", derived_key[i]);
        std::cout << std::endl;

        // Déchiffrer EXACTEMENT comme le client
        AES_ctx ctx;
        AES_init_ctx_iv(&ctx, derived_key, iv);
        AES_CBC_decrypt_buffer(&ctx, encrypted_data, encrypted_data_len);

        // VALIDATION FINALE compatible client
        if (original_len > encrypted_data_len) {
            std::cout << "[FromXorString] Final check failed, original_len=" << original_len
                << " > encrypted_data_len=" << encrypted_data_len << std::endl;
            delete[] encrypted_data;
            throw std::runtime_error("Original length exceeds decrypted data");
        }

        // Allouer le résultat EXACTEMENT comme le client
        const char* result = ThreadSafeBuffer::allocate(original_len + 1);
        memcpy((void*)result, encrypted_data, original_len);
        ((char*)result)[original_len] = '\0';

        // DIAGNOSTIC DÉTAILLÉ
        std::cout << "[FromXorString] Decrypted " << original_len << " bytes successfully" << std::endl;
        std::cout << "[FromXorString] Raw decrypted (hex): ";
        for (size_t i = 0; i < std::min(original_len, (uint32_t)32); i++) {
            printf("%02x ", (unsigned char)result[i]);
        }
        std::cout << std::endl;

        std::cout << "[FromXorString] As string: '";
        for (size_t i = 0; i < original_len; i++) {
            char c = result[i];
            if (c >= 32 && c <= 126) {
                std::cout << c;
            }
            else {
                printf("\\x%02x", (unsigned char)c);
            }
        }
        std::cout << "'" << std::endl;

        // VALIDATION SPÉCIALE pour les données numériques (timestamps, etc.)
        bool allNumeric = true;
        bool hasValidChars = true;
        for (size_t i = 0; i < original_len; i++) {
            char c = result[i];
            if (c < '0' || c > '9') allNumeric = false;
            if (c < 32 || c > 126) hasValidChars = false;
        }

        if (!hasValidChars) {
            std::cout << "[FromXorString] WARNING: Result contains non-printable characters, "
                << "possible decryption issue" << std::endl;
        }

        if (output_len) {
            *output_len = original_len;
        }

        delete[] encrypted_data;
        return result;
    }
    catch (const std::exception& e) {
        std::cout << "[FromXorString] Error: " << e.what() << std::endl;
        throw;
    }

}

const char* NativeCrypto::toBase64(const char* input, size_t input_len, size_t* output_len) {
    size_t encoded_len = 4 * ((input_len + 2) / 3);
    
    static ThreadSafeBuffer buffer;
    char* encoded = buffer.allocate(encoded_len + 1);
    
    int val = 0, valb = -6;
    size_t pos = 0;
    
    for (size_t i = 0; i < input_len; i++) {
        val = (val << 8) + static_cast<unsigned char>(input[i]);
        valb += 8;
        while (valb >= 0) {
            encoded[pos++] = base64Chars[(val >> valb) & 0x3F];
            valb -= 6;
        }
    }
    
    if (valb > -6) {
        encoded[pos++] = base64Chars[((val << 8) >> (valb + 8)) & 0x3F];
    }
    
    while (pos % 4) {
        encoded[pos++] = '=';
    }
    
    encoded[pos] = '\0';
    
    if (output_len) *output_len = pos;
    
    return encoded;
}

unsigned char* NativeCrypto::fromBase64(const char* input, size_t* output_len) {

    size_t input_len = 0;
    if (input) {
        for (size_t i = 0; i < 1024*1024 && input[i] != '\0'; i++) {
            input_len++;
        }
    }
    if (input_len % 4 != 0) return nullptr;
    
    size_t decoded_len = input_len / 4 * 3;
    if (input[input_len - 1] == '=') decoded_len--;
    if (input[input_len - 2] == '=') decoded_len--;
    
    unsigned char* decoded = new unsigned char[decoded_len + 1];
    
    int val = 0, valb = -8;
    size_t pos = 0;
    
    for (size_t i = 0; i < input_len; i++) {
        if (input[i] == '=') break;
        
        size_t char_pos = base64Chars.find(input[i]);
        if (char_pos == std::string::npos) {
            delete[] decoded;
            return nullptr;
        }
        
        val = (val << 6) + char_pos;
        valb += 6;
        if (valb >= 0) {
            decoded[pos++] = static_cast<unsigned char>((val >> valb) & 0xFF);
            valb -= 8;
        }
    }
    
    decoded[pos] = '\0';
    
    if (output_len) *output_len = pos;
    
    return decoded;
}

const char* NativeCrypto::encryptXor(const char* input, size_t input_len, const char* key) {

    size_t key_len = 0;
    if (key) {
        for (size_t i = 0; i < 256 && key[i] != '\0'; i++) {
            key_len++;
        }
    }
    if (key_len == 0) return nullptr;
    
    static ThreadSafeBuffer buffer;
    char* result = buffer.allocate(input_len + 1);
    
    for (size_t i = 0; i < input_len; i++) {
        result[i] = input[i] ^ key[i % key_len];
    }
    result[input_len] = '\0';
    
    return result;
}

const char* NativeCrypto::decryptXor(const char* input, const char* key) {

    size_t input_len = 0;
    if (input) {
        for (size_t i = 0; i < 1024*1024 && input[i] != '\0'; i++) {
            input_len++;
        }
    }
    return encryptXor(input, input_len, key);
}