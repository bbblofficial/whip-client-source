#include "protocol.h"
#include <cstring>
#include <ctime>
#include <iostream>
#include <random>
#include "../include/utils/chacha20poly1305/chacha20poly1305.h"

#ifdef Themida
#include "SecureEngineMacros.h"
#pragma optimize("", off)
#endif

bool BinaryProtocol::encryptWithChaCha20Poly1305(const uint8_t* data, size_t dataSize, const char* key, uint8_t** outData, size_t* outSize) {
#ifdef Themida
    VM_LION_BLACK_START
#endif

    if (!data || dataSize == 0 || !key || !outData || !outSize) {
        return false;
    }

    try {
        uint8_t nonce[24];
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<int> dis(0, 255);
        for (int i = 0; i < 24; i++) {
            nonce[i] = static_cast<uint8_t>(dis(gen));
        }

#ifdef Themida
    VM_LION_BLACK_END
#endif

#ifdef Themida
    VM_EAGLE_RED_START
#endif

        uint8_t cryptoKey[32];
        size_t keyLen = strlen(key);
        for (size_t i = 0; i < 32; i++) {
            cryptoKey[i] = key[i % keyLen] ^ (i * 13);
        }

#ifdef Themida
    VM_EAGLE_RED_END
#endif

        chacha20poly1305_ctx ctx;
        xchacha20poly1305_init(&ctx, cryptoKey, nonce);

        uint8_t* ciphertext = new uint8_t[dataSize];
        chacha20poly1305_encrypt(&ctx, const_cast<uint8_t*>(data), ciphertext, dataSize);

        uint8_t mac[16];
        chacha20poly1305_finish(&ctx, mac);

#ifdef Themida
    VM_DOLPHIN_BLACK_START
#endif

        *outSize = 24 + dataSize + 16;
        *outData = new uint8_t[*outSize];

        memcpy(*outData, nonce, 24);
        memcpy(*outData + 24, ciphertext, dataSize);
        memcpy(*outData + 24 + dataSize, mac, 16);

        delete[] ciphertext;
        return true;
    }
    catch (const std::exception& e) {
        return false;
    }

#ifdef Themida
    VM_DOLPHIN_BLACK_END
#endif
}

bool BinaryProtocol::decryptWithChaCha20Poly1305(const uint8_t* encryptedData, size_t encryptedSize, const char* key, uint8_t** outData, size_t* outSize) {
    try {
#ifdef Themida
        VM_TIGER_RED_START
#endif

        if (!encryptedData || !key || !outData || !outSize) {
            return false;
        }

        if (encryptedSize < 24 + 16) {
            return false;
        }

        uint8_t nonce[24];
        memcpy(nonce, encryptedData, 24);

        size_t ciphertextSize = encryptedSize - 24 - 16;
        uint8_t* ciphertext = new uint8_t[ciphertextSize];
        memcpy(ciphertext, encryptedData + 24, ciphertextSize);

        uint8_t receivedMac[16];
        memcpy(receivedMac, encryptedData + 24 + ciphertextSize, 16);

#ifdef Themida
        VM_TIGER_RED_END
#endif

#ifdef Themida
        VM_LION_WHITE_START
#endif

        uint8_t cryptoKey[32];
        size_t keyLen = strlen(key);
        for (size_t i = 0; i < 32; i++) {
            cryptoKey[i] = key[i % keyLen] ^ (i * 13);
        }

#ifdef Themida
        VM_LION_WHITE_END
#endif

        chacha20poly1305_ctx ctx;
        xchacha20poly1305_init(&ctx, cryptoKey, nonce);

        uint8_t* plaintext = new uint8_t[ciphertextSize];
        chacha20poly1305_decrypt(&ctx, ciphertext, plaintext, ciphertextSize);

        uint8_t computedMac[16];
        chacha20poly1305_finish(&ctx, computedMac);

#ifdef Themida
        VM_SHARK_RED_START
#endif

        if (memcmp(receivedMac, computedMac, 16) != 0) {
            delete[] ciphertext;
            delete[] plaintext;
            return false;
        }

        delete[] ciphertext;

        *outData = plaintext;
        *outSize = ciphertextSize;
        return true;
    }
    catch (const std::exception& e) {
        return false;
    }

#ifdef Themida
    VM_SHARK_RED_END
#endif
}

BinaryMessageHeader BinaryProtocol::createLoaderHeader(MessageType type, uint32_t payloadSize) {
#ifdef Themida
    VM_DOLPHIN_WHITE_START
#endif

    BinaryMessageHeader header{};
    header.magic = LOADER_PROTOCOL_MAGIC;
    header.version = PROTOCOL_VERSION;
    header.type = static_cast<uint16_t>(type);
    header.timestamp = static_cast<uint32_t>(time(nullptr));
    header.payload_size = payloadSize;
    header.mapping_size = 0;
    header.checksum = 0;

#ifdef Themida
    VM_DOLPHIN_WHITE_END
#endif

    return header;
}