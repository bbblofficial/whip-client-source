#pragma once
#include <string>
#include <vector>
#include <cstdint>
#include <cstring>
#include "Thread/ThreadSafeBuffer.h"

class NativeCrypto {
public:

    static const char *aesEncrypt(const char *input, size_t input_len, const char *key);

    static const char *aesEncrypt(const char *input, const char *key) {
        size_t input_len = strlen(input);
        return aesEncrypt(input, input_len, key);
    }

    static const char *aesDecrypt(const char *input, const char *key, size_t *output_len = nullptr);

    static const char *toBase64(const char *input, size_t input_len, size_t *output_len = nullptr);

    static const char *toBase64(const char *input) {
        size_t input_len = strlen(input);
        return toBase64(input, input_len, nullptr);
    }

    static unsigned char *fromBase64(const char *input, size_t *output_len);

    static const char *encryptXor(const char *input, size_t input_len, const char *key);

    static const char *decryptXor(const char *input, const char *key);

private:

    static const uint8_t sbox[256];
    static const uint8_t inv_sbox[256];
    static const uint32_t rcon[11];

    static void keyExpansion(const uint8_t *key, uint32_t *roundKeys);

    static void addRoundKey(uint8_t *state, const uint32_t *roundKey);

    static void subBytes(uint8_t *state);

    static void invSubBytes(uint8_t *state);

    static void shiftRows(uint8_t *state);

    static void invShiftRows(uint8_t *state);

    static void mixColumns(uint8_t *state);

    static void invMixColumns(uint8_t *state);

    static void aesEncryptBlock(const uint8_t *input, uint8_t *output, const uint32_t *roundKeys);

    static void aesDecryptBlock(const uint8_t *input, uint8_t *output, const uint32_t *roundKeys);

    static uint8_t gmul(uint8_t a, uint8_t b);

    static void pkcs7Pad(std::vector<uint8_t> &data, size_t blockSize);

    static bool pkcs7Unpad(std::vector<uint8_t> &data);

    static const std::string base64Chars;

    static inline bool isBase64(unsigned char c) {
        return (isalnum(c) || (c == '+') || (c == '/'));
    }

    static const std::vector<unsigned char> FIXED_SALT;
};

class EncryptionUtils {
public:
    static const char *encrypt(const char *input) {
        return NativeCrypto::encryptXor(input, strlen(input), "default_key");
    }

    static const char *decrypt(const char *input) {
        return NativeCrypto::decryptXor(input, "default_key");
    }

    static const char *aesEncrypt(const char *input, size_t input_len, const char *key) {
        return NativeCrypto::aesEncrypt(input, input_len, key);
    }

    static const char *aesEncrypt(const char *input, const char *key) {
        return NativeCrypto::aesEncrypt(input, key);
    }

    static const char *aesDecrypt(const char *input, const char *key, size_t *output_len = nullptr) {
        return NativeCrypto::aesDecrypt(input, key, output_len);
    }

    static const char *toBase64(const char *input, size_t input_len, size_t *output_len = nullptr) {
        return NativeCrypto::toBase64(input, input_len, output_len);
    }

    static const char *toBase64(const char *input) {
        return NativeCrypto::toBase64(input);
    }

    static unsigned char *fromBase64(const char *input, size_t *output_len) {
        return NativeCrypto::fromBase64(input, output_len);
    }

    static const char *encryptXor(const char *input, size_t input_len, const char *key) {
        return NativeCrypto::encryptXor(input, input_len, key);
    }

    static const char *decryptXor(const char *input, const char *key) {
        return NativeCrypto::decryptXor(input, key);
    }
};
