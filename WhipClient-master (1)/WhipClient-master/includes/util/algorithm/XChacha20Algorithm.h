#pragma once
#include <stdint.h>
#include <string.h>

class XChaCha20 {
private:
    static uint32_t rotl32(uint32_t x, int n);
    static void chacha20Block(const uint32_t *key, const uint32_t *nonce, uint32_t counter, uint32_t *output);
    static void hchacha20(const uint32_t *key, const uint32_t *nonce, uint32_t *output);
    static void quarterRound(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d);

public:

    static bool process(const uint8_t* key, size_t keyLength,
        const uint8_t* nonce, size_t nonceLength,
        const uint8_t* data, size_t dataLength,
        uint8_t* output);

    static const char* encrypt(const char* input, size_t input_len, const char* key);
    static const char* decrypt(const char* input, const char* key, size_t* output_len = nullptr);
};
