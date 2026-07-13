#include "xchacha20.h"
#include <random>
#include "../Thread/ThreadSafeBuffer.h"

// Rotate left operation
uint32_t XChaCha20::rotl32(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}

// Quarter round function
void XChaCha20::quarterRound(uint32_t &a, uint32_t &b, uint32_t &c, uint32_t &d) {
    a += b;
    d ^= a;
    d = rotl32(d, 16);
    c += d;
    b ^= c;
    b = rotl32(b, 12);
    a += b;
    d ^= a;
    d = rotl32(d, 8);
    c += d;
    b ^= c;
    b = rotl32(b, 7);
}

// Core ChaCha20 block function
void XChaCha20::chacha20Block(const uint32_t *key, const uint32_t *nonce, uint32_t counter, uint32_t *output) {
    // ChaCha20 constants
    const uint32_t constants[4] = {
        0x61707865, 0x3320646e, 0x79622d32, 0x6b206574
    };

    // Initialize state
    uint32_t state[16];
    
    // Constants
    state[0] = constants[0];
    state[1] = constants[1];
    state[2] = constants[2];
    state[3] = constants[3];
    
    // Key
    for (int i = 0; i < 8; i++) {
        state[4 + i] = key[i];
    }
    
    // Counter
    state[12] = counter;
    
    // Nonce
    state[13] = nonce[0];
    state[14] = nonce[1];
    state[15] = nonce[2];

    // Copy state to working state
    uint32_t working[16];
    for (int i = 0; i < 16; i++) {
        working[i] = state[i];
    }

    // 20 rounds (10 double rounds)
    for (int i = 0; i < 10; i++) {
        // Column round
        quarterRound(working[0], working[4], working[8], working[12]);
        quarterRound(working[1], working[5], working[9], working[13]);
        quarterRound(working[2], working[6], working[10], working[14]);
        quarterRound(working[3], working[7], working[11], working[15]);

        // Diagonal round
        quarterRound(working[0], working[5], working[10], working[15]);
        quarterRound(working[1], working[6], working[11], working[12]);
        quarterRound(working[2], working[7], working[8], working[13]);
        quarterRound(working[3], working[4], working[9], working[14]);
    }

    // Add original state
    for (int i = 0; i < 16; i++) {
        output[i] = working[i] + state[i];
    }
}

// HChaCha20 for key derivation
void XChaCha20::hchacha20(const uint32_t *key, const uint32_t *nonce, uint32_t *output) {
    // ChaCha20 constants
    const uint32_t constants[4] = {
        0x61707865, 0x3320646e, 0x79622d32, 0x6b206574
    };

    // Initialize state
    uint32_t state[16];
    
    // Constants
    state[0] = constants[0];
    state[1] = constants[1];
    state[2] = constants[2];
    state[3] = constants[3];
    
    // Key
    for (int i = 0; i < 8; i++) {
        state[4 + i] = key[i];
    }
    
    // Nonce (first 16 bytes as 4 32-bit words)
    state[12] = nonce[0];
    state[13] = nonce[1];
    state[14] = nonce[2];
    state[15] = nonce[3];

    // Copy state to working state
    uint32_t working[16];
    for (int i = 0; i < 16; i++) {
        working[i] = state[i];
    }

    // 20 rounds (10 double rounds)
    for (int i = 0; i < 10; i++) {
        // Column round
        quarterRound(working[0], working[4], working[8], working[12]);
        quarterRound(working[1], working[5], working[9], working[13]);
        quarterRound(working[2], working[6], working[10], working[14]);
        quarterRound(working[3], working[7], working[11], working[15]);

        // Diagonal round
        quarterRound(working[0], working[5], working[10], working[15]);
        quarterRound(working[1], working[6], working[11], working[12]);
        quarterRound(working[2], working[7], working[8], working[13]);
        quarterRound(working[3], working[4], working[9], working[14]);
    }

    // Output: first 4 words and last 4 words of the state
    output[0] = working[0];
    output[1] = working[1];
    output[2] = working[2];
    output[3] = working[3];
    output[4] = working[12];
    output[5] = working[13];
    output[6] = working[14];
    output[7] = working[15];
}

// Main XChaCha20 process function
bool XChaCha20::process(const uint8_t *key, size_t keyLength,
                       const uint8_t *nonce, size_t nonceLength,
                       const uint8_t *data, size_t dataLength,
                       uint8_t *output) {
    // Validate inputs
    if (!key || !nonce || !data || !output) {
        return false;
    }
    if ((keyLength != 16 && keyLength != 32) || nonceLength != 24) {
        return false;
    }

    // Create derived key using HChaCha20
    uint32_t derivedKey[8];
    uint32_t nonce_words[4];
    uint32_t key_words[8] = {0}; // Initialize to zero

    // Convert nonce to 32-bit words (little-endian)
    for (int i = 0; i < 4; i++) {
        nonce_words[i] = ((uint32_t) nonce[i * 4]) |
                         ((uint32_t) nonce[i * 4 + 1] << 8) |
                         ((uint32_t) nonce[i * 4 + 2] << 16) |
                         ((uint32_t) nonce[i * 4 + 3] << 24);
    }

    // Convert key to 32-bit words (little-endian)
    for (size_t i = 0; i < keyLength / 4; i++) {
        key_words[i] = ((uint32_t) key[i * 4]) |
                       ((uint32_t) key[i * 4 + 1] << 8) |
                       ((uint32_t) key[i * 4 + 2] << 16) |
                       ((uint32_t) key[i * 4 + 3] << 24);
    }

    // If 16-byte key, duplicate it
    if (keyLength == 16) {
        for (int i = 0; i < 4; i++) {
            key_words[i + 4] = key_words[i];
        }
    }

    // Derive key using HChaCha20
    hchacha20(key_words, nonce_words, derivedKey);

    // Use last 8 bytes of nonce as ChaCha20 nonce
    uint32_t chacha_nonce[3];
    chacha_nonce[0] = 0; // Counter starts at 0
    chacha_nonce[1] = ((uint32_t) nonce[16]) |
                      ((uint32_t) nonce[17] << 8) |
                      ((uint32_t) nonce[18] << 16) |
                      ((uint32_t) nonce[19] << 24);
    chacha_nonce[2] = ((uint32_t) nonce[20]) |
                      ((uint32_t) nonce[21] << 8) |
                      ((uint32_t) nonce[22] << 16) |
                      ((uint32_t) nonce[23] << 24);

    // Process data in 64-byte blocks
    size_t fullBlocks = dataLength / 64;
    size_t remainder = dataLength % 64;

    for (size_t block = 0; block < fullBlocks; block++) {
        uint32_t keystream[16];
        chacha20Block(derivedKey, chacha_nonce, (uint32_t)block, keystream);

        // XOR with input data
        for (int i = 0; i < 16; i++) {
            uint32_t inputWord = ((uint32_t) data[block * 64 + i * 4]) |
                                ((uint32_t) data[block * 64 + i * 4 + 1] << 8) |
                                ((uint32_t) data[block * 64 + i * 4 + 2] << 16) |
                                ((uint32_t) data[block * 64 + i * 4 + 3] << 24);
            
            uint32_t outputWord = inputWord ^ keystream[i];
            
            output[block * 64 + i * 4] = outputWord & 0xFF;
            output[block * 64 + i * 4 + 1] = (outputWord >> 8) & 0xFF;
            output[block * 64 + i * 4 + 2] = (outputWord >> 16) & 0xFF;
            output[block * 64 + i * 4 + 3] = (outputWord >> 24) & 0xFF;
        }
    }

    // Handle remaining bytes
    if (remainder > 0) {
        uint32_t keystream[16];
        chacha20Block(derivedKey, chacha_nonce, (uint32_t)fullBlocks, keystream);

        uint8_t *keystreamBytes = (uint8_t*)keystream;
        for (size_t i = 0; i < remainder; i++) {
            output[fullBlocks * 64 + i] = data[fullBlocks * 64 + i] ^ keystreamBytes[i];
        }
    }

    return true;
}

const char *XChaCha20::encrypt(const char *input, size_t input_len, const char *key) {
    if (!input || !key || input_len == 0) {
        return nullptr;
    }

    // Generate a random 24-byte nonce
    uint8_t nonce[24];
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);

    for (int i = 0; i < 24; i++) {
        nonce[i] = (uint8_t)dis(gen);
    }

    // Create 16-byte key from input key
    uint8_t derived_key[16];
    size_t key_len = strlen(key);
    for (size_t i = 0; i < 16; i++) {
        derived_key[i] = key[i % key_len];
    }

    // Allocate buffer for encrypted data
    uint8_t *encrypted = new uint8_t[input_len];
    if (!encrypted) {
        return nullptr;
    }

    // Encrypt the data
    bool success = process(derived_key, 16, nonce, 24, 
                          (const uint8_t*)input, input_len, encrypted);

    if (!success) {
        delete[] encrypted;
        return nullptr;
    }

    // Combine nonce + encrypted data and convert to hex
    size_t total_size = 24 + input_len;
    size_t hex_size = total_size * 2;
    
    char *hex_result = new char[hex_size + 1];
    if (!hex_result) {
        delete[] encrypted;
        return nullptr;
    }

    // Convert to hex string
    const char hex_chars[] = "0123456789ABCDEF";
    
    // First the nonce
    for (int i = 0; i < 24; i++) {
        hex_result[i * 2] = hex_chars[nonce[i] >> 4];
        hex_result[i * 2 + 1] = hex_chars[nonce[i] & 0xF];
    }
    
    // Then the encrypted data
    for (size_t i = 0; i < input_len; i++) {
        hex_result[(24 + i) * 2] = hex_chars[encrypted[i] >> 4];
        hex_result[(24 + i) * 2 + 1] = hex_chars[encrypted[i] & 0xF];
    }
    
    hex_result[hex_size] = '\0';
    delete[] encrypted;

    // Store in thread-safe buffer
    const char *thread_safe_result = ThreadSafeBuffer::allocate(hex_size + 1);
    if (!thread_safe_result) {
        delete[] hex_result;
        return nullptr;
    }
    
    for (size_t i = 0; i <= hex_size; i++) {
        ((char*)thread_safe_result)[i] = hex_result[i];
    }
    
    delete[] hex_result;
    return thread_safe_result;
}

const char *XChaCha20::decrypt(const char *input, const char *key, size_t *output_len) {
    if (!input || !key) {
        return nullptr;
    }

    size_t hex_len = strlen(input);
    if (hex_len < 48 || hex_len % 2 != 0) { // At least 24 bytes (48 hex chars) for nonce
        return nullptr;
    }

    size_t binary_len = hex_len / 2;
    if (binary_len <= 24) {
        return nullptr;
    }

    // Convert hex string to binary
    uint8_t *binary_data = new uint8_t[binary_len];
    if (!binary_data) {
        return nullptr;
    }

    for (size_t i = 0; i < hex_len; i += 2) {
        char byte_string[3] = {input[i], input[i + 1], 0};
        unsigned int byte_val;
        if (sscanf(byte_string, "%x", &byte_val) != 1) {
            delete[] binary_data;
            return nullptr;
        }
        binary_data[i / 2] = (uint8_t)byte_val;
    }

    // Extract nonce (first 24 bytes)
    uint8_t nonce[24];
    for (int i = 0; i < 24; i++) {
        nonce[i] = binary_data[i];
    }

    // Extract encrypted data (remainder)
    size_t encrypted_len = binary_len - 24;
    uint8_t *encrypted_data = binary_data + 24;

    // Create 16-byte key from input key
    uint8_t derived_key[16];
    size_t key_len = strlen(key);
    for (size_t i = 0; i < 16; i++) {
        derived_key[i] = key[i % key_len];
    }

    // Allocate buffer for decrypted data
    uint8_t *decrypted = new uint8_t[encrypted_len + 1];
    if (!decrypted) {
        delete[] binary_data;
        return nullptr;
    }

    // Decrypt the data
    bool success = process(derived_key, 16, nonce, 24, 
                          encrypted_data, encrypted_len, decrypted);

    delete[] binary_data;

    if (!success) {
        delete[] decrypted;
        return nullptr;
    }

    // Null-terminate the result
    decrypted[encrypted_len] = '\0';

    // Set output length if requested
    if (output_len) {
        *output_len = encrypted_len;
    }

    // Store in thread-safe buffer
    const char *thread_safe_result = ThreadSafeBuffer::allocate(encrypted_len + 1);
    if (!thread_safe_result) {
        delete[] decrypted;
        return nullptr;
    }
    
    for (size_t i = 0; i <= encrypted_len; i++) {
        ((char*)thread_safe_result)[i] = decrypted[i];
    }
    
    delete[] decrypted;
    return thread_safe_result;
}