#pragma once
#include <string>
#include <vector>

#ifdef USE_OPENSSL
    #include <openssl/evp.h>
    #include <openssl/aes.h>
    #include <openssl/err.h>
#else
#include "native_crypto.h"
#endif

#include "Thread/ThreadSafeBuffer.h"

#ifndef USE_OPENSSL
// Utiliser l'implémentation native qui inclut déjà EncryptionUtils
#else
// Implémentation OpenSSL originale
class EncryptionUtils {
public:
    static const char* encrypt(const char* input);
    static const char* decrypt(const char* input);

    static const char* aesEncrypt(const char* input, size_t input_len, const char* key);

    static const char* aesEncrypt(const char* input, const char* key) {
        size_t input_len = 0;
        for (input_len = 0; input[input_len] != '\0'; input_len++);
        return aesEncrypt(input, input_len, key);
    }

    static const char* aesDecrypt(const char* input, const char* key, size_t* output_len = nullptr);

    static const char* toBase64(const char* input, size_t input_len, size_t* output_len = nullptr);

    static const char* toBase64(const char* input) {
        size_t input_len = 0;
        for (input_len = 0; input[input_len] != '\0'; input_len++);
        return toBase64(input, input_len, nullptr);
    }

    static unsigned char* fromBase64(const char* input, size_t* output_len);

    static const char* encryptXor(const char* input, size_t input_len, const char* key);
    static const char* decryptXor(const char* input, const char* key);

private:
    static const std::vector<unsigned char> FIXED_SALT;
    static void handleOpenSSLError(const char* operation);
    static void initOpenSSL();
    static std::string base64Chars;
};
#endif
