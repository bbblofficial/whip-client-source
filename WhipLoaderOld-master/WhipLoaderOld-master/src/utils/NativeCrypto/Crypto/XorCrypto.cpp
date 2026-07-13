#include "utils/NativeCrypto/Crypto/XorCrypto.h"

#include <vector>

#include "utils/NativeCrypto/NativeCrypto.h"

#ifdef Themida
#include "SecureEngineMacros.h"
#pragma optimize("", off)
#endif

namespace NativeCrypto::Crypto {
    bool encryptXor(const u8 *toEncrypt, const u32 data_len, const char *key,
                    u8 *encrypted, u32 *encrypted_len) {
        const u32 key_len = XOR_Internal::get_key_length(key);
        if (key_len == 0) {
            return false;
        }

        XOR_Internal::xor_process(toEncrypt, data_len, key, key_len, encrypted);

        *encrypted_len = data_len;
        return true;
    }

    bool decryptXor(const u8 *encrypted, const u32 encrypted_len, const char *key,
                    u8 *decrypted, u32 *decrypted_len) {
        const u32 key_len = XOR_Internal::get_key_length(key);
        if (key_len == 0) {
            return false;
        }

        XOR_Internal::xor_process(encrypted, encrypted_len, key, key_len, decrypted);

        *decrypted_len = encrypted_len;
        return true;
    }

    bool encryptXor(const u8 *toEncrypt, const u32 data_len, const char *key,
                    void *encrypted_vector) {
        if (!toEncrypt || !key || !encrypted_vector || data_len == 0) {
            return false;
        }

        auto *vec = static_cast<std::vector<u8> *>(encrypted_vector);

        const u32 key_len = XOR_Internal::get_key_length(key);
        if (key_len == 0) {
            return false;
        }

        vec->resize(data_len);

        XOR_Internal::xor_process(toEncrypt, data_len, key, key_len, vec->data());

        return true;
    }

    bool decryptXor(const void *encrypted_vector, const char *key,
                    u8 *decrypted, u32 *decrypted_len) {
        if (!encrypted_vector || !key || !decrypted || !decrypted_len) {
            return false;
        }

        const auto *vec = static_cast<const std::vector<u8> *>(encrypted_vector);

        if (vec->empty()) {
            return false;
        }

        const u32 key_len = XOR_Internal::get_key_length(key);
        if (key_len == 0) {
            return false;
        }

        const u32 data_len = static_cast<u32>(vec->size());

        XOR_Internal::xor_process(vec->data(), data_len, key, key_len, decrypted);

        *decrypted_len = data_len;
        return true;
    }

    std::vector<u8> decryptXor(const std::vector<u8> &input, const char *key) {
#ifdef Themida
        VM_LION_BLACK_START
#endif

        u32 key_len = XOR_Internal::get_key_length(key);
        if (key_len == 0) return {};

        std::vector<u8> result;
        result.reserve(input.size());

        for (u32 i = 0; i < input.size(); i++) {
            result.push_back(input[i] ^ static_cast<u8>(key[i % key_len]));
        }

#ifdef Themida
        VM_LION_BLACK_END
#endif

        return result;
    }

    std::vector<u8> encryptXor(const std::vector<u8> &input, const char *key) {
        return decryptXor(input, key);
    }

    std::vector<u8> encryptXor(const char *input, const char *key) {
        if (!input || !key) return {};

        const u32 input_len = Utils::strlen_safe(input);
        const std::vector<u8> input_vec(input, input + input_len);

        return encryptXor(input_vec, key);
    }

    namespace XOR_Internal {
        u32 get_key_length(const char *key) {
            if (!key) return 0;

            u32 key_len = 0;
            for (u32 i = 0; i < 256 && key[i] != '\0'; i++) {
                key_len++;
            }

            return key_len;
        }

        void xor_process(const u8 *data, const u32 data_len, const char *key, const u32 key_len, u8 *output) {

            for (u32 i = 0; i < data_len; i++) {
                output[i] = data[i] ^ static_cast<u8>(key[i % key_len]);
            }

        }

        u32 get_vector_size(const void *vector_ptr) {
            const auto *vec = static_cast<const std::vector<u8> *>(vector_ptr);
            return static_cast<u32>(vec->size());
        }

        const u8 *get_vector_data(const void *vector_ptr) {
            const auto *vec = static_cast<const std::vector<u8> *>(vector_ptr);
            return vec->data();
        }

        void resize_vector(void *vector_ptr, const u32 new_size) {
            auto *vec = static_cast<std::vector<u8> *>(vector_ptr);
            vec->resize(new_size);
        }

        u8 *get_vector_data_mutable(void *vector_ptr) {
            auto *vec = static_cast<std::vector<u8> *>(vector_ptr);
            return vec->data();
        }
    }
}
