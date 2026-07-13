#pragma once
#include <vector>

namespace NativeCrypto {
    using u8 = unsigned char;
    using u32 = unsigned int;
    using u64 = unsigned long long;

    namespace Crypto {
        // Base64 Encoding/Decoding
        char *encodeBase64(const u8 *data, u32 data_len, u32 *output_len);

        u8 *decodeBase64(const char *input, u32 *output_len);

        void freeBase64(void *ptr);

        // XOR Cipher
        bool encryptXor(const u8 *toEncrypt, u32 data_len, const char *key,
                        u8 *encrypted, u32 *encrypted_len);

        bool decryptXor(const u8 *encrypted, u32 encrypted_len, const char *key,
                        u8 *decrypted, u32 *decrypted_len);

        std::vector<u8> encryptXor(const std::vector<u8> &input, const char *key);

        std::vector<u8> decryptXor(const std::vector<u8> &input, const char *key);

        std::vector<u8> encryptXor(const char *input, const char *key);

        bool encryptXor(const u8 *toEncrypt, u32 data_len, const char *key,
                        void *encrypted_vector);

        bool decryptXor(const void *encrypted_vector, const char *key,
                        u8 *decrypted, u32 *decrypted_len);

        // AES-128-GCM Authenticated Encryption
        bool encryptAES128GCM(const u8 *plaintext, u32 plaintext_len,
                              const u8 *key, const u8 *iv,
                              const u8 *aad, u32 aad_len,
                              u8 *ciphertext, u8 *tag);

        bool decryptAES128GCM(const u8 *ciphertext, u32 ciphertext_len,
                              const u8 *key, const u8 *iv,
                              const u8 *aad, u32 aad_len,
                              const u8 *tag, u8 *plaintext);

        // ChaCha20-Poly1305 Authenticated Encryption
        bool encryptChaCha20Poly1305(const u8 *plaintext, u32 plaintext_len,
                                     const u8 *key, const u8 *nonce,
                                     const u8 *aad, u32 aad_len,
                                     u8 *ciphertext, u8 *tag);

        bool decryptChaCha20Poly1305(const u8 *ciphertext, u32 ciphertext_len,
                                     const u8 *key, const u8 *nonce,
                                     const u8 *aad, u32 aad_len,
                                     const u8 *tag, u8 *plaintext);

        // XChaCha20-Poly1305 (extended nonce)
        bool encryptXChaCha20Poly1305(const u8 *plaintext, u32 plaintext_len,
                                      const u8 *key, const u8 *nonce,
                                      const u8 *aad, u32 aad_len,
                                      u8 *ciphertext, u8 *tag);

        bool decryptXChaCha20Poly1305(const u8 *ciphertext, u32 ciphertext_len,
                                      const u8 *key, const u8 *nonce,
                                      const u8 *aad, u32 aad_len,
                                      const u8 *tag, u8 *plaintext);

        // SHA-256 Hashing
        void hashSHA256(const u8 *data, u32 data_len, u8 *hash);

        void hashSHA256Hex(const u8 *data, u32 data_len, char *hash_hex);

        // HMAC-SHA256
        bool hmacSHA256(const u8 *key, u32 key_len,
                        const u8 *data, u32 data_len,
                        u8 *hmac_out);

        // HKDF-SHA256 Key Derivation
        bool deriveKeyHKDF(const u8 *salt, u32 salt_len,
                           const u8 *ikm, u32 ikm_len,
                           const u8 *info, u32 info_len,
                           u8 *okm, u32 okm_len);

        bool extractHKDF(const u8 *salt, u32 salt_len,
                         const u8 *ikm, u32 ikm_len,
                         u8 *prk);

        bool expandHKDF(const u8 *prk, u32 prk_len,
                        const u8 *info, u32 info_len,
                        u8 *okm, u32 okm_len);

        // P-256 Elliptic Curve Operations
        bool generateP256KeyPair(u8 *private_key, u8 *public_key);

        bool deriveP256PublicKey(const u8 *private_key, u8 *public_key);

        bool computeP256SharedSecret(const u8 *private_key, const u8 *peer_public_key,
                                     u8 *shared_secret);

        bool signP256ECDSA(const u8 *private_key, const u8 *hash, u32 hash_len,
                           u8 *signature);

        bool verifyP256ECDSA(const u8 *public_key, const u8 *hash, u32 hash_len,
                             const u8 *signature);

        // Random bytes generation
        bool generateRandomBytes(u8 *buffer, u32 length);
        void hkdfSHA256(uint8_t* str, int i, uint8_t* text, int i1, const uint8_t* info, size_t size,
                       uint8_t* string, int i2);
        void randomBytes(uint8_t* iv, int i);
        bool aesGcmEncrypt(const uint8_t* plaintext, size_t size, uint8_t* str, int i, uint8_t* iv, int i1,
                          uint8_t* encrypted, size_t* encrypted_len);
        bool aesGcmDecrypt(const uint8_t* encrypted, size_t size, uint8_t* str, int i, uint8_t* iv, int i1,
                          uint8_t* plaintext, size_t* decrypted_len);
        bool p256Verify(uint8_t* str, uint8_t* text, const uint8_t* signature);
        bool p256Sign(uint8_t* str, uint8_t* text, uint8_t* signature);
    }

    namespace Utils {
        u32 strlen_safe(const char *str);

        void memcopy_safe(const void *src, void *dst, u32 size);

        void memzero_safe(void *ptr, u32 size);

        char *strchr_safe(const char *str, char c);
    }
}
