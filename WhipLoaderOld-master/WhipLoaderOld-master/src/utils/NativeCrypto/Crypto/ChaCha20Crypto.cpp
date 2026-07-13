#include "utils/NativeCrypto/Crypto/ChaCha20Crypto.h"
#include "utils/chacha20poly1305/chacha20poly1305.h"
#include "utils/NativeCrypto/NativeCrypto.h"

namespace NativeCrypto::Crypto {
    bool encryptChaCha20Poly1305(const u8 *plaintext, u32 plaintext_len,
                                 const u8 *key, const u8 *nonce,
                                 const u8 *aad, u32 aad_len,
                                 u8 *ciphertext, u8 *tag) {
        // Standard ChaCha20-Poly1305 uses 12-byte nonce
        // This implementation only supports XChaCha20-Poly1305 with 24-byte nonce
        return false;
    }

    bool decryptChaCha20Poly1305(const u8 *ciphertext, u32 ciphertext_len,
                                 const u8 *key, const u8 *nonce,
                                 const u8 *aad, u32 aad_len,
                                 const u8 *tag, u8 *plaintext) {
        // Standard ChaCha20-Poly1305 uses 12-byte nonce
        // This implementation only supports XChaCha20-Poly1305 with 24-byte nonce
        return false;
    }

    bool encryptXChaCha20Poly1305(const u8 *plaintext, u32 plaintext_len,
                                  const u8 *key, const u8 *nonce,
                                  const u8 *aad, u32 aad_len,
                                  u8 *ciphertext, u8 *tag) {
        return ChaCha20_Internal::encrypt_xchacha20poly1305(plaintext, plaintext_len,
                                                            key, nonce, aad, aad_len,
                                                            ciphertext, tag);
    }

    bool decryptXChaCha20Poly1305(const u8 *ciphertext, u32 ciphertext_len,
                                  const u8 *key, const u8 *nonce,
                                  const u8 *aad, u32 aad_len,
                                  const u8 *tag, u8 *plaintext) {
        return ChaCha20_Internal::decrypt_xchacha20poly1305(ciphertext, ciphertext_len,
                                                            key, nonce, aad, aad_len,
                                                            tag, plaintext);
    }

    namespace ChaCha20_Internal {
        bool encrypt_xchacha20poly1305(const u8 *plaintext, u32 plaintext_len,
                                       const u8 *key, const u8 *nonce,
                                       const u8 *aad, u32 aad_len,
                                       u8 *ciphertext, u8 *tag) {
            if (!plaintext || !key || !nonce || !ciphertext || !tag) {
                return false;
            }

            chacha20poly1305_ctx ctx;
            xchacha20poly1305_init(&ctx, const_cast<u8*>(key), const_cast<u8*>(nonce));

            // Authenticate additional data if present
            if (aad && aad_len > 0) {
                chacha20poly1305_auth(&ctx, const_cast<u8*>(aad), aad_len);
            }

            // Encrypt plaintext
            chacha20poly1305_encrypt(&ctx, const_cast<u8*>(plaintext), ciphertext, plaintext_len);

            // Generate authentication tag
            chacha20poly1305_finish(&ctx, tag);

            return true;
        }

        bool decrypt_xchacha20poly1305(const u8 *ciphertext, u32 ciphertext_len,
                                       const u8 *key, const u8 *nonce,
                                       const u8 *aad, u32 aad_len,
                                       const u8 *tag, u8 *plaintext) {
            if (!ciphertext || !key || !nonce || !tag || !plaintext) {
                return false;
            }

            chacha20poly1305_ctx ctx;
            xchacha20poly1305_init(&ctx, const_cast<u8*>(key), const_cast<u8*>(nonce));

            // Authenticate additional data if present
            if (aad && aad_len > 0) {
                chacha20poly1305_auth(&ctx, const_cast<u8*>(aad), aad_len);
            }

            // Decrypt ciphertext
            chacha20poly1305_decrypt(&ctx, const_cast<u8*>(ciphertext), plaintext, ciphertext_len);

            // Verify authentication tag
            u8 computed_tag[16];
            chacha20poly1305_finish(&ctx, computed_tag);

            // Constant-time comparison
            return verify_tag_constant_time(computed_tag, tag, 16);
        }

        bool verify_tag_constant_time(const u8 *tag1, const u8 *tag2, u32 tag_len) {
            u8 diff = 0;
            for (u32 i = 0; i < tag_len; i++) {
                diff |= tag1[i] ^ tag2[i];
            }
            return diff == 0;
        }
    }
}
