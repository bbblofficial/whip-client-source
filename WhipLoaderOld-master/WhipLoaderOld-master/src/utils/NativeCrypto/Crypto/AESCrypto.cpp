#include "utils/NativeCrypto/Crypto/AESCrypto.h"
#include "utils/aes128gcm/aes128gcm.h"
#include "utils/NativeCrypto/NativeCrypto.h"

namespace NativeCrypto::Crypto {
    bool encryptAES128GCM(const u8 *plaintext, u32 plaintext_len,
                          const u8 *key, const u8 *iv,
                          const u8 *aad, u32 aad_len,
                          u8 *ciphertext, u8 *tag) {
        return AES_Internal::encrypt_gcm(plaintext, plaintext_len, key, iv,
                                         aad, aad_len, ciphertext, tag);
    }

    bool decryptAES128GCM(const u8 *ciphertext, u32 ciphertext_len,
                          const u8 *key, const u8 *iv,
                          const u8 *aad, u32 aad_len,
                          const u8 *tag, u8 *plaintext) {
        return AES_Internal::decrypt_gcm(ciphertext, ciphertext_len, key, iv,
                                         aad, aad_len, tag, plaintext);
    }

    namespace AES_Internal {
        bool encrypt_gcm(const u8 *plaintext, u32 plaintext_len,
                         const u8 *key, const u8 *iv,
                         const u8 *aad, u32 aad_len,
                         u8 *ciphertext, u8 *tag) {
            if (!plaintext || !key || !iv || !ciphertext || !tag) {
                return false;
            }

            // AES-GCM requires plaintext length to be a multiple of 16 bytes
            if (plaintext_len % 16 != 0) {
                return false;
            }

            u32 len_p_blocks = plaintext_len / 16;
            u32 len_ad_blocks = aad ? (aad_len / 16) : 0;

            aes128gcm(ciphertext, tag, key, iv, plaintext, len_p_blocks,
                      aad ? aad : reinterpret_cast<const u8*>(""), len_ad_blocks);

            return true;
        }

        bool decrypt_gcm(const u8 *ciphertext, u32 ciphertext_len,
                         const u8 *key, const u8 *iv,
                         const u8 *aad, u32 aad_len,
                         const u8 *tag, u8 *plaintext) {
            if (!ciphertext || !key || !iv || !tag || !plaintext) {
                return false;
            }

            if (ciphertext_len % 16 != 0) {
                return false;
            }

            // Decrypt using AES-GCM
            u8 computed_tag[16];
            u32 len_p_blocks = ciphertext_len / 16;

            // FIX: Arrondir supérieur comme le serveur !
            u32 len_ad_blocks = aad ? ((aad_len + 15) / 16) : 0;  // <-- CORRECTION ICI

            // In GCM, decryption is the same as encryption (CTR mode)
            aes128gcm(plaintext, computed_tag, key, iv, ciphertext, len_p_blocks,
                      aad ? aad : reinterpret_cast<const u8*>(""), len_ad_blocks);

            // Verify tag using constant-time comparison
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
