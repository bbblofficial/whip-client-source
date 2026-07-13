#pragma once
#include "../NativeCrypto.h"

namespace NativeCrypto::Crypto::AES_Internal {
    bool encrypt_gcm(const u8 *plaintext, u32 plaintext_len,
                     const u8 *key, const u8 *iv,
                     const u8 *aad, u32 aad_len,
                     u8 *ciphertext, u8 *tag);

    bool decrypt_gcm(const u8 *ciphertext, u32 ciphertext_len,
                     const u8 *key, const u8 *iv,
                     const u8 *aad, u32 aad_len,
                     const u8 *tag, u8 *plaintext);

    bool verify_tag_constant_time(const u8 *tag1, const u8 *tag2, u32 tag_len);
}
