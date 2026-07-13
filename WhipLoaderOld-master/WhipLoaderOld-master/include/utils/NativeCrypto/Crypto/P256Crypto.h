#pragma once
#include "../NativeCrypto.h"

namespace NativeCrypto::Crypto::P256_Internal {
    bool generate_keypair(u8 *private_key, u8 *public_key);

    bool compute_shared_secret(const u8 *private_key, const u8 *peer_public_key,
                               u8 *shared_secret);

    bool sign_ecdsa(const u8 *private_key, const u8 *hash, u32 hash_len,
                   u8 *signature);

    bool verify_ecdsa(const u8 *public_key, const u8 *hash, u32 hash_len,
                     const u8 *signature);
    bool derive_public_key(const u8* private_key, u8* public_key);
    bool generate_random_bytes(u8* buffer, u32 u32);
}
