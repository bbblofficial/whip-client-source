#pragma once
#include "../NativeCrypto.h"

namespace NativeCrypto::Crypto::SHA256_Internal {
    void compute_hash_bytes(const u8 *data, u32 data_len, u8 *hash);

    void compute_hash_hex(const u8 *data, u32 data_len, char *hash_hex);
    bool compute_hmac(const u8* key, u32 u32, const u8* data, NativeCrypto::u32 data_len, u8* hmac_out);
}
