#include "utils/NativeCrypto/Crypto/SHA256Crypto.h"
#include "utils/sha256/sha256.h"
#include "utils/NativeCrypto/NativeCrypto.h"
#include <cstring>

namespace NativeCrypto::Crypto {
    void hashSHA256(const u8 *data, u32 data_len, u8 *hash) {
        SHA256_Internal::compute_hash_bytes(data, data_len, hash);
    }

    void hashSHA256Hex(const u8 *data, u32 data_len, char *hash_hex) {
        SHA256_Internal::compute_hash_hex(data, data_len, hash_hex);
    }

    bool hmacSHA256(const u8 *key, u32 key_len,
                    const u8 *data, u32 data_len,
                    u8 *hmac_out) {
        return SHA256_Internal::compute_hmac(key, key_len, data, data_len, hmac_out);
    }

    namespace SHA256_Internal {

        void compute_hash_bytes(const u8 *data, u32 data_len, u8 *hash) {
            if (!data || !hash) {
                return;
            }

            sha256_bytes(data, data_len, hash);
        }

        void compute_hash_hex(const u8 *data, u32 data_len, char *hash_hex) {
            if (!data || !hash_hex) {
                return;
            }

            sha256_hex(data, data_len, hash_hex);
        }

        bool compute_hmac(const u8 *key, u32 key_len,
                          const u8 *data, u32 data_len,
                          u8 *hmac_out) {
            if (!key || !data || !hmac_out) {
                return false;
            }

            // HMAC-SHA256 implementation following RFC 2104
            constexpr u32 BLOCK_SIZE = 64;  // SHA-256 block size
            constexpr u32 HASH_SIZE = 32;   // SHA-256 output size

            u8 key_block[BLOCK_SIZE] = {0};

            // If key is longer than block size, hash it first
            if (key_len > BLOCK_SIZE) {
                sha256_bytes(key, key_len, key_block);
            } else {
                memcpy(key_block, key, key_len);
            }

            // Compute inner and outer padded keys
            u8 i_key_pad[BLOCK_SIZE];
            u8 o_key_pad[BLOCK_SIZE];

            for (u32 i = 0; i < BLOCK_SIZE; i++) {
                i_key_pad[i] = key_block[i] ^ 0x36;
                o_key_pad[i] = key_block[i] ^ 0x5c;
            }

            // Inner hash: H(i_key_pad || message)
            u8 *inner_data = new u8[BLOCK_SIZE + data_len];
            memcpy(inner_data, i_key_pad, BLOCK_SIZE);
            memcpy(inner_data + BLOCK_SIZE, data, data_len);

            u8 inner_hash[HASH_SIZE];
            sha256_bytes(inner_data, BLOCK_SIZE + data_len, inner_hash);
            delete[] inner_data;

            // Outer hash: H(o_key_pad || inner_hash)
            u8 outer_data[BLOCK_SIZE + HASH_SIZE];
            memcpy(outer_data, o_key_pad, BLOCK_SIZE);
            memcpy(outer_data + BLOCK_SIZE, inner_hash, HASH_SIZE);

            sha256_bytes(outer_data, BLOCK_SIZE + HASH_SIZE, hmac_out);

            // Secure cleanup
            memset(key_block, 0, BLOCK_SIZE);
            memset(i_key_pad, 0, BLOCK_SIZE);
            memset(o_key_pad, 0, BLOCK_SIZE);
            memset(inner_hash, 0, HASH_SIZE);
            memset(outer_data, 0, BLOCK_SIZE + HASH_SIZE);

            return true;
        }
    }
}