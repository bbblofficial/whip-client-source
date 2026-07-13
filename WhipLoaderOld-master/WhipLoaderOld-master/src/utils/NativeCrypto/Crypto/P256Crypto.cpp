#include "utils/NativeCrypto/Crypto/P256Crypto.h"
#include "utils/curveP256m/p256-m.h"
#include "utils/NativeCrypto/NativeCrypto.h"

namespace NativeCrypto::Crypto {
    bool generateP256KeyPair(u8 *private_key, u8 *public_key) {
        return P256_Internal::generate_keypair(private_key, public_key);
    }

    bool computeP256SharedSecret(const u8 *private_key, const u8 *peer_public_key,
                                u8 *shared_secret) {
        return P256_Internal::compute_shared_secret(private_key, peer_public_key, shared_secret);
    }

    bool signP256ECDSA(const u8 *private_key, const u8 *hash, u32 hash_len,
                      u8 *signature) {
        return P256_Internal::sign_ecdsa(private_key, hash, hash_len, signature);
    }

    bool verifyP256ECDSA(const u8 *public_key, const u8 *hash, u32 hash_len,
                        const u8 *signature) {
        return P256_Internal::verify_ecdsa(public_key, hash, hash_len, signature);
    }

    bool deriveP256PublicKey(const u8 *private_key, u8 *public_key) {
        return P256_Internal::derive_public_key(private_key, public_key);
    }

    bool generateRandomBytes(u8 *buffer, u32 length) {
        return P256_Internal::generate_random_bytes(buffer, length);
    }

    namespace P256_Internal {
        bool generate_keypair(u8 *private_key, u8 *public_key) {
            if (!private_key || !public_key) {
                return false;
            }

            int result = p256_gen_keypair(private_key, public_key);

            return result == P256_SUCCESS;
        }

        bool compute_shared_secret(const u8 *private_key, const u8 *peer_public_key,
                                   u8 *shared_secret) {
            if (!private_key || !peer_public_key || !shared_secret) {
                return false;
            }

            int result = p256_ecdh_shared_secret(shared_secret, private_key, peer_public_key);

            return result == P256_SUCCESS;
        }

        bool sign_ecdsa(const u8 *private_key, const u8 *hash, u32 hash_len,
                       u8 *signature) {
            if (!private_key || !hash || !signature) {
                return false;
            }

            int result = p256_ecdsa_sign(signature, private_key, hash, hash_len);

            return result == P256_SUCCESS;
        }

        bool verify_ecdsa(const u8 *public_key, const u8 *hash, u32 hash_len,
                         const u8 *signature) {
            if (!public_key || !hash || !signature) {
                return false;
            }

            int result = p256_ecdsa_verify(signature, public_key, hash, hash_len);

            return result == P256_SUCCESS;
        }

        bool derive_public_key(const u8 *private_key, u8 *public_key) {
            if (!private_key || !public_key) {
                return false;
            }

            // Use p256-m to derive public key from private key
            int result = p256_public_from_private(public_key, private_key);

            return result == P256_SUCCESS;
        }

        bool generate_random_bytes(u8 *buffer, u32 length) {
            if (!buffer || length == 0) {
                return false;
            }

            // Use p256-m random generation
            return p256_generate_random(buffer, length) == P256_SUCCESS;
        }
    }
}
