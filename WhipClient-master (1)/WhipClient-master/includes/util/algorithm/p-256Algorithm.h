

#ifndef P256_M_H
#define P256_M_H

#include <random>
#include <stdint.h>
#include <stddef.h>

#define P256_SUCCESS            0
#define P256_RANDOM_FAILED      -1
#define P256_INVALID_PUBKEY     -2
#define P256_INVALID_PRIVKEY    -3
#define P256_INVALID_SIGNATURE  -4

#ifdef __cplusplus
extern "C" {
#endif

inline int p256_generate_random(uint8_t *output, unsigned output_size) {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);

    for (unsigned i = 0; i < output_size; i++) {
        output[i] = static_cast<uint8_t>(dis(gen));
    }

    return 0;
}

int p256_gen_keypair(uint8_t priv[32], uint8_t pub[64]);

int p256_ecdh_shared_secret(uint8_t secret[32],
                            const uint8_t priv[32], const uint8_t pub[64]);

int p256_ecdsa_sign(uint8_t sig[64], const uint8_t priv[32],
                    const uint8_t *hash, size_t hlen);

int p256_ecdsa_verify(const uint8_t sig[64], const uint8_t pub[64],
                      const uint8_t *hash, size_t hlen);

#ifdef __cplusplus
}
#endif

#endif
