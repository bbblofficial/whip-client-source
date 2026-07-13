#ifndef HKDF_SHA256_H
#define HKDF_SHA256_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define HKDF_SHA256_HASH_SIZE 32

/*
 * HKDF-SHA256: HMAC-based Extract-and-Expand Key Derivation Function
 *
 * This is a simplified version that uses only SHA-256.
 * Based on RFC 5869.
 */

/*
 * hkdf_sha256
 *
 * Description:
 *      Complete HKDF operation (extract + expand) using SHA-256.
 *
 * Parameters:
 *      salt: Optional salt value (can be NULL)
 *      salt_len: Length of salt (ignored if salt is NULL)
 *      ikm: Input keying material
 *      ikm_len: Length of input keying material
 *      info: Optional context/application info (can be NULL)
 *      info_len: Length of info (ignored if info is NULL)
 *      okm: Output buffer for derived key material
 *      okm_len: Desired length of output (max 255 * 32 = 8160 bytes)
 *
 * Returns:
 *      0 on success, -1 on error
 */
int hkdf_sha256(
    const uint8_t *salt, size_t salt_len,
    const uint8_t *ikm, size_t ikm_len,
    const uint8_t *info, size_t info_len,
    uint8_t *okm, size_t okm_len
);

/*
 * hkdf_sha256_extract
 *
 * Description:
 *      HKDF extraction step using SHA-256.
 *      Produces a pseudo-random key from input keying material.
 *
 * Parameters:
 *      salt: Optional salt value (can be NULL)
 *      salt_len: Length of salt
 *      ikm: Input keying material
 *      ikm_len: Length of input keying material
 *      prk: Output buffer for pseudo-random key (must be 32 bytes)
 *
 * Returns:
 *      0 on success, -1 on error
 */
int hkdf_sha256_extract(
    const uint8_t *salt, size_t salt_len,
    const uint8_t *ikm, size_t ikm_len,
    uint8_t prk[HKDF_SHA256_HASH_SIZE]
);

/*
 * hkdf_sha256_expand
 *
 * Description:
 *      HKDF expansion step using SHA-256.
 *      Expands a pseudo-random key into output keying material.
 *
 * Parameters:
 *      prk: Pseudo-random key (from extract step)
 *      prk_len: Length of prk (should be 32 bytes)
 *      info: Optional context/application info (can be NULL)
 *      info_len: Length of info
 *      okm: Output buffer for derived key material
 *      okm_len: Desired length of output (max 255 * 32 = 8160 bytes)
 *
 * Returns:
 *      0 on success, -1 on error
 */
int hkdf_sha256_expand(
    const uint8_t *prk, size_t prk_len,
    const uint8_t *info, size_t info_len,
    uint8_t *okm, size_t okm_len
);

#ifdef __cplusplus
}
#endif

#endif /* HKDF_SHA256_H */
