#include "util/algorithm/HKDFAlgorithm.h"

#include "util/algorithm/sha256.h"
#include <string.h>

static void hmac_sha256(
    const uint8_t *key, size_t key_len,
    const uint8_t *data, size_t data_len,
    uint8_t output[HKDF_SHA256_HASH_SIZE]
) {
    uint8_t k_ipad[64];
    uint8_t k_opad[64];
    uint8_t temp_key[HKDF_SHA256_HASH_SIZE];
    struct sha256 sha;
    size_t i;

    if (key_len > 64) {
        sha256_bytes(key, key_len, temp_key);
        key = temp_key;
        key_len = HKDF_SHA256_HASH_SIZE;
    }

    memset(k_ipad, 0x36, 64);
    memset(k_opad, 0x5c, 64);

    for (i = 0; i < key_len; i++) {
        k_ipad[i] ^= key[i];
        k_opad[i] ^= key[i];
    }

    sha256_init(&sha);
    sha256_append(&sha, k_ipad, 64);
    sha256_append(&sha, data, data_len);
    sha256_finalize_bytes(&sha, output);

    sha256_init(&sha);
    sha256_append(&sha, k_opad, 64);
    sha256_append(&sha, output, HKDF_SHA256_HASH_SIZE);
    sha256_finalize_bytes(&sha, output);
}

int hkdf_sha256_extract(
    const uint8_t *salt, size_t salt_len,
    const uint8_t *ikm, size_t ikm_len,
    uint8_t prk[HKDF_SHA256_HASH_SIZE]
) {
    uint8_t null_salt[HKDF_SHA256_HASH_SIZE];

    if (!ikm || !prk) {
        return -1;
    }

    if (!salt) {
        memset(null_salt, 0, HKDF_SHA256_HASH_SIZE);
        salt = null_salt;
        salt_len = HKDF_SHA256_HASH_SIZE;
    }

    hmac_sha256(salt, salt_len, ikm, ikm_len, prk);

    return 0;
}

int hkdf_sha256_expand(
    const uint8_t *prk, size_t prk_len,
    const uint8_t *info, size_t info_len,
    uint8_t *okm, size_t okm_len
) {
    uint8_t T[HKDF_SHA256_HASH_SIZE];
    uint8_t counter;
    size_t n, i, offset;
    struct sha256 sha;
    uint8_t temp_input[HKDF_SHA256_HASH_SIZE + 256 + 1];
    size_t temp_len;

    if (!prk || !okm || okm_len == 0) {
        return -1;
    }

    if (prk_len < HKDF_SHA256_HASH_SIZE) {
        return -1;
    }

    n = (okm_len + HKDF_SHA256_HASH_SIZE - 1) / HKDF_SHA256_HASH_SIZE;

    if (n > 255) {
        return -1;
    }

    if (!info) {
        info_len = 0;
    }

    offset = 0;
    for (i = 1; i <= n; i++) {
        counter = (uint8_t) i;

        temp_len = 0;

        if (i > 1) {
            memcpy(temp_input + temp_len, T, HKDF_SHA256_HASH_SIZE);
            temp_len += HKDF_SHA256_HASH_SIZE;
        }

        if (info_len > 0) {
            memcpy(temp_input + temp_len, info, info_len);
            temp_len += info_len;
        }

        temp_input[temp_len] = counter;
        temp_len++;

        hmac_sha256(prk, prk_len, temp_input, temp_len, T);

        size_t copy_len = HKDF_SHA256_HASH_SIZE;
        if (offset + copy_len > okm_len) {
            copy_len = okm_len - offset;
        }

        memcpy(okm + offset, T, copy_len);
        offset += copy_len;
    }

    return 0;
}

int hkdf_sha256(
    const uint8_t *salt, size_t salt_len,
    const uint8_t *ikm, size_t ikm_len,
    const uint8_t *info, size_t info_len,
    uint8_t *okm, size_t okm_len
) {
    uint8_t prk[HKDF_SHA256_HASH_SIZE];
    int ret;

    ret = hkdf_sha256_extract(salt, salt_len, ikm, ikm_len, prk);
    if (ret != 0) {
        return ret;
    }

    ret = hkdf_sha256_expand(prk, HKDF_SHA256_HASH_SIZE, info, info_len, okm, okm_len);

    memset(prk, 0, HKDF_SHA256_HASH_SIZE);

    return ret;
}
