#include "utils/NativeCrypto/Crypto/HKDFCrypto.h"
#include "utils/hkdf/hkdf.h"
#include "utils/NativeCrypto/NativeCrypto.h"

namespace NativeCrypto::Crypto {
    bool deriveKeyHKDF(const u8 *salt, u32 salt_len,
                       const u8 *ikm, u32 ikm_len,
                       const u8 *info, u32 info_len,
                       u8 *okm, u32 okm_len) {
        return HKDF_Internal::derive_key_full(salt, salt_len, ikm, ikm_len,
                                              info, info_len, okm, okm_len);
    }

    bool extractHKDF(const u8 *salt, u32 salt_len,
                     const u8 *ikm, u32 ikm_len,
                     u8 *prk) {
        return HKDF_Internal::extract_phase(salt, salt_len, ikm, ikm_len, prk);
    }

    bool expandHKDF(const u8 *prk, u32 prk_len,
                    const u8 *info, u32 info_len,
                    u8 *okm, u32 okm_len) {
        return HKDF_Internal::expand_phase(prk, prk_len, info, info_len, okm, okm_len);
    }

    namespace HKDF_Internal {
        bool derive_key_full(const u8 *salt, u32 salt_len,
                             const u8 *ikm, u32 ikm_len,
                             const u8 *info, u32 info_len,
                             u8 *okm, u32 okm_len) {
            if (!ikm || !okm || okm_len == 0) {
                return false;
            }

            int result = hkdf_sha256(salt, salt_len, ikm, ikm_len,
                                     info, info_len, okm, okm_len);

            return result == 0;
        }

        bool extract_phase(const u8 *salt, u32 salt_len,
                           const u8 *ikm, u32 ikm_len,
                           u8 *prk) {
            if (!ikm || !prk) {
                return false;
            }

            int result = hkdf_sha256_extract(salt, salt_len, ikm, ikm_len, prk);

            return result == 0;
        }

        bool expand_phase(const u8 *prk, u32 prk_len,
                          const u8 *info, u32 info_len,
                          u8 *okm, u32 okm_len) {
            if (!prk || !okm || okm_len == 0) {
                return false;
            }

            int result = hkdf_sha256_expand(prk, prk_len, info, info_len, okm, okm_len);

            return result == 0;
        }
    }
}
