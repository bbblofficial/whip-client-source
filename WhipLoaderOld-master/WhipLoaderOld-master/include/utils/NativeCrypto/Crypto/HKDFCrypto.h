#pragma once
#include "../NativeCrypto.h"

namespace NativeCrypto::Crypto::HKDF_Internal {
    bool derive_key_full(const u8 *salt, u32 salt_len,
                        const u8 *ikm, u32 ikm_len,
                        const u8 *info, u32 info_len,
                        u8 *okm, u32 okm_len);

    bool extract_phase(const u8 *salt, u32 salt_len,
                      const u8 *ikm, u32 ikm_len,
                      u8 *prk);

    bool expand_phase(const u8 *prk, u32 prk_len,
                     const u8 *info, u32 info_len,
                     u8 *okm, u32 okm_len);
}
