#pragma once
#include "../NativeCrypto.h"

namespace NativeCrypto::Crypto::XOR_Internal {
    void xor_process(const u8 *data, u32 data_len, const char *key, u32 key_len, u8 *output);

    u32 get_key_length(const char *key);

    u32 get_vector_size(const void *vector_ptr);

    const u8 *get_vector_data(const void *vector_ptr);

    void resize_vector(void *vector_ptr, u32 new_size);

    u8 *get_vector_data_mutable(void *vector_ptr);
}
