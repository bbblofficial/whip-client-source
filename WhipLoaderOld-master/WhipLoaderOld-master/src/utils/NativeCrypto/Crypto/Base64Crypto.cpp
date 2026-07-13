#include "utils/NativeCrypto/Crypto/Base64Crypto.h"

#include <new>

#include "utils/NativeCrypto/NativeCrypto.h"

namespace NativeCrypto::Crypto {
    char *encodeBase64(const u8 *data, u32 data_len, u32 *output_len) {
        if (!data || data_len == 0) {
            if (output_len) *output_len = 0;
            return nullptr;
        }

        const u32 encoded_size = ((data_len + 2) / 3) * 4;

        const auto encoded = static_cast<char *>(Base64_Internal::secure_alloc(encoded_size + 1));
        if (!encoded) {
            if (output_len) *output_len = 0;
            return nullptr;
        }

        const auto base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                "abcdefghijklmnopqrstuvwxyz"
                "0123456789+/";;

        u32 i = 0;
        u32 j = 0;

        while (i + 3 <= data_len) {
            const u32 val = (static_cast<u32>(data[i]) << 16) |
                            (static_cast<u32>(data[i + 1]) << 8) |
                            static_cast<u32>(data[i + 2]);

            encoded[j++] = base64_chars[(val >> 18) & 0x3F];
            encoded[j++] = base64_chars[(val >> 12) & 0x3F];
            encoded[j++] = base64_chars[(val >> 6) & 0x3F];
            encoded[j++] = base64_chars[val & 0x3F];

            i += 3;
        }

        if (i < data_len) {
            u32 val = static_cast<u32>(data[i]) << 16;

            if (i + 1 < data_len) {
                val |= static_cast<u32>(data[i + 1]) << 8;
            }

            encoded[j++] = base64_chars[(val >> 18) & 0x3F];
            encoded[j++] = base64_chars[(val >> 12) & 0x3F];

            if (i + 1 < data_len) {
                encoded[j++] = base64_chars[(val >> 6) & 0x3F];
                encoded[j++] = '=';
            } else {
                encoded[j++] = '=';
                encoded[j++] = '=';
            }
        }

        encoded[j] = '\0';

        if (output_len) {
            *output_len = j;
        }

        return encoded;
    }

    u8 *decodeBase64(const char *input, u32 *output_len) {
        if (!input || !output_len) {
            return nullptr;
        }

        const auto base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                "abcdefghijklmnopqrstuvwxyz"
                "0123456789+/";;

        u32 input_len = 0;

        while (input[input_len] != '\0') {
            char c = input[input_len];
            if (Utils::strchr_safe(base64_chars, c) == nullptr && c != '=') {
                break;
            }
            input_len++;
        }

        const u32 max_output_size = (input_len * 3) / 4 + 1;
        const auto decoded = static_cast<u8 *>(Base64_Internal::secure_alloc(max_output_size));
        if (!decoded) {
            *output_len = 0;
            return nullptr;
        }

        u32 bit_stream = 0;
        u32 counter = 0;
        u32 offset = 0;
        u32 out_pos = 0;

        for (u32 i = 0; i < input_len; i++) {
            char c = input[i];

            if (const char *pos = Utils::strchr_safe(base64_chars, c)) {
                const u32 num_val = pos - base64_chars;
                offset = 18 - (counter % 4) * 6;
                bit_stream += num_val << offset;

                if (offset == 12) {
                    decoded[out_pos++] = (bit_stream >> 16) & 0xFF;
                }
                if (offset == 6) {
                    decoded[out_pos++] = (bit_stream >> 8) & 0xFF;
                }
                if (offset == 0 && counter != 4) {
                    decoded[out_pos++] = bit_stream & 0xFF;
                    bit_stream = 0;
                }
                counter++;
            } else if (c != '=') {
                Base64_Internal::secure_free(decoded);
                *output_len = 0;
                return nullptr;
            }
        }

        *output_len = out_pos;
        return decoded;
    }

    void freeBase64(void *ptr) {
        Base64_Internal::secure_free(ptr);
    }

    namespace Base64_Internal {
        u8 get_base64_index(const u8 c) {
            const auto base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                    "abcdefghijklmnopqrstuvwxyz"
                    "0123456789+/";;
            if (const char *p = Utils::strchr_safe(base64_chars, c)) {
                return static_cast<u8>(p - base64_chars);
            }
            return 0;
        }

        void *secure_alloc(const u32 size) {
            return new(std::nothrow) u8[size];
        }

        void secure_free(void *ptr) {
            if (ptr) {
                delete[] static_cast<u8 *>(ptr);
            }
        }
    }
}
