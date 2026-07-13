#include "utils/NativeCrypto/NativeCrypto.h"
#include <cstddef>

namespace NativeCrypto::Utils {
    u32 strlen_safe(const char *str) {
        if (!str) {
            return 0;
        }

        u32 len = 0;
        while (str[len] != '\0') {
            len++;
        }
        return len;
    }

    void memcopy_safe(const void *src, void *dst, const u32 size) {
        if (!src || !dst || size == 0) {
            return;
        }

        const auto *s = static_cast<const u8 *>(src);
        auto *d = static_cast<u8 *>(dst);

        for (u32 i = 0; i < size; i++) {
            d[i] = s[i];
        }
    }

    void memzero_safe(void *ptr, const u32 size) {
        if (!ptr || size == 0) {
            return;
        }

        auto *p = static_cast<u8 *>(ptr);

        // Use volatile to prevent compiler optimization
        volatile u8 *vp = p;
        for (u32 i = 0; i < size; i++) {
            vp[i] = 0;
        }
    }

    char* strchr_safe(const char* str, const char c) {
        if (!str) {
            return nullptr;
        }

        while (*str != '\0') {
            if (*str == c) {
                return const_cast<char *>(str);
            }
            str++;
        }

        return nullptr;
    }
}

