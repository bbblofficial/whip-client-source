#pragma once
#include "../NativeCrypto.h"

namespace NativeCrypto {
    namespace Crypto {
        namespace Base64_Internal {
            const char *get_base64_chars();

            u8 get_base64_index(u8 c);

            // Allocation sécurisée sans new/delete visible
            void *secure_alloc(u32 size);

            void secure_free(void *ptr);
        }
    }
}
