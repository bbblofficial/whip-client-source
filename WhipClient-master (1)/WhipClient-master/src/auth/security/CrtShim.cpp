

#include <windows.h>

static int __cdecl memicmp_impl(const void* buf1, const void* buf2, size_t count) {
    const unsigned char* p1 = (const unsigned char*)buf1;
    const unsigned char* p2 = (const unsigned char*)buf2;
    for (size_t i = 0; i < count; ++i) {
        unsigned char c1 = p1[i];
        unsigned char c2 = p2[i];
        if (c1 >= 'A' && c1 <= 'Z') c1 += 32;
        if (c2 >= 'A' && c2 <= 'Z') c2 += 32;
        if (c1 != c2) return (int)c1 - (int)c2;
    }
    return 0;
}

typedef int(__cdecl* memicmp_fn)(const void*, const void*, size_t);

extern "C" {
    memicmp_fn __imp__memicmp = memicmp_impl;
}
