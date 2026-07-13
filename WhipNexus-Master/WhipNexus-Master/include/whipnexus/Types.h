#ifndef WHIPNEXUS_TYPES_H
#define WHIPNEXUS_TYPES_H

// Types de base - primitifs C++ sans includes
using byte = unsigned char;
using i16 = short;
using u16 = unsigned short;
using i32 = int;
using u32 = unsigned int;
using i64 = long long;
using u64 = unsigned long long;

// Buffer sans STL
struct Buffer {
    byte* data;
    u32 size;
    u32 capacity;

    Buffer();
    explicit Buffer(u32 cap);
    ~Buffer();

    void resize(u32 newSize);
    void clear();

    Buffer(const Buffer&) = delete;
    Buffer& operator=(const Buffer&) = delete;

    Buffer(Buffer&& other) noexcept;
    Buffer& operator=(Buffer&& other) noexcept;
};

// String simple UTF-8
struct String {
    char* data;
    u16 length;

    String();
    explicit String(const char* str);
    ~String();

    void set(const char* str);
    void clear();

    String(const String& other);
    String& operator=(const String& other);
    String(String&& other) noexcept;
    String& operator=(String&& other) noexcept;
};

#endif // WHIPNEXUS_TYPES_H