#pragma once

#include "../util/Types.h"
#include <memory>
#include <cstring>

template<typename T>
class SecureValue {
public:
    SecureValue() = default;
    explicit SecureValue(const T& value) : value_(value) {}
    explicit SecureValue(T&& value) : value_(std::move(value)) {}

    ~SecureValue() { clear(); }

    SecureValue(const SecureValue&) = delete;
    SecureValue& operator=(const SecureValue&) = delete;

    SecureValue(SecureValue&& other) noexcept : value_(std::move(other.value_)) {
        other.clear();
    }

    SecureValue& operator=(SecureValue&& other) noexcept {
        if (this != &other) {
            clear();
            value_ = std::move(other.value_);
            other.clear();
        }
        return *this;
    }

    T& get() noexcept { return value_; }
    const T& get() const noexcept { return value_; }

    T* operator->() noexcept { return &value_; }
    const T* operator->() const noexcept { return &value_; }

    T& operator*() noexcept { return value_; }
    const T& operator*() const noexcept { return value_; }

    void clear() noexcept {
        volatile auto* ptr = reinterpret_cast<volatile unsigned char*>(&value_);
        for (size_t i = 0; i < sizeof(T); ++i) {
            ptr[i] = 0;
        }
    }

private:
    T value_{};
};

class SecureBuffer {
public:
    SecureBuffer() = default;
    explicit SecureBuffer(size_t size);
    SecureBuffer(const Byte* data, size_t size);
    ~SecureBuffer();

    SecureBuffer(const SecureBuffer&) = delete;
    SecureBuffer& operator=(const SecureBuffer&) = delete;

    SecureBuffer(SecureBuffer&& other) noexcept;
    SecureBuffer& operator=(SecureBuffer&& other) noexcept;

    [[nodiscard]] Byte* data() noexcept;
    [[nodiscard]] const Byte* data() const noexcept;
    [[nodiscard]] size_t size() const noexcept;
    [[nodiscard]] bool empty() const noexcept;

    [[nodiscard]] Byte& operator[](size_t index);
    [[nodiscard]] const Byte& operator[](size_t index) const;

    void resize(size_t newSize);
    void clear() noexcept;
    void append(const Byte* data, size_t size);

    [[nodiscard]] Bytes toBytes() const;
    [[nodiscard]] ByteView view() const noexcept;

private:
    void secureErase() noexcept;

    Byte* data_ = nullptr;
    size_t size_ = 0;
    size_t capacity_ = 0;
};

class SecureString {
public:
    SecureString() = default;
    explicit SecureString(std::string_view str);
    explicit SecureString(const char* str);
    ~SecureString();

    SecureString(const SecureString&) = delete;
    SecureString& operator=(const SecureString&) = delete;

    SecureString(SecureString&& other) noexcept;
    SecureString& operator=(SecureString&& other) noexcept;

    [[nodiscard]] const char* c_str() const noexcept;
    [[nodiscard]] std::string_view view() const noexcept;
    [[nodiscard]] size_t length() const noexcept;
    [[nodiscard]] bool empty() const noexcept;

    void clear() noexcept;
    void assign(std::string_view str);

private:
    void secureErase() noexcept;

    char* data_ = nullptr;
    size_t length_ = 0;
};

struct SecureMemoryUtils {
    static void secureZero(void* ptr, size_t size) noexcept;

    [[nodiscard]] static bool constantTimeCompare(const void* a, const void* b, size_t size) noexcept;

    [[nodiscard]] static bool randomBytes(Byte* buffer, size_t size) noexcept;
};

// Template specialization for fixed-size byte arrays (encrypted in memory)
template<size_t N>
struct SecureByteArray {
    Byte data[N];

    SecureByteArray() {
        SecureMemoryUtils::secureZero(data, N);
    }

    ~SecureByteArray() {
        volatile Byte* p = data;
        for (size_t i = 0; i < N; ++i) p[i] = 0;
    }

    SecureByteArray(const SecureByteArray&) = delete;
    SecureByteArray& operator=(const SecureByteArray&) = delete;
    SecureByteArray(SecureByteArray&&) = delete;
    SecureByteArray& operator=(SecureByteArray&&) = delete;
};