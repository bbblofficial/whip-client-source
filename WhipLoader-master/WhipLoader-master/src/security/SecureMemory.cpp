#include "security/SecureMemory.h"
#include <algorithm>
#include <cstring>
#include <random>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <winnt.h>
#include <whipsyscall/WhipSysCall.h>
#endif

SecureBuffer::SecureBuffer(size_t size) : data_(nullptr), size_(0), capacity_(0) {
    if (size > 0) {
        data_ = new Byte[size];
        size_ = size;
        capacity_ = size;
        std::memset(data_, 0, size);
    }
}

SecureBuffer::SecureBuffer(const Byte* data, size_t size) : data_(nullptr), size_(0), capacity_(0) {
    if (data && size > 0) {
        data_ = new Byte[size];
        size_ = size;
        capacity_ = size;
        std::memcpy(data_, data, size);
    }
}

SecureBuffer::~SecureBuffer() {
    secureErase();
    delete[] data_;
}

SecureBuffer::SecureBuffer(SecureBuffer&& other) noexcept
    : data_(other.data_), size_(other.size_), capacity_(other.capacity_) {
    other.data_ = nullptr;
    other.size_ = 0;
    other.capacity_ = 0;
}

SecureBuffer& SecureBuffer::operator=(SecureBuffer&& other) noexcept {
    if (this != &other) {
        secureErase();
        delete[] data_;

        data_ = other.data_;
        size_ = other.size_;
        capacity_ = other.capacity_;

        other.data_ = nullptr;
        other.size_ = 0;
        other.capacity_ = 0;
    }
    return *this;
}

Byte* SecureBuffer::data() noexcept {
    return data_;
}

const Byte* SecureBuffer::data() const noexcept {
    return data_;
}

size_t SecureBuffer::size() const noexcept {
    return size_;
}

bool SecureBuffer::empty() const noexcept {
    return size_ == 0;
}

Byte& SecureBuffer::operator[](size_t index) {
    return data_[index];
}

const Byte& SecureBuffer::operator[](size_t index) const {
    return data_[index];
}

void SecureBuffer::resize(size_t newSize) {
    if (newSize == size_) {
        return;
    }

    if (newSize == 0) {
        clear();
        return;
    }

    if (newSize <= capacity_) {
        size_ = newSize;
        return;
    }

    Byte* newData = new Byte[newSize];
    if (data_) {
        std::memcpy(newData, data_, std::min(size_, newSize));
        secureErase();
        delete[] data_;
    }

    if (newSize > size_) {
        std::memset(newData + size_, 0, newSize - size_);
    }

    data_ = newData;
    size_ = newSize;
    capacity_ = newSize;
}

void SecureBuffer::clear() noexcept {
    secureErase();
    delete[] data_;
    data_ = nullptr;
    size_ = 0;
    capacity_ = 0;
}

void SecureBuffer::append(const Byte* data, size_t size) {
    if (!data || size == 0) {
        return;
    }

    size_t oldSize = size_;
    resize(size_ + size);
    std::memcpy(data_ + oldSize, data, size);
}

Bytes SecureBuffer::toBytes() const {
    if (!data_ || size_ == 0) {
        return Bytes{};
    }
    return Bytes(data_, data_ + size_);
}

ByteView SecureBuffer::view() const noexcept {
    if (!data_ || size_ == 0) {
        return ByteView{};
    }
    return ByteView(data_, size_);
}

void SecureBuffer::secureErase() noexcept {
    if (data_ && size_ > 0) {
        volatile Byte* ptr = data_;
        for (size_t i = 0; i < size_; ++i) {
            ptr[i] = 0;
        }
    }
}

SecureString::SecureString(std::string_view str) : data_(nullptr), length_(0) {
    if (!str.empty()) {
        length_ = str.length();
        data_ = new char[length_ + 1];
        std::memcpy(data_, str.data(), length_);
        data_[length_] = '\0';
    }
}

SecureString::SecureString(const char* str) : data_(nullptr), length_(0) {
    if (str) {
        length_ = std::strlen(str);
        if (length_ > 0) {
            data_ = new char[length_ + 1];
            std::memcpy(data_, str, length_);
            data_[length_] = '\0';
        }
    }
}

SecureString::~SecureString() {
    secureErase();
    delete[] data_;
}

SecureString::SecureString(SecureString&& other) noexcept
    : data_(other.data_), length_(other.length_) {
    other.data_ = nullptr;
    other.length_ = 0;
}

SecureString& SecureString::operator=(SecureString&& other) noexcept {
    if (this != &other) {
        secureErase();
        delete[] data_;

        data_ = other.data_;
        length_ = other.length_;

        other.data_ = nullptr;
        other.length_ = 0;
    }
    return *this;
}

const char* SecureString::c_str() const noexcept {
    return data_ ? data_ : "";
}

std::string_view SecureString::view() const noexcept {
    return data_ ? std::string_view(data_, length_) : std::string_view{};
}

size_t SecureString::length() const noexcept {
    return length_;
}

bool SecureString::empty() const noexcept {
    return length_ == 0;
}

void SecureString::clear() noexcept {
    secureErase();
    delete[] data_;
    data_ = nullptr;
    length_ = 0;
}

void SecureString::assign(std::string_view str) {
    secureErase();
    delete[] data_;

    if (!str.empty()) {
        length_ = str.length();
        data_ = new char[length_ + 1];
        std::memcpy(data_, str.data(), length_);
        data_[length_] = '\0';
    } else {
        data_ = nullptr;
        length_ = 0;
    }
}

void SecureString::secureErase() noexcept {
    if (data_ && length_ > 0) {
        volatile char* ptr = data_;
        for (size_t i = 0; i < length_; ++i) {
            ptr[i] = '\0';
        }
    }
}

void SecureMemoryUtils::secureZero(void* ptr, size_t size) noexcept {
    if (!ptr || size == 0) {
        return;
    }
    volatile unsigned char* p = static_cast<volatile unsigned char*>(ptr);
    for (size_t i = 0; i < size; ++i) {
        p[i] = 0;
    }
}

bool SecureMemoryUtils::constantTimeCompare(const void* a, const void* b, size_t size) noexcept {
    if (!a || !b) {
        return false;
    }

    const unsigned char* aa = static_cast<const unsigned char*>(a);
    const unsigned char* bb = static_cast<const unsigned char*>(b);

    unsigned char result = 0;
    for (size_t i = 0; i < size; ++i) {
        result |= aa[i] ^ bb[i];
    }

    return result == 0;
}

bool SecureMemoryUtils::randomBytes(Byte* buffer, size_t size) noexcept {
    if (!buffer || size == 0) {
        return false;
    }

#ifdef _WIN32
    // Resolve RtlGenRandom directly from ntdll export table (no bcrypt.dll import)
    // Uses PEB-based ntdll walk provided by WhipSysCall — avoids IAT entry.
    static BOOL(NTAPI* pRtlGenRandom)(PVOID, ULONG) = []() -> BOOL(NTAPI*)(PVOID, ULONG) {
        PVOID base = SyscallResolverHelpers::GetNtdllBase();
        if (!base) return nullptr;
        auto* b = static_cast<BYTE*>(base);
        auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(b);
        auto* nt  = reinterpret_cast<IMAGE_NT_HEADERS64*>(b + dos->e_lfanew);
        auto* exp = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(
            b + nt->OptionalHeader.DataDirectory[0].VirtualAddress);
        auto* names   = reinterpret_cast<DWORD*>(b + exp->AddressOfNames);
        auto* ords    = reinterpret_cast<WORD*> (b + exp->AddressOfNameOrdinals);
        auto* funcs   = reinterpret_cast<DWORD*>(b + exp->AddressOfFunctions);
        const char* target = "RtlGenRandom";
        for (DWORD i = 0; i < exp->NumberOfNames; i++) {
            const char* name = reinterpret_cast<const char*>(b + names[i]);
            bool match = true;
            for (int j = 0; ; j++) {
                if (name[j] != target[j]) { match = false; break; }
                if (!name[j]) break;
            }
            if (match)
                return reinterpret_cast<BOOL(NTAPI*)(PVOID, ULONG)>(b + funcs[ords[i]]);
        }
        return nullptr;
    }();

    if (pRtlGenRandom)
        return pRtlGenRandom(buffer, static_cast<ULONG>(size)) != FALSE;
    return false;
#else
    std::random_device rd;
    for (size_t i = 0; i < size; ++i) {
        buffer[i] = static_cast<Byte>(rd());
    }
    return true;
#endif
}