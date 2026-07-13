#pragma optimize("", off)
#include "whipnexus/Types.h"
#include "whipnexus/SyscallManager.h"

#ifdef BUILD_WITH_VMPROTECT
#include "VMProtectSDK.h"
#endif

// Buffer implementation
Buffer::Buffer() : data(nullptr), size(0), capacity(0) {
    VMProtectBeginUltra("Buffer_ctor");
    VMProtectEnd();
}

Buffer::Buffer(u32 cap) : data(nullptr), size(0), capacity(cap) {
    VMProtectBeginUltra("Buffer_ctor_cap");
    if (cap > 0) {
        data = (byte*)SyscallManager::GetWrappers()->HeapAlloc(cap);
    }
    VMProtectEnd();
}

Buffer::~Buffer() {
    VMProtectBeginUltra("Buffer_dtor");
    clear();
    VMProtectEnd();
}

void Buffer::resize(u32 newSize) {
    VMProtectBeginUltra("Buffer_resize");
    if (newSize > capacity) {
        u32 newCap = newSize * 2;
        byte* newData = (byte*)SyscallManager::GetWrappers()->HeapReAlloc(data, newCap);
        if (newData) {
            data = newData;
            capacity = newCap;
        }
    }
    size = newSize;
    VMProtectEnd();
}

void Buffer::clear() {
    VMProtectBeginUltra("Buffer_clear");
    if (data) {
        if (capacity > 0) SyscallManager::SecureZero(data, capacity);
        SyscallManager::GetWrappers()->HeapFree(data);
        data = nullptr;
    }
    size = 0;
    capacity = 0;
    VMProtectEnd();
}

Buffer::Buffer(Buffer&& other) noexcept
    : data(other.data), size(other.size), capacity(other.capacity) {
    VMProtectBeginUltra("Buffer_move_ctor");
    other.data = nullptr;
    other.size = 0;
    other.capacity = 0;
    VMProtectEnd();
}

Buffer& Buffer::operator=(Buffer&& other) noexcept {
    VMProtectBeginUltra("Buffer_move_assign");
    if (this != &other) {
        clear();
        data = other.data;
        size = other.size;
        capacity = other.capacity;
        other.data = nullptr;
        other.size = 0;
        other.capacity = 0;
    }
    return *this;
    VMProtectEnd();
}

// String implementation
String::String() : data(nullptr), length(0) {
    VMProtectBeginUltra("String_ctor");
    VMProtectEnd();
}

String::String(const char* str) : data(nullptr), length(0) {
    VMProtectBeginUltra("String_ctor_str");
    set(str);
    VMProtectEnd();
}

String::~String() {
    VMProtectBeginUltra("String_dtor");
    clear();
    VMProtectEnd();
}

void String::set(const char* str) {
    VMProtectBeginUltra("String_set");
    clear();
    if (str) {
        length = (u16)SyscallManager::StrLen(str);
        if (length > 0) {
            data = (char*)SyscallManager::GetWrappers()->HeapAlloc(length + 1);
            SyscallManager::SecureMemCpy(data, str, length);
            data[length] = '\0';
        }
    }
    VMProtectEnd();
}

void String::clear() {
    VMProtectBeginUltra("String_clear");
    if (data) {
        if (length > 0) SyscallManager::SecureZero(data, length + 1);
        SyscallManager::GetWrappers()->HeapFree(data);
        data = nullptr;
    }
    length = 0;
    VMProtectEnd();
}

String::String(const String& other) : data(nullptr), length(0) {
    VMProtectBeginUltra("String_copy_ctor");
    if (other.data && other.length > 0) {
        length = other.length;
        data = (char*)SyscallManager::GetWrappers()->HeapAlloc(length + 1);
        SyscallManager::SecureMemCpy(data, other.data, length);
        data[length] = '\0';
    }
    VMProtectEnd();
}

String& String::operator=(const String& other) {
    VMProtectBeginUltra("String_copy_assign");
    if (this != &other) {
        clear();
        if (other.data && other.length > 0) {
            length = other.length;
            data = (char*)SyscallManager::GetWrappers()->HeapAlloc(length + 1);
            SyscallManager::SecureMemCpy(data, other.data, length);
            data[length] = '\0';
        }
    }
    return *this;
    VMProtectEnd();
}

String::String(String&& other) noexcept : data(other.data), length(other.length) {
    VMProtectBeginUltra("String_move_ctor");
    other.data = nullptr;
    other.length = 0;
    VMProtectEnd();
}

String& String::operator=(String&& other) noexcept {
    VMProtectBeginUltra("String_move_assign");
    if (this != &other) {
        clear();
        data = other.data;
        length = other.length;
        other.data = nullptr;
        other.length = 0;
    }
    return *this;
    VMProtectEnd();
}