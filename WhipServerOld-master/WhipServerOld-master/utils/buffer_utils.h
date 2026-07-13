#pragma once
#include <cstddef>
#include <cstring>
#include <vector>
#include <memory>
#include <iostream>

inline bool compareBuffers(const void* buf1, const void* buf2, size_t len) {
    return memcmp(buf1, buf2, len) == 0;
}

inline void copyBuffer(void* dest, const void* src, size_t len) {
    memcpy(dest, src, len);
}

inline size_t safeStringLength(const char* str, size_t maxLen) {
    size_t i = 0;
    while (i < maxLen && str[i] != '\0') {
        i++;
    }
    return i;
}

inline void safeStringCopy(char* dest, const char* src, size_t destSize) {
    if (destSize == 0) return;

    size_t i = 0;
    while (i < destSize - 1 && src[i] != '\0') {
        dest[i] = src[i];
        i++;
    }
    dest[i] = '\0'; // Toujours ajouter le caractère nul à la fin
}

class ThreadLocalBufferManager {
private:
    static thread_local std::vector<std::unique_ptr<char[]>> buffers;
    static constexpr size_t MAX_BUFFERS = 5;

public:
    char* allocate(size_t size) {
        try {
            // Cleanup old buffers if we have too many
            while (buffers.size() > MAX_BUFFERS) {
                buffers.erase(buffers.begin());
            }

            // Allocate new buffer
            std::unique_ptr<char[]> newBuffer = std::make_unique<char[]>(size);
            char* result = newBuffer.get();

            // Keep buffer in our list and return pointer
            buffers.push_back(std::move(newBuffer));
            return result;
        }
        catch (const std::exception& e) {
            std::cerr << "Buffer allocation failed: " << e.what() << std::endl;
            return nullptr;
        }
    }
};

// Définition de la variable statique thread_local
thread_local std::vector<std::unique_ptr<char[]>> ThreadLocalBufferManager::buffers;