#pragma once
#include <vector>
#include <memory>

class ThreadSafeBuffer {
private:
    static thread_local std::vector<std::unique_ptr<char[]>> bufferPool;

public:
    static const char* allocate(size_t size) {
        while (bufferPool.size() > 3) {
            bufferPool.erase(bufferPool.begin());
        }

        std::unique_ptr<char[]> newBuffer(new char[size]);
        char* buffer = newBuffer.get();
        bufferPool.push_back(std::move(newBuffer));
        return buffer;
    }
};