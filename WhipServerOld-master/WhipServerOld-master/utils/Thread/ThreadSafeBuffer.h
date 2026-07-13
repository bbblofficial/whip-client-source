#pragma once
#include <vector>
#include <memory>
#include <cstring>

class ThreadSafeBuffer {
private:
    static thread_local std::vector<std::unique_ptr<char[]>> bufferPool;
    static thread_local size_t bufferIndex;

public:
    static char* allocate(size_t size) {
        // SOLUTION : Toujours allouer un nouveau buffer ET l'initialiser � z�ro
        std::unique_ptr<char[]> newBuffer(new char[size]);
        char* buffer = newBuffer.get();

        // CRITIQUE : Initialiser TOUT le buffer � z�ro
        memset(buffer, 0, size);

        // Limiter la taille du pool pour �viter la fragmentation
        while (bufferPool.size() >= 5) {
            bufferPool.erase(bufferPool.begin());
        }

        bufferPool.push_back(std::move(newBuffer));
        return buffer;
    }

    // Nouvelle m�thode pour forcer le nettoyage
    static void clearPool() {
        bufferPool.clear();
    }
};