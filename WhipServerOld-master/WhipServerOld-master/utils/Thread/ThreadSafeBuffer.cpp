// ThreadSafeBuffer.cpp
#include "ThreadSafeBuffer.h"

// Définition de la variable statique
thread_local std::vector<std::unique_ptr<char[]>> ThreadSafeBuffer::bufferPool;
thread_local size_t ThreadSafeBuffer::bufferIndex = 0;