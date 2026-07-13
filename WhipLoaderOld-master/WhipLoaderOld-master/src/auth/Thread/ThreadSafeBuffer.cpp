#include "ThreadSafeBuffer.h"

thread_local std::vector<std::unique_ptr<char[]>> ThreadSafeBuffer::bufferPool;