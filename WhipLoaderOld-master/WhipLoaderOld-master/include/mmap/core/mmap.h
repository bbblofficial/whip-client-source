#pragma once

#include <Windows.h>
#include <string>
#include <vector>
#include <memory>

#include "mmap/core/mmap.h"
#include "mmap/execution/tls_manager.h"
#include "mmap/injection/manual_mapping.h"
#include "mmap/memory/process_memory.h"
#include "mmap/system/syscall_manager.h"
#include "mmap/utils/utility.h"

class DllInjector {
public:
    DllInjector();
    ~DllInjector();

    bool Initialize();
    bool InjectFromBytes(const unsigned char* dllBytes, size_t dllSize, const std::string& processName);
    bool Destruct();

    bool IsInitialized() const { return m_initialized; }

private:
    bool m_initialized;

    std::unique_ptr<ErrorHandler> m_errorHandler;
    std::unique_ptr<NameRandomizer> m_nameRandomizer;
    std::unique_ptr<SyscallManager> m_syscallManager;
    std::unique_ptr<ProcessInterface> m_processInterface;
    std::unique_ptr<MemoryManager> m_memoryManager;
    std::unique_ptr<PEParser> m_peParser;
    std::unique_ptr<StaticTlsResolver> m_staticTlsResolver;
    std::unique_ptr<ManualMapper> m_manualMapper;
    std::unique_ptr<ExecutionEngine> m_executionEngine;

    void Cleanup();
};