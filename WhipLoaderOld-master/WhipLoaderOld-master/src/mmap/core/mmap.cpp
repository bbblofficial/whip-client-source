#include "mmap/core/mmap.h"
#include <iostream>

DllInjector::DllInjector() : m_initialized(false) {
}

DllInjector::~DllInjector() {
}

bool DllInjector::Initialize() {
    if (m_initialized) {
        return true;
    }

    try {
        m_errorHandler = std::make_unique<ErrorHandler>();
        m_nameRandomizer = std::make_unique<NameRandomizer>();
        m_syscallManager = std::make_unique<SyscallManager>(m_errorHandler.get());

        if (!m_syscallManager->Initialize()) {
            Cleanup();
            return false;
        }

        m_processInterface = std::make_unique<ProcessInterface>(
            m_errorHandler.get(),
            m_nameRandomizer.get(),
            m_syscallManager.get()
        );

        m_memoryManager = std::make_unique<MemoryManager>(
            m_errorHandler.get(),
            m_nameRandomizer.get(),
            m_processInterface.get(),
            m_syscallManager.get()
        );

        m_peParser = std::make_unique<PEParser>(
            m_errorHandler.get(),
            m_nameRandomizer.get(),
            m_memoryManager.get()
        );

        m_staticTlsResolver = std::make_unique<StaticTlsResolver>(
            m_errorHandler.get(),
            m_nameRandomizer.get(),
            m_processInterface.get(),
            m_memoryManager.get()
        );

        m_manualMapper = std::make_unique<ManualMapper>(
            m_errorHandler.get(),
            m_nameRandomizer.get(),
            m_processInterface.get(),
            m_memoryManager.get(),
            m_staticTlsResolver.get()
        );

        m_executionEngine = std::make_unique<ExecutionEngine>(
            m_errorHandler.get(),
            m_nameRandomizer.get(),
            m_processInterface.get(),
            m_memoryManager.get(),
            m_staticTlsResolver.get()
        );

        m_initialized = true;
        return true;
    }
    catch (...) {
        Cleanup();
        return false;
    }
}

bool DllInjector::InjectFromBytes(const unsigned char* dllBytes, size_t dllSize, const std::string& processName) {
    if (!m_initialized) {
        return false;
    }

    if (!dllBytes || dllSize == 0) {
        return false;
    }

    ProcessId processId = m_processInterface->FindProcessByName(processName);
    if (processId == 0) {
        return false;
    }

    if (!m_processInterface->OpenProcess(processId)) {
        return false;
    }

    if (!m_peParser->LoadDllFromMemory(dllBytes, dllSize)) {
        return false;
    }

    DWORD imageSize = m_peParser->GetSizeOfImage();
    DWORD entryPointRVA = m_peParser->GetEntryPointRVA();
    bool is64Bit = m_peParser->Is64Bit();
    bool targetIs64Bit = m_processInterface->IsTarget64Bit();

    if (is64Bit != targetIs64Bit) {
        return false;
    }

    MemoryAddress baseAddress = m_manualMapper->MapDll(m_peParser.get());
    if (!baseAddress) {
        return false;
    }

    if (entryPointRVA != 0) {
        if (!m_executionEngine->ExecuteDllMain(baseAddress, entryPointRVA)) {
            return false;
        }
    }

    return true;
}

bool DllInjector::Destruct() {
    if (!m_initialized) {
        return false;
    }

    bool result = false;
    if (m_manualMapper) {
        result = m_manualMapper->UnloadInjectedDll();
    }
    Cleanup();
    return result;
}

void DllInjector::Cleanup() {
    m_executionEngine.reset();
    m_manualMapper.reset();
    m_staticTlsResolver.reset();
    m_peParser.reset();
    m_memoryManager.reset();
    m_processInterface.reset();
    m_syscallManager.reset();
    m_nameRandomizer.reset();
    m_errorHandler.reset();

    m_initialized = false;
}