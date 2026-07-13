#include "mmap/core/common.h"
#include "mmap/execution/tls_manager.h"
#include "mmap/injection/manual_mapping.h"
#include "mmap/memory/process_memory.h"
#include "mmap/system/syscall_manager.h"
#include "mmap/utils/utility.h"

#include <random>
#include <chrono>
#include <sstream>
#include <iomanip>
#include <iostream>

InjectorController::InjectorController()
    : m_errorHandler(nullptr),
    m_nameRandomizer(nullptr),
    m_processInterface(nullptr),
    m_syscallManager(nullptr),
    m_memoryManager(nullptr),
    m_peParser(nullptr),
    m_tlsCallback(nullptr),
    m_remoteVEHrelocator(nullptr),
    m_manualMapper(nullptr),
    m_executionEngine(nullptr),
    m_staticTlsResolver(nullptr) {
}

InjectorController::~InjectorController() {
}

bool InjectorController::Initialize() {

    m_errorHandler = new ErrorHandler();
    m_nameRandomizer = new NameRandomizer();
    m_syscallManager = new SyscallManager(m_errorHandler);
    m_processInterface = new ProcessInterface(m_errorHandler, m_nameRandomizer, m_syscallManager);
    m_memoryManager = new MemoryManager(m_errorHandler, m_nameRandomizer, m_processInterface, m_syscallManager);
    m_peParser = new PEParser(m_errorHandler, m_nameRandomizer, m_memoryManager);
    m_staticTlsResolver = new StaticTlsResolver(m_errorHandler, m_nameRandomizer, m_processInterface, m_memoryManager);
    m_manualMapper = new ManualMapper(m_errorHandler, m_nameRandomizer, m_processInterface, m_memoryManager, m_staticTlsResolver);
    m_executionEngine = new ExecutionEngine(m_errorHandler, m_nameRandomizer, m_processInterface, m_memoryManager, m_staticTlsResolver);

    if (!m_syscallManager->Initialize()) {
        return false;
    }
    return true;
}

bool InjectorController::InjectDll(const std::string& dllPath, const std::string& processName) {
    if (dllPath.empty() || processName.empty()) {
        m_errorHandler->SetError(ErrorCode::INVALID_PARAMETER,
            "DLL path or process name is empty");
        return false;
    }

    DWORD fileAttributes = GetFileAttributesA(dllPath.c_str());
    if (fileAttributes == INVALID_FILE_ATTRIBUTES) {
        m_errorHandler->SetError(ErrorCode::FILE_NOT_FOUND,
            "DLL file not found: " + dllPath);
        return false;
    }

    m_nameRandomizer->ApplyRandomTiming(5, 20);

    ProcessId processId = m_processInterface->FindProcessByName(processName);
    if (processId == 0) {
        return false;
    }

    if (!m_processInterface->OpenProcess(processId)) {
        return false;
    }

    if (!m_peParser->LoadDll(dllPath)) {
        return false;
    }

    MemoryAddress baseAddress = m_manualMapper->MapDll(m_peParser);
    if (!baseAddress) {
        return false;
    }

    DWORD entryPointRVA = m_peParser->GetEntryPointRVA();

    if (entryPointRVA != 0) {
        if (!m_executionEngine->ExecuteDllMain(baseAddress, entryPointRVA)) {
            return false;
        }
    }
    else {
    }

    return true;
}

bool InjectorController::UnloadInjectedDll() {
    if (!m_manualMapper) {
        m_errorHandler->SetError(ErrorCode::INVALID_PARAMETER,
            "Manual mapper is not initialized");
        return false;
    }

    return m_manualMapper->UnloadInjectedDll();
}

std::string InjectorController::GetLastErrorMessage() const {
    if (!m_errorHandler) {
    }

    return m_errorHandler->GetLastErrorMessage();
}

void InjectorController::CleanupResources() {
    if (m_executionEngine) {
        delete m_executionEngine;
        m_executionEngine = nullptr;
    }

    if (m_manualMapper) {
        delete m_manualMapper;
        m_manualMapper = nullptr;
    }

    if (m_peParser) {
        delete m_peParser;
        m_peParser = nullptr;
    }

    if (m_memoryManager) {
        delete m_memoryManager;
        m_memoryManager = nullptr;
    }

    if (m_processInterface) {
        delete m_processInterface;
        m_processInterface = nullptr;
    }

    if (m_syscallManager) {
        delete m_syscallManager;
        m_syscallManager = nullptr;
    }

    if (m_nameRandomizer) {
        delete m_nameRandomizer;
        m_nameRandomizer = nullptr;
    }

    if (m_errorHandler) {
        delete m_errorHandler;
        m_errorHandler = nullptr;
    }
}