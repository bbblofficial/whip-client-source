#pragma once

#include <mutex>
#include "mmap/core/common.h"
#include "mmap/memory/process_memory.h"
#include "mmap/utils/utility.h"

class PEParser {
public:
    PEParser(ErrorHandler* errorHandler, NameRandomizer* nameRandomizer, MemoryManager* memoryManager);
    ~PEParser();

    bool LoadDll(const std::string& dllPath);

    bool LoadDllFromMemory(const unsigned char* dllBytes, size_t dllSize);

    const BYTE* GetDllData() const;

    MemorySize GetDllSize() const;

    PIMAGE_DOS_HEADER GetDosHeader() const;

    void* GetNtHeaders() const;

    PIMAGE_FILE_HEADER GetFileHeader() const;

    void* GetOptionalHeader() const;

    PIMAGE_SECTION_HEADER GetSectionHeaders() const;

    WORD GetNumberOfSections() const;

    DWORD GetSizeOfImage() const;

    DWORD GetEntryPointRVA() const;

    ULONGLONG GetImageBase() const;

    bool Is64Bit() const;

    PIMAGE_DATA_DIRECTORY GetDataDirectory(DWORD directoryEntry) const;

    DWORD RvaToFileOffset(DWORD rva) const;

    void* GetRvaPointer(DWORD rva) const;

    bool HasTLSCallbacks() const;

    std::vector<DWORD> GetTLSCallbackRVAs(void* mappedBaseAddress, HANDLE targetProcess) const;

private:
    ErrorHandler* m_errorHandler;
    NameRandomizer* m_nameRandomizer;
    MemoryManager* m_memoryManger;

    std::vector<BYTE> m_dllData;
    bool m_is64Bit;

    bool ParsePEHeaders();
    DWORD GetFileSize(const std::string& filePath) const;
};

class ImportResolver {
public:
    ImportResolver(ErrorHandler* errorHandler, NameRandomizer* nameRandomizer, ProcessInterface* processInterface, MemoryManager* memoryManager);
    ~ImportResolver();

    bool ResolveImports(const PEParser* peParser, MemoryAddress baseAddress, MemoryManager* memoryManager);

    const std::vector<std::string>& GetLoadedModules() const { return m_loadedModules; }


private:
    ErrorHandler* m_errorHandler;
    NameRandomizer* m_nameRandomizer;
    ProcessInterface* m_processInterface;
    MemoryManager* m_memoryManager;

    struct RemoteModuleExports {
        MemoryAddress baseAddress;
        std::vector<std::string> functionNames;
        std::vector<MemoryAddress> functionAddresses;
        std::vector<WORD> ordinals;
        bool isValid;
        std::string resolvedModuleName;
    };

    std::unordered_map<std::string, RemoteModuleExports> m_remoteExports;

    MemoryAddress FindFunctionInRemoteExports(const std::string& moduleName, const std::string& functionName);

    MemoryAddress GetOrLoadRemoteModule(const std::string& moduleName);

    RemoteModuleExports ReadRemoteModuleExports(const std::string& moduleName, MemoryAddress moduleBase, HANDLE targetProcess);

    MemoryAddress FindFunctionByOrdinalInRemoteExports(const std::string& moduleName, WORD targetOrdinal);

    MemoryAddress SearchFunctionInAllLoadedModules(const std::string& functionName);

    MemoryAddress GetRemoteModuleBase(const std::string& moduleName);

    std::string ResolveApiSetByPattern(const std::string& apiSetName);

    MemoryAddress LoadModuleInRemoteProcess(const std::string& moduleName, HANDLE targetProcess);

    std::vector<std::string> GetSearchOrderForFunction(const std::string& functionName);

    MemoryAddress SearchFunctionInSpecificModule(MemoryAddress moduleBase, const std::string& functionName, HANDLE targetProcess);

    MemoryAddress ResolveForwardedFunction(MemoryAddress moduleBase, DWORD forwardRVA, HANDLE targetProcess);

    MemoryAddress ResolveByOrdinalInModule(MemoryAddress moduleBase, WORD targetOrdinal, HANDLE targetProcess);

    std::vector<std::string> m_loadedModules;
};

class ExecutionEngine;

class ManualMapper {
public:
    ManualMapper(ErrorHandler* errorHandler, NameRandomizer* nameRandomizer,
        ProcessInterface* processInterface, MemoryManager* memoryManager, StaticTlsResolver* staticTlsResolver);
    ~ManualMapper();

    MemoryAddress MapDll(const PEParser* peParser);

    bool HijackThreadWithExitShellcode(HANDLE hProcess, DWORD threadId);

    std::vector<DWORD> FindThreadsInDll(HANDLE hProcess, DWORD processId, DWORD64 dllStart, DWORD64 dllEnd);

    bool UnloadInjectedDll();

    // Gestion des exception handlers
    bool ApplyRemoteExceptionHandlers(const PEParser* peParser, DWORD64 remoteBaseAddress);
    bool ApplyRemoveExceptionHandlers(HANDLE hProcess);

    bool ProcessRelocations(const PEParser* peParser, MemoryAddress baseAddress, ULONGLONG deltaBase);
    bool InitializeSecurityCookie(const PEParser* peParser, MemoryAddress baseAddress);
    bool CleanupHeaders(MemoryAddress baseAddress);

    StaticTlsResolver* GetTlsResolver() const { return m_staticTlsResolver; }

    void SetExecutionEngine(ExecutionEngine* executionEngine) { m_executionEngine = executionEngine; }
    ExecutionEngine* GetExecutionEngine() const { return m_executionEngine; }

    MemoryAddress GetBaseAddress() const { return m_mappedBaseAddress; }
    DWORD GetEntryPointRVA() const { return m_entryPointRVA; }

private:
    ErrorHandler* m_errorHandler;
    NameRandomizer* m_nameRandomizer;
    ProcessInterface* m_processInterface;
    MemoryManager* m_memoryManager;
    ImportResolver* m_importResolver;
    StaticTlsResolver* m_staticTlsResolver;
    ExecutionEngine* m_executionEngine;

    MemoryAddress m_mappedBaseAddress;
    MemorySize m_mappedImageSize;
    DWORD m_entryPointRVA;
    const PEParser* m_cachedPEParser;

    // Exception handlers tracking
    PRUNTIME_FUNCTION m_remoteFunctionTable;
    DWORD m_remoteFunctionTableEntryCount;

    // Méthodes privées pour RtlAddFunctionTable / RtlDeleteFunctionTable
    bool CallRemoteRtlAddFunctionTable(HANDLE hProcess, PRUNTIME_FUNCTION functionTable,
                                       DWORD entryCount, DWORD64 baseAddress);
    bool CallRemoteRtlDeleteFunctionTable(HANDLE hProcess, PRUNTIME_FUNCTION functionTable);

    // Gestion des threads pour unload sécurisé
    std::vector<DWORD> SuspendAllThreadsExceptCurrent(DWORD processId);
    void ResumeAllThreads(const std::vector<DWORD>& threadIds);
    bool PatchInvalidParameterHandler(HANDLE hProcess);

    DWORD GetSectionProtection(DWORD characteristics) const;
    bool MapSections(const PEParser* peParser, MemoryAddress baseAddress);
    bool ApplyRelocations(PIMAGE_BASE_RELOCATION relocationBlock, MemoryAddress baseAddress,
                         ULONGLONG deltaBase, DWORD blockSize, const PEParser* peParser);
    bool CallRemoteDllMain(HANDLE hProcess, DWORD reason);
    bool CallRemoteFreeLibrary(HANDLE hProcess, const std::string& moduleName);
    bool UnloadImportedModules(HANDLE hProcess);
};

class ExecutionEngine {
public:
    ExecutionEngine(ErrorHandler* errorHandler, NameRandomizer* nameRandomizer,
        ProcessInterface* processInterface, MemoryManager* memoryManager, StaticTlsResolver* staticTlsResolver);
    ~ExecutionEngine();

    bool ExecuteDllMain(MemoryAddress baseAddress, DWORD entryPointRVA);

    bool DetachDll(MemoryAddress baseAddress, DWORD entryPointRVA);

private:
    ErrorHandler* m_errorHandler;
    NameRandomizer* m_nameRandomizer;
    ProcessInterface* m_processInterface;
    MemoryManager* m_memoryManager;
    TlsCallback* m_tlsCallback;
    ManualMapper* m_manualMapper;
    StaticTlsResolver* m_staticTlsResolver;

    MemoryAddress m_shellcodeAddress;
    MemoryAddress m_parameterAddress;
    CONTEXT m_originalThreadContext;
    bool m_threadHijacked;
};