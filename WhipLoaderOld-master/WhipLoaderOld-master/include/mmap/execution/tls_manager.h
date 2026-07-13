#pragma once

#include "mmap/core/common.h"
#include "mmap/memory/process_memory.h"
#include "mmap/utils/utility.h"

class StaticTlsResolver
{
public:
    StaticTlsResolver(ErrorHandler* errorHandler, NameRandomizer* nameRandomizer,
        ProcessInterface* processInterface, MemoryManager* memoryManager);
    ~StaticTlsResolver();

    [[nodiscard]] bool HasTlsData() const {
        return (m_tlsIndex != TLS_OUT_OF_INDEXES &&
            m_tlsDataTemplate != nullptr &&
            m_tlsDataSize > 0);
    }

    bool ExecuteTlsCallbacks(const PEParser* peParser, MemoryAddress baseAddress,
        DWORD reason = DLL_PROCESS_ATTACH, PVOID context = nullptr);

    void Cleanup();

    [[nodiscard]] ULONG GetTlsIndex() const { return m_tlsIndex; }
    [[nodiscard]] MemoryAddress GetTlsDataTemplate() const { return m_tlsDataTemplate; }
    [[nodiscard]] SIZE_T GetTlsDataSize() const { return m_tlsDataSize; }
    [[nodiscard]] bool IsInitialized() const { return m_tlsIndex != TLS_OUT_OF_INDEXES && m_tlsDataTemplate != nullptr; }

private:
    ErrorHandler* m_errorHandler;
    NameRandomizer* m_nameRandomizer;
    ProcessInterface* m_processInterface;
    MemoryManager* m_memoryManager;

    ULONG m_tlsIndex;
    MemoryAddress m_tlsDataTemplate;
    SIZE_T m_tlsDataSize;
    MemoryAddress m_tlsCallbacksAddr;

    IMAGE_TLS_DIRECTORY64 m_tlsDirectory;

    PIMAGE_TLS_DIRECTORY GetTlsDirectory(const PEParser* peParser, MemoryAddress baseAddress);
    bool HasTlsData(PIMAGE_TLS_DIRECTORY tlsDirectory);
    bool HasTlsCallbacks(PIMAGE_TLS_DIRECTORY tlsDirectory);
    bool ValidateTlsDirectory(PIMAGE_TLS_DIRECTORY tlsDirectory);

    bool ExtractCallbacksFromAddress(MemoryAddress callbacksAddress, std::vector<ULONGLONG>& callbacks);

    MemoryAddress GetTlsCallbacksAddress(const PEParser* peParser, MemoryAddress baseAddress);
    bool ExecuteCallbacksViaShellcode(MemoryAddress callbacksAddress, MemoryAddress imageBase,
        DWORD reason, PVOID context);

    bool RelocateAddress(ULONGLONG* address, ULONGLONG originalImageBase, ULONGLONG newImageBase);
};


struct TlsCallbackParams
{
    ULONGLONG imageBase;
    ULONGLONG reason;
    ULONGLONG context;
    ULONGLONG callbacksArray;
};