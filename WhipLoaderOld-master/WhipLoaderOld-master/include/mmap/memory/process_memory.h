#pragma once

#include "mmap/core/common.h"
#include "mmap/memory/process_memory.h"

class ProcessInterface {
public:
    ProcessInterface(ErrorHandler* errorHandler, NameRandomizer* nameRandomizer, SyscallManager* syscallManager);
    ~ProcessInterface();

    ProcessId FindProcessByName(const std::string& processName);

    bool OpenProcess(ProcessId processId);

    void CloseProcess();

    ProcessHandle GetProcessHandle() const;

    ProcessId GetProcessId() const;

    bool IsTarget64Bit() const;

    ThreadId FindThreadInProcess();

    bool OpenThread(ThreadId threadId);

    ThreadHandle GetThreadHandle() const;

    ThreadId GetMainThreadId() const;

    bool SuspendThread(ThreadId threadId);

    bool ResumeThread(ThreadId threadId);

    bool GetThreadContext(ThreadId threadId, LPCONTEXT context);

    bool SetThreadContext(ThreadId threadId, LPCONTEXT context);

    bool WaitForThread(ThreadId threadId, DWORD timeoutMs);

    FARPROC GetRemoteProcAddress(HANDLE hProcess, LPCSTR moduleName, LPCSTR functionName);

    std::string GetLastErrorMessage() const;

private:
    ErrorHandler* m_errorHandler;
    NameRandomizer* m_nameRandomizer;
    SyscallManager* m_syscallManager;

    ProcessHandle m_processHandle;
    ThreadHandle m_threadHandle;
    ProcessId m_processId;
    ThreadId m_threadId;
    bool m_isTarget64Bit;

    ThreadId FindMainThreadId(ProcessId processId) const;
    bool DetermineArchitecture();
};

class MemoryManager {
public:
    MemoryManager(ErrorHandler* errorHandler, NameRandomizer* nameRandomizer,
        ProcessInterface* processInterface, SyscallManager* syscallManager);
    ~MemoryManager();

    bool WaitForThread(ThreadHandle threadHandle, DWORD timeoutMs = INFINITE);

    bool CreateSuspendedThread(MemoryAddress startAddress, MemoryAddress parameter, ThreadHandle* threadHandle);
    bool QueueApcThread(ThreadHandle threadHandle, MemoryAddress apcRoutine,
        MemoryAddress arg1 = nullptr, MemoryAddress arg2 = nullptr, MemoryAddress arg3 = nullptr);
    bool ResumeThread(ThreadHandle threadHandle);
    bool SuspendThread(ThreadHandle threadHandle);

    MemoryAddress QueryRemotePebAddress();
    MemoryAddress QueryRemoteTebAddress(HANDLE hThread);
    bool ReadTlsBitmap(ULONG* bitmap);
    bool WriteTlsBitmap(ULONG* bitmap);
    bool ReadTlsSlot(DWORD threadId, ULONG tlsIndex, MemoryAddress* tlsData);

    MemoryAddress AllocateMemory(MemorySize size, DWORD protection);

    bool OpenProcess(DWORD processId, DWORD desiredAccess, ProcessHandle* processHandle);

    bool CreateRemoteThread(MemoryAddress startAddress, MemoryAddress parameter, ThreadHandle* threadHandle);

    bool FreeMemory(MemoryAddress address);

    bool WriteMemory(MemoryAddress address, const void* buffer, MemorySize size);

    bool ReadMemory(MemoryAddress address, void* buffer, MemorySize size);

    bool ReadMemoryFast(MemoryAddress address, void* buffer, MemorySize size);

    bool ProtectMemory(MemoryAddress address, MemorySize size, DWORD protection, PDWORD oldProtection);

    bool FlushInstructionCache(MemoryAddress address, MemorySize size);

    std::string GetLastErrorMessage() const;

private:
    ErrorHandler* m_errorHandler;
    NameRandomizer* m_nameRandomizer;
    ProcessInterface* m_processInterface;
    SyscallManager* m_syscallManager;

    std::vector<std::pair<MemoryAddress, MemorySize>> m_allocatedMemory;
    std::vector<SectionHandle> m_sectionHandles;

    MemoryAddress m_cachedPebAddress;
    std::unordered_map<DWORD, MemoryAddress> m_cachedTebAddresses;
};