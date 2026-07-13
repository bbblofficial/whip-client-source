#include "mmap/memory/process_memory.h"
#include "mmap/system/syscall_manager.h"
#include "mmap/utils/utility.h"

ProcessInterface::ProcessInterface(ErrorHandler* errorHandler, NameRandomizer* nameRandomizer,
                                   SyscallManager* syscallManager)
    : m_errorHandler(errorHandler),
    m_nameRandomizer(nameRandomizer),
    m_syscallManager(syscallManager),
    m_processHandle(NULL),
    m_threadHandle(NULL),
    m_processId(0),
    m_threadId(0),
    m_isTarget64Bit(false) {
}

ProcessInterface::~ProcessInterface() {
    CloseProcess();

    m_errorHandler = nullptr;
    m_nameRandomizer = nullptr;
    m_syscallManager = nullptr;

    m_processHandle = NULL;
    m_threadHandle = NULL;
    m_processId = 0;
    m_threadId = 0;
    m_isTarget64Bit = false;
}

ProcessId ProcessInterface::FindProcessByName(const std::string& processName) {
    m_nameRandomizer->ApplyRandomTiming(5, 20);

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) {
        m_errorHandler->SetError(ErrorCode::PROCESS_NOT_FOUND,
            "Failed to create process snapshot", GetLastError());
        return 0;
    }

    ProcessId result = 0;

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hSnap, &pe32)) {
        do {
            if (_stricmp(Utils::WideStringToString(
                std::wstring(pe32.szExeFile, pe32.szExeFile + strlen(pe32.szExeFile))
            ).c_str(), processName.c_str()) == 0) {
                result = pe32.th32ProcessID;
                break;
            }
        } while (Process32Next(hSnap, &pe32));
    }

    CloseHandle(hSnap);

    if (result == 0) {
        m_errorHandler->SetError(ErrorCode::PROCESS_NOT_FOUND,
            "Process not found: " + processName);
    }

    return result;
}

bool ProcessInterface::OpenProcess(ProcessId processId) {
    m_nameRandomizer->ApplyRandomTiming(1, 10);

    CloseProcess();
    m_processId = processId;

    if (!m_syscallManager->OpenProcess(processId, PROCESS_ALL_ACCESS, &m_processHandle)) {
        if (!m_syscallManager->OpenProcess(
            processId,
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE |
            PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD | PROCESS_SUSPEND_RESUME,
            &m_processHandle)) {

            m_errorHandler->SetError(ErrorCode::PROCESS_ACCESS_DENIED,
                "Failed to open process with syscalls");
            return false;
        }
    }

    if (!DetermineArchitecture()) {
        CloseProcess();
        return false;
    }

    m_errorHandler->ClearError();
    return true;
}

void ProcessInterface::CloseProcess() {
    if (m_threadHandle) {
        CloseHandle(m_threadHandle);
        m_threadHandle = NULL;
        m_threadId = 0;
    }

    if (m_processHandle) {
        CloseHandle(m_processHandle);
        m_processHandle = NULL;
        m_processId = 0;
    }
}

ProcessHandle ProcessInterface::GetProcessHandle() const {
    return m_processHandle;
}

ProcessId ProcessInterface::GetProcessId() const {
    return m_processId;
}

bool ProcessInterface::IsTarget64Bit() const {
    return m_isTarget64Bit;
}

ThreadId ProcessInterface::FindThreadInProcess() {
    m_nameRandomizer->ApplyRandomTiming(1, 5);

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnap == INVALID_HANDLE_VALUE) {
        m_errorHandler->SetError(ErrorCode::THREAD_HIJACK_FAILED,
            "Failed to create thread snapshot", GetLastError());
        return 0;
    }

    ThreadId result = 0;

    THREADENTRY32 te32;
    te32.dwSize = sizeof(THREADENTRY32);

    if (Thread32First(hSnap, &te32)) {
        do {
            if (te32.th32OwnerProcessID == m_processId) {
                result = te32.th32ThreadID;
                break;
            }
        } while (Thread32Next(hSnap, &te32));
    }

    CloseHandle(hSnap);

    if (result == 0) {
        m_errorHandler->SetError(ErrorCode::THREAD_HIJACK_FAILED,
            "No threads found in target process");
    }

    return result;
}

bool ProcessInterface::OpenThread(ThreadId threadId) {
    m_nameRandomizer->ApplyRandomTiming(1, 5);

    if (m_threadHandle) {
        CloseHandle(m_threadHandle);
        m_threadHandle = NULL;
    }

    m_threadId = threadId;
    m_threadHandle = ::OpenThread(THREAD_ALL_ACCESS, FALSE, threadId);

    if (m_threadHandle == NULL) {
        m_errorHandler->SetError(ErrorCode::THREAD_HIJACK_FAILED,
            "Failed to open thread", GetLastError());
        return false;
    }

    m_errorHandler->ClearError();
    return true;
}

ThreadHandle ProcessInterface::GetThreadHandle() const {
    return m_threadHandle;
}

ThreadId ProcessInterface::GetMainThreadId() const {
    return FindMainThreadId(m_processId);
}

bool ProcessInterface::SuspendThread(ThreadId threadId) {
    ThreadHandle hThread = ::OpenThread(THREAD_SUSPEND_RESUME, FALSE, threadId);
    if (hThread == NULL) {
        m_errorHandler->SetError(ErrorCode::THREAD_HIJACK_FAILED,
            "Failed to open thread for suspension", GetLastError());
        return false;
    }

    bool success = false;
    DWORD result = ::SuspendThread(hThread);

    if (result != static_cast<DWORD>(-1)) {
        success = true;
    }
    else {
        m_errorHandler->SetError(ErrorCode::THREAD_HIJACK_FAILED,
            "Failed to suspend thread", GetLastError());
    }

    CloseHandle(hThread);
    return success;
}

bool ProcessInterface::ResumeThread(ThreadId threadId) {
    ThreadHandle hThread = ::OpenThread(THREAD_SUSPEND_RESUME, FALSE, threadId);
    if (hThread == NULL) {
        m_errorHandler->SetError(ErrorCode::THREAD_HIJACK_FAILED,
            "Failed to open thread for resumption", GetLastError());
        return false;
    }

    bool success = false;
    DWORD result = ::ResumeThread(hThread);

    if (result != static_cast<DWORD>(-1)) {
        success = true;
    }
    else {
        m_errorHandler->SetError(ErrorCode::THREAD_HIJACK_FAILED,
            "Failed to resume thread", GetLastError());
    }

    CloseHandle(hThread);
    return success;
}

bool ProcessInterface::GetThreadContext(ThreadId threadId, LPCONTEXT context) {
    ThreadHandle hThread = ::OpenThread(THREAD_GET_CONTEXT, FALSE, threadId);
    if (hThread == NULL) {
        m_errorHandler->SetError(ErrorCode::THREAD_HIJACK_FAILED,
            "Failed to open thread for context", GetLastError());
        return false;
    }

    bool success = false;
    BOOL result = ::GetThreadContext(hThread, context);

    if (result) {
        success = true;
    }
    else {
        m_errorHandler->SetError(ErrorCode::THREAD_HIJACK_FAILED,
            "Failed to get thread context", GetLastError());
    }

    CloseHandle(hThread);
    return success;
}

bool ProcessInterface::SetThreadContext(ThreadId threadId, LPCONTEXT context) {
    ThreadHandle hThread = ::OpenThread(THREAD_SET_CONTEXT, FALSE, threadId);
    if (hThread == NULL) {
        m_errorHandler->SetError(ErrorCode::THREAD_HIJACK_FAILED,
            "Failed to open thread for context", GetLastError());
        return false;
    }

    bool success = false;
    BOOL result = ::SetThreadContext(hThread, context);

    if (result) {
        success = true;
    }
    else {
        m_errorHandler->SetError(ErrorCode::THREAD_HIJACK_FAILED,
            "Failed to set thread context", GetLastError());
    }

    CloseHandle(hThread);
    return success;
}

bool ProcessInterface::WaitForThread(ThreadId threadId, DWORD timeoutMs) {
    ThreadHandle hThread = ::OpenThread(SYNCHRONIZE, FALSE, threadId);
    if (hThread == NULL) {
        m_errorHandler->SetError(ErrorCode::THREAD_HIJACK_FAILED,
            "Failed to open thread for waiting", GetLastError());
        return false;
    }

    bool success = false;
    DWORD result = WaitForSingleObject(hThread, timeoutMs);

    if (result == WAIT_OBJECT_0) {
        success = true;
    }
    else if (result == WAIT_FAILED) {
        m_errorHandler->SetError(ErrorCode::THREAD_HIJACK_FAILED,
            "Failed to wait for thread", GetLastError());
    }

    CloseHandle(hThread);
    return success;
}

std::string ProcessInterface::GetLastErrorMessage() const {
    return m_errorHandler->GetLastErrorMessage();
}

ThreadId ProcessInterface::FindMainThreadId(ProcessId processId) const {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnap == INVALID_HANDLE_VALUE) {
        return 0;
    }

    THREADENTRY32 te32;
    te32.dwSize = sizeof(THREADENTRY32);
    ThreadId mainThreadId = 0;
    FILETIME earliestCreationTime = { MAXDWORD, MAXDWORD };

    if (Thread32First(hSnap, &te32)) {
        do {
            if (te32.th32OwnerProcessID == processId) {
                ThreadHandle hThread = ::OpenThread(THREAD_QUERY_INFORMATION, FALSE, te32.th32ThreadID);
                if (hThread) {
                    FILETIME creationTime, exitTime, kernelTime, userTime;
                    if (GetThreadTimes(hThread, &creationTime, &exitTime, &kernelTime, &userTime)) {
                        if (CompareFileTime(&creationTime, &earliestCreationTime) < 0) {
                            earliestCreationTime = creationTime;
                            mainThreadId = te32.th32ThreadID;
                        }
                    }
                    CloseHandle(hThread);
                }
            }
        } while (Thread32Next(hSnap, &te32));
    }

    CloseHandle(hSnap);
    return mainThreadId;
}

bool ProcessInterface::DetermineArchitecture() {
    m_isTarget64Bit = Utils::IsProcess64Bit(m_processHandle);
    return true;
}

FARPROC ProcessInterface::GetRemoteProcAddress(HANDLE hProcess, LPCSTR moduleName, LPCSTR functionName) {
    HMODULE hMods[1024];
    DWORD cbNeeded;

    if (!EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        return nullptr;
    }

    DWORD moduleCount = cbNeeded / sizeof(HMODULE);

    for (DWORD i = 0; i < moduleCount; i++) {
        char modName[MAX_PATH];
        if (GetModuleBaseNameA(hProcess, hMods[i], modName, sizeof(modName))) {
            if (_stricmp(modName, moduleName) == 0) {
                HMODULE localModule = GetModuleHandleA(moduleName);
                if (!localModule) {
                    return nullptr;
                }

                FARPROC localAddr = GetProcAddress(localModule, functionName);
                if (!localAddr) {
                    return nullptr;
                }

                DWORD64 offset = (DWORD64)localAddr - (DWORD64)localModule;

                return (FARPROC)((DWORD64)hMods[i] + offset);
            }
        }
    }

    return nullptr;
}