#pragma optimize("", off)
#include "whipnexus/SyscallManager.h"

#ifdef BUILD_WITH_VMPROTECT
#include "VMProtectSDK.h"
#endif

SyscallResolver SyscallManager::resolver;
SyscallWrappers SyscallManager::wrappers(&SyscallManager::resolver);
bool SyscallManager::initialized = false;

bool SyscallManager::Init() {
    if (initialized) return true;

    if (!resolver.Init()) {
        return false;
    }

    initialized = true;
    return true;
}

void SyscallManager::Cleanup() {
    initialized = false;
}

SyscallWrappers* SyscallManager::GetWrappers() {
    return &wrappers;
}

SyscallResolver* SyscallManager::GetResolver() {
    return &resolver;
}

void* SyscallManager::CreateThread(void* startAddr, void* param, u32* threadId) {
    DWORD tid = 0;
    HANDLE hThread = ::CreateThread(
        nullptr,                                    // Default security
        0,                                          // Default stack size
        (LPTHREAD_START_ROUTINE)startAddr,         // Start address
        param,                                      // Parameter
        0,                                          // Run immediately
        threadId ? &tid : nullptr                   // Thread ID output
    );

    if (threadId) *threadId = tid;
    return (void*)hThread;
}

u32 SyscallManager::WaitForThread(void* handle, u32 timeout) {
    if (!handle) return WAIT_FAILED;
    return ::WaitForSingleObject((HANDLE)handle, timeout);
}

bool SyscallManager::TerminateThread(void* handle) {
    if (!handle) return false;
    return ::TerminateThread((HANDLE)handle, 1) != 0;
}

bool SyscallManager::CloseHandle(void* handle) {
    if (!handle) return false;
    return ::CloseHandle((HANDLE)handle) != 0;
}

void* SyscallManager::CreateCriticalSection() {
    CRITICAL_SECTION* cs = (CRITICAL_SECTION*)wrappers.HeapAlloc(sizeof(CRITICAL_SECTION));
    if (cs) {
        ::InitializeCriticalSection(cs);
    }
    return (void*)cs;
}

void SyscallManager::DeleteCriticalSection(void* cs) {
    if (!cs) return;
    ::DeleteCriticalSection((CRITICAL_SECTION*)cs);
    wrappers.HeapFree(cs);
}

void SyscallManager::EnterCriticalSection(void* cs) {
    if (cs) {
        ::EnterCriticalSection((CRITICAL_SECTION*)cs);
    }
}

void SyscallManager::LeaveCriticalSection(void* cs) {
    if (cs) {
        ::LeaveCriticalSection((CRITICAL_SECTION*)cs);
    }
}
