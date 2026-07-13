#pragma once

#include "Types.h"
#include <TlHelp32.h>

namespace ManualMapper
{
    class ProcessUtils
    {
    public:
        static DWORD GetProcessIdByName(const std::wstring& processName);
        static HANDLE OpenProcess(DWORD processId);
        static void CloseProcess(HANDLE processHandle);
        static bool IsProcess64Bit(HANDLE processHandle);
        static void* GetRemoteModuleHandle(HANDLE processHandle, const std::string& moduleName);
        static void* GetRemoteProcAddress(HANDLE processHandle, void* moduleBase, const std::string& functionName);
        static void* GetRemoteProcAddressByOrdinal(HANDLE processHandle, void* moduleBase, WORD ordinal);
    };
}