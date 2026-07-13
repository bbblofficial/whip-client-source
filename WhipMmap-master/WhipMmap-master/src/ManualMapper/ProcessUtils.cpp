#include "ManualMapper/ProcessUtils.h"
#include "ManualMapper/SyscallHelper.h"
#include <algorithm>

namespace ManualMapper
{
    DWORD ProcessUtils::GetProcessIdByName(const std::wstring& processName)
    {
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot == INVALID_HANDLE_VALUE)
            return 0;

        PROCESSENTRY32W entry = { 0 };
        entry.dwSize = sizeof(PROCESSENTRY32W);

        if (Process32FirstW(snapshot, &entry))
        {
            do
            {
                if (processName == entry.szExeFile)
                {
                    CloseHandle(snapshot);
                    return entry.th32ProcessID;
                }
            } while (Process32NextW(snapshot, &entry));
        }

        CloseHandle(snapshot);
        return 0;
    }

    HANDLE ProcessUtils::OpenProcess(DWORD processId)
    {
        struct {
            ULONG Length;
            HANDLE RootDirectory;
            PVOID ObjectName;
            ULONG Attributes;
            PVOID SecurityDescriptor;
            PVOID SecurityQualityOfService;
        } objectAttributes = { 0 };

        objectAttributes.Length = sizeof(objectAttributes);

        struct {
            PVOID UniqueProcess;
            PVOID UniqueThread;
        } clientId = { 0 };

        clientId.UniqueProcess = reinterpret_cast<PVOID>(static_cast<uintptr_t>(processId));

        HANDLE processHandle = nullptr;
        NTSTATUS status = Syscalls::NtOpenProcess(
            &processHandle,
            PROCESS_ALL_ACCESS,
            &objectAttributes,
            &clientId
        );

        return (status >= 0) ? processHandle : nullptr;
    }

    void ProcessUtils::CloseProcess(HANDLE processHandle)
    {
        if (processHandle && processHandle != INVALID_HANDLE_VALUE)
            CloseHandle(processHandle);
    }

    bool ProcessUtils::IsProcess64Bit(HANDLE processHandle)
    {
        BOOL isWow64 = FALSE;
        IsWow64Process(processHandle, &isWow64);

#ifdef _WIN64
        return !isWow64;
#else
        return false;
#endif
    }

    void* ProcessUtils::GetRemoteModuleHandle(HANDLE processHandle, const std::string& moduleName)
    {
        DWORD processId = GetProcessId(processHandle);
        if (processId == 0)
            return nullptr;

        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, processId);
        if (snapshot == INVALID_HANDLE_VALUE)
            return nullptr;

        MODULEENTRY32 entry = { 0 };
        entry.dwSize = sizeof(MODULEENTRY32);

        std::string lowerModuleName = moduleName;
        std::transform(lowerModuleName.begin(), lowerModuleName.end(), lowerModuleName.begin(), ::tolower);

        if (Module32First(snapshot, &entry))
        {
            do
            {
                std::string currentModule = entry.szModule;
                std::transform(currentModule.begin(), currentModule.end(), currentModule.begin(), ::tolower);

                if (currentModule == lowerModuleName)
                {
                    CloseHandle(snapshot);
                    return entry.modBaseAddr;
                }
            } while (Module32Next(snapshot, &entry));
        }

        CloseHandle(snapshot);
        return nullptr;
    }

    void* ProcessUtils::GetRemoteProcAddress(HANDLE processHandle, void* moduleBase, const std::string& functionName)
    {
        if (!moduleBase)
            return nullptr;

        IMAGE_DOS_HEADER dosHeader;
        if (!Syscalls::ReadMemory(processHandle, moduleBase, &dosHeader, sizeof(IMAGE_DOS_HEADER)))
            return nullptr;

        if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE)
            return nullptr;

        IMAGE_NT_HEADERS ntHeaders;
        void* ntHeadersAddr = reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(moduleBase) + dosHeader.e_lfanew);
        if (!Syscalls::ReadMemory(processHandle, ntHeadersAddr, &ntHeaders, sizeof(IMAGE_NT_HEADERS)))
            return nullptr;

        if (ntHeaders.Signature != IMAGE_NT_SIGNATURE)
            return nullptr;

        IMAGE_DATA_DIRECTORY exportDir = ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (exportDir.Size == 0)
            return nullptr;

        void* exportDirAddr = reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(moduleBase) + exportDir.VirtualAddress);
        IMAGE_EXPORT_DIRECTORY exportDirectory;
        if (!Syscalls::ReadMemory(processHandle, exportDirAddr, &exportDirectory, sizeof(IMAGE_EXPORT_DIRECTORY)))
            return nullptr;

        DWORD* nameRvas = new DWORD[exportDirectory.NumberOfNames];
        void* namesAddr = reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(moduleBase) + exportDirectory.AddressOfNames);
        Syscalls::ReadMemory(processHandle, namesAddr, nameRvas, exportDirectory.NumberOfNames * sizeof(DWORD));

        WORD* ordinals = new WORD[exportDirectory.NumberOfNames];
        void* ordinalsAddr = reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(moduleBase) + exportDirectory.AddressOfNameOrdinals);
        Syscalls::ReadMemory(processHandle, ordinalsAddr, ordinals, exportDirectory.NumberOfNames * sizeof(WORD));

        DWORD* functionRvas = new DWORD[exportDirectory.NumberOfFunctions];
        void* functionsAddr = reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(moduleBase) + exportDirectory.AddressOfFunctions);
        Syscalls::ReadMemory(processHandle, functionsAddr, functionRvas, exportDirectory.NumberOfFunctions * sizeof(DWORD));

        void* result = nullptr;
        for (DWORD i = 0; i < exportDirectory.NumberOfNames; ++i)
        {
            char name[256] = { 0 };
            void* nameAddr = reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(moduleBase) + nameRvas[i]);
            Syscalls::ReadMemory(processHandle, nameAddr, name, sizeof(name) - 1);

            if (functionName == name)
            {
                WORD ordinal = ordinals[i];
                DWORD functionRva = functionRvas[ordinal];

                if (functionRva >= exportDir.VirtualAddress &&
                    functionRva < exportDir.VirtualAddress + exportDir.Size)
                {
                    char forwarder[256] = { 0 };
                    void* forwarderAddr = reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(moduleBase) + functionRva);
                    Syscalls::ReadMemory(processHandle, forwarderAddr, forwarder, sizeof(forwarder) - 1);

                    std::string forwarderStr(forwarder);
                    size_t dotPos = forwarderStr.find('.');
                    if (dotPos != std::string::npos)
                    {
                        std::string forwardDll = forwarderStr.substr(0, dotPos) + ".dll";
                        std::string forwardFunc = forwarderStr.substr(dotPos + 1);

                        void* forwardModule = GetRemoteModuleHandle(processHandle, forwardDll);
                        if (forwardModule)
                        {
                            result = GetRemoteProcAddress(processHandle, forwardModule, forwardFunc);
                            break;
                        }
                    }
                }
                else
                {
                    result = reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(moduleBase) + functionRva);
                    break;
                }
            }
        }

        delete[] nameRvas;
        delete[] ordinals;
        delete[] functionRvas;

        return result;
    }

    void* ProcessUtils::GetRemoteProcAddressByOrdinal(HANDLE processHandle, void* moduleBase, WORD ordinal)
    {
        if (!moduleBase)
            return nullptr;

        IMAGE_DOS_HEADER dosHeader;
        if (!Syscalls::ReadMemory(processHandle, moduleBase, &dosHeader, sizeof(IMAGE_DOS_HEADER)))
            return nullptr;

        if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE)
            return nullptr;

        IMAGE_NT_HEADERS ntHeaders;
        void* ntHeadersAddr = reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(moduleBase) + dosHeader.e_lfanew);
        if (!Syscalls::ReadMemory(processHandle, ntHeadersAddr, &ntHeaders, sizeof(IMAGE_NT_HEADERS)))
            return nullptr;

        if (ntHeaders.Signature != IMAGE_NT_SIGNATURE)
            return nullptr;

        IMAGE_DATA_DIRECTORY exportDir = ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (exportDir.Size == 0)
            return nullptr;

        void* exportDirAddr = reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(moduleBase) + exportDir.VirtualAddress);
        IMAGE_EXPORT_DIRECTORY exportDirectory;
        if (!Syscalls::ReadMemory(processHandle, exportDirAddr, &exportDirectory, sizeof(IMAGE_EXPORT_DIRECTORY)))
            return nullptr;

        DWORD ordinalBase = exportDirectory.Base;

        if (ordinal < ordinalBase || ordinal >= ordinalBase + exportDirectory.NumberOfFunctions)
            return nullptr;

        DWORD functionIndex = ordinal - ordinalBase;

        DWORD* functionRvas = new DWORD[exportDirectory.NumberOfFunctions];
        void* functionsAddr = reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(moduleBase) + exportDirectory.AddressOfFunctions);
        Syscalls::ReadMemory(processHandle, functionsAddr, functionRvas, exportDirectory.NumberOfFunctions * sizeof(DWORD));

        DWORD functionRva = functionRvas[functionIndex];
        delete[] functionRvas;

        if (functionRva == 0)
            return nullptr;

        if (functionRva >= exportDir.VirtualAddress &&
            functionRva < exportDir.VirtualAddress + exportDir.Size)
        {
            char forwarder[256] = { 0 };
            void* forwarderAddr = reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(moduleBase) + functionRva);
            Syscalls::ReadMemory(processHandle, forwarderAddr, forwarder, sizeof(forwarder) - 1);

            std::string forwarderStr(forwarder);
            size_t dotPos = forwarderStr.find('.');
            if (dotPos != std::string::npos)
            {
                std::string forwardDll = forwarderStr.substr(0, dotPos) + ".dll";
                std::string forwardFunc = forwarderStr.substr(dotPos + 1);

                void* forwardModule = GetRemoteModuleHandle(processHandle, forwardDll);
                if (forwardModule)
                {
                    if (!forwardFunc.empty() && forwardFunc[0] == '#')
                    {
                        WORD forwardOrdinal = static_cast<WORD>(std::stoi(forwardFunc.substr(1)));
                        return GetRemoteProcAddressByOrdinal(processHandle, forwardModule, forwardOrdinal);
                    }
                    else
                    {
                        return GetRemoteProcAddress(processHandle, forwardModule, forwardFunc);
                    }
                }
            }
            return nullptr;
        }
        else
        {
            return reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(moduleBase) + functionRva);
        }
    }
}