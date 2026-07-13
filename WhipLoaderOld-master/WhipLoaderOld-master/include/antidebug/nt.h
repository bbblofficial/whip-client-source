#pragma once
#include <windows.h>
#include <winternl.h>

// NT API typedefs
typedef NTSTATUS(NTAPI* NtQueryInformationProcessTypedef)(
    HANDLE ProcessHandle,
    DWORD ProcessInformationClass,
    PVOID ProcessInformation,
    DWORD ProcessInformationLength,
    PDWORD ReturnLength
    );

#pragma pack(pop)
