#define WIN32_LEAN_AND_MEAN

#include "antidebug/SecurityHelper.h"
#include "antidebug/nt.h"

#include <winternl.h>
#include <TlHelp32.h>
#include <vector>
#include <string>
#include <winnt.h>

#include "auth/auth.h"

std::uint32_t find_dbg(const char* proc)
{
    auto snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    auto pe = PROCESSENTRY32{ sizeof(PROCESSENTRY32) };

    if (Process32First(snapshot, &pe)) {
        do {
            if (!_stricmp(proc, reinterpret_cast<const char*>(pe.szExeFile))) {
                CloseHandle(snapshot);
                return pe.th32ProcessID;
            }
        } while (Process32Next(snapshot, &pe));
    }
    CloseHandle(snapshot);
    return 0;
}

void debugger_detected(const char* msg)
{

    Auth* auth = Auth::getInstance();

    if (auth) {
        const char* hwid = auth->getHwid();

        if (hwid) {
            auth->reportThreat("debugger", msg);
        } else {
        }
    } else {
    }

    Sleep(100);

    char buffer[256];
    TerminateProcess(GetCurrentProcess(), 1);
}

#pragma region AntiDebug
__forceinline int RemoteDebuggerPresentAPI()
{
    auto dbg_present = 0;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &dbg_present);
    return dbg_present;
}

__forceinline int NtQueryInformationProcessDebugFlags()
{
    const auto debug_flags = 0x1f;
    const auto query_info_process = reinterpret_cast<NtQueryInformationProcessTypedef>(GetProcAddress(
        GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess"));

    auto debug_inherit = 0;
    const auto status = query_info_process(GetCurrentProcess(), debug_flags, &debug_inherit,
        sizeof(DWORD), nullptr);

    if (status == 0x00000000 && debug_inherit == 0)
    {
        return 1;
    }
    return 0;
}

__forceinline int NtQueryInformationProcessDebugObject()
{
    const auto debug_object_handle = 0x1e;
    const auto query_info_process = reinterpret_cast<NtQueryInformationProcessTypedef>(GetProcAddress(
        GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess"));

    HANDLE debug_object = nullptr;
    const auto information_length = sizeof(ULONG) * 2;
    const auto status = query_info_process(GetCurrentProcess(), debug_object_handle, &debug_object,
        information_length, nullptr);

    if (status == 0x00000000 && debug_object)
    {
        return 1;
    }
    return 0;
}

__forceinline bool heapDebuggerFlags()
{
    PPEB pPeb = (PPEB)__readgsqword(0x60);
    PVOID pHeapBase = (PVOID)(*(PDWORD_PTR)((PBYTE)pPeb + 0x30));
    DWORD dwHeapFlagsOffset = 0x70;
    DWORD dwHeapForceFlagsOffset = 0x74;

    PDWORD pdwHeapFlags = (PDWORD)((PBYTE)pHeapBase + dwHeapFlagsOffset);
    PDWORD pdwHeapForceFlags = (PDWORD)((PBYTE)pHeapBase + dwHeapForceFlagsOffset);
    return (*pdwHeapFlags & ~HEAP_GROWABLE) || (*pdwHeapForceFlags != 0);
}

__forceinline bool HeapProtectionFlag()
{
    PROCESS_HEAP_ENTRY HeapEntry = { 0 };
    do
    {
        if (!HeapWalk(GetProcessHeap(), &HeapEntry))
            return false;
    } while (HeapEntry.wFlags != PROCESS_HEAP_ENTRY_BUSY);

    PVOID pOverlapped = (PBYTE)HeapEntry.lpData + HeapEntry.cbData;
    return ((DWORD)(*(PDWORD)pOverlapped) == 0xABABABAB);
}

__forceinline bool PEBBeingDebugged()
{
    PPEB pPeb = (PPEB)__readgsqword(0x60);
    return pPeb->BeingDebugged;
}

__forceinline bool IsDebuggerPresentPatched()
{
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (!hKernel32)
        return false;

    FARPROC pIsDebuggerPresent = GetProcAddress(hKernel32, "IsDebuggerPresent");
    if (!pIsDebuggerPresent)
        return false;

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (INVALID_HANDLE_VALUE == hSnapshot)
        return false;

    PROCESSENTRY32W ProcessEntry;
    ProcessEntry.dwSize = sizeof(PROCESSENTRY32W);

    if (!Process32FirstW(hSnapshot, &ProcessEntry))
        return false;

    bool bDebuggerPresent = false;
    HANDLE hProcess = NULL;
    DWORD dwFuncBytes = 0;
    const DWORD dwCurrentPID = GetCurrentProcessId();
    do
    {
        __try
        {
            if (dwCurrentPID == ProcessEntry.th32ProcessID)
                __leave;

            hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcessEntry.th32ProcessID);
            if (NULL == hProcess)
                __leave;

            if (!ReadProcessMemory(hProcess, pIsDebuggerPresent, &dwFuncBytes, sizeof(DWORD), NULL))
                __leave;

            if (dwFuncBytes != *(PDWORD)pIsDebuggerPresent)
            {
                bDebuggerPresent = true;
                __leave;
            }
        }
        __finally
        {
            if (hProcess)
                CloseHandle(hProcess);
        }
    } while (Process32NextW(hSnapshot, &ProcessEntry));

    if (hSnapshot)
        CloseHandle(hSnapshot);

    return bDebuggerPresent;
}

__forceinline void PatchRemoteBreakin()
{
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll)
        return;

    FARPROC pDbgUiRemoteBreakin = GetProcAddress(hNtdll, "DbgUiRemoteBreakin");
    if (!pDbgUiRemoteBreakin)
        return;

    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (!hKernel32)
        return;

    FARPROC pTerminateProcess = GetProcAddress(hKernel32, "TerminateProcess");
    if (!pTerminateProcess)
        return;

    DbgUiRemoteBreakinPatch patch = { 0 };
    patch.push_0 = '\x6A\x00';
    patch.push = '\x68';
    patch.CurrentPorcessHandle = 0xFFFFFFFF;
    patch.mov_eax = '\xB8';
    patch.TerminateProcess = (DWORD)(DWORD_PTR)pTerminateProcess;
    patch.call_eax = '\xFF\xD0';

    DWORD dwOldProtect;
    if (!VirtualProtect(pDbgUiRemoteBreakin, sizeof(DbgUiRemoteBreakinPatch), PAGE_READWRITE, &dwOldProtect))
        return;

    ::memcpy_s(pDbgUiRemoteBreakin, sizeof(DbgUiRemoteBreakinPatch),
        &patch, sizeof(DbgUiRemoteBreakinPatch));
    VirtualProtect(pDbgUiRemoteBreakin, sizeof(DbgUiRemoteBreakinPatch), dwOldProtect, &dwOldProtect);
}

__forceinline bool CheckHardwareBP()
{
    CONTEXT ctx;
    ZeroMemory(&ctx, sizeof(CONTEXT));
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    if (!GetThreadContext(GetCurrentThread(), &ctx))
        return false;

    return ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3;
}
#pragma endregion

bool Security::HasHooks()
{
    std::vector<void*> addys{
        (void*)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "GetModuleHandleA"),
        (void*)GetProcAddress(GetModuleHandleW(L"user32.dll"), "FindWindowA"),
        (void*)GetProcAddress(GetModuleHandleW(L"Advapi32.dll"), "RegOpenKeyA"),
        (void*)GetProcAddress(GetModuleHandleW(L"Advapi32.dll"), "RegQueryValueExA"),
        (void*)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtSetInformationThread"),
        (void*)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryVirtualMemory"),
        (void*)GetProcAddress(GetModuleHandleW(L"ws2_32.dll"), "recv"),
        //(void*)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "GetVolumeInformationA"),
        (void*)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "TerminateProcess"),
        (void*)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQuerySystemInformation"),
    };

    for (auto address : addys) {
        if (address) {
            while (*(BYTE*)(address) == 0x90) {
                address = (void*)((uintptr_t)address + 0x1);
                Sleep(1);
            }

            if (*(BYTE*)address == 0xE9 || *(BYTE*)address == 0xC3 ||
                *(BYTE*)address == 0xEB ||
                (*(BYTE*)address == 0xFF && *((BYTE*)address + 1) == 0x25)) {
                return true;
            }
        }
    }

    return false;
}

bool Security::IsBeingDebugged()
{
    return RemoteDebuggerPresentAPI() ||
           NtQueryInformationProcessDebugFlags() ||
           NtQueryInformationProcessDebugObject() ||
           heapDebuggerFlags() ||
           HeapProtectionFlag() ||
           PEBBeingDebugged() ||
           IsDebuggerPresentPatched() ||
           CheckHardwareBP();
}

void Security::AntiAttach()
{
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll)
        return;

    FARPROC pDbgBreakPoint = GetProcAddress(hNtdll, "DbgBreakPoint");
    if (!pDbgBreakPoint)
        return;

    DWORD dwOldProtect;
    if (!VirtualProtect(pDbgBreakPoint, 1, PAGE_EXECUTE_READWRITE, &dwOldProtect))
        return;

    *(PBYTE)pDbgBreakPoint = (BYTE)0xC3;

    PatchRemoteBreakin();
}

bool IsUsingVMWARE() {
    DWORD error = ERROR_SUCCESS;
    DWORD acpiDataSize = 0;
    BYTE* acpiData = NULL;
    DWORD bytesWritten = 0;

    acpiDataSize = GetSystemFirmwareTable('ACPI', 'TEPH', NULL, 0);

    acpiData = (BYTE*)HeapAlloc(GetProcessHeap(), 0, acpiDataSize);
    if (!acpiData) {
        return false;
    }

    bytesWritten = GetSystemFirmwareTable('ACPI', 'TEPH', acpiData, acpiDataSize);

    if (bytesWritten != acpiDataSize) {
        HeapFree(GetProcessHeap(), 0, acpiData);
        return false;
    }

    std::string haystack(acpiData, acpiData + bytesWritten);
    bool result = haystack.find("VMWARE") != std::string::npos;

    HeapFree(GetProcessHeap(), 0, acpiData);
    return result;
}

bool HasVm3dgl() {
    WIN32_FIND_DATAW findFileData;
    HANDLE file = FindFirstFileW(
        L"C:\\Windows\\System32\\vm3dgl.dll",
        &findFileData
    );

    if (file != INVALID_HANDLE_VALUE) {
        FindClose(file);
        return true;
    }
    return false;
}

bool HasSuspiciousRegistery() {
    HKEY hkResult;
    LONG key = RegOpenKeyExW(
        HKEY_LOCAL_MACHINE,
        L"System\\ControlSet001\\Services\\VMTools",
        0,
        KEY_QUERY_VALUE,
        &hkResult
    );

    if (key == ERROR_SUCCESS) {
        RegCloseKey(hkResult);
        return true;
    }
    return false;
}

bool HasSuspiciousSpecs() {
    SYSTEM_INFO lpSystemInfo;
    GetSystemInfo(&lpSystemInfo);
    DWORD numberOfProcessors = lpSystemInfo.dwNumberOfProcessors;
    if (numberOfProcessors < 2)
        return true;

    MEMORYSTATUSEX memoryStatus;
    memoryStatus.dwLength = sizeof(memoryStatus);
    GlobalMemoryStatusEx(&memoryStatus);
    DWORD RAMMB = (DWORD)(memoryStatus.ullTotalPhys / 1024 / 1024);
    if (RAMMB < 2048)
        return true;

    return false;
}

bool Security::IsOnVM()
{
    return HasSuspiciousSpecs() || HasSuspiciousRegistery() || HasVm3dgl() || IsUsingVMWARE();
}

#pragma region txtSectionIntegrity

int GetAllModule(std::vector<LPVOID>& modules) {
    MODULEENTRY32W mEntry;
    memset(&mEntry, 0, sizeof(mEntry));
    mEntry.dwSize = sizeof(MODULEENTRY32);

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE)
        return -1;

    if (Module32FirstW(hSnapshot, &mEntry)) {
        do {
            modules.emplace_back(mEntry.modBaseAddr);
        } while (Module32NextW(hSnapshot, &mEntry));
    }

    CloseHandle(hSnapshot);

    if (modules.empty()) {
        return -1;
    }

    return 0;
}

int GetTextSectionInfo(LPVOID lpModBaseAddr, PSECTIONINFO info) {
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpModBaseAddr;
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        return -1;
    }

    PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((BYTE*)lpModBaseAddr + pDosHeader->e_lfanew);
    if (pNtHeader->Signature != IMAGE_NT_SIGNATURE) {
        return -1;
    }

    PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((BYTE*)pNtHeader +
        sizeof(DWORD) +
        sizeof(IMAGE_FILE_HEADER) +
        pNtHeader->FileHeader.SizeOfOptionalHeader);

    for (int i = 0; i < pNtHeader->FileHeader.NumberOfSections; ++i) {
        char* name = (char*)pSectionHeader->Name;

        if (!strcmp(name, ".text")) {
            info->lpVirtualAddress = (LPVOID)((DWORD64)lpModBaseAddr + pSectionHeader->VirtualAddress);
            info->dwSizeOfRawData = pSectionHeader->SizeOfRawData;
            return 0;
        }

        ++pSectionHeader;
    }

    return -1;
}

DWORD64 Security::HashSection(LPVOID lpSectionAddress, DWORD dwSizeOfRawData) {
    DWORD64 hash = 0;
    BYTE* str = (BYTE*)lpSectionAddress;
    for (DWORD i = 0; i < dwSizeOfRawData; ++i, ++str) {
        if (*str) {
            hash = *str + (hash << 6) + (hash << 16) - hash;
        }
    }

    return hash;
}
#pragma endregion

std::vector<HASHSET> Security::GetModulesSectionHash()
{
    std::vector<LPVOID> modules;
    GetAllModule(modules);
    std::vector<HASHSET> hashes;
    hashes.reserve(modules.size());

    for (auto& module : modules) {
        SECTIONINFO info;
        if (GetTextSectionInfo(module, &info) == 0) {
            DWORD64 dwRealHash = HashSection(info.lpVirtualAddress, info.dwSizeOfRawData);
            hashes.emplace_back(HASHSET{ dwRealHash, info });
        }
    }

    return hashes;
}

void Security::exe_detect()
{
    const char* suspicious_processes[] = {
        "KsDumperClient.exe", "HTTPDebuggerUI.exe", "HTTPDebuggerSvc.exe",
        "FolderChangesView.exe", "procmon.exe", "idaq.exe", "ida.exe",
        "idaq64.exe", "Wireshark.exe", "Fiddler.exe", "Xenos64.exe",
        "Cheat Engine.exe", "HTTP Debugger Windows Service (32 bit).exe",
        "KsDumper.exe", "x64dbg.exe", "x32dbg.exe", "Fiddler Everywhere.exe",
        "die.exe", "OLLYDBG.exe", "HxD64.exe", "HxD32.exe", "snowman.exe",
        "NLClientApp.exe"
    };

    for (const char* proc : suspicious_processes) {
        if (find_dbg(proc)) {
            debugger_detected(proc);
        }
    }
}

void Security::title_detect()
{
    const char* suspicious_windows[] = {
        "IDA: Quick start", "Memory Viewer", "Cheat Engine", "Cheat Engine 7.4",
        "Cheat Engine 7.3", "Cheat Engine 7.2", "Cheat Engine 7.1", "Cheat Engine 7.0",
        "Process List", "x32DBG", "x64DBG", "KsDumper", "Fiddler Everywhere",
        "Fiddler Classic", "Fiddler Jam", "FiddlerCap", "FiddlerCore",
        "Scylla x86 v0.9.8", "Scylla x64 v0.9.8", "Scylla x86 v0.9.5a",
        "Scylla x64 v0.9.5a", "Scylla x86 v0.9.5", "Scylla x64 v0.9.5",
        "Detect It Easy v3.01", "OllyDbg", "HxD", "Snowman", "NetLimiter"
    };

    for (const char* window_title : suspicious_windows) {
        HWND window = FindWindowA(0, window_title);
        if (window) {
            debugger_detected(window_title);
        }
    }
}