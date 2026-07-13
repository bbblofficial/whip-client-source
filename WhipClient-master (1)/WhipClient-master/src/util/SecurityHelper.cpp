#define WIN32_LEAN_AND_MEAN

#include "../../includes/util/SecurityHelper.h"

#include "includes/util/nt.h"
#include "util/ClientStrings.h"

#ifdef VMP
#include "VMProtectSDK.h"
#endif

#include <winternl.h>
#include <TlHelp32.h>
#include "../../includes/util/HWIDUtils.h"

#include "../../includes/util/algorithm/XORSTRAlgorithm.h"
#include "auth/service/WhipAuthService.h"

DWORD find_dbg(const char* proc)
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

namespace {

	static volatile LONG g_externalPending = 0;
	static char          g_externalName[64] = { 0 };
}

void debugger_detected(const char* name)
{
	if (!name) return;
	size_t i = 0;
	for (; i < sizeof(g_externalName) - 1 && name[i] != '\0'; ++i) {
		g_externalName[i] = name[i];
	}
	g_externalName[i] = '\0';
	InterlockedExchange(&g_externalPending, 1);
}

bool Security::ConsumeExternalDetection(char* nameOut, size_t cap)
{
	if (InterlockedCompareExchange(&g_externalPending, 0, 1) != 1) return false;
	if (nameOut && cap > 0) {
		size_t i = 0;
		for (; i < cap - 1 && g_externalName[i] != '\0'; ++i) {
			nameOut[i] = g_externalName[i];
		}
		nameOut[i] = '\0';
	}
	return true;
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
		sizeof(DWORD),
		nullptr);

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
		information_length,
		nullptr);

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
	patch.TerminateProcess = (DWORD)pTerminateProcess;
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
#ifdef VMP
	VMProtectBeginUltra("HasHooks");
#endif

	auto fc1 = &WhipAuthService::authenticate;
	auto fc2 = &WhipAuthService::isAuthenticated;
	auto fc3 = &WhipAuthService::sendHeartbeat;
	auto fc4 = &WhipAuthService::startHeartbeatLoop;
	auto fc5 = &WhipAuthService::stopHeartbeatLoop;
	auto fc6 = &WhipAuthService::logout;
	auto fc7 = &WhipAuthService::getClient;

	auto fc10 = &WhipNexus::init;
	auto fc11 = &WhipNexus::connect;
	auto fc12 = &WhipNexus::disconnect;
	auto fc13 = &WhipNexus::sendPacket;
	auto fc14 = &WhipNexus::receiveDecryptedPacket;
	auto fc15 = &WhipNexus::registerHandler;
	auto fc16 = &WhipNexus::computeHmac;
	auto fc17 = &WhipNexus::isConnected;
	auto fc18 = &WhipNexus::generateRandomBytes;

	auto fc20 = &SessionManager::hasActiveSession;
	auto fc21 = &SessionManager::createSession;
	auto fc22 = &SessionManager::destroySession;
	auto fc23 = &SessionManager::updateHeartbeat;
	auto fc24 = &SessionManager::validateSession;

	void* addys[] = {

		(void*)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "GetModuleHandleA"),
		(void*)GetProcAddress(GetModuleHandleW(L"user32.dll"), "FindWindowA"),
		(void*)GetProcAddress(GetModuleHandleW(L"Advapi32.dll"), "RegOpenKeyA"),
		(void*)GetProcAddress(GetModuleHandleW(L"Advapi32.dll"), "RegQueryValueExA"),
		(void*)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtSetInformationThread"),
		(void*)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryVirtualMemory"),
		(void*)GetProcAddress(GetModuleHandleW(L"ws2_32.dll"), "recv"),
		(void*)GetProcAddress(GetModuleHandleW(L"ws2_32.dll"), "send"),
		(void*)GetProcAddress(GetModuleHandleW(L"ws2_32.dll"), "connect"),
		(void*)GetProcAddress(GetModuleHandleW(L"ws2_32.dll"), "socket"),
		(void*)GetProcAddress(GetModuleHandleW(L"ws2_32.dll"), "closesocket"),
		(void*)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "GetVolumeInformationA"),
		(void*)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "TerminateProcess"),
		(void*)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQuerySystemInformation"),

		(void*&)fc1, (void*&)fc2, (void*&)fc3, (void*&)fc4, (void*&)fc5,
		(void*&)fc6, (void*&)fc7,

		(void*&)fc10, (void*&)fc11, (void*&)fc12, (void*&)fc13, (void*&)fc14,
		(void*&)fc15, (void*&)fc16, (void*&)fc17, (void*&)fc18,

		(void*&)fc20, (void*&)fc21, (void*&)fc22, (void*&)fc23, (void*&)fc24,
	};

	const DWORD addysCount = sizeof(addys) / sizeof(addys[0]);
	for (DWORD i = 0; i < addysCount; i++) {
		void* address = addys[i];
		if (address) {

			while (*(BYTE*)(address) == 0x90) {
				address = (void*)((uintptr_t)address + 0x1);
				Sleep(1);
			}

			if (*(BYTE*)address == 0xE9 || *(BYTE*)address == 0xC3) {
				return true;
			}
		}
	}

#ifdef VMP
	VMProtectEnd();
#endif
	return false;
}

bool Security::IsBeingDebugged()
{
	return RemoteDebuggerPresentAPI() || NtQueryInformationProcessDebugFlags() || NtQueryInformationProcessDebugObject() || heapDebuggerFlags() || HeapProtectionFlag() || PEBBeingDebugged() || IsDebuggerPresentPatched();
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
}

bool IsUsingVMWARE() {
#ifdef VMP
	VMProtectBeginUltra("IsUsingVMWARE");
#endif
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

	const char* needle = "VMWARE";
	const DWORD needleLen = 6;
	bool found = false;
	for (DWORD i = 0; i + needleLen <= bytesWritten; i++) {
		bool match = true;
		for (DWORD j = 0; j < needleLen; j++) {
			if (acpiData[i + j] != (BYTE)needle[j]) { match = false; break; }
		}
		if (match) { found = true; break; }
	}

	HeapFree(GetProcessHeap(), 0, acpiData);
#ifdef VMP
	VMProtectEnd();
#endif
	return found;
}

bool HasVm3dgl() {
#ifdef VMP
	VMProtectBeginUltra("HasVm3dgl");
#endif
	WIN32_FIND_DATAW findFileData;
	HANDLE file = FindFirstFileW(
		L"C:\\Windows\\System32\\vm3dgl.dll",
		&findFileData
	);

	return file != INVALID_HANDLE_VALUE;
#ifdef VMP
	VMProtectEnd();
#endif
}

bool HasSuspiciousRegistery() {
#ifdef VMP
	VMProtectBeginUltra("HasSuspiciousRegistery");
#endif
	HKEY hkResult;
	LONG key = RegOpenKeyExW(
		HKEY_LOCAL_MACHINE,
		L"System\\ControlSet001\\Services\\VMTools",
		0,
		KEY_QUERY_VALUE,
		&hkResult
	);

	return key == ERROR_SUCCESS;
#ifdef VMP
	VMProtectEnd();
#endif
}

bool HasSuspiciousSpecs() {
#ifdef VMP
	VMProtectBeginUltra("HasSuspiciousSpecs");
#endif
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
#ifdef VMP
	VMProtectEnd();
#endif
}

bool Security::IsOnVM()
{
	return HasSuspiciousSpecs() || HasSuspiciousRegistery() || HasVm3dgl() || IsUsingVMWARE();
}

#pragma region txtSectionIntegrity

static int GetAllModule(LPVOID* modules, DWORD* count) {
	*count = 0;
	MODULEENTRY32W mEntry = {};
	mEntry.dwSize = sizeof(MODULEENTRY32);

	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, NULL);
	if (hSnapshot == INVALID_HANDLE_VALUE) return -1;

	if (Module32FirstW(hSnapshot, &mEntry)) {
		do {
			if (*count < MAX_MODULES_COUNT) {
				modules[(*count)++] = mEntry.modBaseAddr;
			}
		} while (Module32NextW(hSnapshot, &mEntry));
	}

	CloseHandle(hSnapshot);
	return (*count == 0) ? -1 : 0;
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
	for (int i = 0; i < (int)dwSizeOfRawData; ++i, ++str) {
		if (*str) {
			hash = *str + (hash << 6) + (hash << 16) - hash;
		}
	}

	return hash;
}
#pragma endregion

HashSetList Security::GetModulesSectionHash()
{
	LPVOID modules[MAX_MODULES_COUNT] = {};
	DWORD count = 0;
	GetAllModule(modules, &count);

	HashSetList result;
	for (DWORD i = 0; i < count; i++) {
		SECTIONINFO info = {};
		if (GetTextSectionInfo(modules[i], &info) == 0) {
			DWORD64 dwRealHash = HashSection(info.lpVirtualAddress, info.dwSizeOfRawData);
			HASHSET hs = { dwRealHash, info };
			result.add(hs);
		}
	}

	return result;
}

void Security::exe_detect()
{

#ifdef VMP
	VMProtectBeginUltra("exe_detect");
#endif

		if (find_dbg(XorStr("KsDumperClient.exe").c_str()))
		{
			debugger_detected(XorStr("KsDumper").c_str());
		}
		else if (find_dbg(XorStr("HTTPDebuggerUI.exe").c_str()))
		{
			debugger_detected(XorStr("HTTP Debugger").c_str());
		}
		else if (find_dbg(XorStr("HTTPDebuggerSvc.exe").c_str()))
		{
			debugger_detected(XorStr("HTTP Debugger Service").c_str());
		}
		else if (find_dbg(XorStr("FolderChangesView.exe").c_str()))
		{
			debugger_detected(XorStr("FolderChangesView").c_str());
		}
		else if (find_dbg(XorStr("procmon.exe").c_str()))
		{
			debugger_detected(XorStr("Process Monitor").c_str());
		}
		else if (find_dbg(XorStr("idaq.exe").c_str()))
		{
			debugger_detected(XorStr("IDA").c_str());
		}
		else if (find_dbg(XorStr("ida.exe").c_str()))
		{
			debugger_detected(XorStr("IDA").c_str());
		}
		else if (find_dbg(XorStr("idaq64.exe").c_str()))
		{
			debugger_detected(XorStr("IDA").c_str());
		}
		else if (find_dbg(XorStr("Wireshark.exe").c_str()))
		{
			debugger_detected(XorStr("WireShark").c_str());
		}
		else if (find_dbg(XorStr("Fiddler.exe").c_str()))
		{
			debugger_detected(XorStr("Fiddler").c_str());
		}
		else if (find_dbg(XorStr("Xenos64.exe").c_str()))
		{
			debugger_detected(XorStr("Xenos64").c_str());
		}
		else if (find_dbg(XorStr("Cheat Engine.exe").c_str()))
		{
			debugger_detected(XorStr("CheatEngine").c_str());
		}
		else if (find_dbg(XorStr("HTTP Debugger Windows Service (32 bit).exe").c_str()))
		{
			debugger_detected(XorStr("HTTP Debugger").c_str());
		}
		else if (find_dbg(XorStr("KsDumper.exe").c_str()))
		{
			debugger_detected(XorStr("KsDumper").c_str());
		}
		else if (find_dbg(XorStr("x64dbg.exe").c_str()))
		{
			debugger_detected(XorStr("x64DBG").c_str());
		}
		else if (find_dbg(XorStr("x32dbg.exe").c_str()))
		{
			debugger_detected(XorStr("x32DBG").c_str());
		}
		else if (find_dbg(XorStr("Fiddler Everywhere.exe").c_str()))
		{
			debugger_detected(XorStr("FiddlerEverywhere").c_str());
		}
		else if (find_dbg(XorStr("die.exe").c_str()))
		{
			debugger_detected(XorStr("DetectItEasy").c_str());
		}
		else if (find_dbg(XorStr("OLLYDBG.exe").c_str()))
		{
			debugger_detected(XorStr("OLLYDBG").c_str());
		}
		else if (find_dbg(XorStr("HxD64.exe").c_str()))
		{
			debugger_detected(XorStr("HxD64").c_str());
		}
		else if (find_dbg(XorStr("HxD32.exe").c_str()))
		{
			debugger_detected(XorStr("HxD32").c_str());
		}
		else if (find_dbg(XorStr("snowman.exe").c_str()))
		{
			debugger_detected(XorStr("Snowman").c_str());
		}
		else if (find_dbg(XorStr("NLClientApp.exe").c_str()))
		{
			debugger_detected(XorStr("NLClientApp").c_str());
		}
		else if (find_dbg(XorStr("ImHex.exe").c_str()))
		{
			debugger_detected(XorStr("ImHex").c_str());
		}
		else if (find_dbg(XorStr("ReClass.NET.exe").c_str()))
		{
			debugger_detected(XorStr("ReClass.NET").c_str());
		}
		else if (find_dbg(XorStr("ReClass64.exe").c_str()))
		{
			debugger_detected(XorStr("ReClass").c_str());
		}
		else if (find_dbg(XorStr("ReClass.exe").c_str()))
		{
			debugger_detected(XorStr("ReClass").c_str());
		}
		else if (find_dbg(XorStr("x96dbg.exe").c_str()))
		{
			debugger_detected(XorStr("x96DBG").c_str());
		}
		else if (find_dbg(XorStr("charles.exe").c_str()))
		{
			debugger_detected(XorStr("Charles").c_str());
		}
		else if (find_dbg(XorStr("mitmproxy.exe").c_str()))
		{
			debugger_detected(XorStr("mitmproxy").c_str());
		}
		else if (find_dbg(XorStr("mitmdump.exe").c_str()))
		{
			debugger_detected(XorStr("mitmproxy").c_str());
		}
		else if (find_dbg(XorStr("wpepro.exe").c_str()))
		{
			debugger_detected(XorStr("WPEPro").c_str());
		}
		else if (find_dbg(XorStr("HTTP Toolkit.exe").c_str()))
		{
			debugger_detected(XorStr("HTTPToolkit").c_str());
		}

#ifdef VMP
	VMProtectEnd();
#endif

}

void Security::title_detect()
{

#ifdef VMP
	VMProtectBeginUltra("title_detect");
#endif

		HWND window;
		window = FindWindowA(0, XorStr(("IDA: Quick start")).c_str());
		if (window)
		{
			debugger_detected(XorStr("IDA").c_str());
		}

		window = FindWindowA(0, XorStr(("Memory Viewer")).c_str());
		if (window)
		{
			debugger_detected(XorStr("CheatEngine").c_str());
		}

		window = FindWindowA(0, XorStr(("Cheat Engine")).c_str());
		if (window)
		{
			debugger_detected(XorStr("CheatEngine").c_str());
		}

		window = FindWindowA(0, XorStr(("Cheat Engine 7.4")).c_str());
		if (window)
		{
			debugger_detected(XorStr("CheatEngine").c_str());
		}

		window = FindWindowA(0, XorStr(("Cheat Engine 7.3")).c_str());
		if (window)
		{
			debugger_detected(XorStr("CheatEngine").c_str());
		}

		window = FindWindowA(0, XorStr(("Cheat Engine 7.2")).c_str());
		if (window)
		{
			debugger_detected(XorStr("CheatEngine").c_str());
		}

		window = FindWindowA(0, XorStr(("Cheat Engine 7.1")).c_str());
		if (window)
		{
			debugger_detected(XorStr("CheatEngine").c_str());
		}

		window = FindWindowA(0, XorStr(("Cheat Engine 7.0")).c_str());
		if (window)
		{
			debugger_detected(XorStr("CheatEngine").c_str());
		}

		window = FindWindowA(0, XorStr(("Process List")).c_str());
		if (window)
		{
			debugger_detected(XorStr("CheatEngine").c_str());
		}

		window = FindWindowA(0, XorStr(("x32DBG")).c_str());
		if (window)
		{
			debugger_detected(XorStr("x32DBG").c_str());
		}

		window = FindWindowA(0, XorStr(("x64DBG")).c_str());
		if (window)
		{
			debugger_detected(XorStr("x64DBG").c_str());
		}

		window = FindWindowA(0, XorStr(("KsDumper")).c_str());
		if (window)
		{
			debugger_detected(XorStr("KsDumper").c_str());
		}
		window = FindWindowA(0, XorStr(("Fiddler Everywhere")).c_str());
		if (window)
		{
			debugger_detected(XorStr("FiddlerEverywhere").c_str());
		}
		window = FindWindowA(0, XorStr(("Fiddler Classic")).c_str());
		if (window)
		{
			debugger_detected(XorStr("FiddlerClassic").c_str());
		}

		window = FindWindowA(0, XorStr(("Fiddler Jam")).c_str());
		if (window)
		{
			debugger_detected(XorStr("FiddlerJam").c_str());
		}

		window = FindWindowA(0, XorStr(("FiddlerCap")).c_str());
		if (window)
		{
			debugger_detected(XorStr("FiddlerCap").c_str());
		}

		window = FindWindowA(0, XorStr(("FiddlerCore")).c_str());
		if (window)
		{
			debugger_detected(XorStr("FiddlerCore").c_str());
		}

		window = FindWindowA(0, XorStr(("Scylla x86 v0.9.8")).c_str());
		if (window)
		{
			debugger_detected(XorStr("Scylla_x86").c_str());
		}

		window = FindWindowA(0, XorStr(("Scylla x64 v0.9.8")).c_str());
		if (window)
		{
			debugger_detected(XorStr("Scylla_x64").c_str());
		}

		window = FindWindowA(0, XorStr(("Scylla x86 v0.9.5a")).c_str());
		if (window)
		{
			debugger_detected(XorStr("Scylla_x86").c_str());
		}

		window = FindWindowA(0, XorStr(("Scylla x64 v0.9.5a")).c_str());
		if (window)
		{
			debugger_detected(XorStr("Scylla_x64").c_str());
		}

		window = FindWindowA(0, XorStr(("Scylla x86 v0.9.5")).c_str());
		if (window)
		{
			debugger_detected(XorStr("Scylla_x86").c_str());
		}

		window = FindWindowA(0, XorStr(("Scylla x64 v0.9.5")).c_str());
		if (window)
		{
			debugger_detected(XorStr("Scylla_x64").c_str());
		}

		window = FindWindowA(0, XorStr(("Detect It Easy v3.01")).c_str());
		if (window)
		{
			debugger_detected(XorStr("DetectItEasy").c_str());
		}

		window = FindWindowA(0, XorStr(("OllyDbg")).c_str());
		if (window)
		{
			debugger_detected(XorStr("OllyDbg").c_str());
		}

		window = FindWindowA(0, XorStr(("HxD")).c_str());
		if (window)
		{
			debugger_detected(XorStr("HxD").c_str());
		}

		window = FindWindowA(0, XorStr(("Snowman")).c_str());
		if (window)
		{
			debugger_detected(XorStr("Snowman").c_str());
		}

		window = FindWindowA(0, XorStr(("NetLimiter")).c_str());
		if (window)
		{
			debugger_detected(XorStr("NetLimiter").c_str());
		}

		window = FindWindowA(0, XorStr(("ImHex")).c_str());
		if (window)
		{
			debugger_detected(XorStr("ImHex").c_str());
		}

		window = FindWindowA(0, XorStr(("ReClass.NET")).c_str());
		if (window)
		{
			debugger_detected(XorStr("ReClass.NET").c_str());
		}

		window = FindWindowA(0, XorStr(("ReClass 2016")).c_str());
		if (window)
		{
			debugger_detected(XorStr("ReClass").c_str());
		}

		window = FindWindowA(0, XorStr(("Charles")).c_str());
		if (window)
		{
			debugger_detected(XorStr("Charles").c_str());
		}

		window = FindWindowA(0, XorStr(("HTTP Toolkit")).c_str());
		if (window)
		{
			debugger_detected(XorStr("HTTPToolkit").c_str());
		}

		window = FindWindowA(0, XorStr(("mitmproxy")).c_str());
		if (window)
		{
			debugger_detected(XorStr("mitmproxy").c_str());
		}

#ifdef VMP
	VMProtectEnd();
#endif

}

void Security::hw_breakpoint_detect()
{
#ifdef VMP
	VMProtectBeginUltra("hw_bp_detect");
#endif

	const DWORD ownPid = GetCurrentProcessId();
	const DWORD ownTid = GetCurrentThreadId();

	HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (snap == INVALID_HANDLE_VALUE) {
#ifdef VMP
		VMProtectEnd();
#endif
		return;
	}

	THREADENTRY32 te = { sizeof(THREADENTRY32) };
	if (Thread32First(snap, &te)) {
		do {
			if (te.th32OwnerProcessID != ownPid) continue;
			if (te.th32ThreadID == ownTid) continue;

			HANDLE hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION,
			                            FALSE, te.th32ThreadID);
			if (!hThread) continue;

			CONTEXT ctx = { 0 };
			ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
			if (GetThreadContext(hThread, &ctx)) {

				if (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3 ||
				    (ctx.Dr7 & 0xFF)) {
					debugger_detected(XorStr("HW-BP").c_str());
					CloseHandle(hThread);
					break;
				}
			}
			CloseHandle(hThread);
		} while (Thread32Next(snap, &te));
	}
	CloseHandle(snap);

#ifdef VMP
	VMProtectEnd();
#endif
}

void Security::kernel_debugger_detect()
{
#ifdef VMP
	VMProtectBeginUltra("kdbg_detect");
#endif

	struct {
		BOOLEAN KernelDebuggerEnabled;
		BOOLEAN KernelDebuggerNotPresent;
	} info = { FALSE, TRUE };

	using NtQuerySystemInformation_t = NTSTATUS (NTAPI*)(
		ULONG SystemInformationClass,
		PVOID SystemInformation,
		ULONG SystemInformationLength,
		PULONG ReturnLength);

	HMODULE ntdll = GetModuleHandleA(XorStr("ntdll.dll").c_str());
	if (!ntdll) {
#ifdef VMP
		VMProtectEnd();
#endif
		return;
	}

	auto pNtQSI = reinterpret_cast<NtQuerySystemInformation_t>(
		GetProcAddress(ntdll, XorStr("NtQuerySystemInformation").c_str()));
	if (!pNtQSI) {
#ifdef VMP
		VMProtectEnd();
#endif
		return;
	}

	ULONG retLen = 0;
	NTSTATUS st = pNtQSI(0x23 ,
	                     &info, sizeof(info), &retLen);

	if (st >= 0 && info.KernelDebuggerEnabled && !info.KernelDebuggerNotPresent) {
		debugger_detected(XorStr("KernelDebugger").c_str());
	}

#ifdef VMP
	VMProtectEnd();
#endif
}
