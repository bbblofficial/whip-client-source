#pragma once
#include <Windows.h>

#include "hashutils.h"

#ifdef Themida
#include "secureEngineMacros.h"
#pragma optimize("", off)
#endif

// Buffer statique pour éviter les allocations dynamiques
static char hwid_buffer[65]; // 64 caractères + null terminator

inline DWORD volumeInfo() {
#ifdef Themida
	VM_EAGLE_RED_START
#endif
	DWORD hddNumber = 0;
	if (GetVolumeInformationA("C:\\", NULL, 0, &hddNumber, NULL, NULL, NULL, 0)) {
		return hddNumber;
	}
	return 0;
#ifdef Themida
	VM_EAGLE_RED_END
#endif
}

inline DWORD sysInfo() {
#ifdef Themida
	VM_EAGLE_RED_START
#endif
	SYSTEM_INFO siSysInfo;
	GetSystemInfo(&siSysInfo);

	DWORD info1 = siSysInfo.dwOemId;
	DWORD info2 = siSysInfo.dwNumberOfProcessors;
	DWORD info3 = siSysInfo.dwProcessorType;
	DWORD info4 = (DWORD)siSysInfo.dwActiveProcessorMask;
	DWORD info5 = (DWORD)siSysInfo.wProcessorLevel;
	DWORD info6 = (DWORD)siSysInfo.wProcessorRevision;

	return (info1 ^ info2 ^ info3 ^ info4 ^ info5 ^ info6) * 123456789;
#ifdef Themida
	VM_EAGLE_RED_END
#endif
}

inline const char* getHwid() {
#ifdef Themida
	VM_EAGLE_RED_START
#endif

	DWORD combined = volumeInfo() + sysInfo();

	char temp_buffer[32];
	wsprintfA(temp_buffer, "%lu", combined);

	picosha2::hash256_cstring(temp_buffer, hwid_buffer, sizeof(hwid_buffer));

	return hwid_buffer;

#ifdef Themida
	VM_EAGLE_RED_END
#endif
}