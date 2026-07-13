#pragma once

#include <windows.h>

#define MAX_MODULES_COUNT 256

typedef struct {
	LPVOID lpVirtualAddress;
	DWORD dwSizeOfRawData;
} SECTIONINFO, * PSECTIONINFO;

typedef struct {
	DWORD64 dwRealHash;
	SECTIONINFO SectionInfo;
} HASHSET, * PHASHSET;

struct HashSetList {
	HASHSET items[MAX_MODULES_COUNT];
	DWORD count;

	__forceinline HashSetList() : count(0) {}
	__forceinline bool empty() const { return count == 0; }
	__forceinline DWORD size() const { return count; }
	__forceinline void add(const HASHSET& h) {
		if (count < MAX_MODULES_COUNT) items[count++] = h;
	}
};

class Security
{
	DWORD64 m_OrgTextSection;
public:
	Security() = default;
	~Security() = default;

	bool HasHooks();
	bool IsBeingDebugged();
	void AntiAttach();
	bool IsOnVM();

	DWORD64 HashSection(LPVOID lpSectionAddress, DWORD dwSizeOfRawData);
	HashSetList GetModulesSectionHash();
	void exe_detect();
	void title_detect();

	void hw_breakpoint_detect();

	void kernel_debugger_detect();

	static bool ConsumeExternalDetection(char* nameOut, size_t cap);
};
