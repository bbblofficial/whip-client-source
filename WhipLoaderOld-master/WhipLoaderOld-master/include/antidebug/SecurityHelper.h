#pragma once
#include <Windows.h>
#include <vector>

typedef struct {
    LPVOID lpVirtualAddress;
    DWORD dwSizeOfRawData;
} SECTIONINFO, * PSECTIONINFO;

typedef struct {
    DWORD64 dwRealHash;
    SECTIONINFO SectionInfo;
} HASHSET, * PHASHSET;

struct DbgUiRemoteBreakinPatch {
    WORD push_0;
    BYTE push;
    DWORD CurrentPorcessHandle;
    BYTE mov_eax;
    DWORD TerminateProcess;
    WORD call_eax;
};

class Security {
public:
    bool IsBeingDebugged();
    bool HasHooks();
    bool IsOnVM();
    void AntiAttach();
    void exe_detect();
    void title_detect();

    std::vector<HASHSET> GetModulesSectionHash();
    DWORD64 HashSection(LPVOID lpSectionAddress, DWORD dwSizeOfRawData);
};