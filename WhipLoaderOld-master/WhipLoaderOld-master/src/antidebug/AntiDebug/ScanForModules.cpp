#include "antidebug/AntiDebug/pch.h"

#define NUMCHARS(a) (sizeof(a)/sizeof(*a))

static HRESULT NormalizeNTPathOld(wchar_t* pszPath, size_t nMax)
{
	wchar_t* pszSlash = wcschr(&pszPath[1], L'\\');
	if (pszSlash) pszSlash = wcschr(pszSlash + 1, L'\\');
	if (!pszSlash)
		return E_FAIL;

	wchar_t cSave = *pszSlash;
	*pszSlash = 0;

	wchar_t szNTPath[_MAX_PATH];
	wchar_t szDrive[_MAX_PATH] = L"A:";

	for (wchar_t cDrive = L'A'; cDrive <= L'Z'; ++cDrive)
	{
		szDrive[0] = cDrive;
		szNTPath[0] = 0;

		if (QueryDosDeviceW(szDrive, szNTPath, _countof(szNTPath)) &&
			_wcsicmp(szNTPath, pszPath) == 0)
		{
			wcscat_s(szDrive, _countof(szDrive), L"\\");
			wcscat_s(szDrive, _countof(szDrive), pszSlash + 1);
			wcscpy_s(pszPath, nMax, szDrive);
			return S_OK;
		}
	}

	*pszSlash = cSave;
	return E_FAIL;
}


static HRESULT NormalizeNTPath(TCHAR* pszPath, size_t nMax)
// Normalizes the path returned by GetProcessImageFileName
{
	if (!pszPath || !*pszPath)
		return E_FAIL;

	// Trouve le deuxième backslash (après "\Device\HarddiskVolumeX")
	TCHAR* pszSlash = StrChr(&pszPath[1], _T('\\'));
	if (pszSlash) pszSlash = StrChr(pszSlash + 1, _T('\\'));
	if (!pszSlash)
		return E_FAIL;

	const TCHAR cSave = *pszSlash;
	*pszSlash = 0;

	TCHAR szNTPath[_MAX_PATH];
	TCHAR szDrive[_MAX_PATH] = _T("A:"); // utilise _T() au lieu de L"..."

	// Vérifie chaque lecteur local
	for (TCHAR cDrive = _T('A'); cDrive <= _T('Z'); ++cDrive)
	{
		szDrive[0] = cDrive;
		szNTPath[0] = 0;

		// QueryDosDeviceA ou QueryDosDeviceW selon UNICODE
		if (QueryDosDevice(szDrive, szNTPath, NUMCHARS(szNTPath)) != 0 &&
			StrCmpI(szNTPath, pszPath) == 0)
		{
			// Match trouvé
			StringCbCat(szDrive, sizeof(szDrive), _T("\\"));
			StringCbCat(szDrive, sizeof(szDrive), pszSlash + 1);
			StringCbCopy(pszPath, nMax * sizeof(TCHAR), szDrive);
			return S_OK;
		}
	}

	*pszSlash = cSave;
	return E_FAIL;
}

bool IsGlobalizationNls(TCHAR* filename)
{
	// exclude this nls
	// consider removing this hack with proper implementation of memory scan
	PCTSTR ret = StrStrI(filename, _T("\\Windows\\Globalization\\Sorting\\SortDefault.nls"));
	return (ret != NULL);
}

bool IsBadLibrary(TCHAR* filename, DWORD filenameLength)
{
    if (!filename || !*filename)
        return true;

    TCHAR systemDrive[MAX_PATH] = { 0 };
    TCHAR systemDriveDevice[MAX_PATH] = { 0 };
    TCHAR systemRootPath[MAX_PATH] = { 0 };
    TCHAR exePath[MAX_PATH] = { 0 };
    TCHAR normalisedPath[MAX_PATH] = { 0 };

    if (IsGlobalizationNls(filename))
        return false;

    // Copie sécurisée et normalisation
    StringCbCopy(normalisedPath, sizeof(normalisedPath), filename);
    NormalizeNTPath(normalisedPath, MAX_PATH);

    size_t normalisedPathLength = 0;
    StringCbLength(normalisedPath, sizeof(normalisedPath), &normalisedPathLength);

    // Calcul réel de la longueur du nom de fichier
    if (filenameLength == INVALID_FILE_SIZE)
    {
        size_t filenameActualLength = 0;
        StringCbLength(filename, sizeof(filename), &filenameActualLength);
        filenameLength = (DWORD)filenameActualLength;
    }

    GetSystemDirectory(systemRootPath, NUMCHARS(systemRootPath));

#ifdef _X86_
    TCHAR syswow64Path[MAX_PATH] = { 0 };
    SHGetFolderPath(NULL, CSIDL_SYSTEMX86, NULL, 0, syswow64Path);
    StringCbCat(syswow64Path, sizeof(syswow64Path), _T("\\"));
    size_t syswow64PathLength = 0;
    StringCbLength(syswow64Path, sizeof(syswow64Path), &syswow64PathLength);
#endif

    size_t exePathLength = GetProcessImageFileName(GetCurrentProcess(), exePath, MAX_PATH);
    NormalizeNTPath(exePath, MAX_PATH);
    StringCbLength(exePath, sizeof(exePath), &exePathLength);

    if (GetEnvironmentVariable(_T("SystemDrive"), systemDrive, NUMCHARS(systemDrive)) > 0)
    {
        // Attention : QueryDosDevice ne doit pas être forcée en version "W" quand on compile en TCHAR
        if (QueryDosDevice(systemDrive, systemDriveDevice, NUMCHARS(systemDriveDevice)) > 0)
        {
            StringCbCat(systemDriveDevice, sizeof(systemDriveDevice), _T("\\Windows\\System32\\"));
            size_t systemDriveDevicelength = 0;
            StringCbLength(systemDriveDevice, sizeof(systemDriveDevice), &systemDriveDevicelength);

            // Vérifie le chemin NT
            if (StrNCmpI(systemDriveDevice, filename, (int)(min(systemDriveDevicelength, filenameLength) / sizeof(TCHAR))) == 0)
                return false;

            // Vérifie le chemin système normal
            StringCbCat(systemRootPath, sizeof(systemRootPath), _T("\\"));
            size_t systemRootPathLength = 0;
            StringCbLength(systemRootPath, sizeof(systemRootPath), &systemRootPathLength);

            if (StrNCmpI(systemRootPath, normalisedPath, (int)(min(systemRootPathLength, normalisedPathLength) / sizeof(TCHAR))) == 0)
                return false;

#ifdef _X86_
            if (IsWoW64() && StrNCmpI(syswow64Path, normalisedPath, (int)(min(syswow64PathLength, normalisedPathLength) / sizeof(TCHAR))) == 0)
                return false;
#endif

            // Vérifie si c’est l’exécutable lui-même
            if (StrCmpI(exePath, normalisedPath) == 0)
                return false;
        }
    }

    return true;
}

BOOL ScanForModules_EnumProcessModulesEx_Internal(DWORD moduleFlag)
{
	//printf("EnumProcessModulesEx()\n");
	HMODULE* moduleList;
	HMODULE* tmp;
	DWORD currentSize = 1024 * sizeof(HMODULE);
	DWORD requiredSize = 0;
	bool anyBadLibs = false;

	// the EnumProcessModulesEx API was moved from psapi.dll into kernel32.dll for Windows 7, then back out afterwards.
	// check for availability of either.
	if (!API::IsAvailable(API_EnumProcessModulesEx_PSAPI) && !API::IsAvailable(API_EnumProcessModulesEx_Kernel))
	{
		// neither available
		return FALSE;
	}

	// API is available in one of the two libraries, use whichever is available.
	pEnumProcessModulesEx fnEnumProcessModulesEx;
	if (API::IsAvailable(API_EnumProcessModulesEx_PSAPI))
	{
		fnEnumProcessModulesEx = static_cast<pEnumProcessModulesEx>(API::GetAPI(API_IDENTIFIER::API_EnumProcessModulesEx_PSAPI));
	}
	else
	{
		fnEnumProcessModulesEx = static_cast<pEnumProcessModulesEx>(API::GetAPI(API_IDENTIFIER::API_EnumProcessModulesEx_Kernel));
	}

	moduleList = static_cast<HMODULE*>(calloc(1024, sizeof(HMODULE)));
	if (moduleList) {

		if (fnEnumProcessModulesEx(GetCurrentProcess(), moduleList, currentSize, &requiredSize, moduleFlag))
		{
			bool success = true;
			if (requiredSize > currentSize)
			{
				currentSize = requiredSize;
				tmp = static_cast<HMODULE*>(realloc(moduleList, currentSize));
				if (tmp) {
					moduleList = tmp;
					if (fnEnumProcessModulesEx(GetCurrentProcess(), moduleList, currentSize, &requiredSize, moduleFlag) == FALSE)
					{
						success = false;
					}
				}
				else {
					success = false; //realloc failed
				}
			}
			if (success)
			{
				DWORD count = requiredSize / sizeof(HMODULE);
				TCHAR moduleName[MAX_PATH];
				for (DWORD i = 0; i < count; i++)
				{
					DWORD len;
					if ((len = GetModuleFileNameEx(GetCurrentProcess(), moduleList[i], moduleName, MAX_PATH)) > 0)
					{
						bool isBad = IsBadLibrary(moduleName, len);
						if (isBad)
						anyBadLibs |= isBad;
					}
				}
			}
		}

		free(moduleList);
	}
	return anyBadLibs ? TRUE : FALSE;
}

BOOL ScanForModules_EnumProcessModulesEx_32bit()
{
	return ScanForModules_EnumProcessModulesEx_Internal(LIST_MODULES_32BIT);
}

BOOL ScanForModules_EnumProcessModulesEx_64bit()
{

	return ScanForModules_EnumProcessModulesEx_Internal(LIST_MODULES_64BIT);
}

BOOL ScanForModules_EnumProcessModulesEx_All()
{
	return ScanForModules_EnumProcessModulesEx_Internal(LIST_MODULES_ALL);
}

BOOL ScanForModules_MemoryWalk_GMI()
{
	// TODO: Convert this to the new enumerate_memory() API for speed!

	MEMORY_BASIC_INFORMATION memInfo = { 0 };
	HMODULE moduleHandle = 0;
	TCHAR moduleName[MAX_PATH];
	MODULEINFO moduleInfo = { 0 };

	auto memoryRegions = enumerate_memory();

	bool anyBadLibs = false;

	for (PMEMORY_BASIC_INFORMATION region : *memoryRegions)
	{
		if (region->State == MEM_FREE)
		{
			delete region;
			continue;
		}

		PBYTE addr = static_cast<PBYTE>(region->BaseAddress);
		PBYTE regionEnd = addr + region->RegionSize;

		//printf("Scanning %p - %p ...\n", addr, regionEnd);

		while (addr < regionEnd)
		{
			bool skippedForward = false;
			if (VirtualQuery(addr, &memInfo, sizeof(MEMORY_BASIC_INFORMATION)) >= sizeof(MEMORY_BASIC_INFORMATION))
			{
				if (memInfo.State != MEM_FREE)
				{
					if (GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (TCHAR*)addr, &moduleHandle))
					{
						SecureZeroMemory(moduleName, MAX_PATH * sizeof(TCHAR));
						DWORD len = GetModuleFileName(moduleHandle, moduleName, MAX_PATH);
						//printf(" [!] %p: %S\n", addr, moduleName);
						bool isBad = IsBadLibrary(moduleName, len);
						if (isBad)
							printf(" [!] Injected library: %S\n", moduleName);
						anyBadLibs |= isBad;

						if (GetModuleInformation(GetCurrentProcess(), moduleHandle, &moduleInfo, sizeof(MODULEINFO)))
						{
							size_t moduleSizeRoundedUp = (moduleInfo.SizeOfImage + 1);
							moduleSizeRoundedUp += 4096 - (moduleSizeRoundedUp % 4096);
							PBYTE nextPos = static_cast<PBYTE>(moduleInfo.lpBaseOfDll) + moduleSizeRoundedUp;
							if (nextPos > addr)
							{
								//printf(" -> Moving from %x to %x\n", addr, nextPos);
								addr = nextPos;
								skippedForward = true;
							}
						}
					}
				}
			}
			if (!skippedForward)
				addr += 4096;
		}
		delete region;
	}
	delete memoryRegions;

	return anyBadLibs ? TRUE : FALSE;
}

BOOL ScanForModules_MemoryWalk_Hidden()
{
	HMODULE moduleHandle = 0;
	TCHAR moduleName[MAX_PATH];

	auto memoryRegions = enumerate_memory();

	bool anyBadLibs = false;

	bool firstPrint = true;
	for (PMEMORY_BASIC_INFORMATION region : *memoryRegions)
	{
		if (region->State == MEM_FREE)
		{
			delete region;
			continue;
		}

		PBYTE addr = static_cast<PBYTE>(region->BaseAddress);
		PBYTE regionEnd = addr + region->RegionSize;

		//printf("Scanning %p - %p ...\n", addr, regionEnd);

		while (addr < regionEnd)
		{
			bool skippedForward = false;

			if (GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (TCHAR*)addr, &moduleHandle) == FALSE)
			{
				// not a known module
				if ((region->State & MEM_COMMIT) == MEM_COMMIT &&
					((region->Protect == PAGE_READONLY) ||
						(region->Protect == PAGE_READWRITE) ||
						(region->Protect == PAGE_EXECUTE_READ) ||
						(region->Protect == PAGE_EXECUTE_READWRITE) ||
						(region->Protect == PAGE_EXECUTE_WRITECOPY)))
				{
					auto moduleData = static_cast<PBYTE>(region->BaseAddress);
					if (moduleData[0] == 'M' && moduleData[1] == 'Z')
					{
						if (firstPrint)
						{
							firstPrint = false;
							printf("\n\n");

							if (IsWoW64())
							{
								printf(" [!] Running on WoW64, there will be false positives due to wow64 DLLs.\n");
							}
						}

						printf(" [!] Executable at %p\n", region->BaseAddress);
						anyBadLibs = true;
					}
				}
			}
			else
			{
				MODULEINFO modInfo = { 0 };
				if (GetModuleInformation(GetCurrentProcess(), moduleHandle, &modInfo, sizeof(MODULEINFO)))
				{
					size_t moduleSizeRoundedUp = (modInfo.SizeOfImage + 1);
					moduleSizeRoundedUp += 4096 - (moduleSizeRoundedUp % 4096);
					PBYTE nextPos = static_cast<PBYTE>(modInfo.lpBaseOfDll) + moduleSizeRoundedUp;
					if (nextPos > addr)
					{
						//printf(" -> Moving from %x to %x\n", addr, nextPos);
						addr = nextPos;
						skippedForward = true;
					}
				}
			}

			SecureZeroMemory(moduleName, sizeof(TCHAR) * MAX_PATH);
			DWORD len;
			if ((len = GetMappedFileName(GetCurrentProcess(), region->AllocationBase, moduleName, MAX_PATH)) > 0)
			{
				bool isBad = IsBadLibrary(moduleName, len);
				if (isBad)
					printf(" [!] Injected library: %S\n", moduleName);
				anyBadLibs |= isBad;

				// mapped files take up a whole region, so just skip to the end of the region
				addr = regionEnd;
				skippedForward = true;
			}

			if (!skippedForward)
				addr += 4096;
		}

		delete region;
	}
	delete memoryRegions;

	return anyBadLibs ? TRUE : FALSE;
}

BOOL ScanForModules_DotNetModuleStructures()
{
	HMODULE moduleHandle = 0;

	auto memoryRegions = enumerate_memory();

	bool anyBadLibs = false;

	/*
	This works because the .NET runtime loads structures into memory that describe modules. This happens even if the module is loaded dynamically, from memory.
	If al-khaser were a .NET application we'd need to apply some additional checks on the results, but since it isn't then we can just report every .NET module we find.
	This check is quite effective because it catches pretty much any kind of .NET injection, even if the injector uses tricks like messing with PE headers or patching EWT.
	*/

	bool firstPrint = true;
	for (PMEMORY_BASIC_INFORMATION region : *memoryRegions)
	{
		if (region->State == MEM_FREE || region->Type == MEM_MAPPED || region->Type == MEM_IMAGE)
		{
			//printf("region %p skipped for being free, mapped, or image.\n", region->BaseAddress);
			delete region;
			continue;
		}

		if ((region->State & MEM_COMMIT) == MEM_COMMIT &&
			region->Protect == PAGE_READWRITE &&
			region->AllocationProtect == PAGE_READWRITE)
		{
			uint64_t* addr = static_cast<uint64_t*>(region->BaseAddress);
			uint64_t* regionEnd = addr + (region->RegionSize / sizeof(uint64_t));

			// check first qword at region base address. should be zero.
			if (*addr == 0)
			{
				// find the pattern of QWORDs we want (0, 0, 0, 0, 0, 0, pointer, length, 1, 2, 0, 2, 0, 2, 0)
				while (addr < regionEnd - 32)
				{
					uint64_t* ptr = addr;
					bool sixZeroes = true;
					for (int i = 0; i < 6; i++)
					{
						sixZeroes &= *(ptr++) == 0;
					}
					if (sixZeroes)
					{
						//printf("got six zeroes at %p\n", ptr);
						uint64_t stringPtrVal = *ptr;
						PCWSTR stringPtr = reinterpret_cast<PCWSTR>(*ptr);
						ptr++;
						uint64_t stringLen = *ptr;
						ptr++;
						if (*ptr++ == 1 && *ptr++ == 2 && *ptr++ == 0 && *ptr++ == 2 && *ptr++ == 0 && *ptr++ == 2 && *ptr++ == 0)
						{
							// pattern matches, check string addr
							if ((stringPtrVal & 0xFFFFFFFF00000000ULL) == ((uint64_t)ptr & 0xFFFFFFFF00000000ULL))
							{
								// check string length is sane
								if (stringLen < MAX_PATH * sizeof(wchar_t))
								{
									// ok, we're sure it's the right structure. report it.

									if (firstPrint)
									{
										printf("\n\n");
									}
									printf(" [!] Found module: %S (structure address %p)\n", stringPtr, stringPtr);
									anyBadLibs = true;
								}
							}
						}
					}
					addr++;
				}
			}
		}

		delete region;
	}
	delete memoryRegions;

	return anyBadLibs ? TRUE : FALSE;
}

std::vector<LDR_DATA_TABLE_ENTRY*>* WalkLDR(PPEB_LDR_DATA ldrData)
{
	auto entryList = new std::vector<LDR_DATA_TABLE_ENTRY*>();

	LIST_ENTRY* head = ldrData->InMemoryOrderModuleList.Flink;
	LIST_ENTRY* node = head;

	do
	{
		LDR_DATA_TABLE_ENTRY ldrEntry = { 0 };
		LDR_DATA_TABLE_ENTRY* pLdrEntry = CONTAINING_RECORD(node, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

		if (attempt_to_read_memory(pLdrEntry, &ldrEntry, sizeof(ldrEntry)))
		{
			entryList->push_back(new LDR_DATA_TABLE_ENTRY(ldrEntry));

			node = ldrEntry.InMemoryOrderLinks.Flink;
		}
		else
		{
			printf(" [!] Error reading entry.\n");
			break;
		}
	} while (node != head);

	entryList->pop_back();

	return entryList;
}

std::vector<LDR_DATA_TABLE_ENTRY64*>* WalkLDR(PPEB_LDR_DATA64 ldrData)
{
	auto entryList = new std::vector<LDR_DATA_TABLE_ENTRY64*>();

	LIST_ENTRY64 head;
	if (!attempt_to_read_memory_wow64(&head, sizeof(LIST_ENTRY64), ldrData->InMemoryOrderModuleList.Flink))
	{
		printf(" [!] Error reading list head.\n");
	}
	ULONGLONG nodeAddr = ldrData->InMemoryOrderModuleList.Flink;
	LIST_ENTRY64 node = head;
	LDR_DATA_TABLE_ENTRY64 ldrEntry = { 0 };

	do
	{
		if (attempt_to_read_memory_wow64(&ldrEntry, sizeof(LDR_DATA_TABLE_ENTRY64), nodeAddr - sizeof(LIST_ENTRY64)))
		{
			entryList->push_back(new LDR_DATA_TABLE_ENTRY64(ldrEntry));

			if (!attempt_to_read_memory_wow64(&node, sizeof(LIST_ENTRY64), ldrEntry.InMemoryOrderLinks.Flink))
			{
				break;
			}

			nodeAddr = ldrEntry.InMemoryOrderLinks.Flink;
		}
		else
		{
			break;
		}
	} while (nodeAddr != ldrData->InMemoryOrderModuleList.Flink);

	entryList->pop_back();

	return entryList;
}

BOOL ScanForModules_LDR_Direct()
{
    PROCESS_BASIC_INFORMATION pbi = { 0 };

    bool anyBadLibs = false;

    auto NtQueryInformationProcess = static_cast<pNtQueryInformationProcess>(API::GetAPI(API_IDENTIFIER::API_NtQueryInformationProcess));
    NTSTATUS status = NtQueryInformationProcess(GetCurrentProcess(), ProcessBasicInformation, &pbi, sizeof(pbi), nullptr);
    if (status != 0)
    {
        _tprintf(_T("Failed to get process information. Status: %d\n"), (int)status);
        return FALSE;
    }

    if (pbi.PebBaseAddress == nullptr)
        return FALSE;

    PPEB peb = pbi.PebBaseAddress;
    if (peb->Ldr != nullptr)
    {
        PPEB_LDR_DATA ldrData = peb->Ldr;

        auto ldrEntries = WalkLDR(ldrData);
        if (ldrEntries)
        {
            for (LDR_DATA_TABLE_ENTRY* ldrEntry : *ldrEntries)
            {
                if (!ldrEntry)
                    continue;

                // FullDllName.Buffer is a UNICODE_STRING buffer: Length is in bytes
                USHORT lengthBytes = ldrEntry->FullDllName.Length;
                size_t lengthChars = (lengthBytes / sizeof(TCHAR));

                // Defensive: ensure we have at least something to check
                if (ldrEntry->FullDllName.Buffer && lengthChars > 0)
                {
                    // Buffer is already in-process memory => can use it directly
                    TCHAR* moduleName = reinterpret_cast<TCHAR*>(ldrEntry->FullDllName.Buffer);

                    bool isBad = IsBadLibrary(moduleName, (DWORD)lengthBytes);
                    if (isBad)
                        _tprintf(_T(" [!] Injected library: %Ts\n"), moduleName); // _T("%Ts") uses generic-text; if problems, use %ls for wide
                    anyBadLibs |= isBad;
                }
                else
                {
                    _tprintf(_T(" [!] Empty module name or zero length in LDR entry.\n"));
                }

                delete ldrEntry;
            }
            delete ldrEntries;
        }
    }

    // WOW64 path: read 32-bit LDR entries from 64-bit process
    if (IsWoW64())
    {
        PPEB64 peb64 = reinterpret_cast<PPEB64>(GetPeb64());
        if (peb64)
        {
            PEB_LDR_DATA64 ldrData64 = { 0 };

            if (attempt_to_read_memory_wow64(&ldrData64, sizeof(PEB_LDR_DATA64), peb64->Ldr))
            {
                auto ldrEntries64 = WalkLDR(&ldrData64);
                if (ldrEntries64)
                {
                    for (LDR_DATA_TABLE_ENTRY64* ldrEntry64 : *ldrEntries64)
                    {
                        if (!ldrEntry64)
                        {
                            continue;
                        }

                        // FullDllName.Length is bytes (WCHAR size), Buffer is a 32-bit pointer in the target WOW64 memory.
                        USHORT lengthBytes = ldrEntry64->FullDllName.Length;
                        size_t lengthChars = (lengthBytes / sizeof(WCHAR));

                        if (lengthChars == 0 || ldrEntry64->FullDllName.Buffer == 0)
                        {
                            _tprintf(_T(" [!] WOW64 module entry with empty name or buffer.\n"));
                            delete ldrEntry64;
                            continue;
                        }

                        // allocate (chars + 1) wchar_t and read exactly lengthBytes
                        WCHAR* dllNameBuffer = new (std::nothrow) WCHAR[lengthChars + 1];
                        if (!dllNameBuffer)
                        {
                            _tprintf(_T(" [!] Allocation failure for WOW64 dll name buffer.\n"));
                            delete ldrEntry64;
                            continue;
                        }

                        SecureZeroMemory(dllNameBuffer, (lengthChars + 1) * sizeof(WCHAR));

                        // attempt_to_read_memory_wow64 expects byte size
                        if (attempt_to_read_memory_wow64(dllNameBuffer, (SIZE_T)lengthBytes, reinterpret_cast<PVOID>(ldrEntry64->FullDllName.Buffer)))
                        {
                            // Ensure null terminator
                            dllNameBuffer[lengthChars] = L'\0';

                            // Now convert or pass directly: IsBadLibrary expects TCHAR* and filenameLength in bytes
                            bool isBad = IsBadLibrary(reinterpret_cast<TCHAR*>(dllNameBuffer), (DWORD)lengthBytes);
                            if (isBad)
                                _tprintf(_T(" [!] Injected library (WOW64): %ls\n"), dllNameBuffer);
                            anyBadLibs |= isBad;
                        }
                        else
                        {
                            _tprintf(_T(" [!] Failed to read module name at %llx.\n"), (unsigned long long)ldrEntry64->FullDllName.Buffer);
                        }

                        delete[] dllNameBuffer;
                        delete ldrEntry64;
                    }
                    delete ldrEntries64;
                }
            }
            else
            {
                _tprintf(_T(" [!] Failed to read PEB_LDR_DATA64 from WOW64 PEB.\n"));
            }
        }
        else
        {
            _tprintf(_T(" [!] Failed to get PEB64.\n"));
        }
    }

    return anyBadLibs ? TRUE : FALSE;
}

VOID NTAPI LdrEnumCallback(_In_ PLDR_DATA_TABLE_ENTRY ModuleInformation, _In_ PVOID Parameter, _Out_ BOOLEAN* Stop)
{
	// add ldr entry to table from param
	auto ldtEntries = static_cast<std::vector<LDR_DATA_TABLE_ENTRY>*>(Parameter);

	ldtEntries->push_back(LDR_DATA_TABLE_ENTRY(*ModuleInformation));

	Stop = FALSE;
}

BOOL ScanForModules_LdrEnumerateLoadedModules()
{
	if (!API::IsAvailable(API_IDENTIFIER::API_LdrEnumerateLoadedModules))
		return FALSE;

	auto LdrEnumerateLoadedModules = static_cast<pLdrEnumerateLoadedModules>(API::GetAPI(API_IDENTIFIER::API_LdrEnumerateLoadedModules));

	auto ldrEntries = new std::vector<LDR_DATA_TABLE_ENTRY>();

	NTSTATUS status;
	if ((status = LdrEnumerateLoadedModules(FALSE, &LdrEnumCallback, ldrEntries)) != 0)
	{
		printf("LdrEnumerateLoadedModules failed. Status: %x\n", status);
		delete ldrEntries;
		return FALSE;
	}

	bool anyBadEntries = false;
	for (LDR_DATA_TABLE_ENTRY ldrEntry : *ldrEntries)
	{
		bool isBad = IsBadLibrary(reinterpret_cast<TCHAR *>(ldrEntry.FullDllName.Buffer), ldrEntry.FullDllName.Length);
		anyBadEntries |= isBad;
	}

	delete ldrEntries;
	return anyBadEntries ? TRUE : FALSE;
}

BOOL ScanForModules_ToolHelp32()
{
	bool anyBadLibs = false;

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetCurrentProcessId());
	//printf("Snapshot: %p\n", snapshot);
	if (snapshot == INVALID_HANDLE_VALUE)
	{
		printf("Failed to get snapshot. Last error: %u\n", GetLastError());
	}
	else
	{
		MODULEENTRY32 module = { 0 };
		module.dwSize = sizeof(MODULEENTRY32);
		if (Module32First(snapshot, &module) != FALSE)
		{
			do
			{
				bool isBad = IsBadLibrary(module.szExePath, INVALID_FILE_SIZE);
				if (isBad)
					printf(" [!] Injected library: %S\n", module.szExePath);
				anyBadLibs |= isBad;
				//printf(" [!] %S\n", module.szModule);

			} while (Module32Next(snapshot, &module) != FALSE);
		}
		else
		{
			printf("Failed to get first module. Last error: %u\n", GetLastError());
		}

		CloseHandle(snapshot);
	}

	return anyBadLibs ? TRUE : FALSE;
}
