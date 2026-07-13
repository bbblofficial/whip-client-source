#include "mmap/injection/manual_mapping.h"
#include <set>

ImportResolver::ImportResolver(ErrorHandler *errorHandler, NameRandomizer *nameRandomizer,
                               ProcessInterface *processInterface, MemoryManager *memoryManager)
    : m_errorHandler(errorHandler),
      m_nameRandomizer(nameRandomizer),
      m_processInterface(processInterface),
      m_memoryManager(memoryManager) {
}

ImportResolver::~ImportResolver() {
    m_errorHandler = nullptr;
    m_nameRandomizer = nullptr;
    m_processInterface = nullptr;
    m_memoryManager = nullptr;

    m_remoteExports.clear();
}

bool ImportResolver::ResolveImports(const PEParser *peParser, MemoryAddress baseAddress, MemoryManager *memoryManager) {
    if (!peParser || !baseAddress) {
        m_errorHandler->SetError(ErrorCode::INVALID_PARAMETER, "Invalid parameters");
        return false;
    }

    HANDLE targetProcess = m_processInterface->GetProcessHandle();
    if (!targetProcess || targetProcess == INVALID_HANDLE_VALUE) {
        m_errorHandler->SetError(ErrorCode::INVALID_PARAMETER, "Invalid target process handle");
        return false;
    }

    PIMAGE_DATA_DIRECTORY importDir = peParser->GetDataDirectory(IMAGE_DIRECTORY_ENTRY_IMPORT);
    if (!importDir || importDir->VirtualAddress == 0 || importDir->Size == 0) {
        return true;
    }

    auto *importDesc = static_cast<PIMAGE_IMPORT_DESCRIPTOR>(
        peParser->GetRvaPointer(importDir->VirtualAddress));
    if (!importDesc) {
        m_errorHandler->SetError(ErrorCode::IMPORT_RESOLUTION_FAILED, "Invalid import descriptor pointer");
        return false;
    }

    DWORD imageSize = peParser->GetSizeOfImage();
    if (imageSize == 0) {
        m_errorHandler->SetError(ErrorCode::IMPORT_RESOLUTION_FAILED, "Invalid image size");
        return false;
    }

    for (auto *desc = importDesc; desc->Name != 0; ++desc) {
        if (desc->Name >= imageSize) break;

        const char *moduleName = static_cast<char *>(peParser->GetRvaPointer(desc->Name));
        if (!moduleName) continue;

        std::string moduleNameStr(moduleName);

        if (m_remoteExports.find(moduleNameStr) != m_remoteExports.end()) {
            continue;
        }

        MemoryAddress moduleBase = GetOrLoadRemoteModule(moduleNameStr);
        if (!moduleBase) {
            return false;
        }

        RemoteModuleExports exports = ReadRemoteModuleExports(moduleNameStr, moduleBase, targetProcess);
        if (!exports.isValid) {
            return false;
        }

        m_remoteExports[moduleNameStr] = std::move(exports);
    }

    for (auto *currentDesc = importDesc; currentDesc->Name != 0; ++currentDesc) {
        if (currentDesc->Name >= imageSize) break;

        const char *moduleName = static_cast<char *>(peParser->GetRvaPointer(currentDesc->Name));
        if (!moduleName) continue;

        std::string moduleNameStr(moduleName);

        if (currentDesc->FirstThunk == 0 || currentDesc->FirstThunk >= imageSize) {
            continue;
        }

        PIMAGE_THUNK_DATA originalFirstThunk = nullptr;
        if (currentDesc->OriginalFirstThunk != 0 && currentDesc->OriginalFirstThunk < imageSize) {
            originalFirstThunk = static_cast<PIMAGE_THUNK_DATA>(
                peParser->GetRvaPointer(currentDesc->OriginalFirstThunk));
        }

        PIMAGE_THUNK_DATA firstThunk = static_cast<PIMAGE_THUNK_DATA>(
            peParser->GetRvaPointer(currentDesc->FirstThunk));
        if (!firstThunk) continue;

        PIMAGE_THUNK_DATA nameThunk = originalFirstThunk ? originalFirstThunk : firstThunk;

        for (int i = 0; nameThunk[i].u1.AddressOfData != 0; ++i) {
            DWORD iatRva = currentDesc->FirstThunk + (static_cast<DWORD>(i) * sizeof(IMAGE_THUNK_DATA));

            if (iatRva >= imageSize || iatRva + sizeof(ULONGLONG) > imageSize) {
                continue;
            }

            MemoryAddress iatAddress = reinterpret_cast<BYTE *>(baseAddress) + iatRva;

            MEMORY_BASIC_INFORMATION mbi;
            if (VirtualQueryEx(targetProcess, iatAddress, &mbi, sizeof(mbi)) == 0) {
                continue;
            }

            if (mbi.State != MEM_COMMIT || !(mbi.Protect & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE))) {
                continue;
            }

            ULONGLONG currentValue = 0;
            if (!m_memoryManager->ReadMemoryFast(iatAddress, &currentValue, sizeof(currentValue))) {
                continue;
            }

            if ((currentValue & 0xFFFFFFFFFFFFFF00ULL) != 0) {
                char textCheck[9] = {0};
                memcpy(textCheck, &currentValue, 8);
                bool isText = true;
                for (int j = 0; j < 8 && textCheck[j] != 0; j++) {
                    if (textCheck[j] < 32 || textCheck[j] > 126) {
                        isText = false;
                        break;
                    }
                }
                if (isText) {
                    continue;
                }
            }

            MemoryAddress functionAddress = nullptr;

            if (IMAGE_SNAP_BY_ORDINAL(nameThunk[i].u1.Ordinal)) {
                WORD ordinal = IMAGE_ORDINAL(nameThunk[i].u1.Ordinal);
                functionAddress = FindFunctionByOrdinalInRemoteExports(moduleNameStr, ordinal);
            } else {
                DWORD nameRva = nameThunk[i].u1.AddressOfData;
                if (nameRva >= imageSize) continue;

                auto *importByName = static_cast<PIMAGE_IMPORT_BY_NAME>(peParser->GetRvaPointer(nameRva));
                if (!importByName) continue;

                std::string functionName(importByName->Name);
                functionAddress = FindFunctionInRemoteExports(moduleNameStr, functionName);
            }

            if (!functionAddress) {
                return false;
            }

            ULONGLONG funcAddr = reinterpret_cast<ULONGLONG>(functionAddress);
            if (funcAddr < 0x10000 || funcAddr > 0x7FFFFFFEFFFF) {
                continue;
            }

            if (!m_memoryManager->WriteMemory(iatAddress, &functionAddress, sizeof(functionAddress))) {
                return false;
            }

            ULONGLONG verifyValue = 0;
            if (!m_memoryManager->ReadMemoryFast(iatAddress, &verifyValue, sizeof(verifyValue)) ||
                verifyValue != funcAddr) {
                return false;
            }
        }
    }

    return true;
}

MemoryAddress ImportResolver::FindFunctionInRemoteExports(const std::string &moduleName,
                                                          const std::string &functionName) {
    auto it = m_remoteExports.find(moduleName);
    if (it == m_remoteExports.end() || !it->second.isValid) {
        return nullptr;
    }

    const RemoteModuleExports &exports = it->second;

    for (size_t i = 0; i < exports.functionNames.size(); i++) {
        if (exports.functionNames[i] == functionName) {
            return exports.functionAddresses[i];
        }
    }

    return SearchFunctionInAllLoadedModules(functionName);
}

MemoryAddress ImportResolver::GetOrLoadRemoteModule(const std::string &moduleName) {
    if (moduleName.empty() || moduleName.length() > 256) {
        return nullptr;
    }

    MemoryAddress moduleBase = GetRemoteModuleBase(moduleName);
    if (moduleBase) {
        return moduleBase;
    }

    HANDLE targetProcess = m_processInterface->GetProcessHandle();
    if (!targetProcess) {
        return nullptr;
    }

    if (moduleName.find("api-ms-") == 0) {
        std::string realModuleName = ResolveApiSetByPattern(moduleName);

        if (!realModuleName.empty()) {
            moduleBase = GetRemoteModuleBase(realModuleName);
            if (moduleBase) {
                return moduleBase;
            }
        } else {
            return nullptr;
        }
    }

    moduleBase = LoadModuleInRemoteProcess(moduleName, targetProcess);
    if (!moduleBase) {
        return nullptr;
    }

    Sleep(200);

    MemoryAddress verifyBase = GetRemoteModuleBase(moduleName);
    if (!verifyBase) {
        return nullptr;
    }

    return verifyBase;
}

ImportResolver::RemoteModuleExports ImportResolver::ReadRemoteModuleExports(const std::string &moduleName,
                                                                            MemoryAddress moduleBase,
                                                                            HANDLE targetProcess) {
    RemoteModuleExports exports;
    exports.baseAddress = moduleBase;
    exports.isValid = false;

    try {
        IMAGE_DOS_HEADER dosHeader;
        if (!m_memoryManager->ReadMemoryFast(moduleBase, &dosHeader, sizeof(dosHeader)) ||
            dosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
            return exports;
        }

        MemoryAddress ntHeaderAddr = reinterpret_cast<BYTE *>(moduleBase) + dosHeader.e_lfanew;
        IMAGE_NT_HEADERS64 ntHeaders;
        if (!m_memoryManager->ReadMemoryFast(ntHeaderAddr, &ntHeaders, sizeof(ntHeaders)) ||
            ntHeaders.Signature != IMAGE_NT_SIGNATURE) {
            return exports;
        }

        IMAGE_DATA_DIRECTORY exportDir = ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (exportDir.VirtualAddress == 0 || exportDir.Size == 0) {
            return exports;
        }

        MemoryAddress exportDirAddr = reinterpret_cast<BYTE *>(moduleBase) + exportDir.VirtualAddress;
        IMAGE_EXPORT_DIRECTORY exportDirectory;
        if (!m_memoryManager->ReadMemoryFast(exportDirAddr, &exportDirectory, sizeof(exportDirectory))) {
            return exports;
        }

        DWORD numNames = exportDirectory.NumberOfNames;
        DWORD numFunctions = exportDirectory.NumberOfFunctions;

        if (numNames == 0 || numFunctions == 0) {
            return exports;
        }

        exports.functionNames.reserve(numNames);
        exports.functionAddresses.reserve(numNames);
        exports.ordinals.reserve(numNames);

        std::vector<DWORD> nameRVAs(numNames);
        std::vector<WORD> nameOrdinals(numNames);
        std::vector<DWORD> functionRVAs(numFunctions);

        MemoryAddress nameTableAddr = reinterpret_cast<BYTE *>(moduleBase) + exportDirectory.AddressOfNames;
        if (!m_memoryManager->ReadMemoryFast(nameTableAddr, nameRVAs.data(), numNames * sizeof(DWORD))) {
            return exports;
        }

        MemoryAddress ordinalTableAddr = reinterpret_cast<BYTE *>(moduleBase) + exportDirectory.AddressOfNameOrdinals;
        if (!m_memoryManager->ReadMemoryFast(ordinalTableAddr, nameOrdinals.data(), numNames * sizeof(WORD))) {
            return exports;
        }

        MemoryAddress functionTableAddr = reinterpret_cast<BYTE *>(moduleBase) + exportDirectory.AddressOfFunctions;
        if (!m_memoryManager->ReadMemoryFast(functionTableAddr, functionRVAs.data(), numFunctions * sizeof(DWORD))) {
            return exports;
        }

        for (DWORD i = 0; i < numNames; i++) {
            MemoryAddress nameAddr = reinterpret_cast<BYTE *>(moduleBase) + nameRVAs[i];
            char functionName[512] = {0};

            if (!m_memoryManager->ReadMemoryFast(nameAddr, functionName, 511)) {
                continue;
            }

            WORD ordinal = nameOrdinals[i];
            if (ordinal >= numFunctions) {
                continue;
            }

            DWORD functionRVA = functionRVAs[ordinal];
            MemoryAddress functionAddr = reinterpret_cast<BYTE *>(moduleBase) + functionRVA;

            if (functionRVA >= exportDir.VirtualAddress &&
                functionRVA < (exportDir.VirtualAddress + exportDir.Size)) {
                continue;
            }

            exports.functionNames.emplace_back(functionName);
            exports.functionAddresses.push_back(functionAddr);
            exports.ordinals.push_back(ordinal);
        }

        exports.isValid = true;
    } catch (...) {
        exports.isValid = false;
    }

    return exports;
}

MemoryAddress ImportResolver::FindFunctionByOrdinalInRemoteExports(const std::string &moduleName,
                                                                   WORD targetOrdinal) {
    auto it = m_remoteExports.find(moduleName);
    if (it == m_remoteExports.end() || !it->second.isValid) {
        return nullptr;
    }

    const RemoteModuleExports &exports = it->second;

    for (size_t i = 0; i < exports.ordinals.size(); i++) {
        if (exports.ordinals[i] == targetOrdinal) {
            return exports.functionAddresses[i];
        }
    }

    return nullptr;
}

MemoryAddress ImportResolver::SearchFunctionInAllLoadedModules(const std::string &functionName) {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
                                            m_processInterface->GetProcessId());
    if (hSnap == INVALID_HANDLE_VALUE) {
        return nullptr;
    }

    MemoryAddress result = nullptr;

    do {
        MODULEENTRY32 me32;
        me32.dwSize = sizeof(MODULEENTRY32);
        HANDLE targetProcess = m_processInterface->GetProcessHandle();

        std::vector<std::pair<std::string, MemoryAddress> > candidateModules;

        if (!Module32First(hSnap, &me32)) break;

        do {
            std::string currentModuleName(me32.szModule);

            if (currentModuleName.find("api-ms-") == 0 ||
                me32.modBaseAddr == reinterpret_cast<MemoryAddress>(0x180000000)) {
                continue;
            }

            candidateModules.emplace_back(currentModuleName, me32.modBaseAddr);
        } while (Module32Next(hSnap, &me32));

        std::vector<std::string> searchOrder = GetSearchOrderForFunction(functionName);

        for (const std::string &priorityModule: searchOrder) {
            for (const auto &candidate: candidateModules) {
                if (_stricmp(candidate.first.c_str(), priorityModule.c_str()) == 0) {
                    MemoryAddress funcAddr = SearchFunctionInSpecificModule(
                        candidate.second, functionName, targetProcess);
                    if (funcAddr) {
                        result = funcAddr;
                        break;
                    }
                }
            }
            if (result) break;
        }

        if (result) break;

        for (const auto &candidate: candidateModules) {
            bool alreadyTested = false;
            for (const std::string &tested: searchOrder) {
                if (_stricmp(candidate.first.c_str(), tested.c_str()) == 0) {
                    alreadyTested = true;
                    break;
                }
            }
            if (alreadyTested) continue;

            MemoryAddress funcAddr = SearchFunctionInSpecificModule(
                candidate.second, functionName, targetProcess);
            if (funcAddr) {
                result = funcAddr;
                break;
            }
        }
    } while (false);

    CloseHandle(hSnap);
    return result;
}

MemoryAddress ImportResolver::GetRemoteModuleBase(const std::string &moduleName) {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
                                            m_processInterface->GetProcessId());
    if (hSnap == INVALID_HANDLE_VALUE) return nullptr;

    MemoryAddress moduleBase = nullptr;
    MODULEENTRY32 me32;
    me32.dwSize = sizeof(MODULEENTRY32);

    if (Module32First(hSnap, &me32)) {
        do {
            std::string currentModuleName(me32.szModule);
            if (_stricmp(currentModuleName.c_str(), moduleName.c_str()) == 0) {
                moduleBase = me32.modBaseAddr;
                break;
            }
        } while (Module32Next(hSnap, &me32));
    }

    CloseHandle(hSnap);
    return moduleBase;
}

std::string ImportResolver::ResolveApiSetByPattern(const std::string &apiSetName) {
    std::string lowerName = apiSetName;
    std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::tolower);

    if (lowerName.find("api-ms-win-crt-") == 0) {
        return "ucrtbase.dll";
    }

    if (lowerName.find("api-ms-win-core-") == 0) {
        return "kernel32.dll";
    }

    if (lowerName.find("api-ms-win-core-window") == 0 ||
        lowerName.find("api-ms-win-core-gui") == 0) {
        return "user32.dll";
    }

    if (lowerName.find("api-ms-win-core-rtl") == 0 ||
        lowerName.find("api-ms-win-core-heap") == 0) {
        return "ntdll.dll";
    }

    if (lowerName.find("api-ms-win-core-registry") == 0 ||
        lowerName.find("api-ms-win-security") == 0) {
        return "advapi32.dll";
    }

    return "";
}

MemoryAddress ImportResolver::LoadModuleInRemoteProcess(const std::string &moduleName, HANDLE targetProcess) {
    std::wstring moduleNameW = Utils::StringToWideString(moduleName);
    size_t moduleNameSize = moduleNameW.length() * sizeof(wchar_t) + sizeof(wchar_t);

    MemoryAddress remoteModuleName = m_memoryManager->AllocateMemory(moduleNameSize, PAGE_READWRITE);
    if (!remoteModuleName) return nullptr;

    MemoryAddress moduleBase = nullptr;
    ThreadHandle hThread = nullptr;

    do {
        if (!m_memoryManager->WriteMemory(remoteModuleName, moduleNameW.c_str(), moduleNameSize)) {
            break;
        }

        HMODULE kernel32Local = GetModuleHandleA("kernel32.dll");
        if (!kernel32Local) {
            break;
        }

        FARPROC loadLibraryLocal = GetProcAddress(kernel32Local, "LoadLibraryW");
        if (!loadLibraryLocal) {
            break;
        }

        MemoryAddress kernel32Remote = GetRemoteModuleBase("kernel32.dll");
        if (!kernel32Remote) {
            break;
        }

        ULONGLONG offset = reinterpret_cast<ULONGLONG>(loadLibraryLocal) -
                           reinterpret_cast<ULONGLONG>(kernel32Local);
        MemoryAddress loadLibraryRemote = reinterpret_cast<BYTE *>(kernel32Remote) + offset;

        if (!m_memoryManager->CreateRemoteThread(
            reinterpret_cast<MemoryAddress>(loadLibraryRemote),
            remoteModuleName,
            &hThread)) {
            break;
        }

        if (!m_memoryManager->WaitForThread(hThread, 10000)) {
            break;
        }

        DWORD exitCode;
        if (GetExitCodeThread(hThread, &exitCode)) {
            moduleBase = reinterpret_cast<MemoryAddress>(exitCode);
            if (moduleBase && moduleBase != INVALID_HANDLE_VALUE) {
                m_loadedModules.push_back(moduleName);  // *** AJOUTER CETTE LIGNE ***
            }
            if (moduleBase && moduleBase != INVALID_HANDLE_VALUE) {
            } else {
                moduleBase = nullptr;
            }
        }
    } while (false);

    if (hThread) {
        CloseHandle(hThread);
    }

    if (remoteModuleName) {
        m_memoryManager->FreeMemory(remoteModuleName);
    }

    return moduleBase;
}

std::vector<std::string> ImportResolver::GetSearchOrderForFunction(const std::string &functionName) {
    std::vector<std::string> searchOrder;

    std::string lowerFunc = functionName;
    std::transform(lowerFunc.begin(), lowerFunc.end(), lowerFunc.begin(), ::tolower);

    if (lowerFunc.find("rtl") == 0 || lowerFunc.find("nt") == 0 ||
        lowerFunc.find("zw") == 0 || lowerFunc.find("csr") == 0 ||
        lowerFunc == "initializeslisthead" || lowerFunc.find("slist") != std::string::npos) {
        searchOrder.push_back("ntdll.dll");
    }

    if (lowerFunc.find("get") == 0 || lowerFunc.find("set") == 0 ||
        lowerFunc.find("create") == 0 || lowerFunc.find("open") == 0 ||
        lowerFunc.find("close") == 0 || lowerFunc.find("read") == 0 ||
        lowerFunc.find("write") == 0 || lowerFunc.find("wait") == 0) {
        searchOrder.push_back("kernel32.dll");
        searchOrder.push_back("kernelbase.dll");
    }

    if (lowerFunc.find("malloc") != std::string::npos || lowerFunc.find("free") != std::string::npos ||
        lowerFunc.find("printf") != std::string::npos || lowerFunc.find("str") == 0 ||
        lowerFunc.find("mem") == 0 || lowerFunc.find("_") == 0) {
        searchOrder.push_back("ucrtbase.dll");
        searchOrder.push_back("msvcrt.dll");
    }

    searchOrder.push_back("ntdll.dll");
    searchOrder.push_back("kernel32.dll");
    searchOrder.push_back("kernelbase.dll");
    searchOrder.push_back("ucrtbase.dll");
    searchOrder.push_back("user32.dll");
    searchOrder.push_back("advapi32.dll");

    std::vector<std::string> uniqueOrder;
    std::set<std::string> seen;
    for (const std::string &module: searchOrder) {
        if (seen.find(module) == seen.end()) {
            uniqueOrder.push_back(module);
            seen.insert(module);
        }
    }

    return uniqueOrder;
}

MemoryAddress ImportResolver::SearchFunctionInSpecificModule(MemoryAddress moduleBase,
                                                             const std::string &functionName,
                                                             HANDLE targetProcess) {
    try {
        IMAGE_DOS_HEADER dosHeader;
        if (!m_memoryManager->ReadMemoryFast(moduleBase, &dosHeader, sizeof(dosHeader)) ||
            dosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
            return nullptr;
        }

        MemoryAddress ntHeaderAddr = reinterpret_cast<BYTE *>(moduleBase) + dosHeader.e_lfanew;
        IMAGE_NT_HEADERS64 ntHeaders;
        if (!m_memoryManager->ReadMemoryFast(ntHeaderAddr, &ntHeaders, sizeof(ntHeaders)) ||
            ntHeaders.Signature != IMAGE_NT_SIGNATURE) {
            return nullptr;
        }

        IMAGE_DATA_DIRECTORY exportDir = ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (exportDir.VirtualAddress == 0) {
            return nullptr;
        }

        MemoryAddress exportDirAddr = reinterpret_cast<BYTE *>(moduleBase) + exportDir.VirtualAddress;
        IMAGE_EXPORT_DIRECTORY exportDirectory;
        if (!m_memoryManager->ReadMemoryFast(exportDirAddr, &exportDirectory, sizeof(exportDirectory))) {
            return nullptr;
        }

        DWORD numNames = exportDirectory.NumberOfNames;
        DWORD numFunctions = exportDirectory.NumberOfFunctions;

        if (numNames == 0) return nullptr;

        std::vector<DWORD> nameRVAs(numNames);
        std::vector<WORD> nameOrdinals(numNames);
        std::vector<DWORD> functionRVAs(numFunctions);

        MemoryAddress nameTableAddr = reinterpret_cast<BYTE *>(moduleBase) + exportDirectory.AddressOfNames;
        if (!m_memoryManager->ReadMemoryFast(nameTableAddr, nameRVAs.data(), numNames * sizeof(DWORD))) {
            return nullptr;
        }

        MemoryAddress ordinalTableAddr = reinterpret_cast<BYTE *>(moduleBase) + exportDirectory.AddressOfNameOrdinals;
        if (!m_memoryManager->ReadMemoryFast(ordinalTableAddr, nameOrdinals.data(), numNames * sizeof(WORD))) {
            return nullptr;
        }

        MemoryAddress functionTableAddr = reinterpret_cast<BYTE *>(moduleBase) + exportDirectory.AddressOfFunctions;
        if (!m_memoryManager->ReadMemoryFast(functionTableAddr, functionRVAs.data(), numFunctions * sizeof(DWORD))) {
            return nullptr;
        }

        for (DWORD i = 0; i < numNames; i++) {
            MemoryAddress nameAddr = reinterpret_cast<BYTE *>(moduleBase) + nameRVAs[i];
            char currentFunctionName[256] = {0};

            if (!m_memoryManager->ReadMemoryFast(nameAddr, currentFunctionName, 255)) {
                continue;
            }

            if (strcmp(currentFunctionName, functionName.c_str()) == 0) {
                WORD ordinal = nameOrdinals[i];
                if (ordinal < numFunctions) {
                    DWORD functionRVA = functionRVAs[ordinal];

                    if (functionRVA >= exportDir.VirtualAddress &&
                        functionRVA < (exportDir.VirtualAddress + exportDir.Size)) {
                        return ResolveForwardedFunction(moduleBase, functionRVA, targetProcess);
                    }

                    return reinterpret_cast<BYTE *>(moduleBase) + functionRVA;
                }
            }
        }
    } catch (...) {
    }

    return nullptr;
}

MemoryAddress
ImportResolver::ResolveForwardedFunction(MemoryAddress moduleBase, DWORD forwardRVA, HANDLE targetProcess) {
    try {
        MemoryAddress forwardAddr = reinterpret_cast<BYTE *>(moduleBase) + forwardRVA;
        char forwardString[256] = {0};

        if (!m_memoryManager->ReadMemoryFast(forwardAddr, forwardString, 255)) {
            return nullptr;
        }

        std::string forwardStr(forwardString);
        size_t dotPos = forwardStr.find('.');
        if (dotPos == std::string::npos) {
            return nullptr;
        }

        std::string targetModuleName = forwardStr.substr(0, dotPos) + ".dll";
        std::string targetFunctionName = forwardStr.substr(dotPos + 1);

        MemoryAddress targetModuleBase = GetRemoteModuleBase(targetModuleName);
        if (!targetModuleBase) {
            return nullptr;
        }

        if (targetFunctionName[0] == '#') {
            WORD ordinal = static_cast<WORD>(std::stoi(targetFunctionName.substr(1)));
            return ResolveByOrdinalInModule(targetModuleBase, ordinal, targetProcess);
        } else {
            return SearchFunctionInSpecificModule(targetModuleBase, targetFunctionName, targetProcess);
        }
    } catch (...) {
        return nullptr;
    }
}

MemoryAddress ImportResolver::ResolveByOrdinalInModule(MemoryAddress moduleBase, WORD targetOrdinal,
                                                       HANDLE targetProcess) {
    try {
        IMAGE_DOS_HEADER dosHeader;
        if (!m_memoryManager->ReadMemoryFast(moduleBase, &dosHeader, sizeof(dosHeader))) {
            return nullptr;
        }

        MemoryAddress ntHeaderAddr = reinterpret_cast<BYTE *>(moduleBase) + dosHeader.e_lfanew;
        IMAGE_NT_HEADERS64 ntHeaders;
        if (!m_memoryManager->ReadMemoryFast(ntHeaderAddr, &ntHeaders, sizeof(ntHeaders))) {
            return nullptr;
        }

        IMAGE_DATA_DIRECTORY exportDir = ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (exportDir.VirtualAddress == 0) {
            return nullptr;
        }

        MemoryAddress exportDirAddr = reinterpret_cast<BYTE *>(moduleBase) + exportDir.VirtualAddress;
        IMAGE_EXPORT_DIRECTORY exportDirectory;
        if (!m_memoryManager->ReadMemoryFast(exportDirAddr, &exportDirectory, sizeof(exportDirectory))) {
            return nullptr;
        }

        DWORD adjustedOrdinal = targetOrdinal - exportDirectory.Base;
        if (adjustedOrdinal >= exportDirectory.NumberOfFunctions) {
            return nullptr;
        }

        std::vector<DWORD> functionRVAs(exportDirectory.NumberOfFunctions);
        MemoryAddress functionTableAddr = reinterpret_cast<BYTE *>(moduleBase) + exportDirectory.AddressOfFunctions;
        if (!m_memoryManager->ReadMemoryFast(functionTableAddr, functionRVAs.data(),
                                             exportDirectory.NumberOfFunctions * sizeof(DWORD))) {
            return nullptr;
        }

        DWORD functionRVA = functionRVAs[adjustedOrdinal];
        if (functionRVA == 0) {
            return nullptr;
        }

        return reinterpret_cast<BYTE *>(moduleBase) + functionRVA;
    } catch (...) {
        return nullptr;
    }
}
