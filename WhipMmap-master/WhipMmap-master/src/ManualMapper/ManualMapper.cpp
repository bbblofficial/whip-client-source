#include "ManualMapper/ManualMapper.h"
#include <fstream>
#include <iostream>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <sstream>

namespace ManualMapper
{
    ManualMapper::ManualMapper()
        : m_peParser(nullptr), m_remoteHeadersBase(nullptr)
    {
    }

    ManualMapper::~ManualMapper()
    {
        Cleanup();
    }

    ByteArray ManualMapper::ReadFileToMemory(const std::wstring& filePath)
    {
        std::ifstream file((filePath.c_str()), std::ios::binary | std::ios::ate);
        if (!file.is_open())
            return ByteArray();

        size_t fileSize = file.tellg();
        file.seekg(0, std::ios::beg);

        ByteArray buffer(fileSize);
        file.read(reinterpret_cast<char*>(buffer.data()), fileSize);
        file.close();

        return buffer;
    }

    bool ManualMapper::LoadImage(const std::wstring& imagePath)
    {

        ByteArray imageData = ReadFileToMemory(imagePath);
        if (imageData.empty())
        {
            return false;
        }

        m_peParser = new PeParser(imageData);
        if (!m_peParser->IsValid())
        {
            delete m_peParser;
            m_peParser = nullptr;
            return false;
        }

        return true;
    }

    bool ManualMapper::LoadImageFromMemory(const uint8_t* data, size_t size)
    {
        if (!data || size == 0)
        {
            return false;
        }

        ByteArray imageData(data, data + size);

        if (m_peParser)
        {
            delete m_peParser;
            m_peParser = nullptr;
        }

        m_peParser = new PeParser(imageData);
        if (!m_peParser->IsValid())
        {
            delete m_peParser;
            m_peParser = nullptr;
            return false;
        }

        return true;
    }

    bool ManualMapper::MapToProcess(DWORD processId)
    {
        if (!m_peParser)
        {
            return false;
        }

        m_context.processId = processId;
        m_context.processHandle = ProcessUtils::OpenProcess(processId);

        if (!m_context.processHandle)
        {
            return false;
        }

        m_context.imageSize = m_peParser->GetImageSize();

        m_context.remoteImageBase = Syscalls::AllocateMemory(m_context.processHandle, m_context.imageSize);

        if (!m_context.remoteImageBase)
        {
            return false;
        }

        if (!MapHeaders())
        {
            return false;
        }

        if (!MapSections())
        {
            return false;
        }

        if (!RelocateImage())
        {
            return false;
        }

        if (!ResolveImports())
        {
            return false;
        }

        if (!ApplyExceptionHandlers())
        {
            return false;
        }

        if (!ProtectSections())
        {
            return false;
        }

        if (!ExecuteTlsCallbacks())
        {
            return false;
        }

        DWORD entryPointRva = m_peParser->GetEntryPointRva();
        m_context.entryPoint = reinterpret_cast<void*>(
            reinterpret_cast<uintptr_t>(m_context.remoteImageBase) + entryPointRva
        );

        return true;
    }

    bool ManualMapper::Execute()
    {
        if (!m_context.entryPoint || !m_context.processHandle)
        {
            return false;
        }

        ByteArray stubCode = LoaderStub::GenerateStub();
        void* remoteStub = Syscalls::AllocateMemory(m_context.processHandle, stubCode.size());

        if (!remoteStub)
        {
            return false;
        }

        if (!Syscalls::WriteMemory(m_context.processHandle, remoteStub, stubCode.data(), stubCode.size()))
        {
            Syscalls::FreeMemory(m_context.processHandle, remoteStub);
            return false;
        }

        ByteArray verifyStub(stubCode.size());
        if (Syscalls::ReadMemory(m_context.processHandle, remoteStub, verifyStub.data(), stubCode.size()))
        {
            for (size_t i = 0; i < stubCode.size(); ++i)
            {
                if (verifyStub[i] != stubCode[i])
                {
                    break;
                }
            }
        }

        LoaderParams params;
        params.imageBase = m_context.remoteImageBase;
        params.dllMain = m_context.entryPoint;

        void* remoteParams = Syscalls::AllocateMemory(m_context.processHandle, sizeof(LoaderParams));

        if (!remoteParams)
        {
            Syscalls::FreeMemory(m_context.processHandle, remoteStub);
            return false;
        }

        if (!Syscalls::WriteMemory(m_context.processHandle, remoteParams, &params, sizeof(LoaderParams)))
        {
            Syscalls::FreeMemory(m_context.processHandle, remoteStub);
            Syscalls::FreeMemory(m_context.processHandle, remoteParams);
            return false;
        }

        HANDLE hThread = nullptr;
        NTSTATUS status = Syscalls::NtCreateThreadEx(
            &hThread,
            THREAD_ALL_ACCESS,
            nullptr,
            m_context.processHandle,
            remoteStub,
            remoteParams,
            0, 0, 0, 0,
            nullptr
        );

        if (status < 0 || !hThread)
        {
            Syscalls::FreeMemory(m_context.processHandle, remoteStub);
            Syscalls::FreeMemory(m_context.processHandle, remoteParams);
            return false;
        }

        Syscalls::WaitForSingleObject(hThread);

        DWORD exitCode = 0;
        Syscalls::GetExitCodeThread(hThread, &exitCode);
        Syscalls::CloseHandle(hThread);

        Syscalls::FreeMemory(m_context.processHandle, remoteStub);
        Syscalls::FreeMemory(m_context.processHandle, remoteParams);

        if (exitCode != 0)
        {
            if (!WipeHeaders())
            {
            }
        }

        return true;
    }

    void ManualMapper::LogUnload(const std::string& unloadType)
    {
        std::ofstream logFile("mmap", std::ios::app);
        if (!logFile.is_open())
        {
            return;
        }

        auto now = std::chrono::system_clock::now();
        auto time = std::chrono::system_clock::to_time_t(now);
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000;

        std::tm localTime;
        localtime_s(&localTime, &time);

        logFile << "[" << std::put_time(&localTime, "%Y-%m-%d %H:%M:%S")
                << "." << std::setfill('0') << std::setw(3) << ms.count() << "] "
                << "UNLOAD - Type: " << unloadType
                << " | ProcessID: " << m_context.processId
                << " | ImageBase: 0x" << std::hex << std::uppercase
                << reinterpret_cast<uintptr_t>(m_context.remoteImageBase)
                << " | EntryPoint: 0x"
                << reinterpret_cast<uintptr_t>(m_context.entryPoint)
                << std::dec << std::nouppercase << std::endl;

        logFile.close();
    }

    void LogMessage(const std::string& message)
    {
        std::ofstream logFile("mmap", std::ios::app);
        if (!logFile.is_open())
        {
            return;
        }

        auto now = std::chrono::system_clock::now();
        auto time = std::chrono::system_clock::to_time_t(now);
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000;

        std::tm localTime;
        localtime_s(&localTime, &time);

        logFile << "[" << std::put_time(&localTime, "%Y-%m-%d %H:%M:%S")
                << "." << std::setfill('0') << std::setw(3) << ms.count() << "] "
                << message << std::endl;

        logFile.close();
    }

    bool ManualMapper::Unload()
    {
        if (!m_context.remoteImageBase || !m_context.processHandle)
        {
            LogMessage("UNLOAD FAILED - Invalid context");
            return false;
        }

        LogUnload("STANDARD");
        LogMessage("  -> Getting remote module handles...");

        void* remoteNtdll = ProcessUtils::GetRemoteModuleHandle(m_context.processHandle, "ntdll.dll");
        void* remoteKernel32 = ProcessUtils::GetRemoteModuleHandle(m_context.processHandle, "kernel32.dll");

        if (!remoteNtdll || !remoteKernel32)
        {
            LogMessage("  -> FAILED - Could not get ntdll.dll or kernel32.dll");
            return false;
        }

        std::ostringstream oss;
        oss << "  -> ntdll.dll: 0x" << std::hex << std::uppercase
            << reinterpret_cast<uintptr_t>(remoteNtdll)
            << " | kernel32.dll: 0x" << reinterpret_cast<uintptr_t>(remoteKernel32);
        LogMessage(oss.str());
        LogMessage("  -> Resolving NtFreeVirtualMemory, Sleep, and RtlExitUserThread...");

        void* remoteNtFreeVirtualMemory = ProcessUtils::GetRemoteProcAddress(m_context.processHandle, remoteNtdll, "NtFreeVirtualMemory");
        void* remoteSleep = ProcessUtils::GetRemoteProcAddress(m_context.processHandle, remoteKernel32, "Sleep");
        void* remoteRtlExitUserThread = ProcessUtils::GetRemoteProcAddress(m_context.processHandle, remoteNtdll, "RtlExitUserThread");

        if (!remoteNtFreeVirtualMemory || !remoteSleep || !remoteRtlExitUserThread)
        {
            LogMessage("  -> FAILED - Could not resolve required functions");
            return false;
        }

        oss.str("");
        oss << "  -> NtFreeVirtualMemory: 0x" << std::hex << std::uppercase
            << reinterpret_cast<uintptr_t>(remoteNtFreeVirtualMemory)
            << " | Sleep: 0x" << reinterpret_cast<uintptr_t>(remoteSleep)
            << " | RtlExitUserThread: 0x" << reinterpret_cast<uintptr_t>(remoteRtlExitUserThread);
        LogMessage(oss.str());

        void* remoteRtlDeleteFunctionTable = nullptr;
        void* remoteFunctionTable = nullptr;

        PeHeaders headers = m_peParser->GetHeaders();
        IMAGE_DATA_DIRECTORY exceptionDirectory = headers.ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];

        if (exceptionDirectory.Size > 0)
        {
            LogMessage("  -> Preparing exception handler removal...");
            remoteRtlDeleteFunctionTable = ProcessUtils::GetRemoteProcAddress(m_context.processHandle, remoteNtdll, "RtlDeleteFunctionTable");
            remoteFunctionTable = reinterpret_cast<void*>(
                reinterpret_cast<uintptr_t>(m_context.remoteImageBase) + exceptionDirectory.VirtualAddress
            );

            oss.str("");
            oss << "  -> RtlDeleteFunctionTable: 0x" << std::hex << std::uppercase
                << reinterpret_cast<uintptr_t>(remoteRtlDeleteFunctionTable)
                << " | FunctionTable: 0x" << reinterpret_cast<uintptr_t>(remoteFunctionTable);
            LogMessage(oss.str());
        }
        else
        {
            LogMessage("  -> No exception handlers to remove");
        }

        struct UnloaderParams
        {
            void* imageBase;
            void* dllMain;
            void* rtlDeleteFunctionTable;
            void* functionTable;
            void* ntFreeVirtualMemory;
            void* sleep;
            void* unloaderStub;
            void* rtlExitUserThread;
        };

        UnloaderParams params;
        params.imageBase = m_context.remoteImageBase;
        params.dllMain = m_context.entryPoint;
        params.rtlDeleteFunctionTable = remoteRtlDeleteFunctionTable;
        params.functionTable = remoteFunctionTable;
        params.ntFreeVirtualMemory = remoteNtFreeVirtualMemory;
        params.sleep = remoteSleep;
        params.unloaderStub = nullptr;
        params.rtlExitUserThread = remoteRtlExitUserThread;

        // Shellcode order following UnloadInjectedDll:
        // 1. Sleep(500)
        // 2. ExecuteTlsCallbacks (DLL_PROCESS_DETACH) - skipped (complex)
        // 3. CallRemoteDllMain (DLL_PROCESS_DETACH)
        // 4. ApplyRemoveExceptionHandlers
        // 5. NtFreeVirtualMemory
        // 6. RtlExitUserThread (terminate cleanly)
        LogMessage("  -> Building unloader shellcode (Sleep -> DllMain -> RemoveExceptionHandlers -> NtFreeVirtualMemory -> Exit)...");

        ByteArray shellcode = {
            // Prologue - allocate extra stack space for NtFreeVirtualMemory parameters
            0x48, 0x83, 0xEC, 0x48,                      // sub rsp, 0x48
            0x48, 0x89, 0xCB,                            // mov rbx, rcx (save params)

            // 1. Sleep(500)
            0xB9, 0xF4, 0x01, 0x00, 0x00,                // mov ecx, 500
            0x48, 0x8B, 0x43, 0x28,                      // mov rax, [rbx + 0x28] (sleep)
            0xFF, 0xD0,                                  // call rax

            // 2. TLS Callbacks (DLL_PROCESS_DETACH) - skipped for simplicity

            // 3. CallRemoteDllMain(imageBase, DLL_PROCESS_DETACH, NULL)
            0x48, 0x8B, 0x4B, 0x08,                      // mov rcx, [rbx + 0x08] (dllMain)
            0x48, 0x85, 0xC9,                            // test rcx, rcx
            0x74, 0x14,                                  // je skip_dllmain
            0x48, 0x8B, 0x0B,                            // mov rcx, [rbx] (imageBase)
            0x48, 0x31, 0xD2,                            // xor rdx, rdx (DLL_PROCESS_DETACH = 0)
            0x4D, 0x31, 0xC0,                            // xor r8, r8 (lpReserved = NULL)
            0x48, 0x8B, 0x43, 0x08,                      // mov rax, [rbx + 0x08] (dllMain)
            0xFF, 0xD0,                                  // call rax
            // skip_dllmain:

            // 4. ApplyRemoveExceptionHandlers (RtlDeleteFunctionTable)
            0x48, 0x8B, 0x4B, 0x10,                      // mov rcx, [rbx + 0x10] (rtlDeleteFunctionTable)
            0x48, 0x85, 0xC9,                            // test rcx, rcx
            0x74, 0x0A,                                  // je skip_exception
            0x48, 0x8B, 0x4B, 0x18,                      // mov rcx, [rbx + 0x18] (functionTable)
            0x48, 0x8B, 0x43, 0x10,                      // mov rax, [rbx + 0x10] (rtlDeleteFunctionTable)
            0xFF, 0xD0,                                  // call rax
            // skip_exception:

            // 5. NtFreeVirtualMemory(NtCurrentProcess(), &imageBase, &regionSize, MEM_RELEASE)
            // Setup parameters on stack
            0x48, 0x8B, 0x03,                            // mov rax, [rbx] (imageBase)
            0x48, 0x89, 0x44, 0x24, 0x20,                // mov [rsp + 0x20], rax (store imageBase ptr on stack)
            0x48, 0xC7, 0x44, 0x24, 0x28, 0x00, 0x00, 0x00, 0x00,  // mov qword [rsp + 0x28], 0 (regionSize = 0)

            0x48, 0xC7, 0xC1, 0xFF, 0xFF, 0xFF, 0xFF,    // mov rcx, -1 (NtCurrentProcess())
            0x48, 0x8D, 0x54, 0x24, 0x20,                // lea rdx, [rsp + 0x20] (ptr to imageBase)
            0x4C, 0x8D, 0x44, 0x24, 0x28,                // lea r8, [rsp + 0x28] (ptr to regionSize)
            0x41, 0xB9, 0x00, 0x80, 0x00, 0x00,          // mov r9d, 0x8000 (MEM_RELEASE)
            0x48, 0x8B, 0x43, 0x20,                      // mov rax, [rbx + 0x20] (ntFreeVirtualMemory)
            0xFF, 0xD0,                                  // call rax

            // 6. RtlExitUserThread(0) - clean thread termination
            0x48, 0x31, 0xC9,                            // xor rcx, rcx (exitCode = 0)
            0x48, 0x8B, 0x43, 0x38,                      // mov rax, [rbx + 0x38] (rtlExitUserThread)
            0x48, 0x83, 0xC4, 0x48,                      // add rsp, 0x48 (epilogue)
            0xFF, 0xD0                                   // call rax (never returns)
        };

        LogMessage("  -> Allocating unloader stub...");
        void* remoteUnloaderStub = Syscalls::AllocateMemory(m_context.processHandle, shellcode.size());
        if (!remoteUnloaderStub)
        {
            LogMessage("  -> FAILED - Could not allocate unloader stub");
            return false;
        }

        oss.str("");
        oss << "  -> Unloader stub allocated at: 0x" << std::hex << std::uppercase
            << reinterpret_cast<uintptr_t>(remoteUnloaderStub)
            << " (size: 0x" << shellcode.size() << " bytes)";
        LogMessage(oss.str());

        params.unloaderStub = remoteUnloaderStub;

        LogMessage("  -> Writing unloader shellcode...");
        if (!Syscalls::WriteMemory(m_context.processHandle, remoteUnloaderStub, shellcode.data(), shellcode.size()))
        {
            Syscalls::FreeMemory(m_context.processHandle, remoteUnloaderStub);
            LogMessage("  -> FAILED - Could not write shellcode");
            return false;
        }

        LogMessage("  -> Allocating unloader parameters...");
        void* remoteParams = Syscalls::AllocateMemory(m_context.processHandle, sizeof(UnloaderParams));
        if (!remoteParams)
        {
            Syscalls::FreeMemory(m_context.processHandle, remoteUnloaderStub);
            LogMessage("  -> FAILED - Could not allocate parameters");
            return false;
        }

        oss.str("");
        oss << "  -> Parameters allocated at: 0x" << std::hex << std::uppercase
            << reinterpret_cast<uintptr_t>(remoteParams);
        LogMessage(oss.str());

        if (!Syscalls::WriteMemory(m_context.processHandle, remoteParams, &params, sizeof(UnloaderParams)))
        {
            Syscalls::FreeMemory(m_context.processHandle, remoteParams);
            Syscalls::FreeMemory(m_context.processHandle, remoteUnloaderStub);
            LogMessage("  -> FAILED - Could not write parameters");
            return false;
        }

        LogMessage("  -> Protecting unloader stub memory...");
        DWORD oldProtect = 0;
        if (!Syscalls::ProtectMemory(m_context.processHandle, remoteUnloaderStub, shellcode.size(), PAGE_EXECUTE_READ, &oldProtect))
        {
            LogMessage("  -> WARNING - Could not protect memory");
        }
        else
        {
            LogMessage("  -> Memory protection applied (PAGE_EXECUTE_READ)");
        }

        LogMessage("  -> Creating remote thread to execute unloader...");
        HANDLE hThread = nullptr;
        NTSTATUS status = Syscalls::NtCreateThreadEx(
            &hThread,
            THREAD_ALL_ACCESS,
            nullptr,
            m_context.processHandle,
            remoteUnloaderStub,
            remoteParams,
            0, 0, 0, 0,
            nullptr
        );

        if (status < 0 || !hThread)
        {
            oss.str("");
            oss << "  -> FAILED - NtCreateThreadEx failed with status: 0x"
                << std::hex << std::uppercase << static_cast<DWORD>(status);
            LogMessage(oss.str());
            Syscalls::FreeMemory(m_context.processHandle, remoteParams);
            Syscalls::FreeMemory(m_context.processHandle, remoteUnloaderStub);
            return false;
        }

        oss.str("");
        oss << "  -> Thread created successfully (Handle: 0x"
            << std::hex << std::uppercase << reinterpret_cast<uintptr_t>(hThread) << ")";
        LogMessage(oss.str());
        LogMessage("  -> Waiting for unloader thread to complete...");

        Syscalls::WaitForSingleObject(hThread);
        Syscalls::CloseHandle(hThread);

        LogMessage("  -> Unloader thread completed");

        // Free the remote parameters that were allocated
        LogMessage("  -> Freeing unloader parameters...");
        oss.str("");
        oss << "  -> Freeing remoteParams at: 0x" << std::hex << std::uppercase
            << reinterpret_cast<uintptr_t>(remoteParams);
        LogMessage(oss.str());
        Syscalls::FreeMemory(m_context.processHandle, remoteParams);
        LogMessage("  -> Parameters freed");

        // Free the unloader stub (no longer self-freed)
        LogMessage("  -> Freeing unloader stub...");
        oss.str("");
        oss << "  -> Freeing remoteUnloaderStub at: 0x" << std::hex << std::uppercase
            << reinterpret_cast<uintptr_t>(remoteUnloaderStub);
        LogMessage(oss.str());
        Syscalls::FreeMemory(m_context.processHandle, remoteUnloaderStub);
        LogMessage("  -> Unloader stub freed");

        // Free any tracked allocations that weren't freed yet
        if (!m_context.allocations.empty())
        {
            oss.str("");
            oss << "  -> Freeing " << std::dec << m_context.allocations.size() << " tracked allocations...";
            LogMessage(oss.str());

            for (const auto& alloc : m_context.allocations)
            {
                if (alloc.address)
                {
                    oss.str("");
                    oss << "  -> Freeing [" << alloc.description << "] at 0x"
                        << std::hex << std::uppercase << reinterpret_cast<uintptr_t>(alloc.address)
                        << " (size: 0x" << alloc.size << " bytes)";
                    LogMessage(oss.str());
                    Syscalls::FreeMemory(m_context.processHandle, alloc.address);
                }
            }

            m_context.allocations.clear();
            LogMessage("  -> All tracked allocations freed");
        }

        LogMessage("  -> Cleaning up context...");

        m_context.remoteImageBase = nullptr;
        m_context.entryPoint = nullptr;
        m_context.imageSize = 0;

        oss.str("");
        oss << "  -> Memory freed: ImageBase, Unloader Stub, Parameters, Tracked allocations";
        LogMessage(oss.str());
        LogMessage("  -> UNLOAD COMPLETE");
        return true;
    }

    bool ManualMapper::MapToProcess(const std::wstring& processName)
    {
        DWORD processId = ProcessUtils::GetProcessIdByName(processName);
        if (processId == 0)
            return false;

        return MapToProcess(processId);
    }

    bool ManualMapper::MapHeaders()
    {
        const ByteArray& imageData = m_peParser->GetImageData();
        PeHeaders headers = m_peParser->GetHeaders();

        size_t headersSize = headers.ntHeaders->OptionalHeader.SizeOfHeaders;

        return Syscalls::WriteMemory(
            m_context.processHandle,
            m_context.remoteImageBase,
            imageData.data(),
            headersSize
        );
    }

    bool ManualMapper::MapSections()
    {
        const ByteArray& imageData = m_peParser->GetImageData();
        size_t sectionCount = m_peParser->GetSectionCount();

        for (size_t i = 0; i < sectionCount; ++i)
        {
            PIMAGE_SECTION_HEADER section = m_peParser->GetSectionHeader(i);
            if (!section)
            {
                return false;
            }

            void* sectionDestination = reinterpret_cast<void*>(
                reinterpret_cast<uintptr_t>(m_context.remoteImageBase) + section->VirtualAddress
            );

            const void* sectionSource = imageData.data() + section->PointerToRawData;
            size_t sectionSize = section->SizeOfRawData;

            if (!Syscalls::WriteMemory(m_context.processHandle, sectionDestination, sectionSource, sectionSize))
            {
                return false;
            }
        }
        return true;
    }

    bool ManualMapper::RelocateImage()
    {
        PeHeaders headers = m_peParser->GetHeaders();
        IMAGE_DATA_DIRECTORY relocDirectory = headers.ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

        if (relocDirectory.Size == 0)
        {
            return true;
        }

        uintptr_t imageDelta = reinterpret_cast<uintptr_t>(m_context.remoteImageBase) -
                               headers.ntHeaders->OptionalHeader.ImageBase;

        if (imageDelta == 0)
        {
            return true;
        }

        const ByteArray& imageData = m_peParser->GetImageData();
        DWORD relocRva = relocDirectory.VirtualAddress;
        DWORD relocFileOffset = m_peParser->RvaToFileOffset(relocRva);
        int relocCount = 0;

        DWORD currentOffset = 0;
        while (currentOffset < relocDirectory.Size)
        {
            DWORD blockFileOffset = relocFileOffset + currentOffset;

            if (blockFileOffset + sizeof(IMAGE_BASE_RELOCATION) > imageData.size())
            {
                break;
            }

            auto* relocBlock = reinterpret_cast<PIMAGE_BASE_RELOCATION>(
                const_cast<Byte*>(imageData.data()) + blockFileOffset
            );

            if (relocBlock->SizeOfBlock == 0)
                break;

            DWORD entryCount = (relocBlock->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            WORD* entries = reinterpret_cast<WORD*>(relocBlock + 1);

            for (DWORD i = 0; i < entryCount; ++i)
            {
                WORD entry = entries[i];
                WORD type = entry >> 12;
                WORD offset = entry & 0xFFF;

                if (type == IMAGE_REL_BASED_DIR64 || type == IMAGE_REL_BASED_HIGHLOW)
                {
                    void* remoteAddress = reinterpret_cast<void*>(
                        reinterpret_cast<uintptr_t>(m_context.remoteImageBase) + relocBlock->VirtualAddress + offset
                    );

                    uintptr_t value = 0;
                    if (!Syscalls::ReadMemory(m_context.processHandle, remoteAddress, &value, sizeof(uintptr_t)))
                    {
                        continue;
                    }

                    value += imageDelta;

                    if (!Syscalls::WriteMemory(m_context.processHandle, remoteAddress, &value, sizeof(uintptr_t)))
                    {
                        continue;
                    }

                    relocCount++;
                }
            }

            currentOffset += relocBlock->SizeOfBlock;
        }

        return true;
    }

    bool ManualMapper::ResolveImports()
    {
        PeHeaders headers = m_peParser->GetHeaders();
        IMAGE_DATA_DIRECTORY importDirectory = headers.ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

        if (importDirectory.Size == 0)
        {
            return true;
        }

        const ByteArray& imageData = m_peParser->GetImageData();
        DWORD importDescriptorFileOffset = m_peParser->RvaToFileOffset(importDirectory.VirtualAddress);


        if (importDescriptorFileOffset >= imageData.size())
        {
            return false;
        }

        auto* importDescriptor = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(
            const_cast<Byte*>(imageData.data()) + importDescriptorFileOffset
        );

        while (importDescriptor->Name != 0)
        {
            DWORD moduleNameFileOffset = m_peParser->RvaToFileOffset(importDescriptor->Name);
            if (moduleNameFileOffset >= imageData.size())
            {
                break;
            }

            const char* moduleName = reinterpret_cast<const char*>(imageData.data() + moduleNameFileOffset);

            std::string actualModuleName = moduleName;
            if (actualModuleName.find("api-ms-win-crt-") == 0)
            {
                actualModuleName = "ucrtbase.dll";
            }
            else if (actualModuleName.find("api-ms-win-") == 0)
            {
                actualModuleName = "kernelbase.dll";
            }

            void* remoteModuleBase = nullptr;
            auto cacheIt = m_moduleCache.find(actualModuleName);
            if (cacheIt != m_moduleCache.end())
            {
                remoteModuleBase = cacheIt->second;
            }
            else
            {
                remoteModuleBase = ProcessUtils::GetRemoteModuleHandle(m_context.processHandle, actualModuleName);
            }

            if (!remoteModuleBase)
            {

                void* remoteKernel32 = ProcessUtils::GetRemoteModuleHandle(m_context.processHandle, "kernel32.dll");
                if (!remoteKernel32)
                {
                    importDescriptor++;
                    continue;
                }

                void* remoteLoadLibraryA = ProcessUtils::GetRemoteProcAddress(m_context.processHandle, remoteKernel32, "LoadLibraryA");
                if (!remoteLoadLibraryA)
                {
                    importDescriptor++;
                    continue;
                }

                void* remoteModuleName = Syscalls::AllocateMemory(m_context.processHandle, actualModuleName.length() + 1);
                Syscalls::WriteMemory(m_context.processHandle, remoteModuleName, actualModuleName.c_str(), actualModuleName.length() + 1);

                HANDLE hThread = nullptr;
                NTSTATUS ntStatus = Syscalls::NtCreateThreadEx(
                    &hThread,
                    THREAD_ALL_ACCESS,
                    nullptr,
                    m_context.processHandle,
                    remoteLoadLibraryA,
                    remoteModuleName,
                    0, 0, 0, 0,
                    nullptr
                );

                if (ntStatus >= 0 && hThread)
                {
                    Syscalls::WaitForSingleObject(hThread);
                    Syscalls::CloseHandle(hThread);
                }

                Syscalls::FreeMemory(m_context.processHandle, remoteModuleName);

                remoteModuleBase = ProcessUtils::GetRemoteModuleHandle(m_context.processHandle, moduleName);

                if (!remoteModuleBase)
                {
                    importDescriptor++;
                    continue;
                }
            }

            m_moduleCache[actualModuleName] = remoteModuleBase;

            DWORD thunkRva = importDescriptor->OriginalFirstThunk;
            DWORD iatRva = importDescriptor->FirstThunk;

            DWORD thunkFileOffset = m_peParser->RvaToFileOffset(thunkRva);

            auto* thunk = reinterpret_cast<PIMAGE_THUNK_DATA>(
                const_cast<Byte*>(imageData.data()) + thunkFileOffset
            );

            int functionCount = 0;
            DWORD currentIatRva = iatRva;

            while (thunk->u1.AddressOfData != 0)
            {
                uintptr_t functionAddr = 0;

                if (thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)
                {
                    WORD ordinal = thunk->u1.Ordinal & 0xFFFF;

                    functionAddr = reinterpret_cast<uintptr_t>(
                        ProcessUtils::GetRemoteProcAddressByOrdinal(m_context.processHandle, remoteModuleBase, ordinal)
                    );

                    if (!functionAddr)
                    {
                        return false;
                    }

                }
                else
                {
                    DWORD importByNameFileOffset = m_peParser->RvaToFileOffset(static_cast<DWORD>(thunk->u1.AddressOfData));
                    auto* importByName = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(
                        const_cast<Byte*>(imageData.data()) + importByNameFileOffset
                    );

                    functionAddr = reinterpret_cast<uintptr_t>(
                        ProcessUtils::GetRemoteProcAddress(m_context.processHandle, remoteModuleBase, importByName->Name)
                    );

                    if (!functionAddr)
                    {
                        HMODULE localModule = GetModuleHandleA(actualModuleName.c_str());
                        if (localModule)
                        {
                            functionAddr = reinterpret_cast<uintptr_t>(GetProcAddress(localModule, importByName->Name));
                            if (functionAddr)
                            {
                            }
                        }

                        if (!functionAddr)
                        {
                            return false;
                        }
                    }

                }

                void* remoteIatEntry = reinterpret_cast<void*>(
                    reinterpret_cast<uintptr_t>(m_context.remoteImageBase) + currentIatRva
                );

                if (!Syscalls::WriteMemory(m_context.processHandle, remoteIatEntry, &functionAddr, sizeof(uintptr_t)))
                {
                    return false;
                }

                thunk++;
                currentIatRva += sizeof(uintptr_t);
                functionCount++;
            }

            importDescriptor++;
        }

        return true;
    }

    bool ManualMapper::ApplyExceptionHandlers()
    {
        PeHeaders headers = m_peParser->GetHeaders();
        IMAGE_DATA_DIRECTORY exceptionDirectory = headers.ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];

        if (exceptionDirectory.Size == 0)
        {
            return true;
        }

        void* remoteNtdll = ProcessUtils::GetRemoteModuleHandle(m_context.processHandle, "ntdll.dll");
        if (!remoteNtdll)
        {
            return false;
        }

        void* remoteRtlAddFunctionTable = ProcessUtils::GetRemoteProcAddress(
            m_context.processHandle,
            remoteNtdll,
            "RtlAddFunctionTable"
        );

        if (!remoteRtlAddFunctionTable)
        {
            return false;
        }

        void* remoteFunctionTable = reinterpret_cast<void*>(
            reinterpret_cast<uintptr_t>(m_context.remoteImageBase) + exceptionDirectory.VirtualAddress
        );

        DWORD entryCount = exceptionDirectory.Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY);

        ByteArray shellcode = {
            0x48, 0x83, 0xEC, 0x28,
            0x48, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x48, 0xC7, 0xC2, 0x00, 0x00, 0x00, 0x00,
            0x49, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xFF, 0xD0,
            0x48, 0x83, 0xC4, 0x28,
            0xC3
        };

        *reinterpret_cast<uintptr_t*>(&shellcode[6]) = reinterpret_cast<uintptr_t>(remoteFunctionTable);
        *reinterpret_cast<DWORD*>(&shellcode[17]) = entryCount;
        *reinterpret_cast<uintptr_t*>(&shellcode[23]) = reinterpret_cast<uintptr_t>(m_context.remoteImageBase);
        *reinterpret_cast<uintptr_t*>(&shellcode[33]) = reinterpret_cast<uintptr_t>(remoteRtlAddFunctionTable);

        void* remoteShellcode = Syscalls::AllocateMemory(m_context.processHandle, shellcode.size());
        if (!remoteShellcode)
        {
            return false;
        }

        if (!Syscalls::WriteMemory(m_context.processHandle, remoteShellcode, shellcode.data(), shellcode.size()))
        {
            Syscalls::FreeMemory(m_context.processHandle, remoteShellcode);
            return false;
        }

        HANDLE hThread = nullptr;
        NTSTATUS ntStatus = Syscalls::NtCreateThreadEx(
            &hThread,
            THREAD_ALL_ACCESS,
            nullptr,
            m_context.processHandle,
            remoteShellcode,
            nullptr,
            0, 0, 0, 0,
            nullptr
        );

        if (ntStatus < 0 || !hThread)
        {
            Syscalls::FreeMemory(m_context.processHandle, remoteShellcode);
            return false;
        }

        Syscalls::WaitForSingleObject(hThread);

        DWORD exitCode = 0;
        Syscalls::GetExitCodeThread(hThread, &exitCode);
        Syscalls::CloseHandle(hThread);

        Syscalls::FreeMemory(m_context.processHandle, remoteShellcode);

        if (exitCode == 0)
        {
            return false;
        }

        return true;
    }

    DWORD ManualMapper::GetSectionProtection(DWORD characteristics)
    {
        DWORD protection = 0;

        bool isExecutable = (characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
        bool isReadable = (characteristics & IMAGE_SCN_MEM_READ) != 0;
        bool isWritable = (characteristics & IMAGE_SCN_MEM_WRITE) != 0;

        if (isExecutable)
        {
            if (isWritable && isReadable)
                protection = PAGE_EXECUTE_READWRITE;
            else if (isWritable)
                protection = PAGE_EXECUTE_WRITECOPY;
            else if (isReadable)
                protection = PAGE_EXECUTE_READ;
            else
                protection = PAGE_EXECUTE;
        }
        else
        {
            if (isWritable && isReadable)
                protection = PAGE_READWRITE;
            else if (isWritable)
                protection = PAGE_WRITECOPY;
            else if (isReadable)
                protection = PAGE_READONLY;
            else
                protection = PAGE_NOACCESS;
        }

        return protection;
    }

    bool ManualMapper::ProtectSections()
    {
        size_t sectionCount = m_peParser->GetSectionCount();

        for (size_t i = 0; i < sectionCount; ++i)
        {
            PIMAGE_SECTION_HEADER section = m_peParser->GetSectionHeader(i);
            if (!section)
                continue;

            void* sectionAddress = reinterpret_cast<void*>(
                reinterpret_cast<uintptr_t>(m_context.remoteImageBase) + section->VirtualAddress
            );

            DWORD protection = GetSectionProtection(section->Characteristics);

            if (!Syscalls::ProtectMemory(m_context.processHandle, sectionAddress, section->Misc.VirtualSize, protection))
            {
                return false;
            }
        }

        return true;
    }

    bool ManualMapper::ExecuteTlsCallbacks()
    {
        PIMAGE_TLS_DIRECTORY64 tlsDir = m_peParser->GetTlsDirectory();

        if (!tlsDir)
        {
            return true;
        }

        if (tlsDir->AddressOfCallBacks == 0)
        {
            return true;
        }

        ULONGLONG imageBase = m_peParser->GetHeaders().ntHeaders->OptionalHeader.ImageBase;

        if (tlsDir->AddressOfCallBacks < imageBase)
        {
            return true;
        }

        ULONGLONG callbackArrayRva = tlsDir->AddressOfCallBacks - imageBase;
        void* remoteCallbackArray = reinterpret_cast<void*>(
            reinterpret_cast<uintptr_t>(m_context.remoteImageBase) + callbackArrayRva
        );

        ULONGLONG callbacks[32] = {0};
        if (!Syscalls::ReadMemory(m_context.processHandle, remoteCallbackArray, callbacks, sizeof(callbacks)))
        {
            return false;
        }

        int callbackCount = 0;
        for (int i = 0; i < 32 && callbacks[i] != 0; ++i)
        {
            LoaderParams params;
            params.imageBase = m_context.remoteImageBase;
            params.dllMain = reinterpret_cast<void*>(callbacks[i]);

            ByteArray stubCode = LoaderStub::GenerateStub();
            void* remoteStub = Syscalls::AllocateMemory(m_context.processHandle, stubCode.size());

            if (!remoteStub)
            {
                continue;
            }

            Syscalls::WriteMemory(m_context.processHandle, remoteStub, stubCode.data(), stubCode.size());

            void* remoteParams = Syscalls::AllocateMemory(m_context.processHandle, sizeof(LoaderParams));
            Syscalls::WriteMemory(m_context.processHandle, remoteParams, &params, sizeof(LoaderParams));

            HANDLE hThread = nullptr;
            NTSTATUS ntStatus = Syscalls::NtCreateThreadEx(
                &hThread,
                THREAD_ALL_ACCESS,
                nullptr,
                m_context.processHandle,
                remoteStub,
                remoteParams,
                0, 0, 0, 0,
                nullptr
            );

            if (ntStatus >= 0 && hThread)
            {
                Syscalls::WaitForSingleObject(hThread);
                DWORD exitCode = 0;
                Syscalls::GetExitCodeThread(hThread, &exitCode);
                Syscalls::CloseHandle(hThread);
            }

            Syscalls::FreeMemory(m_context.processHandle, remoteStub);
            Syscalls::FreeMemory(m_context.processHandle, remoteParams);

            callbackCount++;
        }

        return true;
    }

    bool ManualMapper::WipeHeaders()
    {
        if (!m_context.remoteImageBase || !m_context.processHandle)
        {
            return false;
        }

        PeHeaders headers = m_peParser->GetHeaders();
        size_t headersSize = headers.ntHeaders->OptionalHeader.SizeOfHeaders;

        ByteArray zeroBuffer(headersSize, 0);

        if (!Syscalls::WriteMemory(m_context.processHandle, m_context.remoteImageBase,
                                      zeroBuffer.data(), headersSize))
        {
            return false;
        }

        return true;
    }

    void* ManualMapper::TranslateRva(DWORD rva) const
    {
        if (m_remoteHeadersBase)
        {
            PeHeaders headers = m_peParser->GetHeaders();
            if (rva < headers.ntHeaders->OptionalHeader.SizeOfHeaders)
            {
                return reinterpret_cast<void*>(
                    reinterpret_cast<uintptr_t>(m_remoteHeadersBase) + rva
                );
            }
        }

        for (const auto& section : m_scatteredSections)
        {
            if (rva >= section.originalRva && rva < section.originalRva + section.virtualSize)
            {
                return reinterpret_cast<void*>(
                    reinterpret_cast<uintptr_t>(section.remoteAddress) + (rva - section.originalRva)
                );
            }
        }
        return nullptr;
    }

    int ManualMapper::FindSectionForRva(DWORD rva) const
    {
        for (size_t i = 0; i < m_scatteredSections.size(); i++)
        {
            if (rva >= m_scatteredSections[i].originalRva &&
                rva < m_scatteredSections[i].originalRva + m_scatteredSections[i].virtualSize)
            {
                return static_cast<int>(i);
            }
        }
        return -1;
    }

    bool ManualMapper::ScatterMapToProcess(DWORD processId)
    {
        if (!m_peParser)
        {
            return false;
        }

        m_context.processId = processId;
        m_context.processHandle = ProcessUtils::OpenProcess(processId);

        if (!m_context.processHandle)
        {
            return false;
        }

        m_context.imageSize = m_peParser->GetImageSize();
        m_context.isScattered = true;

        PeHeaders headers = m_peParser->GetHeaders();
        size_t headersSize = (headers.ntHeaders->OptionalHeader.SizeOfHeaders + 0xFFF) & ~0xFFF;

        m_remoteHeadersBase = Syscalls::AllocateMemory(m_context.processHandle, headersSize);
        if (!m_remoteHeadersBase)
        {
            return false;
        }

        m_context.remoteImageBase = m_remoteHeadersBase;

        const ByteArray& imageData = m_peParser->GetImageData();
        if (!Syscalls::WriteMemory(m_context.processHandle, m_remoteHeadersBase,
                                       imageData.data(), headers.ntHeaders->OptionalHeader.SizeOfHeaders))
        {
            return false;
        }

        if (!AllocateScatteredSections())
        {
            return false;
        }

        if (!CopyRawToScatteredSections())
        {
            return false;
        }

        if (!RelocateScattered())
        {
            return false;
        }

        if (!ResolveImportsScattered())
        {
            return false;
        }

        if (!BuildInterSectionJumps())
        {
            return false;
        }

        if (!ProtectScatteredSections())
        {
            return false;
        }

        DWORD epRva = m_peParser->GetEntryPointRva();
        int epSection = FindSectionForRva(epRva);
        if (epSection >= 0)
        {
            m_context.entryPoint = reinterpret_cast<void*>(
                reinterpret_cast<uintptr_t>(m_scatteredSections[epSection].remoteAddress) +
                (epRva - m_scatteredSections[epSection].originalRva)
            );
        }
        else
        {
            return false;
        }

        for (const auto& s : m_scatteredSections)
        {
        }

        return true;
    }

    bool ManualMapper::ScatterMapToProcess(const std::wstring& processName)
    {
        DWORD processId = ProcessUtils::GetProcessIdByName(processName);
        if (processId == 0)
            return false;

        return ScatterMapToProcess(processId);
    }

    bool ManualMapper::AllocateScatteredSections()
    {
        size_t sectionCount = m_peParser->GetSectionCount();
        m_scatteredSections.clear();

        const size_t TRAMPOLINE_ENTRY_SIZE = 12;

        for (size_t i = 0; i < sectionCount; ++i)
        {
            PIMAGE_SECTION_HEADER section = m_peParser->GetSectionHeader(i);
            if (!section)
                return false;

            ScatteredSection scattered;
            scattered.index = static_cast<int>(i);
            memcpy(scattered.name, section->Name, IMAGE_SIZEOF_SHORT_NAME);
            scattered.name[IMAGE_SIZEOF_SHORT_NAME] = '\0';
            scattered.originalRva = section->VirtualAddress;
            scattered.virtualSize = section->Misc.VirtualSize;
            scattered.rawSize = section->SizeOfRawData;
            scattered.rawDataOffset = section->PointerToRawData;
            scattered.characteristics = section->Characteristics;
            scattered.trampolineOffset = section->Misc.VirtualSize;

            size_t trampolineTableSize = sectionCount * TRAMPOLINE_ENTRY_SIZE;
            size_t totalSize = section->Misc.VirtualSize + trampolineTableSize;
            scattered.allocationSize = (totalSize + 0xFFF) & ~0xFFF;

            scattered.remoteAddress = Syscalls::AllocateMemory(
                m_context.processHandle, scattered.allocationSize
            );

            if (!scattered.remoteAddress)
            {
                for (auto& prev : m_scatteredSections)
                    Syscalls::FreeMemory(m_context.processHandle, prev.remoteAddress);
                m_scatteredSections.clear();
                return false;
            }

            m_scatteredSections.push_back(scattered);
        }

        return true;
    }

    bool ManualMapper::CopyRawToScatteredSections()
    {
        const ByteArray& imageData = m_peParser->GetImageData();

        for (auto& section : m_scatteredSections)
        {
            if (section.rawSize == 0)
                continue;

            const void* srcData = imageData.data() + section.rawDataOffset;
            size_t copySize = (section.rawSize < section.virtualSize) ? section.rawSize : section.virtualSize;

            if (!Syscalls::WriteMemory(m_context.processHandle, section.remoteAddress,
                                          srcData, copySize))
            {
                return false;
            }

        }

        return true;
    }

    bool ManualMapper::RelocateScattered()
    {
        PeHeaders headers = m_peParser->GetHeaders();
        IMAGE_DATA_DIRECTORY relocDir = headers.ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

        if (relocDir.Size == 0)
        {
            return true;
        }

        ULONGLONG preferredBase = headers.ntHeaders->OptionalHeader.ImageBase;
        const ByteArray& imageData = m_peParser->GetImageData();
        DWORD relocFileOffset = m_peParser->RvaToFileOffset(relocDir.VirtualAddress);
        int relocCount = 0;
        int skippedCount = 0;

        DWORD currentOffset = 0;
        while (currentOffset < relocDir.Size)
        {
            DWORD blockFileOffset = relocFileOffset + currentOffset;
            if (blockFileOffset + sizeof(IMAGE_BASE_RELOCATION) > imageData.size())
                break;

            auto* block = reinterpret_cast<PIMAGE_BASE_RELOCATION>(
                const_cast<Byte*>(imageData.data()) + blockFileOffset
            );

            if (block->SizeOfBlock == 0)
                break;

            DWORD entryCount = (block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            WORD* entries = reinterpret_cast<WORD*>(block + 1);

            for (DWORD i = 0; i < entryCount; i++)
            {
                WORD type = entries[i] >> 12;
                WORD offset = entries[i] & 0xFFF;

                if (type == IMAGE_REL_BASED_DIR64)
                {
                    DWORD writeRva = block->VirtualAddress + offset;

                    void* writeAddr = TranslateRva(writeRva);
                    if (!writeAddr) { skippedCount++; continue; }

                    uintptr_t value = 0;
                    if (!Syscalls::ReadMemory(m_context.processHandle, writeAddr, &value, sizeof(uintptr_t)))
                    { skippedCount++; continue; }

                    if (value < preferredBase) { skippedCount++; continue; }
                    DWORD targetRva = static_cast<DWORD>(value - preferredBase);

                    void* newTarget = TranslateRva(targetRva);
                    if (!newTarget) { skippedCount++; continue; }

                    uintptr_t newValue = reinterpret_cast<uintptr_t>(newTarget);
                    if (!Syscalls::WriteMemory(m_context.processHandle, writeAddr, &newValue, sizeof(uintptr_t)))
                    { skippedCount++; continue; }

                    relocCount++;
                }
            }

            currentOffset += block->SizeOfBlock;
        }

        if (skippedCount > 0)
        return true;
    }

    bool ManualMapper::ResolveImportsScattered()
    {
        PeHeaders headers = m_peParser->GetHeaders();
        IMAGE_DATA_DIRECTORY importDir = headers.ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

        if (importDir.Size == 0)
        {
            return true;
        }

        const ByteArray& imageData = m_peParser->GetImageData();
        DWORD importFileOffset = m_peParser->RvaToFileOffset(importDir.VirtualAddress);

        if (importFileOffset >= imageData.size())
        {
            return false;
        }

        auto* importDesc = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(
            const_cast<Byte*>(imageData.data()) + importFileOffset
        );

        while (importDesc->Name != 0)
        {
            DWORD nameFileOffset = m_peParser->RvaToFileOffset(importDesc->Name);
            if (nameFileOffset >= imageData.size()) break;

            const char* moduleName = reinterpret_cast<const char*>(imageData.data() + nameFileOffset);

            std::string actualModuleName = moduleName;
            if (actualModuleName.find("api-ms-win-crt-") == 0)
                actualModuleName = "ucrtbase.dll";
            else if (actualModuleName.find("api-ms-win-") == 0)
                actualModuleName = "kernelbase.dll";

            void* remoteModuleBase = nullptr;
            auto cacheIt = m_moduleCache.find(actualModuleName);
            if (cacheIt != m_moduleCache.end())
            {
                remoteModuleBase = cacheIt->second;
            }
            else
            {
                remoteModuleBase = ProcessUtils::GetRemoteModuleHandle(m_context.processHandle, actualModuleName);
            }

            if (!remoteModuleBase)
            {
                void* remoteKernel32 = ProcessUtils::GetRemoteModuleHandle(m_context.processHandle, "kernel32.dll");
                if (remoteKernel32)
                {
                    void* remoteLoadLibraryA = ProcessUtils::GetRemoteProcAddress(
                        m_context.processHandle, remoteKernel32, "LoadLibraryA");
                    if (remoteLoadLibraryA)
                    {
                        void* remoteName = Syscalls::AllocateMemory(
                            m_context.processHandle, actualModuleName.length() + 1);
                        Syscalls::WriteMemory(m_context.processHandle, remoteName,
                                                  actualModuleName.c_str(), actualModuleName.length() + 1);

                        HANDLE hThread = nullptr;
                        Syscalls::NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, nullptr,
                            m_context.processHandle, remoteLoadLibraryA, remoteName, 0, 0, 0, 0, nullptr);

                        if (hThread)
                        {
                            Syscalls::WaitForSingleObject(hThread);
                            Syscalls::CloseHandle(hThread);
                        }
                        Syscalls::FreeMemory(m_context.processHandle, remoteName);
                        remoteModuleBase = ProcessUtils::GetRemoteModuleHandle(m_context.processHandle, moduleName);
                    }
                }

                if (!remoteModuleBase)
                {
                    importDesc++;
                    continue;
                }
            }

            m_moduleCache[actualModuleName] = remoteModuleBase;

            DWORD thunkRva = importDesc->OriginalFirstThunk;
            DWORD iatRva = importDesc->FirstThunk;
            DWORD thunkFileOffset = m_peParser->RvaToFileOffset(thunkRva);

            auto* thunk = reinterpret_cast<PIMAGE_THUNK_DATA>(
                const_cast<Byte*>(imageData.data()) + thunkFileOffset
            );

            int functionCount = 0;
            DWORD currentIatRva = iatRva;

            while (thunk->u1.AddressOfData != 0)
            {
                uintptr_t functionAddr = 0;

                if (thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)
                {
                    WORD ordinal = thunk->u1.Ordinal & 0xFFFF;
                    functionAddr = reinterpret_cast<uintptr_t>(
                        ProcessUtils::GetRemoteProcAddressByOrdinal(m_context.processHandle, remoteModuleBase, ordinal)
                    );
                    if (!functionAddr)
                    {
                        return false;
                    }
                }
                else
                {
                    DWORD importByNameFileOffset = m_peParser->RvaToFileOffset(
                        static_cast<DWORD>(thunk->u1.AddressOfData));
                    auto* importByName = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(
                        const_cast<Byte*>(imageData.data()) + importByNameFileOffset
                    );

                    functionAddr = reinterpret_cast<uintptr_t>(
                        ProcessUtils::GetRemoteProcAddress(m_context.processHandle, remoteModuleBase, importByName->Name)
                    );
                    if (!functionAddr)
                    {
                        return false;
                    }
                }

                void* iatAddr = TranslateRva(currentIatRva);
                if (iatAddr)
                {
                    if (!Syscalls::WriteMemory(m_context.processHandle, iatAddr, &functionAddr, sizeof(uintptr_t)))
                    {
                        return false;
                    }
                }

                thunk++;
                currentIatRva += sizeof(uintptr_t);
                functionCount++;
            }

            importDesc++;
        }

        return true;
    }

    bool ManualMapper::BuildInterSectionJumps()
    {
        for (auto& section : m_scatteredSections)
        {
            ByteArray trampolineTable;

            for (size_t j = 0; j < m_scatteredSections.size(); ++j)
            {
                uintptr_t targetAddr = reinterpret_cast<uintptr_t>(m_scatteredSections[j].remoteAddress);

                trampolineTable.push_back(0x48);
                trampolineTable.push_back(0xB8);
                for (int b = 0; b < 8; ++b)
                    trampolineTable.push_back(static_cast<Byte>(targetAddr >> (b * 8)));

                trampolineTable.push_back(0xFF);
                trampolineTable.push_back(0xE0);
            }

            void* trampolineAddr = reinterpret_cast<void*>(
                reinterpret_cast<uintptr_t>(section.remoteAddress) + section.trampolineOffset
            );

            if (!Syscalls::WriteMemory(m_context.processHandle, trampolineAddr,
                                          trampolineTable.data(), trampolineTable.size()))
            {
                return false;
            }

        }

        return true;
    }

    bool ManualMapper::ProtectScatteredSections()
    {
        for (auto& section : m_scatteredSections)
        {
            DWORD protection = GetSectionProtection(section.characteristics);


            if (!Syscalls::ProtectMemory(m_context.processHandle, section.remoteAddress,
                                            section.allocationSize, protection))
            {
                return false;
            }
        }

        return true;
    }

    bool ManualMapper::ExecuteScattered()
    {
        return Execute();
    }

    bool ManualMapper::UnloadScattered()
    {
        if (!m_context.processHandle)
        {
            LogMessage("UNLOAD SCATTERED FAILED - Invalid process handle");
            return false;
        }

        LogUnload("SCATTERED");

        std::ostringstream oss;
        oss << "  -> Freeing " << m_scatteredSections.size() << " scattered sections...";
        LogMessage(oss.str());

        int freedSections = 0;
        for (auto& section : m_scatteredSections)
        {
            if (section.remoteAddress)
            {
                oss.str("");
                oss << "  -> Freeing section [" << section.name << "] at 0x"
                    << std::hex << std::uppercase << reinterpret_cast<uintptr_t>(section.remoteAddress)
                    << " (size: 0x" << section.allocationSize << " bytes)";
                LogMessage(oss.str());

                Syscalls::FreeMemory(m_context.processHandle, section.remoteAddress);
                section.remoteAddress = nullptr;
                freedSections++;
            }
        }

        oss.str("");
        oss << "  -> Freed " << std::dec << freedSections << " sections";
        LogMessage(oss.str());

        m_scatteredSections.clear();
        LogMessage("  -> Scattered sections cleared");

        if (m_remoteHeadersBase)
        {
            oss.str("");
            oss << "  -> Freeing headers at 0x" << std::hex << std::uppercase
                << reinterpret_cast<uintptr_t>(m_remoteHeadersBase);
            LogMessage(oss.str());

            Syscalls::FreeMemory(m_context.processHandle, m_remoteHeadersBase);
            m_remoteHeadersBase = nullptr;
            LogMessage("  -> Headers freed");
        }

        LogMessage("  -> Cleaning up context...");
        m_context.remoteImageBase = nullptr;
        m_context.entryPoint = nullptr;

        LogMessage("  -> UNLOAD SCATTERED COMPLETE");
        return true;
    }

    void ManualMapper::Cleanup()
    {
        if (m_peParser)
        {
            delete m_peParser;
            m_peParser = nullptr;
        }

        if (m_context.processHandle)
        {
            if (m_context.isScattered)
            {
                for (auto& section : m_scatteredSections)
                {
                    if (section.remoteAddress)
                        Syscalls::FreeMemory(m_context.processHandle, section.remoteAddress);
                }
                m_scatteredSections.clear();

                if (m_remoteHeadersBase)
                {
                    Syscalls::FreeMemory(m_context.processHandle, m_remoteHeadersBase);
                    m_remoteHeadersBase = nullptr;
                }
            }

            ProcessUtils::CloseProcess(m_context.processHandle);
            m_context.processHandle = nullptr;
        }
    }
}