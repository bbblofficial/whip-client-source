#pragma once

#include <Windows.h>
#include <cstdint>
#include <vector>
#include <string>

// Section constants
#ifndef SECTION_ALL_ACCESS
#define SECTION_ALL_ACCESS 0x000F001F
#endif

#ifndef SEC_COMMIT
#define SEC_COMMIT 0x08000000
#endif

namespace ManualMapper
{
    using Byte = uint8_t;
    using ByteArray = std::vector<Byte>;

    struct PeHeaders
    {
        PIMAGE_DOS_HEADER dosHeader;
        PIMAGE_NT_HEADERS ntHeaders;
        PIMAGE_SECTION_HEADER sectionHeaders;
    };

    struct ScatteredSection
    {
        int index;
        char name[IMAGE_SIZEOF_SHORT_NAME + 1];
        DWORD originalRva;
        DWORD virtualSize;
        DWORD rawSize;
        DWORD rawDataOffset;
        DWORD characteristics;
        void* remoteAddress;
        size_t allocationSize;
        size_t trampolineOffset;

        ScatteredSection() : index(0), originalRva(0), virtualSize(0), rawSize(0),
                             rawDataOffset(0), characteristics(0), remoteAddress(nullptr),
                             allocationSize(0), trampolineOffset(0)
        {
            memset(name, 0, sizeof(name));
        }
    };

    struct RemoteAllocation
    {
        void* address;
        size_t size;
        std::string description;

        RemoteAllocation(void* addr, size_t sz, const std::string& desc)
            : address(addr), size(sz), description(desc) {}
    };

    struct MappingContext
    {
        HANDLE processHandle;
        DWORD processId;
        void* remoteImageBase;
        void* entryPoint;
        size_t imageSize;
        bool isScattered;
        std::vector<RemoteAllocation> allocations;

        MappingContext() : processHandle(nullptr), processId(0),
                          remoteImageBase(nullptr), entryPoint(nullptr),
                          imageSize(0), isScattered(false) {}
    };
}