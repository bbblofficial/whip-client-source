#include "ManualMapper/PeParser.h"

namespace ManualMapper
{
    PeParser::PeParser(const ByteArray& imageData)
        : m_imageData(imageData), m_isValid(false)
    {
        ParseHeaders();
    }

    void PeParser::ParseHeaders()
    {
        if (m_imageData.size() < sizeof(IMAGE_DOS_HEADER))
        {
            m_isValid = false;
            return;
        }

        m_headers.dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(m_imageData.data());

        if (m_headers.dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
        {
            m_isValid = false;
            return;
        }

        if (m_imageData.size() < m_headers.dosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS))
        {
            m_isValid = false;
            return;
        }

        m_headers.ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(
            m_imageData.data() + m_headers.dosHeader->e_lfanew
        );

        if (m_headers.ntHeaders->Signature != IMAGE_NT_SIGNATURE)
        {
            m_isValid = false;
            return;
        }

        m_headers.sectionHeaders = IMAGE_FIRST_SECTION(m_headers.ntHeaders);
        m_isValid = true;
    }

    bool PeParser::IsValid() const
    {
        return m_isValid;
    }

    PeHeaders PeParser::GetHeaders() const
    {
        return m_headers;
    }

    size_t PeParser::GetImageSize() const
    {
        if (!m_isValid)
            return 0;

        return m_headers.ntHeaders->OptionalHeader.SizeOfImage;
    }

    DWORD PeParser::GetEntryPointRva() const
    {
        if (!m_isValid)
            return 0;

        return m_headers.ntHeaders->OptionalHeader.AddressOfEntryPoint;
    }

    PIMAGE_SECTION_HEADER PeParser::GetSectionHeader(size_t index) const
    {
        if (!m_isValid || index >= GetSectionCount())
            return nullptr;

        return &m_headers.sectionHeaders[index];
    }

    size_t PeParser::GetSectionCount() const
    {
        if (!m_isValid)
            return 0;

        return m_headers.ntHeaders->FileHeader.NumberOfSections;
    }

    DWORD PeParser::RvaToFileOffset(DWORD rva) const
    {
        if (!m_isValid)
            return 0;

        size_t sectionCount = GetSectionCount();
        for (size_t i = 0; i < sectionCount; ++i)
        {
            PIMAGE_SECTION_HEADER section = &m_headers.sectionHeaders[i];

            if (rva >= section->VirtualAddress &&
                rva < section->VirtualAddress + section->Misc.VirtualSize)
            {
                DWORD offset = rva - section->VirtualAddress;
                return section->PointerToRawData + offset;
            }
        }

        return rva;
    }

    PIMAGE_TLS_DIRECTORY64 PeParser::GetTlsDirectory() const
    {
        if (!m_isValid)
            return nullptr;

        IMAGE_DATA_DIRECTORY tlsDirectory = m_headers.ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];

        if (tlsDirectory.Size == 0)
            return nullptr;

        DWORD tlsFileOffset = RvaToFileOffset(tlsDirectory.VirtualAddress);

        if (tlsFileOffset >= m_imageData.size())
            return nullptr;

        return reinterpret_cast<PIMAGE_TLS_DIRECTORY64>(
            const_cast<Byte*>(m_imageData.data()) + tlsFileOffset
        );
    }
}