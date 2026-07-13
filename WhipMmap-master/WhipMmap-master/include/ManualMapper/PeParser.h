#pragma once

#include "Types.h"

namespace ManualMapper
{
    class PeParser
    {
    public:
        PeParser(const ByteArray& imageData);
        ~PeParser() = default;

        bool IsValid() const;
        PeHeaders GetHeaders() const;
        size_t GetImageSize() const;
        DWORD GetEntryPointRva() const;
        PIMAGE_SECTION_HEADER GetSectionHeader(size_t index) const;
        size_t GetSectionCount() const;
        DWORD RvaToFileOffset(DWORD rva) const;
        PIMAGE_TLS_DIRECTORY64 GetTlsDirectory() const;

        const ByteArray& GetImageData() const { return m_imageData; }

    private:
        ByteArray m_imageData;
        PeHeaders m_headers;
        bool m_isValid;

        void ParseHeaders();
    };
}