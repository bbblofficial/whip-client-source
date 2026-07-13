#pragma once

#include "Types.h"
#include "PeParser.h"
#include "ProcessUtils.h"
#include "SyscallHelper.h"
#include "LoaderStub.h"
#include <map>

// Prevent Windows UNICODE macro from renaming LoadImage -> LoadImageW
#ifdef LoadImage
#undef LoadImage
#endif

namespace ManualMapper
{
    class ManualMapper
    {
    public:
        ManualMapper();
        ~ManualMapper();

        bool LoadImage(const std::wstring& imagePath);
        bool LoadImageFromMemory(const uint8_t* data, size_t size);
        bool MapToProcess(DWORD processId);
        bool MapToProcess(const std::wstring& processName);
        bool Execute();
        bool Unload();

        // Scatter mapping
        bool ScatterMapToProcess(DWORD processId);
        bool ScatterMapToProcess(const std::wstring& processName);
        bool ExecuteScattered();
        bool UnloadScattered();

        const MappingContext& GetContext() const { return m_context; }
        void* GetRemoteImageBase() const { return m_context.remoteImageBase; }
        void* GetEntryPoint() const { return m_context.entryPoint; }

    private:
        PeParser* m_peParser;
        MappingContext m_context;
        std::map<std::string, void*> m_moduleCache;

        // Standard mapping
        bool MapHeaders();
        bool MapSections();
        bool RelocateImage();
        bool ResolveImports();
        bool ApplyExceptionHandlers();
        bool ProtectSections();
        bool ExecuteTlsCallbacks();
        bool WipeHeaders();
        void Cleanup();

        // Scatter mapping internals
        std::vector<ScatteredSection> m_scatteredSections;
        void* m_remoteHeadersBase;

        bool AllocateScatteredSections();
        bool CopyRawToScatteredSections();
        bool RelocateScattered();
        bool ResolveImportsScattered();
        bool BuildInterSectionJumps();
        bool ProtectScatteredSections();

        void* TranslateRva(DWORD rva) const;
        int FindSectionForRva(DWORD rva) const;

        ByteArray ReadFileToMemory(const std::wstring& filePath);
        DWORD GetSectionProtection(DWORD characteristics);
        void LogUnload(const std::string& unloadType);
    };
}