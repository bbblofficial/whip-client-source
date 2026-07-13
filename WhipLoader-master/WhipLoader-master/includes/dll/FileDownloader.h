#pragma once
#include "auth/Credentials.h"
#include "util/Result.h"
#include "util/Types.h"

#ifdef VMP
#include "VMProtectSDK.h"
#endif

#pragma optimize("", off)

class WhipNexusClient;

struct FileData {
    Byte* data;
    u32 size;
    char key[256];

    __forceinline FileData() : data(nullptr), size(0) {
        key[0] = '\0';
    }

    __forceinline ~FileData() {
        if (data) {
            delete[] data;
            data = nullptr;
        }
    }

    FileData(const FileData&) = delete;
    FileData& operator=(const FileData&) = delete;

    __forceinline FileData(FileData&& other) noexcept : data(other.data), size(other.size) {
        for (u32 i = 0; i < 256; ++i) key[i] = other.key[i];
        other.data = nullptr;
        other.size = 0;
    }

    __forceinline FileData& operator=(FileData&& other) noexcept {
        if (this != &other) {
            if (data) delete[] data;
            data = other.data;
            size = other.size;
            for (u32 i = 0; i < 256; ++i) key[i] = other.key[i];
            other.data = nullptr;
            other.size = 0;
        }
        return *this;
    }
};

typedef void (*OnFileDownloadSuccess)(const FileData* file);
typedef void (*OnFileDownloadFailure)(const Error* error);

class FileDownloader {
public:
    FileDownloader(WhipNexusClient* client, const char* pcName, const char* executablePath,
                   const Byte authSalt[16], const Byte algoSeed[32], const Byte codeFingerprint[32]);

    [[nodiscard]] Result<FileData> download(const char* key);

    void downloadAsync(
        const char* key,
        OnFileDownloadSuccess onSuccess,
        OnFileDownloadFailure onFailure
    );


private:
    WhipNexusClient* client_;
    char pcName_[128];
    char executablePath_[512];
    Byte authSalt_[16];
    Byte algoSeed_[32];
    Byte codeFingerprint_[32];
};

FileDownloader* createFileDownloader(
    WhipNexusClient* client,
    const char* pcName,
    const char* executablePath,
    const Byte authSalt[16],
    const Byte algoSeed[32],
    const Byte codeFingerprint[32]
);

#pragma optimize("", on)
