#pragma optimize("", off)
#include "dll/FileDownloader.h"
#include "network/WhipNexusClient.h"
#include "security/Sentinel.h"
#include "auth/Credentials.h"

#ifdef VMP
#include "VMProtectSDK.h"
#endif

#include "antidebug/stack/stack_cpp.hpp"

#include <cstring>
#include <Windows.h>

FileDownloader::FileDownloader(WhipNexusClient* client, const char* pcName, const char* executablePath,
                               const Byte authSalt[16], const Byte algoSeed[32], const Byte codeFingerprint[32])
    : client_(client) {
    authStrCopy(pcName_, pcName, sizeof(pcName_));
    authStrCopy(executablePath_, executablePath, sizeof(executablePath_));
    memcpy(authSalt_, authSalt, 16);
    memcpy(algoSeed_, algoSeed, 32);
    memcpy(codeFingerprint_, codeFingerprint, 32);
}

Result<FileData> FileDownloader::download(const char* key) {
    ad::StackHidden _ad_guard;  // moonwalk: caller frame's RA -> ntdll decoy

    if (!client_) {
        return Result<FileData>::err(ErrorCode::InvalidArgument, "Client is null");
    }

    if (!client_->isAuthenticated()) {
        return Result<FileData>::err(ErrorCode::AuthError, "Not authenticated");
    }

    constexpr u32 maxFileSize = 100 * 1024 * 1024;
    Byte* tempBuffer = new Byte[maxFileSize];
    u32 actualSize = 0;

    uint64_t authTag = Sentinel::deriveAuthTag(
        reinterpret_cast<const uint8_t*>(pcName_),
        static_cast<uint32_t>(strlen(pcName_)),
        authSalt_,
        algoSeed_,
        codeFingerprint_);

    auto result = client_->requestFile(key, pcName_, executablePath_, authTag, tempBuffer, &actualSize, maxFileSize);
    if (!result.isOk()) {
        delete[] tempBuffer;
        return Result<FileData>::err(result.error());
    }

    FileData file;
    file.data = new Byte[actualSize];
    file.size = actualSize;
    authStrCopy(file.key, key, sizeof(file.key));

    memcpy(file.data, tempBuffer, actualSize);

    delete[] tempBuffer;

#ifdef VMP
    VMProtectEnd();
#endif

    return Result<FileData>::ok(static_cast<FileData&&>(file));
}

void FileDownloader::downloadAsync(
    const char* key,
    OnFileDownloadSuccess onSuccess,
    OnFileDownloadFailure onFailure
) {
    auto result = download(key);
    if (result.isOk()) {
        if (onSuccess) {
            onSuccess(&result.value());
        }
    } else {
        if (onFailure) {
            onFailure(&result.error());
        }
    }
}

FileDownloader* createFileDownloader(
    WhipNexusClient* client,
    const char* pcName,
    const char* executablePath,
    const Byte authSalt[16],
    const Byte algoSeed[32],
    const Byte codeFingerprint[32]
) {
    return new FileDownloader(client, pcName, executablePath, authSalt, algoSeed, codeFingerprint);
}

#pragma optimize("", on)
