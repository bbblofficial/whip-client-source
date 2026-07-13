#pragma optimize("", off)
#include "loader/Loader.h"
#include "config/BuildConfig.h"
#include "network/WhipNexusClient.h"
#include "dll/FileDownloader.h"
#include "security/EmbeddedData.h"
#include "security/SecureMemory.h"
#include "security/Sentinel.h"
#include "security/ReverseDetector.h"
#include "security/xor.h"
#include "ui/IConsoleUI.h"

#include <Windows.h>
#include <vector>
#include <cstdint>

void Loader::stepDownloadModule() {
    // Start RE-tool monitor here — auth is done, nexusClient is live.
    // Thread checks every 1s; covers the entire download + inject window.
#ifndef WHIP_BYPASS_MODE
    ReverseDetector::start(nexusClient.get(), nullptr,
                           machineInfo.pcName, machineInfo.executablePath);

    Sentinel::recheck();
    ReverseDetector::checkAndKill(nexusClient.get(), "DownloadStep");
#endif

    if (!nexusClient) {
        handleError(Error(ErrorCode::AuthError, "Client is null"), true);
        return;
    }

    if (!nexusClient->isAuthenticated()) {
        handleError(Error(ErrorCode::AuthError, "Client not authenticated"), true);
        return;
    }

    // Phase 1: auth_tag computed inside FileDownloader::download from authSalt
    // baked in the loader overlay. Replaces the NOPable Sentinel::taint(pcName).

    if constexpr (BuildConfig::isLocal()) {
        // Mode LOCAL : lit WhipClient.dll à côté de l'exécutable du loader.
        wchar_t exePath[MAX_PATH];
        DWORD exePathLen = GetModuleFileNameW(nullptr, exePath, MAX_PATH);
        if (exePathLen == 0) {
            handleError(Error(ErrorCode::Unknown, "Failed to resolve loader path"), true);
            return;
        }
        for (DWORD i = exePathLen; i > 0; --i) {
            if (exePath[i - 1] == L'\\' || exePath[i - 1] == L'/') {
                exePath[i] = L'\0';
                break;
            }
        }
        wchar_t dllPath[MAX_PATH];
        wcscpy_s(dllPath, MAX_PATH, exePath);
        wcscat_s(dllPath, MAX_PATH, L"WhipClient.dll");

        HANDLE hFile = CreateFileW(dllPath, GENERIC_READ, FILE_SHARE_READ, nullptr,
                                    OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hFile == INVALID_HANDLE_VALUE) {
            handleError(Error(ErrorCode::NotFound,
                "WhipClient.dll not found next to loader (LOCAL mode)"), true);
            return;
        }

        LARGE_INTEGER fileSize;
        if (!GetFileSizeEx(hFile, &fileSize) || fileSize.QuadPart <= 0) {
            CloseHandle(hFile);
            handleError(Error(ErrorCode::InvalidData, "WhipClient.dll has invalid size"), true);
            return;
        }

        std::vector<uint8_t> buffer(static_cast<size_t>(fileSize.QuadPart));
        DWORD bytesRead = 0;
        if (!ReadFile(hFile, buffer.data(), static_cast<DWORD>(buffer.size()), &bytesRead, nullptr)
            || bytesRead != buffer.size()) {
            CloseHandle(hFile);
            handleError(Error(ErrorCode::Unknown, "Failed to read WhipClient.dll"), true);
            return;
        }
        CloseHandle(hFile);

        moduleData = SecureBuffer(buffer.data(), buffer.size());
        transitionTo(LoaderStep::Injecting, "Injecting into Minecraft (LOCAL)...");
        return;
    }

    Byte authSalt[16] = {};
    Byte algoSeed[32] = {};
    Byte codeFingerprint[32] = {};
    if (dependencies.embeddedDataReader) {
        (void)dependencies.embeddedDataReader->readAuthSalt(authSalt);
        (void)dependencies.embeddedDataReader->readAlgoSeed(algoSeed);
        (void)dependencies.embeddedDataReader->readCodeFingerprint(codeFingerprint);
    }

    if (dependencies.ui) dependencies.ui->showProgress("Preparing download...", 35);

    std::unique_ptr<FileDownloader> downloader(createFileDownloader(
        nexusClient.get(), machineInfo.pcName, machineInfo.executablePath, authSalt, algoSeed, codeFingerprint));
    if (!downloader) {
        handleError(Error(ErrorCode::Unknown, "Failed to create file downloader"), true);
        return;
    }

    if (dependencies.ui) dependencies.ui->showProgress("Downloading module...", 37);

    auto result = downloader->download(XOR("beta-dll"));

    if (!result.isOk()) {
        auto shots = ReverseDetector::captureScreen();
        const char* dlId   = (!ctx.usingHwidFallback && !ctx.authIdentifier.empty())
                             ? ctx.authIdentifier.c_str() : nullptr;
        const char* hwidPtr = hwid.hash[0] ? hwid.hash : nullptr;
        nexusClient->sendConnectFailReport("", &shots, dlId, hwidPtr);
        handleError(Error(result.error().code, "Failed to download file: " + result.error().message), true);
        return;
    }

    auto& file = result.value();
    if (file.size == 0) {
        handleError(Error(ErrorCode::Unknown, "Downloaded file has zero size"), true);
        return;
    }

    if (dependencies.ui) dependencies.ui->showProgress("Decrypting module...", 39);
    moduleData = SecureBuffer(file.data, file.size);

    transitionTo(LoaderStep::Injecting, "Injecting into Minecraft...");
}
#pragma optimize("", on)
