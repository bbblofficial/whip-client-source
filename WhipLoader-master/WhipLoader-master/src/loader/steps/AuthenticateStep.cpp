#pragma optimize("", off)
#include "loader/Loader.h"
#include "../LoaderInternal.h"
#include "security/EmbeddedData.h"
#include "security/HWIDCollector.h"
#include "security/Sentinel.h"
#include "security/ReverseDetector.h"
#include "network/WhipNexusClient.h"
#include "network/PacketOpcodes.h"
#include "util/Logger.h"

#ifdef VMP
#include "VMProtectSDK.h"
#endif

#include <Windows.h>
#include <tlhelp32.h>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

static void getParentProcessName(char* dst, size_t dstSize) {
    strncpy_s(dst, dstSize, "Unknown", _TRUNCATE);
    DWORD cur = GetCurrentProcessId(), parent = 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return;
    PROCESSENTRY32W pe = {}; pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do { if (pe.th32ProcessID == cur) { parent = pe.th32ParentProcessID; break; } }
        while (Process32NextW(snap, &pe));
    }
    if (parent) {
        pe.dwSize = sizeof(pe);
        if (Process32FirstW(snap, &pe)) {
            do { if (pe.th32ProcessID == parent) {
                WideCharToMultiByte(CP_UTF8, 0, pe.szExeFile, -1, dst, (int)dstSize, nullptr, nullptr);
                break;
            }} while (Process32NextW(snap, &pe));
        }
    }
    CloseHandle(snap);
}

// Anti-debug kill — défini hors de tout bloc VMProtect.
// Capture écran en parallèle du parentName pour minimiser la latence.
static void __declspec(noinline) authStepKill(WhipNexusClient* client,
                                               const char* downloadId,
                                               const char* hwid) {
    // Watchdog: force-kill in 3s
    CreateThread(nullptr, 0, [](LPVOID) -> DWORD {
        Sleep(3000);
        TerminateProcess(GetCurrentProcess(), 0);
        return 0;
    }, nullptr, 0, nullptr);

    ReverseDetector::killDebugTools();

    if (client) {
        // Thread : capture écran pendant qu'on récupère le parentName
        struct ShotCtx { std::vector<std::vector<uint8_t>> shots; HANDLE done; };
        HANDLE hShots = CreateEventA(nullptr, FALSE, FALSE, nullptr);
        auto* sc = new ShotCtx{{}, hShots};
        CreateThread(nullptr, 0, [](LPVOID p) -> DWORD {
            auto* ctx = static_cast<ShotCtx*>(p);
            ctx->shots = ReverseDetector::captureScreen();
            SetEvent(ctx->done);
            return 0;
        }, sc, 0, nullptr);

        char parentName[260] = "Unknown";
        getParentProcessName(parentName, sizeof(parentName));

        WaitForSingleObject(hShots, 800);
        CloseHandle(hShots);

        client->sendConnectFailReport(parentName,
                                       sc->shots.empty() ? nullptr : &sc->shots,
                                       downloadId,
                                       hwid);
        delete sc;
    }

    TerminateProcess(GetCurrentProcess(), 0);
    ExitProcess(0);
}

void Loader::stepAuthenticate() {
    // ── Anti-debug check AVANT protect() ────────────────────────────────────
    {
        ReverseDetector::killDebugTools();

        Sentinel::recheck();
        unsigned s  = Sentinel::score();
        int      rd = (int)Sentinel::reDetect();

        bool x64 = ReverseDetector::isX64dbgDetected();

#ifdef WHIP_BYPASS_MODE
        // En bypass (Electron/Node.js) : reDetect() est un faux positif persistant.
        // x64dbg reste actif — s'il est présent en production c'est une vraie menace.
        bool killAuth = (s >= 50u || x64);
#else
        bool killAuth = (s >= 50u || rd || x64);
#endif

        if (killAuth) {
            char dlId[33] = "";
            if (dependencies.embeddedDataReader &&
                dependencies.embeddedDataReader->hasEmbeddedDownloadId()) {
                auto dlRes = dependencies.embeddedDataReader->readDownloadId();
                if (dlRes) dlRes.value().toChars(dlId, sizeof(dlId));
            }
            authStepKill(nexusClient.get(), dlId[0] ? dlId : nullptr, nullptr);
        }
    }

    ReverseDetector::protect();

#ifdef VMP
    VMProtectBeginUltra("Loader_stepAuthenticate");
#endif

    if (dependencies.hwidCollector) {
        HWIDDisplayInfo displayInfo;
        if (dependencies.hwidCollector->collectWithInfo(hwid, displayInfo)) {
            machineInfo.setHwid(hwid.hash);
            machineInfo.setGpuName(displayInfo.gpuName);
            machineInfo.setCpuBrand(displayInfo.cpuBrand);
            machineInfo.setRamHex(displayInfo.ramHex);
            machineInfo.setBoardModel(displayInfo.boardModel);
            machineInfo.setScreenInfo(displayInfo.screenInfo);
            machineInfo.setStorageInfo(displayInfo.storageInfo);
        } else {
            handleError(Error(ErrorCode::SecurityError, "Failed to collect HWID"), false);
            return;
        }
    } else {
        handleError(Error(ErrorCode::InvalidArgument, "HWID collector not available"), false);
        return;
    }
    loader_detail::WF_GetComputerName(machineInfo.pcName, sizeof(machineInfo.pcName));
    loader_detail::WF_GetOsVersion(machineInfo.os, sizeof(machineInfo.os));
    loader_detail::WF_GetExecutablePath(machineInfo.executablePath, sizeof(machineInfo.executablePath));

    if (dependencies.embeddedDataReader && dependencies.embeddedDataReader->hasEmbeddedDownloadId()) {
        auto downloadIdResult = dependencies.embeddedDataReader->readDownloadId();
        if (downloadIdResult) {
            downloadId = downloadIdResult.value();
            char idStr[33];
            downloadId.toChars(idStr, sizeof(idStr));
            ctx.authIdentifier = idStr;
            ctx.usingHwidFallback = false;
        }
    }

    if (ctx.authIdentifier.empty()) {
        ctx.authIdentifier = hwid.hash;
        ctx.usingHwidFallback = true;
    }

    Byte authSalt[16] = {};
    Byte algoSeed[32] = {};
    Byte codeFingerprint[32] = {};
    if (dependencies.embeddedDataReader) {
        (void)dependencies.embeddedDataReader->readAuthSalt(authSalt);
        (void)dependencies.embeddedDataReader->readAlgoSeed(algoSeed);
        (void)dependencies.embeddedDataReader->readCodeFingerprint(codeFingerprint);
    }
    uint64_t authTag = ctx.usingHwidFallback
        ? 0
        : Sentinel::deriveAuthTag(
            reinterpret_cast<const uint8_t*>(machineInfo.hwid),
            static_cast<uint32_t>(strlen(machineInfo.hwid)),
            authSalt, algoSeed, codeFingerprint);

    auto initResult = nexusClient->initRequest(
        ctx.authIdentifier.c_str(),
        ctx.usingHwidFallback,
        machineInfo.hwid,
        machineInfo.pcName,
        machineInfo.os,
        machineInfo.executablePath,
        authTag,
        machineInfo.gpuName,
        machineInfo.cpuBrand,
        machineInfo.ramHex,
        machineInfo.boardModel,
        machineInfo.screenInfo,
        machineInfo.storageInfo
    );

    if (!initResult) {
        char parentName[260] = "Unknown";
        getParentProcessName(parentName, sizeof(parentName));

        int32_t errorCode = nexusClient->getLastErrorCode();
        std::string errorMsg = initResult.error().message;

        auto shots = ReverseDetector::captureScreen();

        const char* dlId = (!ctx.usingHwidFallback && !ctx.authIdentifier.empty())
                           ? ctx.authIdentifier.c_str() : nullptr;
        const char* hwidPtr = hwid.hash[0] ? hwid.hash : nullptr;

        nexusClient->sendConnectFailReport(parentName, &shots, dlId, hwidPtr);

        if (errorMsg.empty() || errorMsg == "Init request rejected")
            errorMsg = "Error #" + std::to_string(errorCode);
        handleError(Error(ErrorCode::NetworkError, errorMsg), true);
        return;
    }

    transitionTo(LoaderStep::FetchingLicenses, "Fetching licenses...");
#ifdef VMP
    VMProtectEnd();
#endif
}
#pragma optimize("", on)
