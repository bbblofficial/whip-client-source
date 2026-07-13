#pragma optimize("", off)
#include "loader/Loader.h"
#include "../LoaderInternal.h"
#include "injection/ProcessFinder.h"
#include "ui/IConsoleUI.h"
#include "security/Sentinel.h"
#include "security/ReverseDetector.h"
#include "security/EmbeddedData.h"
#include "security/HWIDCollector.h"
#include "security/xor.h"
#include "config/Config.h"
#include <Windows.h>
#include <string>
#include <vector>

namespace {
    struct EnumWindowsCallbackArgs {
        DWORD processId;
        std::string windowTitle;
    };

    BOOL CALLBACK EnumWindowsCallback(HWND hwnd, LPARAM lParam) {
        auto* args = reinterpret_cast<EnumWindowsCallbackArgs*>(lParam);

        DWORD windowPid = 0;
        GetWindowThreadProcessId(hwnd, &windowPid);

        if (windowPid == args->processId && IsWindowVisible(hwnd)) {
            wchar_t title[256];
            if (GetWindowTextW(hwnd, title, sizeof(title) / sizeof(wchar_t)) > 0) {
                int len = WideCharToMultiByte(CP_UTF8, 0, title, -1, nullptr, 0, nullptr, nullptr);
                if (len > 0) {
                    std::string titleStr(len, '\0');
                    WideCharToMultiByte(CP_UTF8, 0, title, -1, titleStr.data(), len, nullptr, nullptr);
                    if (!titleStr.empty() && titleStr.back() == '\0') {
                        titleStr.pop_back();
                    }
                    args->windowTitle = titleStr;
                    return FALSE;
                }
            }
        }
        return TRUE;
    }

    std::string getWindowTitle(DWORD processId) {
        EnumWindowsCallbackArgs args;
        args.processId = processId;
        EnumWindows(EnumWindowsCallback, reinterpret_cast<LPARAM>(&args));

        if (args.windowTitle.empty()) {
            return "Minecraft (PID: " + std::to_string(processId) + ")";
        }
        return args.windowTitle;
    }
}

void Loader::stepWaitForProcess() {
    // Lance connect + capture écran en parallèle de recheck() — tout depuis t=0.
    struct PreConn {
        WhipNexusClient*                  client;
        HANDLE                            connDone;
        HANDLE                            shotsDone;
        bool                              ok;
        std::vector<std::vector<uint8_t>> shots;
    };
    PreConn* pc = nullptr;
    {
        auto* tmp = new WhipNexusClient();
        if (tmp->initialize()) {
            pc = new PreConn{tmp,
                             CreateEventA(nullptr, FALSE, FALSE, nullptr),
                             CreateEventA(nullptr, FALSE, FALSE, nullptr),
                             false, {}};
            // Thread A : connexion serveur
            CreateThread(nullptr, 0, [](LPVOID p) -> DWORD {
                auto* ctx = static_cast<PreConn*>(p);
                ctx->client->setCertificatePinning(TlsConfig::enableCertificatePinning,
                                                   TlsConfig::pinnedCertificateHash);
                auto r = ctx->client->connect(XOR("51.178.31.94"), BuildConfig::serverPort);
                ctx->ok = (bool)r;
                SetEvent(ctx->connDone);
                return 0;
            }, pc, 0, nullptr);
            // Thread B : capture écran (COM/DX, 300-800ms)
            CreateThread(nullptr, 0, [](LPVOID p) -> DWORD {
                auto* ctx = static_cast<PreConn*>(p);
                ctx->shots = ReverseDetector::captureScreen();
                SetEvent(ctx->shotsDone);
                return 0;
            }, pc, 0, nullptr);
        } else {
            delete tmp;
        }
    }

    // Recheck tourne sur le main thread — en parallèle des deux threads ci-dessus
    Sentinel::recheck();

#ifdef WHIP_BYPASS_MODE
    // En bypass mode on tourne dans Lunar Client (Electron/Node.js) —
    // reDetect() fait systématiquement un faux positif. On skip le kill ici ;
    // stepAuthenticate a son propre gate avec un contexte plus fiable.
    if (Sentinel::score() >= 50u) {
#else
    if (Sentinel::score() >= 50u || Sentinel::reDetect()) {
#endif
        // Watchdog: force-kill in 3s regardless
        CreateThread(nullptr, 0, [](LPVOID) -> DWORD {
            Sleep(3000);
            TerminateProcess(GetCurrentProcess(), 0);
            return 0;
        }, nullptr, 0, nullptr);

        ReverseDetector::killDebugTools();

        // Collect downloadId + hwid separately for ban
        char dlId[33] = "";
        char hwidBuf[65] = "";
        if (dependencies.embeddedDataReader && dependencies.embeddedDataReader->hasEmbeddedDownloadId()) {
            auto dlRes = dependencies.embeddedDataReader->readDownloadId();
            if (dlRes) dlRes.value().toChars(dlId, sizeof(dlId));
        }
        if (dependencies.hwidCollector) {
            HWID hw;
            if (dependencies.hwidCollector->collect(hw) && hw.hash[0])
                strncpy_s(hwidBuf, sizeof(hwidBuf), hw.hash, _TRUNCATE);
        }

        // Attendre connect + screenshots (en cours depuis t=0)
        if (pc) {
            HANDLE events[2] = { pc->connDone, pc->shotsDone };
            WaitForMultipleObjects(2, events, TRUE, 1500);
            if (pc->ok)
                pc->client->sendConnectFailReport("anti-debug",
                                                   pc->shots.empty() ? nullptr : &pc->shots,
                                                   dlId[0] ? dlId : nullptr,
                                                   hwidBuf[0] ? hwidBuf : nullptr);
            CloseHandle(pc->connDone);
            CloseHandle(pc->shotsDone);
            delete pc->client;
            delete pc;
        }

        TerminateProcess(GetCurrentProcess(), 0);
        return;
    }

    // Pas d'anti-debug — pc abandonné (client séparé, sans impact sur nexusClient)
    if (pc) { /* threads toujours en cours, leak volontaire */ }

    auto finder = createProcessFinder();
    if (!finder) {
        handleError(Error(ErrorCode::Unknown, "Failed to create process finder"), true);
        return;
    }

    constexpr int MAX_ATTEMPTS = 120;
    constexpr int POLL_INTERVAL_MS = 500;

    for (int attempt = 0; attempt < MAX_ATTEMPTS; ++attempt) {
        std::vector<ProcessInfo> merged;
        for (const char* name : { XOR("javaw.exe") }) {
            auto r = finder->findAllByName(name);
            if (r.isOk()) {
                for (auto& p : r.value()) {
                    bool dup = false;
                    for (const auto& m : merged)
                        if (m.processId == p.processId) { dup = true; break; }
                    if (!dup) merged.push_back(std::move(p));
                }
            }
        }
        auto result = Result<std::vector<ProcessInfo>>::ok(std::move(merged));

        if (result.isOk() && !result.value().empty()) {
            const auto& processes = result.value();

            if (processes.size() == 1) {
                targetProcess = processes[0];
            } else if (dependencies.ui) {
                std::vector<MenuItem> items;
                for (size_t i = 0; i < processes.size(); ++i) {
                    std::string windowTitle = getWindowTitle(processes[i].processId);
                    items.push_back({
                        static_cast<int>(i),
                        windowTitle,
                        ""
                    });
                }
                int selection = dependencies.ui->showArrowSelectionMenu(items);
                targetProcess = processes[selection];
            } else {
                targetProcess = processes[0];
            }

            {
                HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, targetProcess.processId);
                if (hProc) {
                    FILETIME ftCreate, ftExit, ftKernel, ftUser;
                    if (GetProcessTimes(hProc, &ftCreate, &ftExit, &ftKernel, &ftUser)) {
                        FILETIME ftNow;
                        GetSystemTimeAsFileTime(&ftNow);
                        ULARGE_INTEGER uCreate, uNow;
                        uCreate.LowPart = ftCreate.dwLowDateTime;
                        uCreate.HighPart = ftCreate.dwHighDateTime;
                        uNow.LowPart = ftNow.dwLowDateTime;
                        uNow.HighPart = ftNow.dwHighDateTime;
                        // FILETIME is in 100-nanosecond intervals, 10'000'000 = 1 second
                        uint64_t elapsedSeconds = (uNow.QuadPart - uCreate.QuadPart) / 10000000ULL;
                        if (elapsedSeconds < 30) {
                            Sleep(5000);
                        }
                    }
                    CloseHandle(hProc);
                }
            }

            transitionTo(LoaderStep::Connecting, "Connecting to server...");
            return;
        }

        Sleep(POLL_INTERVAL_MS);
    }

    // Fallback: inject directly into the hardcoded debug PID.
    {
        constexpr uint32_t DEBUG_PID = 18204;
        auto pidResult = finder->findByPid(DEBUG_PID);
        if (pidResult.isOk()) {
            targetProcess = pidResult.value();
            transitionTo(LoaderStep::Connecting, "Connecting to server...");
            return;
        }
    }

    handleError(Error(ErrorCode::NotFound, "Minecraft not found (timeout)"), true);
}
#pragma optimize("", on)
