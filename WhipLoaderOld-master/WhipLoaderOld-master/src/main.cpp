#include <iostream>
#include <thread>
#include <chrono>
#include <atomic>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "antidebug/common.h"
#include "antidebug/MonitoringThread.h"
#include "auth/auth.h"
#include "Communication/LoaderCommunication.h"
#include "mmap/core/mmap.h"
#include "utils/hwidutils.h"
#include "utils/cliUtils.h"

namespace {
    enum class ExitReason {
        None,
        Disconnect,
        HeartbeatTimeout,
        ProcessClosed
    };

    constexpr int kTotalSteps = 12;
    constexpr int kStepDelay = 3;
    constexpr int kHeartbeatCheckInterval = 100;
    constexpr int kClientLoadTimeout = 120000;
    constexpr int kMessageBufferSize = 4096;

    std::atomic<bool> g_processRunning{true};
    std::atomic<bool> g_stopMonitoring{false};

    HWND g_consoleWindow = NULL;
}

namespace Console {
    void create() {
        AllocConsole();

        FILE* fp;
        freopen_s(&fp, "CONOUT$", "w", stdout);
        freopen_s(&fp, "CONOUT$", "w", stderr);
        freopen_s(&fp, "CONIN$", "r", stdin);

        g_consoleWindow = GetConsoleWindow();
    }

    void show() {
        if (g_consoleWindow) {
            ShowWindow(g_consoleWindow, SW_SHOW);
            SetForegroundWindow(g_consoleWindow);
        }
    }

    void hide() {
        if (g_consoleWindow) {
            ShowWindow(g_consoleWindow, SW_HIDE);
        }
    }

    void destroy() {
        FreeConsole();
        g_consoleWindow = NULL;
    }
}

void processMonitorThread(const char* processName) {
    while (!g_stopMonitoring.load()) {
        if (!Utils::isProcessRunning(processName)) {
            g_processRunning.store(false);
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }
}

bool initializeLoader(int& step) {
    Utils::showStep("Initializing...", ++step, kTotalSteps);
    EnableDefaultChecks();
    std::this_thread::sleep_for(std::chrono::seconds(kStepDelay));

    Utils::showStep("Initializing API...", ++step, kTotalSteps);
    API::Init();
    std::this_thread::sleep_for(std::chrono::seconds(kStepDelay));

    Utils::showStep("Creating thread...", ++step, kTotalSteps);
    HANDLE hMonitorThread = CreateThread(nullptr, 0, BackgroundMonitoringThread, nullptr, 0, nullptr);
    if (!hMonitorThread) {
        Utils::showError("Failed to create monitoring thread!");
        return false;
    }
    std::this_thread::sleep_for(std::chrono::seconds(kStepDelay));

    return true;
}

const char* retrieveHwid(int& step) {
    Utils::showStep("Retrieving hardware ID...", ++step, kTotalSteps);
    const char* hwid = getHwid();
    std::this_thread::sleep_for(std::chrono::seconds(kStepDelay));
    return hwid;
}

bool authenticate(const char* hwid, unsigned char*& dllBytes, size_t& dllSize, int& step) {
    Utils::showStep("Authenticating with server...", ++step, kTotalSteps);

    Auth* auth = Auth::getInstance();
    bool success = auth->login(hwid, &dllBytes, &dllSize);

    std::this_thread::sleep_for(std::chrono::seconds(kStepDelay));

    return success && auth->isAuthenticated() && dllBytes && dllSize > 0;
}

void processMessages(LoaderCommunicator* comm, DllInjector& injector, int step) {
    char messageBuffer[kMessageBufferSize];
    bool shouldExit = false;
    int loopCount = 0;
    ExitReason exitReason = ExitReason::None;

    while (comm->isConnected() && !shouldExit) {
        int len = comm->receiveMessage(messageBuffer, sizeof(messageBuffer), 100);

        if (len > 0) {
            if (LoaderCommunicator::strStr(messageBuffer, "Disconnect")) {
                exitReason = ExitReason::Disconnect;
                shouldExit = true;
            }
            else if (LoaderCommunicator::strStr(messageBuffer, "StartDestruct") ||
                     LoaderCommunicator::strStr(messageBuffer, "ShowLoader")) {
                Console::show();
                Utils::printLogo();
                Utils::showStep("Destructing client...", step, kTotalSteps);
            }
            else if (LoaderCommunicator::strStr(messageBuffer, "HeartBeat")) {
                comm->updateLastHeartbeat();
            }
            else if (LoaderCommunicator::strStr(messageBuffer, "ThreadId:")) {
                const char* idStr = messageBuffer + 9;
                comm->setClientThreadId(static_cast<DWORD>(atol(idStr)));
            }
        }

        if (!g_processRunning.load()) {
            exitReason = ExitReason::ProcessClosed;
            shouldExit = true;
        }

        if (++loopCount >= kHeartbeatCheckInterval) {
            if (!comm->isClientAlive()) {
                exitReason = ExitReason::HeartbeatTimeout;
                shouldExit = true;
            }
            loopCount = 0;
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    g_stopMonitoring.store(true);
    Console::show();

    if (exitReason == ExitReason::ProcessClosed) {
        Utils::printLogo();
        Utils::showStep("Game closed.", step, kTotalSteps);
        std::this_thread::sleep_for(std::chrono::seconds(2));
    } else {
        Utils::showStep("Destructing client...", step + 1, kTotalSteps);
    }

    injector.Destruct();
    comm->cleanup();
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    (void)hInstance;
    (void)hPrevInstance;
    (void)lpCmdLine;
    (void)nCmdShow;

    Console::create();

    Utils::hideCursor();
    Utils::hideScrollbar();
    SetConsoleOutputCP(CP_UTF8);
    Utils::enableScreenCaptureProtection();
    Utils::printLogo();
    Utils::showCountdown(1);
    Utils::disableConsoleSelection();
    Utils::disableResize();

    int step = 0;

    if (!initializeLoader(step)) {
        std::cin.get();
        Console::destroy();
        return 1;
    }

    const char* hwid = retrieveHwid(step);
    if (!hwid) {

        Utils::showError("Failed to retrieve HWID!");
        std::cin.get();
        Console::destroy();
        return 1;
    }

    unsigned char* dllBytes = nullptr;
    size_t dllSize = 0;

    if (!authenticate(hwid, dllBytes, dllSize, step)) {
        Utils::showError("Authentication failed!");
        delete[] dllBytes;
        std::cin.get();
        Console::destroy();
        return 1;
    }

    Utils::showStep("Initializing injector...", ++step, kTotalSteps);
    DllInjector injector;
    if (!injector.Initialize()) {
        Utils::showError("Failed to initialize injector!");
        delete[] dllBytes;
        std::cin.get();
        Console::destroy();
        return 1;
    }
    std::this_thread::sleep_for(std::chrono::seconds(kStepDelay));

    Utils::showStep("Preparing client...", ++step, kTotalSteps);
    const char* targetProcess = "javaw.exe";
    std::this_thread::sleep_for(std::chrono::seconds(kStepDelay));

    Utils::showStep("Creating communication channel...", ++step, kTotalSteps);
    LoaderCommunicator* comm = LoaderCommunicator::getInstance();
    if (!comm->createPipe()) {
        Utils::showError("Failed to create communication pipe!");
        delete[] dllBytes;
        injector.Destruct();
        std::cin.get();
        Console::destroy();
        return 1;
    }
    std::this_thread::sleep_for(std::chrono::seconds(kStepDelay));

    Utils::showStep("Injecting into target process...", ++step, kTotalSteps);
    bool injectionSuccess = injector.InjectFromBytes(dllBytes, dllSize, targetProcess);
    delete[] dllBytes;
    dllBytes = nullptr;

    if (!injectionSuccess) {
        Utils::showError("Injection failed!");
        injector.Destruct();
        std::cin.get();
        Console::destroy();
        return 1;
    }

    std::thread processMonitor(processMonitorThread, targetProcess);
    std::this_thread::sleep_for(std::chrono::seconds(kStepDelay));

    Utils::showStep("Waiting for client connection...", ++step, kTotalSteps);
    if (!comm->waitForClient()) {
        Utils::showError("Failed to connect to client!");
        g_stopMonitoring.store(true);
        processMonitor.join();
        injector.Destruct();
        std::cin.get();
        Console::destroy();
        return 1;
    }

    /*Utils::showStep("Client connected, waiting for initialization...", ++step, kTotalSteps);
    if (!comm->waitForClientLoaded(kClientLoadTimeout)) {
        Utils::showError("Client failed to load!");
        g_stopMonitoring.store(true);
        processMonitor.join();
        injector.Destruct();
        comm->cleanup();
        std::cin.get();
        Console::destroy();
        return 1;
    }*/

    Utils::showStep("Client loaded successfully!", ++step, kTotalSteps);
    Sleep(1000);
    Console::hide();

    processMonitor.detach();
    processMessages(comm, injector, step);

    Console::destroy();
    return 0;
}