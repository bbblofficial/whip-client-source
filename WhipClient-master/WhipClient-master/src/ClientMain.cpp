#include "../../includes/ClientMain.h"

#include <winternl.h>
#include <new>
#include <wincodec.h>
#include <objbase.h>
#include <aclapi.h>
#include <vector>
#pragma comment(lib, "windowscodecs.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "advapi32.lib")
#include <hook/sub/PredictateApplyHook.h>

#include "auth/service/WhipAuthService.h"
#include "auth/Credentials.h"
#include <whipnexus/WhipNexus.h>
#include <whipnexus/SyscallManager.h>
#include "auth/ipc/LoaderIpcClient.h"
#include "util/MinecraftVersionUtils.h"
#include "handler/HookHandler.h"
#include "util/Debug.h"
#include "handler/ProviderHandler.h"
#include "hook/sub/AddSendQueueHook.h"
#include "hook/sub/AttackTargetEntityHook.h"
#include "hook/sub/ChannelReadHook.h"
#include "hook/sub/ClickBlockMouseHook.h"
#include "hook/sub/ClickMouseHook.h"
#include "hook/sub/GetSlotAtPositionHook.h"
#include "hook/sub/KeyBindingIsPressed.h"
#include "hook/sub/RunTickHook.h"
#include "hook/sub/OnUpdateWalkingPlayerHook.h"
#include "hook/sub/OnLivingUpdateHook.h"
#include "hook/sub/RenderNameHook.h"
#include "hook/sub/CanBeCollidedWithHook.h"
#include "hook/sub/RayTraceHook.h"
#include "hook/sub/RenderEntitySimpleHook.h"
#include "hook/sub/RenderHandHook.h"
#include "hook/sub/OrientCameraHook.h"
#include "module/impl/misc/TickLockerModule.h"
#include "module/impl/visual/NotificationModule.h"
#include "task/impl/InputTask.h"
#include "task/impl/UpdateTask.h"
#include "util/HWIDUtils.h"
#include "util/HWIDCollector.h"
#include "util/TrackedString.h"
#include "util/ClientStrings.h"
#include "config/ModuleConfigRegistry.h"
#include "security/Sentinel.h"
#include "util/SecurityHelper.h"
#include "antidebug/stack/stack_cpp.hpp"
#include "antidebug/vm/vm_cpp.hpp"

namespace {
    inline uint64_t encodeSecurityFlag(uint32_t v) {
        auto cascade = ad::vm::ScoreCascade::from_key(vm_runtime_key_stable());
        return cascade.encode(v);
    }
    inline bool decodeSecurityIsActive(uint64_t encoded) {
        auto cascade = ad::vm::ScoreCascade::from_key(vm_runtime_key_stable());
        return cascade.decode(encoded) == 0u;
    }
}

static std::vector<uint8_t> sc_captureRectJpeg(int mx, int my, int mw, int mh) {
    std::vector<uint8_t> result;
    if (mw <= 0 || mh <= 0) return result;
    int dw = mw / 2, dh = mh / 2;

    HDC     hdcScreen = GetDC(nullptr);
    if (!hdcScreen) return result;
    HDC     hdcMem    = CreateCompatibleDC(hdcScreen);
    HBITMAP hbm       = CreateCompatibleBitmap(hdcScreen, dw, dh);
    HGDIOBJ hOld      = SelectObject(hdcMem, hbm);
    SetStretchBltMode(hdcMem, HALFTONE);
    StretchBlt(hdcMem, 0, 0, dw, dh, hdcScreen, mx, my, mw, mh, SRCCOPY);
    SelectObject(hdcMem, hOld);
    DeleteDC(hdcMem);
    ReleaseDC(nullptr, hdcScreen);

    BITMAPINFOHEADER bi = {};
    bi.biSize = sizeof(bi); bi.biWidth = dw; bi.biHeight = -dh;
    bi.biPlanes = 1; bi.biBitCount = 24; bi.biCompression = BI_RGB;
    UINT stride = (static_cast<UINT>(dw) * 3u + 3u) & ~3u;
    std::vector<uint8_t> pixels(static_cast<size_t>(stride) * dh);
    HDC hdcTmp = CreateCompatibleDC(nullptr);
    GetDIBits(hdcTmp, hbm, 0, static_cast<UINT>(dh),
              pixels.data(), reinterpret_cast<BITMAPINFO*>(&bi), DIB_RGB_COLORS);
    DeleteDC(hdcTmp);
    DeleteObject(hbm);

    do {
        IWICImagingFactory* pFact = nullptr;
        if (FAILED(CoCreateInstance(CLSID_WICImagingFactory, nullptr, CLSCTX_INPROC_SERVER,
                                    IID_IWICImagingFactory, reinterpret_cast<void**>(&pFact))) || !pFact) break;
        IStream* pStream = nullptr;
        if (FAILED(CreateStreamOnHGlobal(nullptr, TRUE, &pStream)) || !pStream) { pFact->Release(); break; }
        IWICBitmapEncoder* pEnc = nullptr;
        if (FAILED(pFact->CreateEncoder(GUID_ContainerFormatJpeg, nullptr, &pEnc)) || !pEnc) {
            pStream->Release(); pFact->Release(); break;
        }
        if (FAILED(pEnc->Initialize(pStream, WICBitmapEncoderNoCache))) {
            pEnc->Release(); pStream->Release(); pFact->Release(); break;
        }
        IWICBitmapFrameEncode* pFrame = nullptr; IPropertyBag2* pProps = nullptr;
        if (FAILED(pEnc->CreateNewFrame(&pFrame, &pProps)) || !pFrame) {
            pEnc->Release(); pStream->Release(); pFact->Release(); break;
        }
        if (pProps) { pProps->Release(); pProps = nullptr; }
        HRESULT hr = pFrame->Initialize(nullptr);
        if (SUCCEEDED(hr)) hr = pFrame->SetSize(static_cast<UINT>(dw), static_cast<UINT>(dh));
        if (FAILED(hr)) { pFrame->Release(); pEnc->Release(); pStream->Release(); pFact->Release(); break; }
        WICPixelFormatGUID fmt = GUID_WICPixelFormat24bppBGR;
        if (FAILED(pFrame->SetPixelFormat(&fmt))) {
            pFrame->Release(); pEnc->Release(); pStream->Release(); pFact->Release(); break;
        }
        hr = pFrame->WritePixels(static_cast<UINT>(dh), stride, static_cast<UINT>(pixels.size()), pixels.data());
        if (SUCCEEDED(hr)) hr = pFrame->Commit();
        if (SUCCEEDED(hr)) hr = pEnc->Commit();
        if (SUCCEEDED(hr)) {
            HGLOBAL hg = nullptr;
            if (SUCCEEDED(GetHGlobalFromStream(pStream, &hg))) {
                SIZE_T sz = GlobalSize(hg); void* p = GlobalLock(hg);
                if (p && sz > 0) result.assign(static_cast<uint8_t*>(p), static_cast<uint8_t*>(p) + sz);
                GlobalUnlock(hg);
            }
        }
        pFrame->Release(); pEnc->Release(); pStream->Release(); pFact->Release();
    } while (false);
    return result;
}

struct sc_MonRect { int x, y, w, h; };
static BOOL CALLBACK sc_enumMonitor(HMONITOR, HDC, LPRECT r, LPARAM lp) {
    reinterpret_cast<std::vector<sc_MonRect>*>(lp)->push_back(
        { r->left, r->top, (int)(r->right - r->left), (int)(r->bottom - r->top) });
    return TRUE;
}

static std::vector<std::vector<uint8_t>> sc_captureAllScreens() {
    HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    bool comOwned = (hr == S_OK || hr == S_FALSE);
    if (FAILED(hr) && hr != RPC_E_CHANGED_MODE) return {};
    std::vector<sc_MonRect> mons;
    EnumDisplayMonitors(nullptr, nullptr, sc_enumMonitor, reinterpret_cast<LPARAM>(&mons));
    std::vector<std::vector<uint8_t>> result;
    if (mons.empty()) {
        auto s = sc_captureRectJpeg(GetSystemMetrics(SM_XVIRTUALSCREEN), GetSystemMetrics(SM_YVIRTUALSCREEN),
                                    GetSystemMetrics(SM_CXVIRTUALSCREEN), GetSystemMetrics(SM_CYVIRTUALSCREEN));
        if (!s.empty()) result.push_back(std::move(s));
    } else {
        for (auto& m : mons) { auto s = sc_captureRectJpeg(m.x, m.y, m.w, m.h); if (!s.empty()) result.push_back(std::move(s)); }
    }
    if (comOwned) CoUninitialize();
    return result;
}

static std::vector<std::vector<uint8_t>> sc_captureAllScreensCore() {
    std::vector<sc_MonRect> mons;
    EnumDisplayMonitors(nullptr, nullptr, sc_enumMonitor, reinterpret_cast<LPARAM>(&mons));
    std::vector<std::vector<uint8_t>> result;
    if (mons.empty()) {
        auto s = sc_captureRectJpeg(GetSystemMetrics(SM_XVIRTUALSCREEN), GetSystemMetrics(SM_YVIRTUALSCREEN),
                                    GetSystemMetrics(SM_CXVIRTUALSCREEN), GetSystemMetrics(SM_CYVIRTUALSCREEN));
        if (!s.empty()) result.push_back(std::move(s));
    } else {
        for (auto& m : mons) { auto s = sc_captureRectJpeg(m.x, m.y, m.w, m.h); if (!s.empty()) result.push_back(std::move(s)); }
    }
    return result;
}

static volatile LONG g_attachPollRunning = 1;

#ifdef WHIP_DEV_MODE
    #define WHIP_SERVER_PORT 7778
#else
    #define WHIP_SERVER_PORT 7777
#endif

#ifndef LOADER_IPC

static DWORD WINAPI UnloadThreadProc(LPVOID param) {
    HMODULE hModule = (HMODULE)param;
    Sleep(100);
    FreeLibraryAndExitThread(hModule, 0);
    return 0;
}
#endif

#ifdef LOADER_IPC
    #define CLIENT_DESTRUCT(ipcClient, reason, message) \
        do { \
            ClientMain::preUnloadStopThreads(); \
            ipcClient.sendDestruct(reason, message); \
            ipcClient.disconnect(); \
        } while(0)
#else
    #define CLIENT_DESTRUCT(ipcClient, reason, message) \
        do { \
            ClientMain::preUnloadStopThreads(); \
            Sleep(3000); \
            HMODULE hModule = ClientMain::getInstance().m_hModule; \
            HANDLE unloadThread = CreateThread(nullptr, 0, UnloadThreadProc, hModule, 0, nullptr); \
            CloseHandle(unloadThread); \
            debug_CloseConsole(); \
            ExitThread(0); \
        } while(0)
#endif

ClientMain::ClientMain()

    : m_jvm(nullptr)
      , m_env(nullptr)
      , m_securityThread(nullptr)
      , m_attachPollThread(nullptr)
      , m_mainThread(nullptr)
      , m_hModule(nullptr)
      , m_securityActiveEncoded(encodeSecurityFlag(0xFFu))
      , m_cleanupCalled(false)
      , m_authService(nullptr) {
}

ClientMain::~ClientMain() {
    cleanup();
}

void ClientMain::cleanup() {
    if (m_cleanupCalled) {
        return;
    }
    m_cleanupCalled = true;
}

#pragma optimize("", off)
bool ClientMain::initialize(HMODULE hModule) {
    m_hModule = hModule;
    m_mainThread = CreateThread(nullptr, 4 * 1024 * 1024, mainThreadProc, nullptr, 0, nullptr);
    if (m_mainThread != nullptr) {
        return true;
    }
    return false;
}

static bool sehSentinelInit() {
    __try {
        Sentinel::init();
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

static DWORD safeRecheck() {
    __try {
        Sentinel::recheck();
        return 0;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }
}

static DWORD safeTaint(unsigned char* data, unsigned int length) {
    __try {
        Sentinel::taint(data, length);
        return 0;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }
}

DWORD WINAPI ClientMain::mainThreadProc(LPVOID param) {
    (void)param;

#ifdef VMP
    VMProtectBeginUltra("MainThread");
#endif

    ad::spoof_my_ra();

    debug_Print("[MAIN] mainThreadProc start");

    ClientMain& client = getInstance();

#ifdef WHIP_DEV_MODE
    debug_CreateConsole();
#endif

    srand(static_cast<unsigned int>(time(nullptr)));

    debug_Print("[MAIN] SyscallManager::Init...");
    if (!SyscallManager::Init()) {
        debug_Print("[MAIN] FAIL: SyscallManager::Init");
        return 1;
    }
    debug_Print("[MAIN] SyscallManager::Init OK");

    sehSentinelInit();
    debug_Print("[MAIN] Sentinel init OK");

    debug_Print("[MAIN] Gui::start...");
    if (!Gui::getInstance().start()) {
        debug_Print("[MAIN] FAIL: Gui::start");
        MessageBoxA(nullptr, "Can't start the gui", "", 0);
        return 0;
    }
    debug_Print("[MAIN] Gui::start OK");

    debug_Print("[MAIN] setupJVM...");
    if (!client.setupJVM()) {
        debug_Print("[MAIN] FAIL: setupJVM");
        return 0;
    }
    debug_Print("[MAIN] setupJVM OK");

    char hwid[128] = {};
    HWIDDisplayInfo dispInfo = {};
    collectHwidWithInfo(hwid, sizeof(hwid), dispInfo);
    debug_Print("[MAIN] hwid collected gpu=%s cpu=%s ram=%s mobo=%s screen=%s storage=%s",
        dispInfo.gpuName, dispInfo.cpuBrand, dispInfo.ramHex,
        dispInfo.boardModel, dispInfo.screenInfo, dispInfo.storageInfo);

    LoaderIpcClient ipcClient;
#ifdef LOADER_IPC
    debug_Print("[MAIN] IPC: initialize...");
    if (auto ipcInitResult = ipcClient.initialize(); !ipcInitResult.isOk()) {
        debug_Print("[MAIN] FAIL: ipcClient.initialize");
        return 0;
    }
    debug_Print("[MAIN] IPC: initialize OK");

    uint16_t ipcPort = 47832;
    debug_Print("[MAIN] IPC: connect port=%u...", (unsigned)ipcPort);
    if (auto ipcConnectResult = ipcClient.connect("127.0.0.1", ipcPort); !ipcConnectResult.isOk()) {
        debug_Print("[MAIN] FAIL: ipcClient.connect port=%u", (unsigned)ipcPort);
        return 0;
    }
    debug_Print("[MAIN] IPC: connect OK");

    debug_Print("[MAIN] IPC: receiveConfig (10s timeout)...");
    auto configResult = ipcClient.receiveConfig(10000);
    if (!configResult.isOk()) {
        debug_Print("[MAIN] FAIL: receiveConfig");
        ipcClient.sendDestruct(ClientDestructReason::Error, "Failed to receive loader config");
        ipcClient.disconnect();
        return 0;
    }
    debug_Print("[MAIN] IPC: receiveConfig OK");

    const LoaderConfig& config = configResult.value();
    debug_Print("[MAIN] config: server=%s port=%u loaderAuthTag=0x%llX",
        config.serverHost.c_str(), (unsigned)config.serverPort, (unsigned long long)config.loaderAuthTag);
    debug_Print("[MAIN] config: token[0..3]=%02X%02X%02X%02X",
        config.temporaryClientToken.data[0], config.temporaryClientToken.data[1],
        config.temporaryClientToken.data[2], config.temporaryClientToken.data[3]);

    ipcClient.sendLoadProgress(ClientLoadStage::Start, "Client starting", 0);

    client.m_authService = (WhipAuthService*)SyscallManager::GetWrappers()->HeapAlloc(sizeof(WhipAuthService));
    if (client.m_authService) new (client.m_authService) WhipAuthService(config.serverHost.c_str(), config.serverPort);

    char pcName[256];
    DWORD pcNameLen = 256;
    GetComputerNameA(pcName, &pcNameLen);
    debug_Print("[MAIN] pcName=%s", pcName);

    wchar_t exePath[MAX_PATH];
    char exePathUtf8[MAX_PATH * 3];
    if (GetModuleFileNameW(nullptr, exePath, MAX_PATH) > 0) {
        WideCharToMultiByte(CP_UTF8, 0, exePath, -1, exePathUtf8, sizeof(exePathUtf8), nullptr, nullptr);
    } else {
        exePathUtf8[0] = 'U'; exePathUtf8[1] = 'n'; exePathUtf8[2] = 'k'; exePathUtf8[3] = 'n';
        exePathUtf8[4] = 'o'; exePathUtf8[5] = 'w'; exePathUtf8[6] = 'n'; exePathUtf8[7] = '\0';
    }

    debug_Print("[MAIN] exePath=%s", exePathUtf8);
    debug_Print("[MAIN] Sentinel::recheck...");
    DWORD recheckEx = safeRecheck();
    if (recheckEx) debug_Print("[MAIN] Sentinel::recheck EXCEPTION 0x%08X", recheckEx);
    debug_Print("[MAIN] Sentinel::recheck done");

    debug_Print("[MAIN] Sentinel::taint...");
    DWORD taintEx = safeTaint(reinterpret_cast<uint8_t*>(const_cast<Byte*>(config.temporaryClientToken.data)), 32);
    if (taintEx) debug_Print("[MAIN] Sentinel::taint EXCEPTION 0x%08X", taintEx);
    debug_Print("[MAIN] Sentinel::taint done");
    debug_Print("[MAIN] authenticateWithToken...");
    if (auto authResult = client.m_authService->authenticateWithToken(config.temporaryClientToken.data, config.clientAttestationKey.data, config.loaderAuthTag, config.hwid.c_str(), pcName, exePathUtf8); !authResult.isOk()) {
        debug_Print("[MAIN] FAIL: authenticateWithToken");
        ipcClient.sendLoadProgress(ClientLoadStage::Auth, "Authentication failed", 0);
        ipcClient.sendDestruct(ClientDestructReason::Error, "Authentication failed");
        ipcClient.disconnect();
        return 0;
    }
    debug_Print("[MAIN] authenticateWithToken OK");
    ipcClient.sendLoadProgress(ClientLoadStage::Auth, "Authenticated", 20);

#else
    client.m_authService = (WhipAuthService*)SyscallManager::GetWrappers()->HeapAlloc(sizeof(WhipAuthService));
    if (client.m_authService) new (client.m_authService) WhipAuthService(Strings::authServerIP(), WHIP_SERVER_PORT);

    MachineInfo machine;
    machine.hwid.set(hwid);
    char pcName[256];
    DWORD pcNameLen = 256;
    GetComputerNameA(pcName, &pcNameLen);
    machine.pcName.set(pcName);
    machine.os.set("Windows");
    machine.gpuName.set(dispInfo.gpuName);
    machine.cpuBrand.set(dispInfo.cpuBrand);
    machine.ramHex.set(dispInfo.ramHex);
    machine.boardModel.set(dispInfo.boardModel);
    machine.screenInfo.set(dispInfo.screenInfo);
    machine.storageInfo.set(dispInfo.storageInfo);

    wchar_t exePath[MAX_PATH];
    char exePathUtf8[MAX_PATH * 3];
    if (GetModuleFileNameW(nullptr, exePath, MAX_PATH) > 0) {
        WideCharToMultiByte(CP_UTF8, 0, exePath, -1, exePathUtf8, sizeof(exePathUtf8), nullptr, nullptr);
        machine.executablePath.set(exePathUtf8);
    } else {
        machine.executablePath.set("Unknown");
    }

    AuthPayload payload;
    payload.machine = machine;
    payload.timestamp = time(nullptr);

    if (auto authResult = client.m_authService->authenticate(payload); !authResult.isOk()) {
        CLIENT_DESTRUCT(ipcClient, ClientDestructReason::Error, "Authentication failed");
        return 0;
    }
#endif

    auto versionsResult = client.m_authService->requestVersions();
    if (!versionsResult.isOk()) {
        CLIENT_DESTRUCT(ipcClient, ClientDestructReason::Error, "Versions download failed");
        return 0;
    }

    if (const String& versionsData = versionsResult.value(); !VersionHandler::getInstance().parseAndRegisterVersions(versionsData.data, versionsData.length)) {
        CLIENT_DESTRUCT(ipcClient, ClientDestructReason::Error, "Failed to parse versions");
        return 0;
    }

#ifdef LOADER_IPC
    ipcClient.sendLoadProgress(ClientLoadStage::Versions, "Versions loaded", 40);
#endif
    if (!client.detectVersion()) {
        CLIENT_DESTRUCT(ipcClient, ClientDestructReason::Error, "Version detection failed");
        return 0;
    }

    if (const int versionKey = VersionDetector::detectCurrentVersion(client.m_env); versionKey == -1) {
        CLIENT_DESTRUCT(ipcClient, ClientDestructReason::Error, "Unknown Minecraft version");
        return 0;
    }
    MinecraftVersion mcVersion = MinecraftSession::getInstance().version;
    MinecraftLauncher mcLauncher = MinecraftSession::getInstance().launcher;
    const char* versionStr = minecraftVersionToString(mcVersion);
    const char* platformStr = minecraftLauncherToString(mcLauncher);

#if defined(WHIP_DEV_MODE) && !defined(LOADER_IPC)
    {
        char localPath[MAX_PATH];
        snprintf(localPath, sizeof(localPath),
                 "C:/Users/Java/Desktop/whip/WhipBin/out/%s/%s.wbin",
                 versionStr, platformStr);
        FILE* f = nullptr;
        if (fopen_s(&f, localPath, "rb") == 0 && f) {
            fseek(f, 0, SEEK_END);
            long size = ftell(f);
            fseek(f, 0, SEEK_SET);
            if (size > 0) {
                auto* buf = static_cast<unsigned char*>(malloc(static_cast<size_t>(size)));
                if (buf && fread(buf, 1, static_cast<size_t>(size), f) == static_cast<size_t>(size)) {
                    fclose(f);
                    if (!client.setupMappings(buf, static_cast<size_t>(size))) {
                        free(buf);
                        CLIENT_DESTRUCT(ipcClient, ClientDestructReason::Error, "Local mappings failed to register");
                        return 0;
                    }
                    free(buf);
                    goto mappings_loaded;
                }
                if (buf) free(buf);
            }
            fclose(f);
        }
    }
#endif

    {
        auto mappingsResult = client.m_authService->requestMappings(versionStr, platformStr);
        if (!mappingsResult.isOk()) {
            CLIENT_DESTRUCT(ipcClient, ClientDestructReason::Error, "Mappings download failed");
            return 0;
        }

        if (const String& mappingsData = mappingsResult.value(); !client.setupMappings((byte*)mappingsData.data, mappingsData.length)) {
            CLIENT_DESTRUCT(ipcClient, ClientDestructReason::Error, "Failed to register mappings");
            return 0;
        }
    }

#if defined(WHIP_DEV_MODE) && !defined(LOADER_IPC)
mappings_loaded:;
#endif

#ifdef LOADER_IPC
    ipcClient.sendLoadProgress(ClientLoadStage::Mappings, "Mappings loaded", 60);
#endif

    char username[32] = {};
    char uuid[36] = {};
    client.extractPlayerInfo(username, uuid);

    {
        char pcName[256] = {};
        DWORD pcNameLen = sizeof(pcName);
        GetComputerNameA(pcName, &pcNameLen);
        auto machineInfoResult = client.m_authService->sendMachineInfo(username, pcName);
        if (!machineInfoResult.isOk()) {
        }
    }

    if (!client.registerHooks()) {
        CLIENT_DESTRUCT(ipcClient, ClientDestructReason::Error, "Hook registration failed");
        return 0;
    }

    if (MinecraftSession::getInstance().launcher == MinecraftLauncher::L_CHEATBREAKER) {
        if (jclass sysCls = client.m_env->FindClass("java/lang/System")) {
            if (jmethodID gcId = client.m_env->GetStaticMethodID(sysCls, "gc", "()V")) {
                client.m_env->CallStaticVoidMethod(sysCls, gcId);
                if (client.m_env->ExceptionCheck()) client.m_env->ExceptionClear();
            }
            client.m_env->DeleteLocalRef(sysCls);
        }
        Sleep(500);
    }

#ifdef LOADER_IPC
    ipcClient.sendLoadProgress(ClientLoadStage::Hooks, "Hooks registered", 80);
#endif
    if (auto initialHeartbeatResult = client.m_authService->sendHeartbeat(); !initialHeartbeatResult.isOk()) {
        CLIENT_DESTRUCT(ipcClient, ClientDestructReason::Error, "Initial heartbeat failed");
        return 0;
    }

    if (!client.m_authService->getClient()->startEventLoop()) {
        CLIENT_DESTRUCT(ipcClient, ClientDestructReason::Error, "Failed to start event loop");
        return 0;
    }

    client.m_authService->startHeartbeatLoop(30);

    client.m_securityActiveEncoded = encodeSecurityFlag(0u);
    client.m_securityThread = CreateThread(nullptr, 0, securityMonitorProc, &client, 0, nullptr);
    if (client.m_securityThread) {
    }

    client.m_attachPollThread = CreateThread(nullptr, 0, attachInstantPollProc, &client, 0, nullptr);
    if (client.m_attachPollThread) {
    }

    client.initializeTasks();
    client.loadModulesAndProviders();

    HookHandler::getInstance().enableAll();

#ifdef LOADER_IPC
    ipcClient.sendLoadProgress(ClientLoadStage::Complete, "Client loaded", 100);
#endif

    client.runMainLoop();

    Gui& gui = Gui::getInstance();
    gui.enableGui = false;

    gui.safeUnload();

    HookHandler::getInstance().suspendAll();

    ModuleHandler::getInstance().unload();

    ProviderHandler::getInstance().unload();

    SettingsHandler::getInstance().cleanup();

    BindManager::getInstance().cleanup();

    TaskHandler& taskHandler = TaskHandler::getInstance();
    taskHandler.stopAllTasks();

    taskHandler.cleanupJniSupport();

    HookHandler::getInstance().cleanup();

    client.m_securityActiveEncoded = encodeSecurityFlag(0xFFu);
    if (client.m_securityThread) {
        DWORD waitResult = WaitForSingleObject(client.m_securityThread, 10000);
        if (waitResult == WAIT_TIMEOUT) {
            TerminateThread(client.m_securityThread, 1);
        }
        CloseHandle(client.m_securityThread);
        client.m_securityThread = nullptr;
    }

    if (client.m_attachPollThread) {
        InterlockedExchange(&g_attachPollRunning, 0);
        DWORD waitResult = WaitForSingleObject(client.m_attachPollThread, 2000);
        if (waitResult == WAIT_TIMEOUT) {
            TerminateThread(client.m_attachPollThread, 1);
        }
        CloseHandle(client.m_attachPollThread);
        client.m_attachPollThread = nullptr;
    }

    Mappings::getInstance().clearMappings();

    VersionHandler::getInstance().clearVersions();

    ConfigManager::getInstance().secureCleanup();
    EventBus::getInstance().clear();
    ModuleHandler::getInstance().clear();
    ProviderHandler::getInstance().clear();

    if (client.m_jvm != nullptr) {
        client.m_jvm->DetachCurrentThread();
    }

    gui.stop();
    ModuleConfigRegistry::getInstance().clear();
    TrackedStringRegistry::instance().clearAll();

    if (client.m_authService) {
        client.m_authService->logout();
        client.m_authService->getClient()->stopEventLoop();
        client.m_authService->~WhipAuthService();
        SyscallManager::GetWrappers()->HeapFree(client.m_authService);
        client.m_authService = nullptr;
    }

    Sentinel::cleanup();

    CLIENT_DESTRUCT(ipcClient, ClientDestructReason::User, "Client shutting down");

    debug_CloseConsole();

#ifdef VMP
    VMProtectEnd();
#endif

    ExitThread(0);
}

void ClientMain::runMainLoop() {
    Gui& gui = Gui::getInstance();
    gui.setScreen(MODULE);
    gui.enableGui = true;
    gui.hideBind0 = VK_F4;

    static_cast<NotificationModule*>(ModuleHandler::getInstance().getModule<ModuleType::NOTIFICATION>())->addMessageNotificationForced(
        Strings::msgPressF4ToOpenGui(), ImColor(135, 206, 235, 255)
    );

    while (!gui.hasRequestUnload()) {
        if (m_authService && !m_authService->isAuthenticated()) {
            break;
        }
    }
}

bool ClientMain::loadModulesAndProviders() {
    ModuleHandler::getInstance().load();
    ProviderHandler::getInstance().load();
    return true;
}

bool ClientMain::initializeTasks() const {
    TaskHandler& taskHandler = TaskHandler::getInstance();
    taskHandler.initializeJniSupport(m_jvm);
    taskHandler.addTask(std::make_unique<InputTask>());
    taskHandler.addTask(std::make_unique<UpdateTask>());
    taskHandler.startAllTasks();
    return true;
}

bool ClientMain::registerHooks() {
    HookHandler& hookHandler = HookHandler::getInstance();

    hookHandler.registerHook(std::make_unique<AttackTargetEntityHook>());
    hookHandler.registerHook(std::make_unique<OnLivingUpdateHook>());
    hookHandler.registerHook(std::make_unique<RenderNameHook>());
    hookHandler.registerHook(std::make_unique<ChannelReadHook>());
    hookHandler.registerHook(std::make_unique<AddSendQueueHook>());
    hookHandler.registerHook(std::make_unique<ClickMouseHook>());
    hookHandler.registerHook(std::make_unique<GetSlotAtPositionHook>());
    hookHandler.registerHook(std::make_unique<OnRunTick>());
    hookHandler.registerHook(std::make_unique<OnUpdateWalkingPlayerHook>());
    hookHandler.registerHook(std::make_unique<KeyBindingIsPressed>());
    hookHandler.registerHook(std::make_unique<GetMouseOverHook>());

    hookHandler.registerHook(std::make_unique<RenderEntitySimpleHook>());
    hookHandler.registerHook(std::make_unique<RenderHandHook>());
    hookHandler.registerHook(std::make_unique<OrientCameraHook>());

    if (MinecraftSession::getInstance().version == MinecraftVersion::V1_8_9) {
        hookHandler.registerHook(std::make_unique<ClickBlockMouseHook>());
        hookHandler.registerHook(std::make_unique<PredictateApplyHook>());
    } else {
        hookHandler.registerHook(std::make_unique<CanBeCollidedWithHook>());
    }

    return hookHandler.initializeHooks(m_env);
}

bool ClientMain::setupMappings(const unsigned char* wbinData, size_t wbinSize) const {
    Version foundVersion = {};
    bool versionFound = VersionHandler::getInstance().findVersion(m_env, &foundVersion);
    return setupMappings(wbinData, wbinSize, foundVersion.classResolvingMethod);
}

bool ClientMain::setupMappings(const unsigned char* wbinData, size_t wbinSize,
                                ClassResolvingMethod method) const {

    Mappings::getInstance().setEnv(m_env);
    Mappings::getInstance().setMethod(method);

    if (!Mappings::getInstance().registerMappingsFromWbin(wbinData, wbinSize)) {
        return false;
    }

    JavaObject::setMappings(&Mappings::getInstance());
    return true;
}

bool ClientMain::extractPlayerInfo(char* username, char* uuid) const {
#ifdef VMP
    VMProtectBeginUltra("clientMain_extractPlayerInfo");
#endif
    const char* playerInfo = getMinecraftPlayerInfo(m_env);

    if (!playerInfo || strcmp(playerInfo, "n/a:n/a") == 0) {
        return false;
    }

    const char* colonPos = strchr(playerInfo, ':');
    if (!colonPos) {
        return false;
    }

    size_t usernameLen = colonPos - playerInfo;
    if (usernameLen >= 32) {
        return false;
    }

    strncpy(username, playerInfo, usernameLen);
    username[usernameLen] = '\0';
    strncpy(uuid, colonPos + 1, 35);
    uuid[35] = '\0';

    return true;
#ifdef VMP
    VMProtectEnd();
#endif
}

bool ClientMain::detectVersion() const {
    Version foundVersion = {};
    if (!VersionHandler::getInstance().findVersion(m_env, &foundVersion)) {
        return false;
    }

    MinecraftSession::getInstance().version = foundVersion.minecraftVersion;
    MinecraftSession::getInstance().launcher = foundVersion.minecraftLauncher;

    const int versionKey = VersionDetector::detectCurrentVersion(m_env);
    if (versionKey == -1) {
    }
    return versionKey != -1;
}

bool ClientMain::setupJVM() {
    jsize size = 0;
    if (JNI_GetCreatedJavaVMs(&m_jvm, 1, &size) != JNI_OK) {
        return false;
    }

    if (m_jvm->AttachCurrentThread((void**)&m_env, nullptr) != JNI_OK) {
        return false;
    }

    Gui::getInstance().setJVM(m_jvm);
    return true;
}

void ClientMain::preUnloadStopThreads() {
    Gui::getInstance().stop();

    ClientMain& client = getInstance();

    if (client.m_authService) {
        client.m_authService->stopHeartbeatLoop();
        client.m_authService->getClient()->stopEventLoop();
    }

    if (client.m_securityThread) {
        client.m_securityActiveEncoded = encodeSecurityFlag(0xFFu);
        DWORD waitResult = WaitForSingleObject(client.m_securityThread, 1000);
        if (waitResult == WAIT_TIMEOUT) {
            TerminateThread(client.m_securityThread, 1);
        } else {
        }
        CloseHandle(client.m_securityThread);
        client.m_securityThread = nullptr;
    }

    if (client.m_attachPollThread) {
        InterlockedExchange(&g_attachPollRunning, 0);
        DWORD waitResult = WaitForSingleObject(client.m_attachPollThread, 1000);
        if (waitResult == WAIT_TIMEOUT) {
            TerminateThread(client.m_attachPollThread, 1);
        }
        CloseHandle(client.m_attachPollThread);
        client.m_attachPollThread = nullptr;
    }

}

DWORD WINAPI ClientMain::securityMonitorProc(LPVOID param) {
#ifdef VMP
    VMProtectBeginUltra("SecurityMonitor");
#endif

    auto* client = static_cast<ClientMain*>(param);
    static char reportBuf[4096];
    Security extScanner;

    HRESULT hrCom  = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    bool comOwned  = (hrCom == S_OK || hrCom == S_FALSE);
    bool comReady  = (hrCom == S_OK || hrCom == S_FALSE || hrCom == RPC_E_CHANGED_MODE);

    std::vector<std::vector<uint8_t>> lastShots;

    while (decodeSecurityIsActive(client->m_securityActiveEncoded)) {
        if (comReady) lastShots = sc_captureAllScreensCore();

        Sentinel::recheck();
        Sentinel::verify();
        extScanner.exe_detect();
        extScanner.title_detect();
        extScanner.hw_breakpoint_detect();
        extScanner.kernel_debugger_detect();

        if (client->m_authService && client->m_authService->isAuthenticated()) {
            uint32_t score = 0, checksRun = 0, checksHit = 0, checkMask = 0, flags = 0;
            if (Sentinel::consumeReport(reportBuf, sizeof(reportBuf),
                                        &score, &checksRun, &checksHit, &checkMask, &flags)) {
                client->m_authService->sendReverseDetected(score, checksRun, checksHit,
                                                           checkMask, flags, reportBuf, &lastShots);
            }

            char extName[64];
            if (Security::ConsumeExternalDetection(extName, sizeof(extName))) {
                char synth[256];
                _snprintf_s(synth, sizeof(synth), _TRUNCATE,
                            "External tooling detected: %s\n", extName);
                client->m_authService->sendReverseDetected(100, 1, 1, 0, 0, synth, &lastShots);
            }
        }

        Sleep(3000 + (rand() % 5001));
    }

    if (comOwned) CoUninitialize();

#ifdef VMP
    VMProtectEnd();
#endif
    return 0;
}
#pragma optimize("", on)

DWORD WINAPI ClientMain::attachInstantPollProc(LPVOID param) {
#ifdef VMP
    VMProtectBeginUltra("AttachInstantPoll");
#endif
    auto* client = static_cast<ClientMain*>(param);
    static char reportBuf[4096];

    while (g_attachPollRunning) {
        uint32_t reason = 0;
        bool latched = Sentinel::pollInstantAttach(&reason);
        if (latched && client->m_authService && client->m_authService->isAuthenticated()) {
            auto shots = sc_captureAllScreens();
            uint32_t score = 0, checksRun = 0, checksHit = 0, checkMask = 0, flags = 0;
            if (Sentinel::consumeReport(reportBuf, sizeof(reportBuf),
                                        &score, &checksRun, &checksHit, &checkMask, &flags)) {
                client->m_authService->sendReverseDetected(score, checksRun, checksHit,
                                                           checkMask, flags, reportBuf, &shots);
            }
        }

        Sleep(50 + (rand() % 101));
    }
#ifdef VMP
    VMProtectEnd();
#endif
    return 0;
}

ClientMain& ClientMain::getInstance() {
    static ClientMain instance;
    return instance;
}
