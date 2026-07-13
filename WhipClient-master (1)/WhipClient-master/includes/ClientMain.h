#ifndef CLIENTMAIN_H
#define CLIENTMAIN_H

#include "auth/version/VersionDetector.h"
#include "auth/service/WhipAuthService.h"
#include "bus/EventBus.h"
#include "gui/Gui.h"
#include "manager/ConfigManager.h"
#include "handler/SettingsHandler.h"
#include "util/MinecraftDetails.h"

class ClientMain {
public:
    static ClientMain& getInstance();

    bool initialize(HMODULE hModule);

    WhipAuthService* getAuthService() const { return m_authService; }

    ClientMain(const ClientMain&) = delete;
    ClientMain& operator=(const ClientMain&) = delete;

private:
    ClientMain();
    ~ClientMain();

    void cleanup();

    bool setupJVM();
    bool detectVersion() const;
    bool setupMappings(const unsigned char* wbinData, size_t wbinSize) const;

    bool setupMappings(const unsigned char* wbinData, size_t wbinSize,
                       ClassResolvingMethod method) const;
    bool extractPlayerInfo(char* username, char* uuid) const;
    bool registerHooks();
    bool initializeTasks() const;

    static bool loadModulesAndProviders();

    void runMainLoop();

    static DWORD WINAPI mainThreadProc(LPVOID param);
    static DWORD WINAPI securityMonitorProc(LPVOID param);

    static DWORD WINAPI attachInstantPollProc(LPVOID param);

    static void preUnloadStopThreads();

    JavaVM* m_jvm;
    JNIEnv* m_env;
    HANDLE m_securityThread;
    HANDLE m_attachPollThread;
    HANDLE m_mainThread;
    HMODULE m_hModule;

    uint64_t m_securityActiveEncoded;
    bool m_cleanupCalled;
    WhipAuthService* m_authService;
};

#endif
