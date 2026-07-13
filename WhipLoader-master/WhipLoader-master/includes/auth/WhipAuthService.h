#pragma once
#include "auth/Credentials.h"
#include "auth/Session.h"
#include "util/Result.h"
#include <windows.h>

#ifdef VMP
#include "VMProtectSDK.h"
#endif

#pragma optimize("", off)

class IHWIDCollector;
class WhipNexusClient;

typedef void (*OnAuthSuccess)(const SessionInfo* session);
typedef void (*OnAuthFailure)(const Error* error);
typedef void (*SessionExpiredCallback)();

class WhipAuthService {
public:
    WhipAuthService(const char* host, u16 port, IHWIDCollector* hwidCollector);
    ~WhipAuthService();

    WhipAuthService(const WhipAuthService&) = delete;
    WhipAuthService& operator=(const WhipAuthService&) = delete;

    [[nodiscard]] VoidResult authenticate(const AuthPayload& payload);

    void authenticateAsync(
        const AuthPayload& payload,
        OnAuthSuccess onSuccess,
        OnAuthFailure onFailure
    );

    [[nodiscard]] bool isAuthenticated() const;
    [[nodiscard]] const SessionInfo* currentSession() const;

    [[nodiscard]] VoidResult sendHeartbeat();
    void startHeartbeatLoop(u32 intervalMs);
    void stopHeartbeatLoop();

    void logout();
    void setOnSessionExpired(SessionExpiredCallback cb);

    __forceinline WhipNexusClient* getClient() const { return client_; }

private:
    char serverHost_[256];
    u16 serverPort_;
    IHWIDCollector* hwidCollector_;

    WhipNexusClient* client_;
    SessionManager sessionManager_;

    char pcName_[128];
    char executablePath_[512];

    volatile LONG heartbeatRunning_;
    HANDLE heartbeatThread_;
    u32 heartbeatIntervalMs_;
    SessionExpiredCallback onSessionExpired_;

    static DWORD WINAPI heartbeatWorkerProc(LPVOID param);
    VoidResult performFullAuthentication(const AuthPayload& payload);
};

#pragma optimize("", on)
