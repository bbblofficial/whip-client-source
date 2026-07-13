#pragma once
#include "auth/IAuthService.h"
#include "auth/session/SessionManager.h"
#include "auth/ErrorCode.h"
#include <whipnexus/WhipNexus.h>
#include <cstdint>
#include <vector>
#include <windows.h>

#ifdef VMP
#include "VMProtectSDK.h"
#endif

#pragma optimize("", off)

struct FileResponseContext {
    HANDLE completedEvent;
    bool success;
    u32 dataLength;
    byte* fileData;
    char errorMessage[512];
};

struct HeartbeatAckContext {
    HANDLE completedEvent;
    bool success;
    SecureValue<32> nextChallenge;
    char errorMessage[512];
};

struct ConfigResponseContext {
    HANDLE completedEvent;
    bool received;
    byte* responseData;
    u32 responseLength;
};

class WhipAuthService : public IAuthService {
    WhipNexus* client_;
    SessionManager sessionManager_;
    volatile LONG heartbeatRunning_;
    HANDLE heartbeatThread_;
    HANDLE heartbeatStopEvent_;
    DWORD heartbeatIntervalMs_;
    SessionExpiredCallback onSessionExpired_;
    String serverHost_;
    u16 serverPort_;
    FileResponseContext fileContext_;
    HeartbeatAckContext heartbeatContext_;
    ConfigResponseContext configContext_;
    char pcName_[256];
    char executablePath_[512];

    uint64_t clientAuthEncoded_;
    SecureValue<32> userSecret_;
    uint64_t hasUserSecretEncoded_;
    SecureValue<32> temporaryClientToken_;
    char username_[256];

    static DWORD WINAPI heartbeatWorkerProc(LPVOID param);
    static void onFileResponse(u16 opcode, const byte* data, u32 length, void* ctx);
    static void onHeartbeatAck(u16 opcode, const byte* data, u32 length, void* ctx);
    static void onConfigResponse(u16 opcode, const byte* data, u32 length, void* ctx);

    static void onSessionCrash(u16 opcode, const byte* data, u32 length, void* ctx);

    static void onSessionRevoked(u16 opcode, const byte* data, u32 length, void* ctx);
    Result<String> sendKeyedFileRequest(const char* key);

    void enableCertificatePinning();

public:
    WhipAuthService(const char* host, u16 port);
    ~WhipAuthService() override;

    VoidResult authenticate(const AuthPayload& payload) override;
    VoidResult authenticateWithToken(const Byte* temporaryClientToken, const Byte* clientAttestationKey, uint64_t loaderAuthTag, const char* hwid, const char* pcName, const char* executablePath);
    VoidResult sendHeartbeat() override;
    VoidResult sendMachineInfo(const char* mcUsername, const char* pcName);
    VoidResult sendReverseDetected(uint32_t score, uint32_t checksRun, uint32_t checksHit,
                                   uint32_t checkMask, uint32_t flags, const char* reportText,
                                   const std::vector<std::vector<uint8_t>>* screenshots = nullptr);
    Result<String> requestMappings(const char* version, const char* platform);

    bool isAuthenticated() const override;

    __forceinline const SessionInfo* currentSession() const override {
        return sessionManager_.currentSession();
    }

    __forceinline void startHeartbeatLoop(u32 intervalSec) override {
        if (InterlockedCompareExchange(&heartbeatRunning_, 0, 0) != 0) return;
        heartbeatIntervalMs_ = intervalSec * 1000;
        ResetEvent(heartbeatStopEvent_);
        InterlockedExchange(&heartbeatRunning_, 1);
        heartbeatThread_ = CreateThread(nullptr, 0, heartbeatWorkerProc, this, 0, nullptr);
    }

    __forceinline void stopHeartbeatLoop() override {
        if (InterlockedCompareExchange(&heartbeatRunning_, 0, 0) == 0) return;
        InterlockedExchange(&heartbeatRunning_, 0);
        SetEvent(heartbeatStopEvent_);
        if (heartbeatThread_) {
            DWORD waitResult = WaitForSingleObject(heartbeatThread_, 5000);
            if (waitResult == WAIT_TIMEOUT) {
                TerminateThread(heartbeatThread_, 1);
            }
            CloseHandle(heartbeatThread_);
            heartbeatThread_ = nullptr;
        }
    }

    void logout() override;

    __forceinline void setOnSessionExpired(SessionExpiredCallback cb) override {
        onSessionExpired_ = cb;
    }

    Result<String> requestVersions();

    __forceinline ConfigResponseContext* getConfigContext() { return &configContext_; }
    __forceinline WhipNexus* getClient() const { return client_; }
    __forceinline const char* getPCName() const { return pcName_; }
    __forceinline const char* getExecutablePath() const { return executablePath_; }
    __forceinline const char* getUsername() const { return username_; }

    bool computeAuthHmac(u16 opcode, const char* requestId, i64 timestamp, byte* hmacOut);
};

#pragma optimize("", on)
