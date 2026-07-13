#pragma optimize("", off)
#include "auth/WhipAuthService.h"
#include "network/WhipNexusClient.h"

#ifdef VMP
#include "VMProtectSDK.h"
#endif

#include "antidebug/stack/stack_cpp.hpp"

WhipAuthService::WhipAuthService(const char* host, u16 port, IHWIDCollector* hwidCollector)
    : serverPort_(port), hwidCollector_(hwidCollector), client_(nullptr),
      heartbeatRunning_(0), heartbeatThread_(nullptr), heartbeatIntervalMs_(30000),
      onSessionExpired_(nullptr) {
#ifdef VMP
    VMProtectBeginUltra("WhipAuthService_ctor");
#endif
    authStrCopy(serverHost_, host, sizeof(serverHost_));
    pcName_[0] = '\0';
    executablePath_[0] = '\0';

#ifdef VMP
    VMProtectEnd();
#endif
}

WhipAuthService::~WhipAuthService() {
#ifdef VMP
    VMProtectBeginUltra("WhipAuthService_dtor");
#endif
    stopHeartbeatLoop();
    logout();

    if (client_) {
        delete client_;
        client_ = nullptr;
    }

#ifdef VMP
    VMProtectEnd();
#endif
}

VoidResult WhipAuthService::authenticate(const AuthPayload& payload) {
#ifdef VMP
    VMProtectBeginUltra("WhipAuthService_authenticate");
#endif

    if (!payload.isValid()) {
        return VoidResult::err(ErrorCode::InvalidArgument, "Invalid auth payload");
    }

    auto result = performFullAuthentication(payload);
    if (!result.isOk()) {
        return result;
    }

    if (!sessionManager_.hasActiveSession()) {
        return VoidResult::err(ErrorCode::AuthError, "Authentication succeeded but session was not created");
    }

    return VoidResult::ok();

#ifdef VMP
    VMProtectEnd();
#endif
}

void WhipAuthService::authenticateAsync(
    const AuthPayload& payload,
    OnAuthSuccess onSuccess,
    OnAuthFailure onFailure
) {
#ifdef VMP
    VMProtectBeginUltra("WhipAuthService_authenticateAsync");
#endif

    auto result = authenticate(payload);
    if (result.isOk() && onSuccess && sessionManager_.hasActiveSession()) {
        onSuccess(&sessionManager_.currentSession());
    } else if (!result.isOk() && onFailure) {
        onFailure(&result.error());
    }

#ifdef VMP
    VMProtectEnd();
#endif
}

bool WhipAuthService::isAuthenticated() const {
#ifdef VMP
    VMProtectBeginUltra("WhipAuthService_isAuthenticated");
#endif

    bool result = client_ && client_->isAuthenticated() && sessionManager_.hasActiveSession();

#ifdef VMP
    VMProtectEnd();
#endif

    return result;
}

const SessionInfo* WhipAuthService::currentSession() const {
#ifdef VMP
    VMProtectBeginUltra("WhipAuthService_currentSession");
#endif

    if (!sessionManager_.hasActiveSession()) return nullptr;

#ifdef VMP
    VMProtectEnd();
#endif

    return &sessionManager_.currentSession();
}

void WhipAuthService::logout() {
#ifdef VMP
    VMProtectBeginUltra("WhipAuthService_logout");
#endif

    stopHeartbeatLoop();

    if (client_ && client_->isAuthenticated()) {
        client_->disconnect();
    }

    sessionManager_.destroySession();

#ifdef VMP
    VMProtectEnd();
#endif
}

VoidResult WhipAuthService::sendHeartbeat() {
#ifdef VMP
    VMProtectBeginUltra("WhipAuthService_sendHeartbeat");
#endif
    ad::StackHidden _ad_guard;  // moonwalk: caller frame's RA -> ntdll decoy

    if (!sessionManager_.hasActiveSession()) {
        return VoidResult::err(ErrorCode::SessionInvalid, "No active session");
    }

    auto result = client_->sendHeartbeat(pcName_, executablePath_);
    if (!result.isOk()) {

        if (sessionManager_.hasActiveSession()) {
            sessionManager_.destroySession();

            if (onSessionExpired_) {
                onSessionExpired_();
            }
        }

        return result;
    }

    sessionManager_.updateHeartbeat(nullptr);

#ifdef VMP
    VMProtectEnd();
#endif

    return VoidResult::ok();
}

DWORD WINAPI WhipAuthService::heartbeatWorkerProc(LPVOID param) {
#ifdef VMP
    VMProtectBeginUltra("WhipAuthService_heartbeatWorkerProc");
#endif

    auto* self = static_cast<WhipAuthService*>(param);

    while (InterlockedCompareExchange(&self->heartbeatRunning_, 1, 1) == 1) {
        Sleep(self->heartbeatIntervalMs_);

        if (InterlockedCompareExchange(&self->heartbeatRunning_, 1, 1) != 1) break;

        if (!self->sessionManager_.hasActiveSession()) {
            break;
        }

        auto result = self->sendHeartbeat();
        if (!result.isOk()) {
            break;
        }
    }

    InterlockedExchange(&self->heartbeatRunning_, 0);

#ifdef VMP
    VMProtectEnd();
#endif

    return 0;
}

void WhipAuthService::startHeartbeatLoop(u32 intervalMs) {
#ifdef VMP
    VMProtectBeginUltra("WhipAuthService_startHeartbeatLoop");
#endif

    if (InterlockedCompareExchange(&heartbeatRunning_, 0, 0) != 0) return;

    heartbeatIntervalMs_ = intervalMs;
    InterlockedExchange(&heartbeatRunning_, 1);
    heartbeatThread_ = CreateThread(nullptr, 0, heartbeatWorkerProc, this, 0, nullptr);

#ifdef VMP
    VMProtectEnd();
#endif
}

void WhipAuthService::stopHeartbeatLoop() {
#ifdef VMP
    VMProtectBeginUltra("WhipAuthService_stopHeartbeatLoop");
#endif

    if (InterlockedCompareExchange(&heartbeatRunning_, 0, 0) == 0) return;

    InterlockedExchange(&heartbeatRunning_, 0);
    if (heartbeatThread_) {
        WaitForSingleObject(heartbeatThread_, 35000);
        CloseHandle(heartbeatThread_);
        heartbeatThread_ = nullptr;
    }

#ifdef VMP
    VMProtectEnd();
#endif
}

void WhipAuthService::setOnSessionExpired(SessionExpiredCallback cb) {
    onSessionExpired_ = cb;
}

VoidResult WhipAuthService::performFullAuthentication(const AuthPayload& payload) {
#ifdef VMP
    VMProtectBeginUltra("WhipAuthService_performFullAuthentication");
#endif
    ad::StackHidden _ad_guard;  // moonwalk: caller frame's RA -> ntdll decoy

    authStrCopy(pcName_, payload.machine.pcName, sizeof(pcName_));
    authStrCopy(executablePath_, payload.machine.executablePath, sizeof(executablePath_));

    if (!client_) {
        client_ = new WhipNexusClient();
    }

    auto initResult = client_->initialize();
    if (!initResult.isOk()) return initResult;

    auto connectResult = client_->connect(serverHost_, serverPort_);
    if (!connectResult.isOk()) {
        return connectResult;
    }

    if (!client_->isConnected()) {
        return VoidResult::err(ErrorCode::SecurityError, "Connection verification failed");
    }


    char downloadIdStr[33];
    payload.downloadId.toChars(downloadIdStr, sizeof(downloadIdStr));

    auto initReqResult = client_->initRequest(
        downloadIdStr,
        false,
        payload.machine.hwid,
        payload.machine.pcName,
        payload.machine.os,
        payload.machine.executablePath,
        0  // Phase 1: WhipAuthService legacy path (HWID flow); auth_tag is computed
           // at the AuthenticateStep callsite of nexusClient->initRequest instead.
    );

    if (!initReqResult.isOk()) {
        client_->disconnect();
        return initReqResult;
    }

    int productCount = client_->getProductCount();
    bool productFound = false;

    for (int i = 0; i < productCount; i++) {
        auto product = client_->getProduct(i);
        if (authStrEq(payload.productCode, product.code)) {
            productFound = true;
            break;
        }
    }

    if (!productFound) {
        client_->disconnect();
        return VoidResult::err(ErrorCode::LicenseError, "Product not found in user's licenses");
    }

    auto selectResult = client_->selectProduct(payload.productCode, payload.machine.pcName, payload.machine.executablePath);
    if (!selectResult.isOk()) {
        client_->disconnect();
        return selectResult;
    }

    i64 expiresAt = client_->getExpiresAt();
    u32 perms = static_cast<u32>(client_->getPermissions());

    char username[128];
    client_->getUsername(username, sizeof(username));

    sessionManager_.createSession(
        username,
        nullptr,
        nullptr,
        expiresAt,
        perms
    );


#ifdef VMP
    VMProtectEnd();
#endif

    return VoidResult::ok();
}

#pragma optimize("", on)
