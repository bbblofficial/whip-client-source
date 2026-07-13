#pragma once
#include "ErrorCode.h"
#include "Credentials.h"
#include "session/Session.h"

typedef void (*SessionExpiredCallback)();

class IAuthService {
public:
    virtual ~IAuthService() = default;

    virtual VoidResult authenticate(const AuthPayload& payload) = 0;
    virtual bool isAuthenticated() const = 0;
    virtual const SessionInfo* currentSession() const = 0;

    virtual VoidResult sendHeartbeat() = 0;
    virtual void startHeartbeatLoop(u32 intervalSec) = 0;
    virtual void stopHeartbeatLoop() = 0;

    virtual void logout() = 0;

    virtual void setOnSessionExpired(SessionExpiredCallback cb) = 0;
};
