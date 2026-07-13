#pragma once
#include "util/Types.h"
#include <windows.h>

#ifdef VMP
#include "VMProtectSDK.h"
#endif

#pragma optimize("", off)

enum class Permission : u32 {
    None            = 0,
    BasicAccess     = 1 << 0,
    PremiumFeatures = 1 << 1,
    BetaAccess      = 1 << 2,
    AdminPanel      = 1 << 3,
};

__forceinline bool hasPermission(u32 flags, Permission p) {
    return (flags & static_cast<u32>(p)) != 0;
}

template<u32 N>
struct SecureValue {
    Byte data[N];

    __forceinline SecureValue() {
        for (u32 i = 0; i < N; ++i) data[i] = 0;
    }

    __forceinline ~SecureValue() {
        volatile Byte* p = data;
        for (u32 i = 0; i < N; ++i) p[i] = 0;
    }

    __forceinline void clear() {
        volatile Byte* p = data;
        for (u32 i = 0; i < N; ++i) p[i] = 0;
    }
};

__forceinline i64 getCurrentUnixTime() {
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    ULARGE_INTEGER ul;
    ul.LowPart = ft.dwLowDateTime;
    ul.HighPart = ft.dwHighDateTime;
    return (i64)((ul.QuadPart / 10000000ULL) - 11644473600LL);
}

struct SessionInfo {
    char sessionId[64];
    char username[128];
    SecureValue<32> sessionToken;
    SecureValue<32> sessionKey;
    i64 createdAt;
    i64 expiresAt;
    i64 lastHeartbeat;
    SecureValue<32> currentChallenge;
    u32 permissions;
    bool isAuthenticated;
    bool isActive;

    __forceinline SessionInfo()
        : createdAt(0), expiresAt(0), lastHeartbeat(0),
          permissions(0), isAuthenticated(false), isActive(false) {
        sessionId[0] = '\0';
        username[0] = '\0';
    }

    __forceinline bool isExpired() const {
        i64 now = getCurrentUnixTime();
        return now >= expiresAt;
    }

    __forceinline bool needsHeartbeat(u32 intervalSec) const {
        i64 now = getCurrentUnixTime();
        return (now - lastHeartbeat) >= intervalSec;
    }

    __forceinline void clear() {
        sessionId[0] = '\0';
        username[0] = '\0';
        sessionToken.clear();
        sessionKey.clear();
        currentChallenge.clear();
        permissions = 0;
        isAuthenticated = false;
        isActive = false;
    }
};

class SessionManager {
    SessionInfo session_;
    bool hasSession_;

public:
    __forceinline SessionManager() : hasSession_(false) {}

    __forceinline ~SessionManager() {
        session_.clear();
    }

    __forceinline bool hasActiveSession() const {
        return hasSession_ && session_.isActive && session_.isAuthenticated && !session_.isExpired();
    }

    __forceinline const SessionInfo& currentSession() const {
        return session_;
    }

    __forceinline void createSession(
        const char* username,
        const Byte* sessionToken,
        const Byte* sessionKey,
        i64 expiresAt,
        u32 permissions
    ) {
#ifdef VMP
        VMProtectBeginUltra("SessionManager_createSession");
#endif
        session_.clear();

        if (username) {
            u32 i = 0;
            while (username[i] && i < sizeof(session_.username) - 1) {
                session_.username[i] = username[i];
                i++;
            }
            session_.username[i] = '\0';
        }

        if (sessionToken) {
            for (u32 i = 0; i < 32; ++i)
                session_.sessionToken.data[i] = sessionToken[i];
        }

        if (sessionKey) {
            for (u32 i = 0; i < 32; ++i)
                session_.sessionKey.data[i] = sessionKey[i];
        }

        session_.createdAt = getCurrentUnixTime();
        session_.lastHeartbeat = session_.createdAt;
        session_.expiresAt = expiresAt;
        session_.permissions = permissions;
        session_.isAuthenticated = true;
        session_.isActive = true;
        hasSession_ = true;

#ifdef VMP
        VMProtectEnd();
#endif
    }

    __forceinline void destroySession() {
#ifdef VMP
        VMProtectBeginUltra("SessionManager_destroySession");
#endif
        session_.clear();
        hasSession_ = false;

#ifdef VMP
        VMProtectEnd();
#endif
    }

    __forceinline void updateHeartbeat(const Byte* newChallenge) {
#ifdef VMP
        VMProtectBeginUltra("SessionManager_updateHeartbeat");
#endif
        if (!hasSession_) return;

        session_.lastHeartbeat = getCurrentUnixTime();

        if (newChallenge) {
            for (u32 i = 0; i < 32; ++i)
                session_.currentChallenge.data[i] = newChallenge[i];
        }

#ifdef VMP
        VMProtectEnd();
#endif
    }

    __forceinline void refreshExpiry(i64 newExpiry) {
        if (hasSession_) {
            session_.expiresAt = newExpiry;
        }
    }

    __forceinline bool validateSession() const {
#ifdef VMP
        VMProtectBeginUltra("SessionManager_validateSession");
#endif
        bool result = hasSession_ &&
                      session_.isActive &&
                      session_.isAuthenticated &&
                      !session_.isExpired();

#ifdef VMP
        VMProtectEnd();
#endif
        return result;
    }
};

#pragma optimize("", on)
