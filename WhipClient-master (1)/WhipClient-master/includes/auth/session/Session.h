#pragma once
#include <whipnexus/Types.h>
#include <whipnexus/SyscallManager.h>
#include <windows.h>

#ifdef VMP
#include "VMProtectSDK.h"
#endif

#pragma optimize("", off)

using Byte = byte;

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
        SyscallManager::SecureZero(data, N);
    }
    __forceinline ~SecureValue() {
        volatile Byte* p = data;
        for (u32 i = 0; i < N; ++i) p[i] = 0;
    }
};

struct SessionInfo {
    String sessionId;
    String username;
    SecureValue<32> sessionToken;
    i64 createdAt;
    i64 expiresAt;
    i64 lastHeartbeat;
    SecureValue<32> currentChallenge;
    u32 permissions;
    bool isAuthenticated;
    bool isActive;

    __forceinline SessionInfo() : createdAt(0), expiresAt(0), lastHeartbeat(0),
        permissions(0), isAuthenticated(false), isActive(false) {}

    __forceinline bool isExpired() const {
        FILETIME ft;
        GetSystemTimeAsFileTime(&ft);
        ULARGE_INTEGER ul;
        ul.LowPart = ft.dwLowDateTime;
        ul.HighPart = ft.dwHighDateTime;
        i64 now = (i64)((ul.QuadPart / 10000000ULL) - 11644473600LL);
        return now >= expiresAt;
    }

    __forceinline bool needsHeartbeat(u32 intervalSec) const {
        FILETIME ft;
        GetSystemTimeAsFileTime(&ft);
        ULARGE_INTEGER ul;
        ul.LowPart = ft.dwLowDateTime;
        ul.HighPart = ft.dwHighDateTime;
        i64 now = (i64)((ul.QuadPart / 10000000ULL) - 11644473600LL);
        return (now - lastHeartbeat) >= intervalSec;
    }

    __forceinline void clear() {
        sessionId.clear();
        username.clear();
        permissions = 0;
        isAuthenticated = false;
        isActive = false;
    }
};

#pragma optimize("", on)
