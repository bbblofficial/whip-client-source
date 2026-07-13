#pragma once
#include "auth/session/Session.h"
#include <whipnexus/SyscallManager.h>
#include <new>

#include "util/debug.h"

#ifdef VMP
#include "VMProtectSDK.h"
#endif

#pragma optimize("", off)

__forceinline i64 getCurrentUnixTime() {
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    ULARGE_INTEGER ul;
    ul.LowPart = ft.dwLowDateTime;
    ul.HighPart = ft.dwHighDateTime;
    return (i64)((ul.QuadPart / 10000000ULL) - 11644473600LL);
}

class SessionManager {
    struct Impl {
        SessionInfo session;
        void* mutex;

        u64 authStateEncoded;
    };
    Impl* impl_;

    static u64 encodeAuthState(u32 v);
    static bool     decodeAuthIsValid(u64 encoded);

public:
    __forceinline SessionManager() {
        impl_ = (Impl*)SyscallManager::GetWrappers()->HeapAlloc(sizeof(Impl));
        if (impl_) {
            new (impl_) Impl();
            impl_->mutex = SyscallManager::CreateCriticalSection();
            impl_->authStateEncoded = encodeAuthState(0xFFu);
        }
    }

    __forceinline ~SessionManager() {
        if (impl_) {
            SyscallManager::DeleteCriticalSection(impl_->mutex);
            impl_->~Impl();
            SyscallManager::GetWrappers()->HeapFree(impl_);
        }
    }

    __forceinline bool hasActiveSession() const {
        SyscallManager::EnterCriticalSection(impl_->mutex);

        bool result = impl_->session.isActive && impl_->session.isAuthenticated
                   && decodeAuthIsValid(impl_->authStateEncoded);
        SyscallManager::LeaveCriticalSection(impl_->mutex);
        return result;
    }

    __forceinline const SessionInfo* currentSession() const {
        SyscallManager::EnterCriticalSection(impl_->mutex);
        const SessionInfo* result = (impl_->session.isActive
            && decodeAuthIsValid(impl_->authStateEncoded)) ? &impl_->session : nullptr;
        SyscallManager::LeaveCriticalSection(impl_->mutex);
        return result;
    }

    void createSession(const char* username, const Byte* token,
                       const Byte* challenge, u32 permissions,
                       i64 expiresAt);

    __forceinline void destroySession() {
        SyscallManager::EnterCriticalSection(impl_->mutex);
        impl_->session.clear();
        impl_->authStateEncoded = encodeAuthState(0xFFu);
        SyscallManager::LeaveCriticalSection(impl_->mutex);
    }

    __forceinline void updateHeartbeat(const Byte* newChallenge) {
        SyscallManager::EnterCriticalSection(impl_->mutex);
        if (impl_->session.isActive) {
            if (newChallenge) SyscallManager::SecureMemCpy(impl_->session.currentChallenge.data, newChallenge, 32);
            impl_->session.lastHeartbeat = getCurrentUnixTime();
        }
        SyscallManager::LeaveCriticalSection(impl_->mutex);
    }

    __forceinline bool validateSession() const {
        SyscallManager::EnterCriticalSection(impl_->mutex);
        bool result = impl_->session.isActive &&
                      impl_->session.isAuthenticated &&
                      decodeAuthIsValid(impl_->authStateEncoded) &&
                      !impl_->session.isExpired();
        SyscallManager::LeaveCriticalSection(impl_->mutex);
        return result;
    }
};

#pragma optimize("", on)
