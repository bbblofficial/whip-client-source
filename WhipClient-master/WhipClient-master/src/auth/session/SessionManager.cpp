#include "auth/session/SessionManager.h"
#include <whipnexus/SyscallManager.h>

#ifdef VMP
#include "VMProtectSDK.h"
#endif

#include "antidebug/vm/vm_cpp.hpp"

#pragma optimize("", off)

static u32 cachedRtKey() {
    static const u32 key = vm_runtime_key_stable();
    return key;
}

u64 SessionManager::encodeAuthState(u32 v) {
    auto cascade = ad::vm::ScoreCascade::from_key(cachedRtKey());
    return cascade.encode(v);
}

bool SessionManager::decodeAuthIsValid(u64 encoded) {
    auto cascade = ad::vm::ScoreCascade::from_key(cachedRtKey());
    return cascade.decode(encoded) == 0u;
}

void SessionManager::createSession(const char* username, const Byte* token,
                                   const Byte* challenge, u32 permissions,
                                   i64 expiresAt) {
#ifdef VMP
    VMProtectBeginUltra("SessionManager_createSession");
#endif
    SyscallManager::EnterCriticalSection(impl_->mutex);
    impl_->session.username.set(username);
    if (token) SyscallManager::SecureMemCpy(impl_->session.sessionToken.data, token, 32);
    if (challenge) SyscallManager::SecureMemCpy(impl_->session.currentChallenge.data, challenge, 32);
    impl_->session.permissions = permissions;
    impl_->session.createdAt = getCurrentUnixTime();
    impl_->session.expiresAt = expiresAt;
    impl_->session.lastHeartbeat = impl_->session.createdAt;
    impl_->session.isAuthenticated = true;
    impl_->session.isActive = true;

    impl_->authStateEncoded = encodeAuthState(0u);
    SyscallManager::LeaveCriticalSection(impl_->mutex);
#ifdef VMP
    VMProtectEnd();
#endif
}

#pragma optimize("", on)
