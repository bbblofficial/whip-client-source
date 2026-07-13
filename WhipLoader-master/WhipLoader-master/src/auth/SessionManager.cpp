#pragma optimize("", off)
#include "auth/Session.h"
#include <stdexcept>
#include <mutex>

struct SessionManager::Impl {
    SessionInfo session;
    mutable std::mutex mutex;
    bool hasSession = false;
};

SessionManager::SessionManager() : impl_(std::make_unique<Impl>()) {}

SessionManager::~SessionManager() = default;

bool SessionManager::hasActiveSession() const noexcept {
    std::lock_guard<std::mutex> lock(impl_->mutex);
    return impl_->hasSession && impl_->session.isAuthenticated && !impl_->session.isExpired();
}

const SessionInfo& SessionManager::currentSession() const {
    std::lock_guard<std::mutex> lock(impl_->mutex);
    if (!impl_->hasSession) {
        throw std::runtime_error("No active session");
    }
    return impl_->session;
}

void SessionManager::createSession(
    const SessionId& id,
    const std::string& username,
    ByteView sessionToken,
    const SessionKey& sessionKey,
    Timestamp expiresAt,
    Permission permissions
) {
    std::lock_guard<std::mutex> lock(impl_->mutex);

    impl_->session.sessionId = id;
    impl_->session.username = username;

    // Copy session token
    if (sessionToken.size() >= 32) {
        std::copy_n(sessionToken.begin(), 32, impl_->session.sessionToken.get().begin());
    }

    impl_->session.sessionKey.get() = sessionKey;
    impl_->session.createdAt = std::chrono::system_clock::now();
    impl_->session.expiresAt = expiresAt;
    impl_->session.lastHeartbeat = std::chrono::system_clock::now();
    impl_->session.permissions = permissions;
    impl_->session.isAuthenticated = true;
    impl_->session.isActive = true;

    impl_->hasSession = true;
}

void SessionManager::destroySession() {
    std::lock_guard<std::mutex> lock(impl_->mutex);
    impl_->session.clear();
    impl_->hasSession = false;
}

void SessionManager::updateHeartbeat(ByteView newChallenge) {
    std::lock_guard<std::mutex> lock(impl_->mutex);
    if (!impl_->hasSession) {
        return;
    }

    impl_->session.lastHeartbeat = std::chrono::system_clock::now();

    // Update challenge if provided
    if (newChallenge.size() >= 32) {
        std::copy_n(newChallenge.begin(), 32, impl_->session.currentChallenge.get().begin());
    }
}

void SessionManager::refreshExpiry(Timestamp newExpiry) {
    std::lock_guard<std::mutex> lock(impl_->mutex);
    if (!impl_->hasSession) {
        return;
    }

    impl_->session.expiresAt = newExpiry;
}

bool SessionManager::validateSession() const {
    std::lock_guard<std::mutex> lock(impl_->mutex);
    if (!impl_->hasSession) {
        return false;
    }

    return impl_->session.isAuthenticated &&
           impl_->session.isActive &&
           !impl_->session.isExpired();
}
#pragma optimize("", on)
