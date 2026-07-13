#pragma once
#include <Windows.h>

class CustomMutex {
public:
    CustomMutex() {
        InitializeCriticalSection(&m_criticalSection);
        m_isInitialized = true;
    }

    ~CustomMutex() {
        if (m_isInitialized) {
            DeleteCriticalSection(&m_criticalSection);
            m_isInitialized = false;
        }
    }

    CustomMutex(const CustomMutex&) = delete;
    CustomMutex& operator=(const CustomMutex&) = delete;

    void lock() {
        if (m_isInitialized) {
            EnterCriticalSection(&m_criticalSection);
        }
    }

    void unlock() {
        if (m_isInitialized) {
            LeaveCriticalSection(&m_criticalSection);
        }
    }

    bool try_lock() {
        if (!m_isInitialized) return false;
        return TryEnterCriticalSection(&m_criticalSection) != 0;
    }

    bool is_initialized() const {
        return m_isInitialized;
    }

private:
    CRITICAL_SECTION m_criticalSection;
    bool m_isInitialized = false;
};

class CustomLockGuard {
public:
    explicit CustomLockGuard(CustomMutex& mutex) : m_mutex(mutex), m_locked(false) {
        m_mutex.lock();
        m_locked = true;
    }

    ~CustomLockGuard() {
        if (m_locked) {
            m_mutex.unlock();
        }
    }

    CustomLockGuard(const CustomLockGuard&) = delete;
    CustomLockGuard& operator=(const CustomLockGuard&) = delete;

private:
    CustomMutex& m_mutex;
    bool m_locked;
};

#define CUSTOM_LOCK(mutex) CustomLockGuard __lock_##__LINE__(mutex)
