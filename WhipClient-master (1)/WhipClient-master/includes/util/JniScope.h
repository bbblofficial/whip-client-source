#pragma once

#include <jni.h>
#include "Singleton.h"

class JvmHolder : public Instance<JvmHolder> {
    JavaVM* m_jvm = nullptr;

public:
    void setJavaVM(JavaVM* jvm) { m_jvm = jvm; }
    JavaVM* getJavaVM() const { return m_jvm; }
    void cleanup() { m_jvm = nullptr; }
};

class JniScope {
    JNIEnv* m_env;
    bool m_shouldDetach;
    bool m_isValid;

public:
    explicit JniScope(const bool autoDetach = true)
        : m_env(nullptr), m_shouldDetach(autoDetach), m_isValid(false) {

        const auto* jvmHolder = JvmHolder::Get();
        if (!jvmHolder || !jvmHolder->getJavaVM()) {
            return;
        }

        JavaVM* jvm = jvmHolder->getJavaVM();
        JNIEnv* env = NULL;
        int result = jvm->AttachCurrentThread((void**)&env, NULL);
        if (result == JNI_OK) {
            this->m_env = env;
        }

        m_isValid = true;
    }

    ~JniScope() {
        if (m_shouldDetach && m_isValid) {
            if (const auto* jvmHolder = JvmHolder::Get(); jvmHolder && jvmHolder->getJavaVM()) {
                jvmHolder->getJavaVM()->DetachCurrentThread();
            }
        }
    }

    JniScope(const JniScope&) = delete;
    JniScope& operator=(const JniScope&) = delete;

    JniScope(JniScope&& other) noexcept
        : m_env(other.m_env), m_shouldDetach(other.m_shouldDetach), m_isValid(other.m_isValid) {
        other.m_env = nullptr;
        other.m_isValid = false;
        other.m_shouldDetach = false;
    }

    JniScope& operator=(JniScope&& other) noexcept {
        if (this != &other) {
            m_env = other.m_env;
            m_shouldDetach = other.m_shouldDetach;
            m_isValid = other.m_isValid;

            other.m_env = nullptr;
            other.m_isValid = false;
            other.m_shouldDetach = false;
        }
        return *this;
    }

    JNIEnv* getEnv() const {
        return m_isValid ? m_env : nullptr;
    }

    JNIEnv* operator->() const {
        return getEnv();
    }

    JNIEnv& operator*() const {
        return *getEnv();
    }

    bool isValid() const {
        return m_isValid;
    }

    explicit operator bool() const {
        return m_isValid;
    }
};

#define JNI_SCOPE() JniScope jniScope
#define JNI_SCOPE_AUTO_DETACH() JniScope jniScope(true)
#define JNI_SCOPE_NO_DETACH() JniScope jniScope(false)

#define JNI_CHECK(scope) if (!(scope).isValid()) return
#define JNI_CHECK_RETURN(scope, retval) if (!(scope).isValid()) return retval
