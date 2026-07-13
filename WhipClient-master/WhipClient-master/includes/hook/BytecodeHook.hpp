#pragma once

#include <jni.h>
#define jthread jni_jthread
#undef jthread

#include <functional>
#include <iostream>
#include <memory>
#include <string>
#include <unordered_map>

#include "dispatcher.hpp"
#include "instrumentation.h"
#include "return_helpers.hpp"
#include "../../includes/util/Debug.h"

class BaseHook;

struct HookResult {
    bool shouldCancel = false;
    bool hasReturnValue = false;
    bool wantsNullReturn = false;
    jobject returnValue = nullptr;

    static constexpr HookResult Continue() {
        return { false, false, false, nullptr };
    }

    static HookResult Cancel(JNIEnv* env) {
        HookResult result;
        result.shouldCancel = true;
        result.hasReturnValue = true;
        result.returnValue = HookReturnHelpers::ReturnBoolean(env, false);
        return result;
    }

    static constexpr HookResult CancelNull() {
        HookResult result{};
        result.shouldCancel = true;
        result.hasReturnValue = true;
        result.wantsNullReturn = true;
        return result;
    }

    static HookResult ReturnBoolean(JNIEnv* env, bool value) {
        HookResult result;
        result.shouldCancel = true;
        result.hasReturnValue = true;
        result.returnValue = HookReturnHelpers::ReturnBoolean(env, value);
        return result;
    }

    static HookResult ReturnInt(JNIEnv* env, int value) {
        HookResult result;
        result.shouldCancel = true;
        result.hasReturnValue = true;
        result.returnValue = HookReturnHelpers::ReturnInteger(env, value);
        return result;
    }

    static HookResult ReturnFloat(JNIEnv* env, float value) {
        HookResult result;
        result.shouldCancel = true;
        result.hasReturnValue = true;
        result.returnValue = HookReturnHelpers::ReturnFloat(env, value);
        return result;
    }

    static HookResult ReturnLong(JNIEnv* env, long value) {
        HookResult result;
        result.shouldCancel = true;
        result.hasReturnValue = true;
        result.returnValue = HookReturnHelpers::ReturnLong(env, value);
        return result;
    }

    static HookResult ReturnDouble(JNIEnv* env, double value) {
        HookResult result;
        result.shouldCancel = true;
        result.hasReturnValue = true;
        result.returnValue = HookReturnHelpers::ReturnDouble(env, value);
        return result;
    }

    static HookResult ReturnObject(JNIEnv* env, jobject value) {
        HookResult result;
        result.shouldCancel = true;
        result.hasReturnValue = true;
        result.returnValue = value;
        return result;
    }
};

using PreHookCallback = std::function<HookResult(JNIEnv* env, jobjectArray args)>;
using PostHookCallback = std::function<void(JNIEnv* env, jobject result, jobjectArray args)>;

struct RegisteredHook {
    int hookId = 0;
    std::string methodName;
    std::string methodSignature;
    std::string className;
    PreHookCallback preCallback;
    PostHookCallback postCallback;
    bool isActive = true;

    bool hasReturnValue = false;
    bool wantsNullReturn = false;
    jobject returnValue = nullptr;
};

class BytecodeHookManager {
public:
    static BytecodeHookManager& getInstance() {
        static BytecodeHookManager instance;
        return instance;
    }

    BytecodeHookManager(const BytecodeHookManager&) = delete;
    BytecodeHookManager& operator=(const BytecodeHookManager&) = delete;

    bool initialize(JNIEnv* env, JavaVM* jvm, jobject classLoader = nullptr) {
        if (m_initialized) return true;

        m_env = env;
        m_jvm = jvm;

        if (!DispatcherHook::Initialize(env, classLoader)) {
            return false;
        }

        if (!JvmInstrumentor::Get().Initialize(jvm)) {
            return false;
        }

        m_initialized = true;
        return true;
    }

    void shutdown() {
        if (!m_initialized) return;

        JNIEnv* env = nullptr;
        bool needDetach = false;

        if (m_jvm) {
            jint result = m_jvm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_8);
            if (result == JNI_EDETACHED) {

                if (m_jvm->AttachCurrentThread(reinterpret_cast<void**>(&env), nullptr) == JNI_OK) {
                    needDetach = true;
                }
            }
        }

        if (env) {
            for (auto& pair : m_hooks) {
                if (pair.second.returnValue) {
                    env->DeleteGlobalRef(pair.second.returnValue);
                    pair.second.returnValue = nullptr;
                }
            }
        }

        DispatcherHook::Shutdown();

        m_hooks.clear();
        m_initialized = false;
        m_env = nullptr;

        if (needDetach && m_jvm) {
            m_jvm->DetachCurrentThread();
        }

    }

    int createHook(jmethodID methodId, PreHookCallback preCallback, PostHookCallback postCallback = nullptr) {
        if (!m_initialized || !methodId) {
            return -1;
        }

        HookCallbacks callbacks;
        callbacks.preHook = &BytecodeHookManager::nativePreHook;
        callbacks.overrideHook = &BytecodeHookManager::nativeOverrideHook;
        callbacks.postHook = postCallback ? &BytecodeHookManager::nativePostHook : nullptr;

        int hookId = DispatcherHook::CreateHook(m_env, methodId, callbacks);
        if (hookId < 0) {
            return -1;
        }

        RegisteredHook hook;
        hook.hookId = hookId;
        hook.preCallback = preCallback;
        hook.postCallback = postCallback;
        hook.isActive = true;

        m_hooks[hookId] = hook;

        return hookId;
    }

    int createHook(jclass clazz, const std::string& methodName, const std::string& signature,
                   PreHookCallback preCallback, PostHookCallback postCallback = nullptr) {
        if (!m_env || !clazz) return -1;

        jmethodID methodId = m_env->GetMethodID(clazz, methodName.c_str(), signature.c_str());
        if (!methodId) {
            m_env->ExceptionClear();
            methodId = m_env->GetStaticMethodID(clazz, methodName.c_str(), signature.c_str());
        }

        if (!methodId) {
            m_env->ExceptionClear();
            return -1;
        }

        return createHook(methodId, preCallback, postCallback);
    }

    struct PendingHookInfo {
        jmethodID methodId;
        PreHookCallback preCallback;
        PostHookCallback postCallback;
        int resultHookId = -1;
    };

    bool createHooksBatch(std::vector<PendingHookInfo>& pendingHooks) {
        if (!m_initialized) {
            std::cout << "[BytecodeHookManager] ERROR: createHooksBatch: not initialized" << std::endl;
            return false;
        }

        std::vector<DispatcherHook::PendingHook> dispatcherHooks;
        for (auto& ph : pendingHooks) {
            HookCallbacks callbacks;
            callbacks.preHook = &BytecodeHookManager::nativePreHook;
            callbacks.overrideHook = &BytecodeHookManager::nativeOverrideHook;
            callbacks.postHook = ph.postCallback ? &BytecodeHookManager::nativePostHook : nullptr;

            dispatcherHooks.push_back({ph.methodId, callbacks, -1});
        }

        JNIEnv* env = getEnv();
        if (!env) {
            std::cout << "[BytecodeHookManager] ERROR: createHooksBatch: getEnv() returned null" << std::endl;
            return false;
        }

        if (!DispatcherHook::CreateHooksBatch(env, dispatcherHooks)) {
            std::cout << "[BytecodeHookManager] ERROR: CreateHooksBatch failed" << std::endl;
            return false;
        }

        for (size_t i = 0; i < pendingHooks.size(); ++i) {
            int hookId = dispatcherHooks[i].hookId;
            pendingHooks[i].resultHookId = hookId;

            RegisteredHook hook;
            hook.hookId = hookId;
            hook.preCallback = pendingHooks[i].preCallback;
            hook.postCallback = pendingHooks[i].postCallback;
            hook.isActive = true;
            m_hooks[hookId] = hook;
        }

        return true;
    }

    void setHookEnabled(int hookId, bool enabled) {
        auto it = m_hooks.find(hookId);
        if (it != m_hooks.end()) {
            it->second.isActive = enabled;
        }
    }

    void removeHook(int hookId, bool restoreBytecode = false) {
        auto it = m_hooks.find(hookId);
        if (it != m_hooks.end()) {

            DispatcherHook::InvalidateHook(hookId);

            if (it->second.returnValue && m_env) {
                m_env->DeleteGlobalRef(it->second.returnValue);
                it->second.returnValue = nullptr;
            }

            if (restoreBytecode && !it->second.className.empty()) {
                JvmInstrumentor::Get().RestoreClass(it->second.className);
            }

            m_hooks.erase(it);
        }
    }

    bool isInitialized() const { return m_initialized; }

    JNIEnv* getEnv() const {
        if (!m_jvm) return nullptr;
        JNIEnv* env = nullptr;
        jint result = m_jvm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_8);
        if (result == JNI_OK) return env;
        if (result == JNI_EDETACHED) {
            if (m_jvm->AttachCurrentThread(reinterpret_cast<void**>(&env), nullptr) == JNI_OK) {
                return env;
            }
        }
        return nullptr;
    }

private:
    BytecodeHookManager() = default;
    ~BytecodeHookManager() { shutdown(); }

    static jint JNICALL nativePreHook(JNIEnv* env, jint hookId, jobjectArray args) {
        auto& manager = getInstance();

        auto it = manager.m_hooks.find(hookId);
        if (it == manager.m_hooks.end() || !it->second.isActive) {
            return 0;
        }

        auto& hook = it->second;
        if (!hook.preCallback) {
            return 0;
        }

        if (env->ExceptionCheck()) {
            env->ExceptionClear();
        }

        HookResult result = hook.preCallback(env, args);

        if (env->ExceptionCheck()) {
            env->ExceptionDescribe();
            env->ExceptionClear();
            if (hook.returnValue) {
                env->DeleteGlobalRef(hook.returnValue);
                hook.returnValue = nullptr;
            }
            hook.hasReturnValue = false;
            return 0;
        }

        if (result.wantsNullReturn) {

            if (hook.returnValue) {
                env->DeleteGlobalRef(hook.returnValue);
                hook.returnValue = nullptr;
            }
            hook.hasReturnValue = true;
            hook.wantsNullReturn = true;
        } else if (result.hasReturnValue && result.returnValue) {
            if (hook.returnValue) {
                env->DeleteGlobalRef(hook.returnValue);
            }

            hook.returnValue = env->NewGlobalRef(result.returnValue);
            hook.hasReturnValue = true;
            hook.wantsNullReturn = false;

            env->DeleteLocalRef(result.returnValue);
        } else {

            if (hook.returnValue) {
                env->DeleteGlobalRef(hook.returnValue);
                hook.returnValue = nullptr;
            }
            hook.hasReturnValue = false;
            hook.wantsNullReturn = false;
        }

        return result.shouldCancel ? 1 : 0;
    }

    static jobject JNICALL nativeOverrideHook(JNIEnv* env, jint hookId, jobjectArray args) {
        auto& manager = getInstance();

        auto it = manager.m_hooks.find(hookId);
        if (it == manager.m_hooks.end() || !it->second.isActive) {
            jobject fallback = HookReturnHelpers::ReturnFalse(env);

            if (!fallback) {
                jclass boolClass = env->FindClass("java/lang/Boolean");
                if (boolClass) {
                    jmethodID valueOf = env->GetStaticMethodID(boolClass, "valueOf", "(Z)Ljava/lang/Boolean;");
                    if (valueOf) {
                        fallback = env->CallStaticObjectMethod(boolClass, valueOf, JNI_FALSE);
                    }
                    env->DeleteLocalRef(boolClass);
                }
            }
            return fallback;
        }

        auto& hook = it->second;

        if (hook.wantsNullReturn) {
            hook.hasReturnValue = false;
            hook.wantsNullReturn = false;
            return nullptr;
        }

        if (!hook.hasReturnValue || !hook.returnValue) {
            jobject fallback = HookReturnHelpers::ReturnFalse(env);

            if (!fallback) {
                jclass boolClass = env->FindClass("java/lang/Boolean");
                if (boolClass) {
                    jmethodID valueOf = env->GetStaticMethodID(boolClass, "valueOf", "(Z)Ljava/lang/Boolean;");
                    if (valueOf) {
                        fallback = env->CallStaticObjectMethod(boolClass, valueOf, JNI_FALSE);
                    }
                    env->DeleteLocalRef(boolClass);
                }
            }
            return fallback;
        }

        jobject localRef = env->NewLocalRef(hook.returnValue);

        env->DeleteGlobalRef(hook.returnValue);
        hook.returnValue = nullptr;
        hook.hasReturnValue = false;

        if (!localRef) {
            jclass boolClass = env->FindClass("java/lang/Boolean");
            if (boolClass) {
                jmethodID valueOf = env->GetStaticMethodID(boolClass, "valueOf", "(Z)Ljava/lang/Boolean;");
                if (valueOf) {
                    localRef = env->CallStaticObjectMethod(boolClass, valueOf, JNI_FALSE);
                }
                env->DeleteLocalRef(boolClass);
            }
        }

        return localRef;
    }

    static void JNICALL nativePostHook(JNIEnv* env, jint hookId, jobject result, jobjectArray args) {
        auto& manager = getInstance();

        auto it = manager.m_hooks.find(hookId);
        if (it == manager.m_hooks.end() || !it->second.isActive) {
            return;
        }

        const auto& hook = it->second;
        if (!hook.postCallback) {
            return;
        }

        hook.postCallback(env, result, args);
    }

    JNIEnv* m_env = nullptr;
    JavaVM* m_jvm = nullptr;
    bool m_initialized = false;
    int m_nextHookId = 1;
    std::unordered_map<int, RegisteredHook> m_hooks;
};

inline BytecodeHookManager& getHookManager() {
    return BytecodeHookManager::getInstance();
}
