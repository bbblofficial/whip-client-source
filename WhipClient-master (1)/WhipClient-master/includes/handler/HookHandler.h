

#pragma once
#ifndef HOOK_HANDLER_H
#define HOOK_HANDLER_H

#include <unordered_map>
#include <string>
#include <memory>
#include <vector>

#include "MappingHandler.h"
#include "hook/base/BaseHook.h"
#include "util/JNIUtils.h"

class HookHandler {
public:
    static HookHandler& getInstance() {
        static HookHandler instance;
        return instance;
    }

    void registerHook(std::unique_ptr<BaseHook> hook) {
        const std::string& id = hook->getName();
        m_hooks[id] = std::move(hook);
    }

    bool initializeHooks(JNIEnv* env, jobject classLoader = nullptr) {
        m_jniEnv = env;

        JavaVM* jvm = nullptr;
        if (env->GetJavaVM(&jvm) != JNI_OK) {
            return false;
        }

        auto& manager = BytecodeHookManager::getInstance();
        if (!manager.initialize(env, jvm, classLoader)) {
            return false;
        }

        const auto& mappings = Mappings::getInstance();

        std::vector<BytecodeHookManager::PendingHookInfo> pendingHooks;
        std::vector<std::string> hookNames;

        for (auto& [id, hook] : m_hooks) {
            if (!hook) {
                return false;
            }

            const std::string& methodName = hook->getName();
            jmethodID methodId = mappings.getInstance().getMethod(methodName.c_str());

            if (!methodId) {
                continue;
            }

            PreHookCallback preCallback = nullptr;
            PostHookCallback postCallback = nullptr;
            auto position = hook->getPosition();

            if (position == HookPosition::OVERRIDE) {
                BaseHook* rawHook = hook.get();
                preCallback = [rawHook](JNIEnv* env, jobjectArray args) {
                    jobject result = rawHook->onOverride(env, args);
                    if (result) return HookResult::ReturnObject(env, result);
                    return HookResult::Cancel(env);
                };
            } else {
                if (position == HookPosition::PRE || position == HookPosition::BOTH) {
                    BaseHook* rawHook = hook.get();
                    preCallback = [rawHook](JNIEnv* env, jobjectArray args) {
                        return rawHook->onPreExecute(env, args);
                    };
                }
                if (position == HookPosition::POST || position == HookPosition::BOTH) {
                    BaseHook* rawHook = hook.get();
                    postCallback = [rawHook](JNIEnv* env, jobject result, jobjectArray args) {
                        rawHook->onPostExecute(env, result, args);
                    };
                }
            }

            pendingHooks.push_back({methodId, preCallback, postCallback, -1});
            hookNames.push_back(methodName);
        }

        if (pendingHooks.empty()) {
            m_isInitialized = true;
            return true;
        }

        if (!manager.createHooksBatch(pendingHooks)) {
            for (auto& [id, hook] : m_hooks) {
                if (!hook) continue;
                const std::string& methodName = hook->getName();
                jmethodID methodId = mappings.getInstance().getMethod(methodName.c_str());
                if (!methodId) continue;
                if (!hook->registerHook(methodId)) {
                }
            }
        } else {

            size_t idx = 0;
            int installed = 0, failed = 0;
            for (auto& [id, hook] : m_hooks) {
                if (!hook) continue;
                jmethodID methodId = mappings.getInstance().getMethod(hook->getName().c_str());
                if (!methodId) continue;
                if (idx < pendingHooks.size() && pendingHooks[idx].resultHookId >= 0) {
                    hook->setHookIdDirect(pendingHooks[idx].resultHookId);
                    installed++;
                } else {
                    failed++;
                }
                idx++;
            }
        }

        for (auto& [id, hook] : m_hooks) {
            if (hook && hook->getHookId() >= 0) {
                hook->setEnabled(false);
            }
        }

        m_isInitialized = true;
        return true;
    }

    void enableAll() {
        for (auto& [id, hook] : m_hooks) {
            if (hook && hook->getHookId() >= 0) {
                hook->setEnabled(true);
            }
        }
    }

    BaseHook* getHookById(const std::string& id) {
        auto it = m_hooks.find(id);
        return it != m_hooks.end() ? it->second.get() : nullptr;
    }

    void suspendAll() {
        for (auto& [id, hook] : m_hooks) {
            if (hook && hook->getHookId() >= 0) {
                DispatcherHook::InvalidateHook(hook->getHookId());
            }
        }

        DispatcherHook::WaitForActiveCallsToComplete();
    }

    void cleanup() {

        for (auto& [id, hook] : m_hooks) {
            if (hook) {
                hook->unregisterHook();
            }
        }

        BytecodeHookManager::getInstance().shutdown();

        m_hooks.clear();
        m_isInitialized = false;
        m_jniEnv = nullptr;

    }

    void setHookEnabled(const std::string& id, bool enabled) {
        auto* hook = getHookById(id);
        if (hook) {
            hook->setEnabled(enabled);
        }
    }

    bool isInitialized() const { return m_isInitialized; }

    JNIEnv* getJNIEnv() const { return m_jniEnv; }

private:
    HookHandler() = default;
    ~HookHandler() = default;

    HookHandler(const HookHandler&) = delete;
    HookHandler& operator=(const HookHandler&) = delete;

    std::unordered_map<std::string, std::unique_ptr<BaseHook>> m_hooks;
    bool m_isInitialized = false;
    JNIEnv* m_jniEnv = nullptr;
};

#endif
