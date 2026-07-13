#ifndef BASE_HOOK_H
#define BASE_HOOK_H

#include <jni.h>
#include <string>
#include <functional>

#include "../includes/hook/BytecodeHook.hpp"
#include "util/Debug.h"

enum class HookPosition {
        PRE,
        POST,
        BOTH,
        OVERRIDE
};

class BaseHook {
    friend class HookHandler;
public:
    explicit BaseHook(const std::string& hookName, HookPosition position = HookPosition::PRE)
        : m_hookName(hookName), m_position(position), m_hookId(-1) {}

    virtual ~BaseHook() = default;

    const std::string& getName() const { return m_hookName; }
    HookPosition getPosition() const { return m_position; }
    bool isActive() const { return m_hookId >= 0; }
    int getHookId() const { return m_hookId; }

    bool registerHook(jmethodID methodId) {
        if (m_hookId >= 0) {
            return true;
        }

        auto& manager = BytecodeHookManager::getInstance();

        PreHookCallback preCallback = nullptr;
        PostHookCallback postCallback = nullptr;

        if (m_position == HookPosition::OVERRIDE) {

            preCallback = [this](JNIEnv* env, jobjectArray args) {
                jobject result = this->onOverride(env, args);
                if (result) {
                    return HookResult::ReturnObject(env, result);
                }
                return HookResult::Cancel(env);
            };
        } else {
            if (m_position == HookPosition::PRE || m_position == HookPosition::BOTH) {
                preCallback = [this](JNIEnv* env, jobjectArray args) {
                    return this->onPreExecute(env, args);
                };
            }

            if (m_position == HookPosition::POST || m_position == HookPosition::BOTH) {
                postCallback = [this](JNIEnv* env, jobject result, jobjectArray args) {
                    this->onPostExecute(env, result, args);
                };
            }
        }

        m_hookId = manager.createHook(methodId, preCallback, postCallback);

        if (m_hookId < 0) {
            return false;
        }

        return true;
    }

    bool registerHook(jclass clazz, const std::string& methodName, const std::string& signature) {
        auto& manager = BytecodeHookManager::getInstance();
        JNIEnv* env = manager.getEnv();
        if (!env || !clazz) return false;

        jmethodID methodId = env->GetMethodID(clazz, methodName.c_str(), signature.c_str());
        if (!methodId) {
            env->ExceptionClear();
            methodId = env->GetStaticMethodID(clazz, methodName.c_str(), signature.c_str());
        }

        if (!methodId) {
            env->ExceptionClear();
            return false;
        }

        m_methodName = methodName;
        m_methodSignature = signature;

        return registerHook(methodId);
    }

    void unregisterHook() {
        if (m_hookId >= 0) {
            BytecodeHookManager::getInstance().removeHook(m_hookId);
            m_hookId = -1;
        }
    }

    void setEnabled(bool enabled) {
        if (m_hookId >= 0) {
            BytecodeHookManager::getInstance().setHookEnabled(m_hookId, enabled);
        }
    }

    void setHookIdDirect(int hookId) { m_hookId = hookId; }

    virtual HookResult onPreExecute(JNIEnv* env, jobjectArray args) {
        (void)env; (void)args;
        return HookResult::Continue();
    }

    virtual void onPostExecute(JNIEnv* env, jobject result, jobjectArray args) {
        (void)env; (void)result; (void)args;
    }

    virtual jobject onOverride(JNIEnv* env, jobjectArray args) {
        (void)env; (void)args;
        return nullptr;
    }

    static jobject getArg(JNIEnv* env, jobjectArray args, int index) {
        if (!args || !env) return nullptr;
        return env->GetObjectArrayElement(args, index);
    }

    static int getArgCount(JNIEnv* env, jobjectArray args) {
        if (!args || !env) return 0;
        return env->GetArrayLength(args);
    }

    static int getIntArg(JNIEnv* env, jobjectArray args, int index) {
        jobject obj = getArg(env, args, index);
        if (!obj || !env) return 0;

        jclass integerClass = env->FindClass("java/lang/Integer");
        if (!integerClass) {
            env->ExceptionClear();
            return 0;
        }

        jmethodID intValue = env->GetMethodID(integerClass, "intValue", "()I");
        if (!intValue) {
            env->ExceptionClear();
            env->DeleteLocalRef(integerClass);
            return 0;
        }

        int result = env->CallIntMethod(obj, intValue);
        env->DeleteLocalRef(integerClass);
        return result;
    }

    static float getFloatArg(JNIEnv* env, jobjectArray args, int index) {
        jobject obj = getArg(env, args, index);
        if (!obj || !env) return 0.0f;

        jclass floatClass = env->FindClass("java/lang/Float");
        if (!floatClass) {
            env->ExceptionClear();
            return 0.0f;
        }

        jmethodID floatValue = env->GetMethodID(floatClass, "floatValue", "()F");
        if (!floatValue) {
            env->ExceptionClear();
            env->DeleteLocalRef(floatClass);
            return 0.0f;
        }

        float result = env->CallFloatMethod(obj, floatValue);
        env->DeleteLocalRef(floatClass);
        return result;
    }

    static long getLongArg(JNIEnv* env, jobjectArray args, int index) {
        jobject obj = getArg(env, args, index);
        if (!obj || !env) return 0L;

        jclass longClass = env->FindClass("java/lang/Long");
        if (!longClass) {
            env->ExceptionClear();
            return 0L;
        }

        jmethodID longValue = env->GetMethodID(longClass, "longValue", "()J");
        if (!longValue) {
            env->ExceptionClear();
            env->DeleteLocalRef(longClass);
            return 0L;
        }

        long result = env->CallLongMethod(obj, longValue);
        env->DeleteLocalRef(longClass);
        return result;
    }

    static double getDoubleArg(JNIEnv* env, jobjectArray args, int index) {
        jobject obj = getArg(env, args, index);
        if (!obj || !env) return 0.0;

        jclass doubleClass = env->FindClass("java/lang/Double");
        if (!doubleClass) {
            env->ExceptionClear();
            return 0.0;
        }

        jmethodID doubleValue = env->GetMethodID(doubleClass, "doubleValue", "()D");
        if (!doubleValue) {
            env->ExceptionClear();
            env->DeleteLocalRef(doubleClass);
            return 0.0;
        }

        double result = env->CallDoubleMethod(obj, doubleValue);
        env->DeleteLocalRef(doubleClass);
        return result;
    }

    static bool getBooleanArg(JNIEnv* env, jobjectArray args, int index) {
        jobject obj = getArg(env, args, index);
        if (!obj || !env) return false;

        jclass booleanClass = env->FindClass("java/lang/Boolean");
        if (!booleanClass) {
            env->ExceptionClear();
            return false;
        }

        jmethodID booleanValue = env->GetMethodID(booleanClass, "booleanValue", "()Z");
        if (!booleanValue) {
            env->ExceptionClear();
            env->DeleteLocalRef(booleanClass);
            return false;
        }

        bool result = env->CallBooleanMethod(obj, booleanValue);
        env->DeleteLocalRef(booleanClass);
        return result;
    }

    std::string m_hookName;
    std::string m_methodName;
    std::string m_methodSignature;
    HookPosition m_position;
    int m_hookId;
};

template<typename Derived>
class StaticBaseHook : public BaseHook {
public:
    explicit StaticBaseHook(HookPosition position = HookPosition::PRE)
        : BaseHook(Derived::getHookName(), position) {}
};

#endif
