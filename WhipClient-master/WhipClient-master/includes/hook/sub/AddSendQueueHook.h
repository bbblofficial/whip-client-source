#pragma once

#include "../includes/hook/base/BaseHook.h"
#include "../includes/bus/EventBus.h"
#include "../includes/event/sub/AddSendQueueEvent.h"

class AddSendQueueHook final : public StaticBaseHook<AddSendQueueHook> {
public:
    AddSendQueueHook() : StaticBaseHook(HookPosition::PRE) {}

    ~AddSendQueueHook() override = default;

    static std::string getHookName() {
        return "NetHandlerPlayClient#addToSendQueue";
    }

protected:
    HookResult onPreExecute(JNIEnv* env, jobjectArray args) override {
        if (!env) {
            return HookResult::Continue();
        }

        jobject packetObj = getArg(env, args, 1);
        if (!packetObj) {
            return HookResult::Continue();
        }

        jclass packetClass = env->GetObjectClass(packetObj);
        if (!packetClass) {
            return HookResult::Continue();
        }

        jmethodID getClassMethod = env->GetMethodID(packetClass, "getClass", "()Ljava/lang/Class;");
        if (!getClassMethod) {
            env->DeleteLocalRef(packetClass);
            return HookResult::Continue();
        }

        jobject classObject = env->CallObjectMethod(packetObj, getClassMethod);
        if (!classObject) {
            env->DeleteLocalRef(packetClass);
            return HookResult::Continue();
        }

        jclass classClass = env->FindClass("java/lang/Class");
        if (!classClass) {
            env->DeleteLocalRef(packetClass);
            env->DeleteLocalRef(classObject);
            return HookResult::Continue();
        }

        jmethodID getNameMethod = env->GetMethodID(classClass, "getName", "()Ljava/lang/String;");
        env->DeleteLocalRef(classClass);

        if (!getNameMethod) {
            env->DeleteLocalRef(packetClass);
            env->DeleteLocalRef(classObject);
            return HookResult::Continue();
        }

        auto className = static_cast<jstring>(env->CallObjectMethod(classObject, getNameMethod));
        env->DeleteLocalRef(classObject);

        if (!className) {
            env->DeleteLocalRef(packetClass);
            return HookResult::Continue();
        }

        const char* nativeString = env->GetStringUTFChars(className, nullptr);
        if (!nativeString) {
            env->DeleteLocalRef(packetClass);
            env->DeleteLocalRef(className);
            return HookResult::Continue();
        }

        AddSendQueueEvent event(env, nativeString, packetObj);
        EventBus::getInstance().dispatch(event);

        bool cancelled = event.isCancelled();

        env->ReleaseStringUTFChars(className, nativeString);
        env->DeleteLocalRef(className);
        env->DeleteLocalRef(packetClass);

        if (cancelled) {
            return HookResult::Cancel(env);
        }

        return HookResult::Continue();
    }
};
