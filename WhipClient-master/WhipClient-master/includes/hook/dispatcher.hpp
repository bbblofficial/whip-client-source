

#pragma once

#include <jni.h>
#include <functional>
#include <vector>

using PreHookFn = jint (*)(JNIEnv* env, jint hookId, jobjectArray args);
using OverrideHookFn = jobject (*)(JNIEnv* env, jint hookId, jobjectArray args);
using PostHookFn = void (*)(JNIEnv* env, jint hookId, jobject result, jobjectArray args);

struct HookCallbacks {
    PreHookFn preHook = nullptr;
    OverrideHookFn overrideHook = nullptr;
    PostHookFn postHook = nullptr;
};

class DispatcherHook {
public:

    static bool Initialize(JNIEnv* env, jobject classLoader = nullptr);

    static void Shutdown();

    static int RegisterHook(HookCallbacks callbacks);

    static int CreateHook(JNIEnv* env, jmethodID method, HookCallbacks callbacks);

    struct PendingHook {
        jmethodID method;
        HookCallbacks callbacks;
        int hookId = -1;
    };
    static bool CreateHooksBatch(JNIEnv* env, std::vector<PendingHook>& hooks);

    static bool IsInitialized();

    static jclass GetDispatcherClass();

    static jobject GetBooleanTrue();

    static jobject GetBooleanFalse();

    static void InvalidateHook(int hookId);

    static void WaitForActiveCallsToComplete();
};
