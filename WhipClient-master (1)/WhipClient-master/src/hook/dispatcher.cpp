#include "../includes/hook/dispatcher.hpp"
#include "../includes/hook/instrumentation.h"
#include "../includes/hook/transformer_registry.hpp"

#include <iostream>
#include <vector>
#include <atomic>
#include <thread>
#include <chrono>
#include <windows.h>

#include "util/Debug.h"
#include "util/MinecraftDetails.h"

static HookCallbacks s_HooksArray[64] = {};
static std::atomic<bool> s_HooksValid[64] = {};
static std::atomic<int> s_NextHookId{1};

static jclass s_DispatcherClass = nullptr;
static jobject s_ClassLoader = nullptr;
static bool s_Initialized = false;

static jobject s_BooleanTrue = nullptr;
static jobject s_BooleanFalse = nullptr;

static std::atomic<int> s_ActiveNativeCalls{0};

class NativeCallGuard {
private:
    bool m_tracked;
public:
    NativeCallGuard() : m_tracked(s_Initialized) {
        if (m_tracked) {
            s_ActiveNativeCalls.fetch_add(1, std::memory_order_acquire);
        }
    }
    ~NativeCallGuard() {
        if (m_tracked) {
            s_ActiveNativeCalls.fetch_sub(1, std::memory_order_release);
        }
    }
    NativeCallGuard(const NativeCallGuard&) = delete;
    NativeCallGuard& operator=(const NativeCallGuard&) = delete;
};

static constexpr uint8_t DISPATCHER_BYTECODE[] = {

    0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x00, 0x00, 0x34, 0x00, 0x18, 0x0A, 0x00, 0x02, 0x00, 0x03, 0x07,
    0x00, 0x04, 0x0C, 0x00, 0x05, 0x00, 0x06, 0x01, 0x00, 0x10, 0x6A, 0x61, 0x76, 0x61, 0x2F, 0x6C,
    0x61, 0x6E, 0x67, 0x2F, 0x4F, 0x62, 0x6A, 0x65, 0x63, 0x74, 0x01, 0x00, 0x06, 0x3C, 0x69, 0x6E,
    0x69, 0x74, 0x3E, 0x01, 0x00, 0x03, 0x28, 0x29, 0x56, 0x09, 0x00, 0x08, 0x00, 0x09, 0x07, 0x00,
    0x0A, 0x0C, 0x00, 0x0B, 0x00, 0x0C, 0x01, 0x00, 0x27, 0x6F, 0x72, 0x67, 0x2F, 0x61, 0x70, 0x61,
    0x63, 0x68, 0x65, 0x2F, 0x63, 0x6F, 0x6D, 0x6D, 0x6F, 0x6E, 0x73, 0x2F, 0x69, 0x6E, 0x74, 0x65,
    0x72, 0x6E, 0x61, 0x6C, 0x2F, 0x50, 0x65, 0x72, 0x66, 0x43, 0x6F, 0x75, 0x6E, 0x74, 0x65, 0x72,
    0x01, 0x00, 0x07, 0x65, 0x6E, 0x61, 0x62, 0x6C, 0x65, 0x64, 0x01, 0x00, 0x01, 0x5A, 0x01, 0x00,
    0x04, 0x43, 0x6F, 0x64, 0x65, 0x01, 0x00, 0x0F, 0x4C, 0x69, 0x6E, 0x65, 0x4E, 0x75, 0x6D, 0x62,
    0x65, 0x72, 0x54, 0x61, 0x62, 0x6C, 0x65, 0x01, 0x00, 0x03, 0x70, 0x72, 0x65, 0x01, 0x00, 0x17,
    0x28, 0x49, 0x5B, 0x4C, 0x6A, 0x61, 0x76, 0x61, 0x2F, 0x6C, 0x61, 0x6E, 0x67, 0x2F, 0x4F, 0x62,
    0x6A, 0x65, 0x63, 0x74, 0x3B, 0x29, 0x49, 0x01, 0x00, 0x08, 0x6F, 0x76, 0x65, 0x72, 0x72, 0x69,
    0x64, 0x65, 0x01, 0x00, 0x28, 0x28, 0x49, 0x5B, 0x4C, 0x6A, 0x61, 0x76, 0x61, 0x2F, 0x6C, 0x61,
    0x6E, 0x67, 0x2F, 0x4F, 0x62, 0x6A, 0x65, 0x63, 0x74, 0x3B, 0x29, 0x4C, 0x6A, 0x61, 0x76, 0x61,
    0x2F, 0x6C, 0x61, 0x6E, 0x67, 0x2F, 0x4F, 0x62, 0x6A, 0x65, 0x63, 0x74, 0x3B, 0x01, 0x00, 0x04,
    0x70, 0x6F, 0x73, 0x74, 0x01, 0x00, 0x29, 0x28, 0x49, 0x4C, 0x6A, 0x61, 0x76, 0x61, 0x2F, 0x6C,
    0x61, 0x6E, 0x67, 0x2F, 0x4F, 0x62, 0x6A, 0x65, 0x63, 0x74, 0x3B, 0x5B, 0x4C, 0x6A, 0x61, 0x76,
    0x61, 0x2F, 0x6C, 0x61, 0x6E, 0x67, 0x2F, 0x4F, 0x62, 0x6A, 0x65, 0x63, 0x74, 0x3B, 0x29, 0x56,
    0x01, 0x00, 0x08, 0x3C, 0x63, 0x6C, 0x69, 0x6E, 0x69, 0x74, 0x3E, 0x01, 0x00, 0x0A, 0x53, 0x6F,
    0x75, 0x72, 0x63, 0x65, 0x46, 0x69, 0x6C, 0x65, 0x01, 0x00, 0x10, 0x50, 0x65, 0x72, 0x66, 0x43,
    0x6F, 0x75, 0x6E, 0x74, 0x65, 0x72, 0x2E, 0x6A, 0x61, 0x76, 0x61, 0x00, 0x21, 0x00, 0x08, 0x00,
    0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x49, 0x00, 0x0B, 0x00, 0x0C, 0x00, 0x00, 0x00, 0x05, 0x00,
    0x01, 0x00, 0x05, 0x00, 0x06, 0x00, 0x01, 0x00, 0x0D, 0x00, 0x00, 0x00, 0x21, 0x00, 0x01, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x05, 0x2A, 0xB7, 0x00, 0x01, 0xB1, 0x00, 0x00, 0x00, 0x01, 0x00, 0x0E,
    0x00, 0x00, 0x00, 0x0A, 0x00, 0x02, 0x00, 0x00, 0x00, 0x19, 0x00, 0x04, 0x00, 0x1A, 0x01, 0x09,
    0x00, 0x0F, 0x00, 0x10, 0x00, 0x00, 0x01, 0x09, 0x00, 0x11, 0x00, 0x12, 0x00, 0x00, 0x01, 0x09,
    0x00, 0x13, 0x00, 0x14, 0x00, 0x00, 0x00, 0x08, 0x00, 0x15, 0x00, 0x06, 0x00, 0x01, 0x00, 0x0D,
    0x00, 0x00, 0x00, 0x1D, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x04, 0xB3, 0x00, 0x07,
    0xB1, 0x00, 0x00, 0x00, 0x01, 0x00, 0x0E, 0x00, 0x00, 0x00, 0x06, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x14, 0x00, 0x01, 0x00, 0x16, 0x00, 0x00, 0x00, 0x02, 0x00, 0x17
};
static constexpr size_t DISPATCHER_BYTECODE_SIZE = sizeof(DISPATCHER_BYTECODE);

static jint JNICALL NativePre(JNIEnv* env, jclass, jint hookId, jobjectArray args) {
    NativeCallGuard guard;

    if (!s_Initialized) return 0;
    if (!args) return 0;

    if (hookId >= 1 && hookId < 64 && s_HooksValid[hookId].load(std::memory_order_acquire)) {
        PreHookFn fn = s_HooksArray[hookId].preHook;
        if (fn) {
            return fn(env, hookId, args);
        }
    }
    return 0;
}

static jobject JNICALL NativeOverride(JNIEnv* env, jclass, jint hookId, jobjectArray args) {
    NativeCallGuard guard;

    if (!s_Initialized) return nullptr;
    if (!args) return nullptr;

    if (hookId >= 1 && hookId < 64 && s_HooksValid[hookId].load(std::memory_order_acquire)) {
        OverrideHookFn fn = s_HooksArray[hookId].overrideHook;
        if (fn) {
            return fn(env, hookId, args);
        }
    }
    return nullptr;
}

static void JNICALL NativePost(JNIEnv* env, jclass, jint hookId, jobject result, jobjectArray args) {
    NativeCallGuard guard;

    if (!s_Initialized) return;
    if (!args) return;

    if (hookId >= 1 && hookId < 64 && s_HooksValid[hookId].load(std::memory_order_acquire)) {
        PostHookFn fn = s_HooksArray[hookId].postHook;
        if (fn) {
            fn(env, hookId, result, args);
        }
    }
}

bool DispatcherHook::Initialize(JNIEnv* env, jobject classLoader) {
    if (s_Initialized) return true;

    if (!TransformerRegistry::Initialize(env)) {
        std::cerr << "[DispatcherHook] Failed to initialize TransformerRegistry." << std::endl;
        return false;
    }

    jobject gameClassLoader = classLoader;

    if (!gameClassLoader) {

        jclass threadClass = env->FindClass("java/lang/Thread");
        jclass classLoaderClass = env->FindClass("java/lang/ClassLoader");
        jclass mapClass = env->FindClass("java/util/Map");
        jclass setClass = env->FindClass("java/util/Set");

        if (threadClass && classLoaderClass && mapClass && setClass) {
            jmethodID getContext = env->GetMethodID(threadClass, "getContextClassLoader", "()Ljava/lang/ClassLoader;");
            jmethodID loadClassMethod = env->GetMethodID(classLoaderClass, "loadClass", "(Ljava/lang/String;)Ljava/lang/Class;");
            jmethodID stackTracesMethod = env->GetStaticMethodID(threadClass, "getAllStackTraces", "()Ljava/util/Map;");
            jmethodID keySetMethod = env->GetMethodID(mapClass, "keySet", "()Ljava/util/Set;");
            jmethodID toArrayMethod = env->GetMethodID(setClass, "toArray", "()[Ljava/lang/Object;");

            jobject stackTraces = env->CallStaticObjectMethod(threadClass, stackTracesMethod);
            jobject keysStackTraces = stackTraces ? env->CallObjectMethod(stackTraces, keySetMethod) : nullptr;
            jobjectArray threadsArray = keysStackTraces ? (jobjectArray)env->CallObjectMethod(keysStackTraces, toArrayMethod) : nullptr;

            if (threadsArray) {
                jint threadsArrayLength = env->GetArrayLength(threadsArray);
                jstring testClassName = env->NewStringUTF("net.minecraft.client.Minecraft");

                for (int i = 0; i < threadsArrayLength && !gameClassLoader; i++) {
                    jobject threadObject = env->GetObjectArrayElement(threadsArray, i);
                    if (!threadObject) continue;

                    jobject threadClassLoader = env->CallObjectMethod(threadObject, getContext);
                    env->DeleteLocalRef(threadObject);
                    if (!threadClassLoader) continue;

                    jclass testClass = (jclass)env->CallObjectMethod(threadClassLoader, loadClassMethod, testClassName);
                    if (env->ExceptionCheck()) {
                        env->ExceptionClear();
                        env->DeleteLocalRef(threadClassLoader);
                        continue;
                    }

                    if (testClass) {
                        gameClassLoader = threadClassLoader;
                        env->DeleteLocalRef(testClass);
                    } else {
                        env->DeleteLocalRef(threadClassLoader);
                    }
                }

                env->DeleteLocalRef(testClassName);
                env->DeleteLocalRef(threadsArray);
            }

            if (keysStackTraces) env->DeleteLocalRef(keysStackTraces);
            if (stackTraces) env->DeleteLocalRef(stackTraces);
        }

        if (threadClass) env->DeleteLocalRef(threadClass);
        if (classLoaderClass) env->DeleteLocalRef(classLoaderClass);
        if (mapClass) env->DeleteLocalRef(mapClass);
        if (setClass) env->DeleteLocalRef(setClass);

        if (!gameClassLoader) {
            jclass clClass = env->FindClass("java/lang/ClassLoader");
            jmethodID getSystemClassLoader = env->GetStaticMethodID(clClass, "getSystemClassLoader", "()Ljava/lang/ClassLoader;");
            gameClassLoader = env->CallStaticObjectMethod(clClass, getSystemClassLoader);
            env->DeleteLocalRef(clClass);
        }
    }

    if (gameClassLoader) {
        s_ClassLoader = env->NewGlobalRef(gameClassLoader);
    }

    auto captureExc = [&](const char* where) -> std::string {
        if (!env->ExceptionCheck()) return {};
        jthrowable t = env->ExceptionOccurred();
        env->ExceptionClear();
        std::string msg = "(could not extract message)";
        if (t) {
            jclass tClass = env->GetObjectClass(t);
            if (tClass) {
                jmethodID toString = env->GetMethodID(tClass, "toString", "()Ljava/lang/String;");
                if (toString) {
                    jstring js = (jstring)env->CallObjectMethod(t, toString);
                    if (js) {
                        const char* c = env->GetStringUTFChars(js, nullptr);
                        if (c) { msg = c; env->ReleaseStringUTFChars(js, c); }
                        env->DeleteLocalRef(js);
                    }
                    if (env->ExceptionCheck()) env->ExceptionClear();
                }
                env->DeleteLocalRef(tClass);
            }
            env->DeleteLocalRef(t);
        }
        std::cerr << "[DispatcherHook] " << where << " exception: " << msg << std::endl;
        return msg;
    };

    s_DispatcherClass = env->DefineClass(
        "org/apache/commons/internal/PerfCounter",
        gameClassLoader,
        reinterpret_cast<const jbyte*>(DISPATCHER_BYTECODE),
        DISPATCHER_BYTECODE_SIZE
    );

    if (!s_DispatcherClass || env->ExceptionCheck()) {
        captureExc("DefineClass(PerfCounter)");

        if (gameClassLoader) {
            jclass classLoaderClass = env->FindClass("java/lang/ClassLoader");
            if (classLoaderClass) {
                jmethodID loadClassMethod = env->GetMethodID(classLoaderClass, "loadClass", "(Ljava/lang/String;)Ljava/lang/Class;");
                if (loadClassMethod) {
                    jstring dispatcherName = env->NewStringUTF("org.apache.commons.internal.PerfCounter");
                    s_DispatcherClass = (jclass)env->CallObjectMethod(gameClassLoader, loadClassMethod, dispatcherName);
                    env->DeleteLocalRef(dispatcherName);
                    if (env->ExceptionCheck()) {
                        captureExc("loadClass(PerfCounter)");
                        s_DispatcherClass = nullptr;
                    }
                }
                env->DeleteLocalRef(classLoaderClass);
            }
        }

        if (!s_DispatcherClass) {
            s_DispatcherClass = env->FindClass("org/apache/commons/internal/PerfCounter");
            if (env->ExceptionCheck()) {
                captureExc("FindClass(PerfCounter)");
                s_DispatcherClass = nullptr;
            }
        }
    }

    if (!s_DispatcherClass) {
        std::cerr << "[DispatcherHook] Failed to resolve org.apache.commons.internal.PerfCounter class." << std::endl;
        return false;
    }

    s_DispatcherClass = (jclass)env->NewGlobalRef(s_DispatcherClass);

    JNINativeMethod methods[] = {
        { const_cast<char*>("pre"), const_cast<char*>("(I[Ljava/lang/Object;)I"), (void*)&NativePre },
        { const_cast<char*>("override"), const_cast<char*>("(I[Ljava/lang/Object;)Ljava/lang/Object;"), (void*)&NativeOverride },
        { const_cast<char*>("post"), const_cast<char*>("(ILjava/lang/Object;[Ljava/lang/Object;)V"), (void*)&NativePost }
    };

    jint registerResult = env->RegisterNatives(s_DispatcherClass, methods, 3);
    if (registerResult < 0) {
        std::cerr << "[DispatcherHook] CRITICAL: RegisterNatives failed with code: " << registerResult << std::endl;
        if (env->ExceptionCheck()) {
            std::cerr << "[DispatcherHook] Exception details:" << std::endl;
            env->ExceptionDescribe();
            env->ExceptionClear();
        }
        return false;
    }

    jclass booleanClass = env->FindClass("java/lang/Boolean");
    if (!booleanClass) {
        std::cerr << "[DispatcherHook] Failed to find Boolean class." << std::endl;
        return false;
    }

    jfieldID trueField = env->GetStaticFieldID(booleanClass, "TRUE", "Ljava/lang/Boolean;");
    jfieldID falseField = env->GetStaticFieldID(booleanClass, "FALSE", "Ljava/lang/Boolean;");

    if (!trueField || !falseField) {
        std::cerr << "[DispatcherHook] Failed to get Boolean.TRUE/FALSE fields." << std::endl;
        env->DeleteLocalRef(booleanClass);
        return false;
    }

    jobject localTrue = env->GetStaticObjectField(booleanClass, trueField);
    jobject localFalse = env->GetStaticObjectField(booleanClass, falseField);

    if (!localTrue || !localFalse) {
        std::cerr << "[DispatcherHook] Failed to get Boolean.TRUE/FALSE objects." << std::endl;
        env->DeleteLocalRef(booleanClass);
        return false;
    }

    s_BooleanTrue = env->NewGlobalRef(localTrue);
    s_BooleanFalse = env->NewGlobalRef(localFalse);

    env->DeleteLocalRef(localTrue);
    env->DeleteLocalRef(localFalse);
    env->DeleteLocalRef(booleanClass);

    if (!s_BooleanTrue || !s_BooleanFalse) {
        std::cerr << "[DispatcherHook] Failed to create global references for Boolean values." << std::endl;
        return false;
    }

    JavaVM* jvm = nullptr;
    env->GetJavaVM(&jvm);
    if (jvm) {
        if (!JvmInstrumentor::Get().Initialize(jvm)) {
            std::cerr << "[DispatcherHook] Failed to initialize Instrumentation backend." << std::endl;
            return false;
        }
    }

    {
        jfieldID enabledField = env->GetStaticFieldID(s_DispatcherClass, "enabled", "Z");
        if (enabledField) {
            env->SetStaticBooleanField(s_DispatcherClass, enabledField, JNI_TRUE);
        } else {
            env->ExceptionClear();
        }
    }

    s_Initialized = true;
    return true;
}

static void* s_SafeStubMemory = nullptr;

static void RegisterSafeStubs(JNIEnv* env, jclass dispatcherClass) {
    if (s_SafeStubMemory) return;

    s_SafeStubMemory = VirtualAlloc(nullptr, 64, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!s_SafeStubMemory) {
        std::cerr << "[DispatcherHook] Failed to allocate safe stub memory!" << std::endl;
        return;
    }

    uint8_t stub[] = { 0x33, 0xC0, 0xC3 };
    memcpy(s_SafeStubMemory, stub, sizeof(stub));

    JNINativeMethod methods[] = {
        { const_cast<char*>("pre"), const_cast<char*>("(I[Ljava/lang/Object;)I"), s_SafeStubMemory },
        { const_cast<char*>("override"), const_cast<char*>("(I[Ljava/lang/Object;)Ljava/lang/Object;"), s_SafeStubMemory },
        { const_cast<char*>("post"), const_cast<char*>("(ILjava/lang/Object;[Ljava/lang/Object;)V"), s_SafeStubMemory }
    };

    if (env->RegisterNatives(dispatcherClass, methods, 3) < 0) {
        std::cerr << "[DispatcherHook] Failed to register safe stubs." << std::endl;
        if (env->ExceptionCheck()) env->ExceptionClear();
    }
}

void DispatcherHook::Shutdown() {
    if (!s_Initialized) return;

    JavaVM* jvm = JvmInstrumentor::Get().GetJvm();
    JNIEnv* env = nullptr;

    bool wasAttached = false;
    if (jvm) {
        jint getEnvResult = jvm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_8);
        if (getEnvResult == JNI_EDETACHED) {

            if (jvm->AttachCurrentThread(reinterpret_cast<void**>(&env), nullptr) == JNI_OK) {
                wasAttached = true;
            }
        } else if (getEnvResult == JNI_OK) {
            wasAttached = false;
        }
    }

    if (env && s_DispatcherClass) {
        jfieldID enabledField = env->GetStaticFieldID(s_DispatcherClass, "enabled", "Z");
        if (enabledField) {
            env->SetStaticBooleanField(s_DispatcherClass, enabledField, JNI_FALSE);
        } else {
            std::cerr << "[DispatcherHook] WARNING: Could not find PerfCounter.enabled field!" << std::endl;
            env->ExceptionClear();
        }
    }

    for (int i = 0; i < 64; ++i) {
        s_HooksValid[i].store(false, std::memory_order_release);
        s_HooksArray[i] = {};
    }
    s_NextHookId.store(1, std::memory_order_relaxed);

    if (env && s_DispatcherClass) {
        RegisterSafeStubs(env, s_DispatcherClass);
    }

    while (s_ActiveNativeCalls.load(std::memory_order_acquire) > 0) {
        std::this_thread::yield();
    }

    s_Initialized = false;

    if (env) {

        if (MinecraftSession::getInstance().launcher == MinecraftLauncher::L_CHEATBREAKER) {
        } else {
            JvmInstrumentor::Get().RevertAll(s_ClassLoader);

            jclass systemClass = env->FindClass("java/lang/System");
            if (systemClass) {
                jmethodID gcMethod = env->GetStaticMethodID(systemClass, "gc", "()V");
                if (gcMethod) {
                    env->CallStaticVoidMethod(systemClass, gcMethod);
                }
                env->DeleteLocalRef(systemClass);
            }
        }

        if (s_DispatcherClass) {

            env->DeleteGlobalRef(s_DispatcherClass);
            s_DispatcherClass = nullptr;
        }

        if (s_ClassLoader) {
            env->DeleteGlobalRef(s_ClassLoader);
            s_ClassLoader = nullptr;
        }

        if (s_BooleanTrue) {
            env->DeleteGlobalRef(s_BooleanTrue);
            s_BooleanTrue = nullptr;
        }
        if (s_BooleanFalse) {
            env->DeleteGlobalRef(s_BooleanFalse);
            s_BooleanFalse = nullptr;
        }

        TransformerRegistry::Shutdown(env);

        if (wasAttached && jvm) {
            jvm->DetachCurrentThread();
        }
    }

}

int DispatcherHook::RegisterHook(HookCallbacks callbacks) {
    int hookId = s_NextHookId.load(std::memory_order_relaxed);
    if (hookId >= 64) {
        std::cerr << "[DispatcherHook] Hook limit (64) exceeded!" << std::endl;
        return -1;
    }
    s_NextHookId.store(hookId + 1, std::memory_order_relaxed);
    s_HooksArray[hookId] = callbacks;
    s_HooksValid[hookId].store(true, std::memory_order_release);
    return hookId;
}

int DispatcherHook::CreateHook(JNIEnv* env, jmethodID method, HookCallbacks callbacks) {
    if (!s_Initialized) return -1;

    int hookId = RegisterHook(callbacks);
    if (hookId < 0) return -1;

    jnihook_result_t res = JvmInstrumentor::Get().Instrument(method, [hookId](const std::vector<uint8_t>& originalBytes, const std::string& name, const std::string& sig) -> std::vector<uint8_t> {
        JNIEnv* lambda_env = nullptr;
        JavaVM* jvm = JvmInstrumentor::Get().GetJvm();
        if (!jvm || jvm->GetEnv(reinterpret_cast<void**>(&lambda_env), JNI_VERSION_1_8) != JNI_OK || !lambda_env) {
            std::cerr << "[DispatcherHook] Failed to get JNIEnv in lambda" << std::endl;
            return {};
        }
        return TransformerRegistry::Transform(lambda_env, originalBytes, name, sig, hookId);
    });

    return res == JNIHOOK_OK ? hookId : -1;
}

bool DispatcherHook::CreateHooksBatch(JNIEnv* env, std::vector<PendingHook>& hooks) {
    if (!s_Initialized) return false;

    std::vector<JvmInstrumentor::BatchEntry> batchEntries;
    for (auto& h : hooks) {
        int hookId = RegisterHook(h.callbacks);
        if (hookId < 0) {
            std::cerr << "[DispatcherHook] Failed to register hook in batch" << std::endl;
            return false;
        }
        h.hookId = hookId;

        batchEntries.push_back({h.method, [hookId](const std::vector<uint8_t>& originalBytes, const std::string& name, const std::string& sig) -> std::vector<uint8_t> {
            JNIEnv* lambda_env = nullptr;
            JavaVM* jvm = JvmInstrumentor::Get().GetJvm();
            if (!jvm || jvm->GetEnv(reinterpret_cast<void**>(&lambda_env), JNI_VERSION_1_8) != JNI_OK || !lambda_env) {
                std::cerr << "[DispatcherHook] Failed to get JNIEnv in batch lambda" << std::endl;
                return {};
            }
            return TransformerRegistry::Transform(lambda_env, originalBytes, name, sig, hookId);
        }});
    }

    jnihook_result_t res = JvmInstrumentor::Get().InstrumentBatch(batchEntries);
    if (res != JNIHOOK_OK) {
        std::cout << "[DispatcherHook] ERROR: Batch instrumentation failed with code: " << res << std::endl;

        for (auto& h : hooks) {
            if (h.hookId >= 0) {
                InvalidateHook(h.hookId);
                h.hookId = -1;
            }
        }
        return false;
    }

    return true;
}

bool DispatcherHook::IsInitialized() {
    return s_Initialized;
}

jclass DispatcherHook::GetDispatcherClass() {
    return s_DispatcherClass;
}

jobject DispatcherHook::GetBooleanTrue() {
    return s_BooleanTrue;
}

jobject DispatcherHook::GetBooleanFalse() {
    return s_BooleanFalse;
}

void DispatcherHook::InvalidateHook(int hookId) {
    if (hookId >= 1 && hookId < 64) {
        s_HooksValid[hookId].store(false, std::memory_order_release);
        s_HooksArray[hookId] = {};
    }
}

void DispatcherHook::WaitForActiveCallsToComplete() {
    while (s_ActiveNativeCalls.load(std::memory_order_acquire) > 0) {
        std::this_thread::yield();
    }
}

namespace DispatcherGlobals {
    jobject GetBooleanTrue() {
        return DispatcherHook::GetBooleanTrue();
    }

    jobject GetBooleanFalse() {
        return DispatcherHook::GetBooleanFalse();
    }
}
