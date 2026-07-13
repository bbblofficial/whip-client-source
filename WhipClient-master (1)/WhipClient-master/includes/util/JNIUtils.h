#pragma once

#include <jni.h>
#include <jvmti.h>
#include <string>

#include "includes/util/debug.h"

static jclass findClassWithThreads(JNIEnv* jenv, const char* name, jobject* classLoader = nullptr) {
    jclass threadClass = jenv->FindClass("java/lang/Thread");
    jclass classClass = jenv->FindClass("java/lang/Class");
    jclass classLoaderClass = jenv->FindClass("java/lang/ClassLoader");
    jmethodID getContext = jenv->GetMethodID(threadClass, "getContextClassLoader", "()Ljava/lang/ClassLoader;");

    jmethodID loadClassMethod = jenv->GetMethodID(classLoaderClass, "loadClass", "(Ljava/lang/String;)Ljava/lang/Class;");

    jclass mapClass = jenv->FindClass("java/util/Map");
    jclass setClass = jenv->FindClass("java/util/Set");
    jmethodID stackTracesMethod = jenv->GetStaticMethodID(threadClass, "getAllStackTraces", "()Ljava/util/Map;");
    jmethodID keySetMethod = jenv->GetMethodID(mapClass, "keySet", "()Ljava/util/Set;");
    jmethodID toArrayMethod = jenv->GetMethodID(setClass, "toArray", "()[Ljava/lang/Object;");
    jclass o = 0;

    std::string dotted = name;
    for (char& ch : dotted) if (ch == '/') ch = '.';

    if (classClass) {
        jobject stackTraces = jenv->CallStaticObjectMethod(threadClass, stackTracesMethod);
        jobject keysStackTraces = stackTraces ? jenv->CallObjectMethod(stackTraces, keySetMethod) : nullptr;
        jobjectArray threadsArray = keysStackTraces ? (jobjectArray)jenv->CallObjectMethod(keysStackTraces, toArrayMethod) : nullptr;
        if (threadsArray) {
            jint threadsArrayLength = jenv->GetArrayLength(threadsArray);

            jstring sName = (jstring)jenv->NewGlobalRef(jenv->NewStringUTF(dotted.c_str()));
            for (int i = 1; i < threadsArrayLength; i++) {
                jobject threadObject = jenv->GetObjectArrayElement(threadsArray, i);
                if (!threadObject) continue;
                jobject threadClassLoader = jenv->CallObjectMethod(threadObject, getContext);
                jenv->DeleteLocalRef(threadObject);
                if (!threadClassLoader) continue;
                if (loadClassMethod && (o = (jclass)jenv->CallObjectMethod(threadClassLoader, loadClassMethod, sName))) {
                    if (!classLoader) jenv->DeleteLocalRef(threadClassLoader);
                    else *classLoader = threadClassLoader;
                    break;
                }
                if (jenv->ExceptionCheck()) jenv->ExceptionClear();
                jenv->DeleteLocalRef(threadClassLoader);
            }
            jenv->DeleteGlobalRef(sName);
        }
#ifdef DEBUGMODE
        else
#endif

        if (threadsArray) jenv->DeleteLocalRef(threadsArray);
    }

    if (threadClass) jenv->DeleteLocalRef(threadClass);
    if (classClass) jenv->DeleteLocalRef(classClass);
    if (classLoaderClass) jenv->DeleteLocalRef(classLoaderClass);

    return o;
}

static jclass findClassViaJvmti(JNIEnv* env, const char* name) {
    JavaVM* vm = nullptr;
    if (env->GetJavaVM(&vm) != JNI_OK || !vm) return nullptr;

    jvmtiEnv* jvmti = nullptr;
    if (vm->GetEnv(reinterpret_cast<void**>(&jvmti), JVMTI_VERSION_1_2) != JNI_OK || !jvmti) {
        return nullptr;
    }

    jint count = 0;
    jclass* classes = nullptr;
    if (jvmti->GetLoadedClasses(&count, &classes) != JVMTI_ERROR_NONE || !classes) {
        return nullptr;
    }

    std::string target = "L";
    target += name;
    target += ';';

    jclass result = nullptr;
    for (jint i = 0; i < count; ++i) {
        char* sig = nullptr;
        if (jvmti->GetClassSignature(classes[i], &sig, nullptr) == JVMTI_ERROR_NONE && sig) {
            if (target == sig) {
                result = static_cast<jclass>(env->NewLocalRef(classes[i]));
                jvmti->Deallocate(reinterpret_cast<unsigned char*>(sig));
                break;
            }
            jvmti->Deallocate(reinterpret_cast<unsigned char*>(sig));
        }
    }
    jvmti->Deallocate(reinterpret_cast<unsigned char*>(classes));
    return result;
}

inline std::string jstring2string(JNIEnv *env, const jstring jStr) {
    const char *cstr = env->GetStringUTFChars(jStr, nullptr);
    auto str = std::string(cstr);
    env->ReleaseStringUTFChars(jStr, cstr);
    return str;
}
