#pragma once

#include <jni.h>

#include "handler/MappingHandler.h"

class GlStateManager {
private:
    static jclass cachedClass(JNIEnv* ) {
        static jclass cls = nullptr;
        if (!cls) cls = Mappings::getInstance().getClass("GlStateManager");
        return cls;
    }

public:
    static void depthMask(JNIEnv* env, bool flag) {
        jclass cls = cachedClass(env);
        if (!cls) return;
        if (jmethodID mid = Mappings::getInstance().getMethod("GlStateManager#depthMask")) {
            env->CallStaticVoidMethod(cls, mid, (jboolean)flag);
            if (env->ExceptionCheck()) env->ExceptionClear();
        }
    }

    static void enableDepth(JNIEnv* env) {
        jclass cls = cachedClass(env);
        if (!cls) return;
        if (jmethodID mid = Mappings::getInstance().getMethod("GlStateManager#enableDepth")) {
            env->CallStaticVoidMethod(cls, mid);
            if (env->ExceptionCheck()) env->ExceptionClear();
        }
    }

    static void disableBlend(JNIEnv* env) {
        jclass cls = cachedClass(env);
        if (!cls) return;
        if (jmethodID mid = Mappings::getInstance().getMethod("GlStateManager#disableBlend")) {
            env->CallStaticVoidMethod(cls, mid);
            if (env->ExceptionCheck()) env->ExceptionClear();
        }
    }

    static void enableTexture2D(JNIEnv* env) {
        jclass cls = cachedClass(env);
        if (!cls) return;
        if (jmethodID mid = Mappings::getInstance().getMethod("GlStateManager#enableTexture2D")) {
            env->CallStaticVoidMethod(cls, mid);
            if (env->ExceptionCheck()) env->ExceptionClear();
        }
    }

    static void enableLighting(JNIEnv* env) {
        jclass cls = cachedClass(env);
        if (!cls) return;
        if (jmethodID mid = Mappings::getInstance().getMethod("GlStateManager#enableLighting")) {
            env->CallStaticVoidMethod(cls, mid);
            if (env->ExceptionCheck()) env->ExceptionClear();
        }
    }

    static void color(JNIEnv* env, float r, float g, float b, float a) {
        jclass cls = cachedClass(env);
        if (!cls) return;
        if (jmethodID mid = Mappings::getInstance().getMethod("GlStateManager#color")) {
            env->CallStaticVoidMethod(cls, mid, r, g, b, a);
            if (env->ExceptionCheck()) env->ExceptionClear();
        }
    }
};
