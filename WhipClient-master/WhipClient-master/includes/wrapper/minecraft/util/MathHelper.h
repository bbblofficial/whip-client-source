#pragma once
#include "../../../../includes/wrapper/primitive/javaobject.h"

class MathHelper : public JavaObject {
    static jclass mathHelperClass;
    static jmethodID sinId;
    static jmethodID cosId;

public:
    MathHelper(JNIEnv* env, jobject obj) : JavaObject(env, obj) {}

    static float sin(JNIEnv* env, float value) {
        if (!mathHelperClass) mathHelperClass = mappings->getClass("MathHelper");
        if (!sinId) sinId = mappings->getMethod("MathHelper#sin");

        return env->CallStaticFloatMethod(mathHelperClass, sinId, value);
    }

    static float cos(JNIEnv* env, float value) {
        if (!mathHelperClass) mathHelperClass = mappings->getClass("MathHelper");
        if (!cosId) cosId = mappings->getMethod("MathHelper#cos");

        return env->CallStaticFloatMethod(mathHelperClass, cosId, value);
    }
};
