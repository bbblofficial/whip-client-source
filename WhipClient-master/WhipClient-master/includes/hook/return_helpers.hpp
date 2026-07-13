

#pragma once

#include <jni.h>

class DispatcherHook;

namespace DispatcherGlobals {
    extern jobject GetBooleanTrue();
    extern jobject GetBooleanFalse();
}

namespace HookReturnHelpers {

    inline jobject ReturnNull(JNIEnv* env) {
        return nullptr;
    }

    inline jobject ReturnFalse(JNIEnv* env) {
        jobject globalFalse = DispatcherGlobals::GetBooleanFalse();
        if (!globalFalse) {

            jclass boolClass = env->FindClass("java/lang/Boolean");
            if (!boolClass) return nullptr;

            jmethodID valueOf = env->GetStaticMethodID(boolClass, "valueOf", "(Z)Ljava/lang/Boolean;");
            if (!valueOf) {
                env->DeleteLocalRef(boolClass);
                return nullptr;
            }

            jobject result = env->CallStaticObjectMethod(boolClass, valueOf, JNI_FALSE);
            env->DeleteLocalRef(boolClass);
            return result;
        }

        return env->NewLocalRef(globalFalse);
    }

    inline jobject ReturnTrue(JNIEnv* env) {
        jobject globalTrue = DispatcherGlobals::GetBooleanTrue();
        if (!globalTrue) {

            jclass boolClass = env->FindClass("java/lang/Boolean");
            if (!boolClass) return nullptr;

            jmethodID valueOf = env->GetStaticMethodID(boolClass, "valueOf", "(Z)Ljava/lang/Boolean;");
            if (!valueOf) {
                env->DeleteLocalRef(boolClass);
                return nullptr;
            }

            jobject result = env->CallStaticObjectMethod(boolClass, valueOf, JNI_TRUE);
            env->DeleteLocalRef(boolClass);
            return result;
        }

        return env->NewLocalRef(globalTrue);
    }

    inline jobject ReturnBoolean(JNIEnv* env, bool value) {
        return value ? ReturnTrue(env) : ReturnFalse(env);
    }

    inline jobject ReturnIntegerZero(JNIEnv* env) {
        jclass intClass = env->FindClass("java/lang/Integer");
        if (!intClass) return nullptr;

        jmethodID valueOf = env->GetStaticMethodID(intClass, "valueOf", "(I)Ljava/lang/Integer;");
        if (!valueOf) {
            env->DeleteLocalRef(intClass);
            return nullptr;
        }

        jobject result = env->CallStaticObjectMethod(intClass, valueOf, 0);
        env->DeleteLocalRef(intClass);
        return result;
    }

    inline jobject ReturnInteger(JNIEnv* env, jint value) {
        jclass intClass = env->FindClass("java/lang/Integer");
        if (!intClass) return nullptr;

        jmethodID valueOf = env->GetStaticMethodID(intClass, "valueOf", "(I)Ljava/lang/Integer;");
        if (!valueOf) {
            env->DeleteLocalRef(intClass);
            return nullptr;
        }

        jobject result = env->CallStaticObjectMethod(intClass, valueOf, value);
        env->DeleteLocalRef(intClass);
        return result;
    }

    inline jobject ReturnFloatZero(JNIEnv* env) {
        jclass floatClass = env->FindClass("java/lang/Float");
        if (!floatClass) return nullptr;

        jmethodID valueOf = env->GetStaticMethodID(floatClass, "valueOf", "(F)Ljava/lang/Float;");
        if (!valueOf) {
            env->DeleteLocalRef(floatClass);
            return nullptr;
        }

        jobject result = env->CallStaticObjectMethod(floatClass, valueOf, 0.0f);
        env->DeleteLocalRef(floatClass);
        return result;
    }

    inline jobject ReturnFloat(JNIEnv* env, jfloat value) {
        jclass floatClass = env->FindClass("java/lang/Float");
        if (!floatClass) return nullptr;

        jmethodID valueOf = env->GetStaticMethodID(floatClass, "valueOf", "(F)Ljava/lang/Float;");
        if (!valueOf) {
            env->DeleteLocalRef(floatClass);
            return nullptr;
        }

        jobject result = env->CallStaticObjectMethod(floatClass, valueOf, value);
        env->DeleteLocalRef(floatClass);
        return result;
    }

    inline jobject ReturnDoubleZero(JNIEnv* env) {
        jclass doubleClass = env->FindClass("java/lang/Double");
        if (!doubleClass) return nullptr;

        jmethodID valueOf = env->GetStaticMethodID(doubleClass, "valueOf", "(D)Ljava/lang/Double;");
        if (!valueOf) {
            env->DeleteLocalRef(doubleClass);
            return nullptr;
        }

        jobject result = env->CallStaticObjectMethod(doubleClass, valueOf, 0.0);
        env->DeleteLocalRef(doubleClass);
        return result;
    }

    inline jobject ReturnDouble(JNIEnv* env, jdouble value) {
        jclass doubleClass = env->FindClass("java/lang/Double");
        if (!doubleClass) return nullptr;

        jmethodID valueOf = env->GetStaticMethodID(doubleClass, "valueOf", "(D)Ljava/lang/Double;");
        if (!valueOf) {
            env->DeleteLocalRef(doubleClass);
            return nullptr;
        }

        jobject result = env->CallStaticObjectMethod(doubleClass, valueOf, value);
        env->DeleteLocalRef(doubleClass);
        return result;
    }

    inline jobject ReturnLongZero(JNIEnv* env) {
        jclass longClass = env->FindClass("java/lang/Long");
        if (!longClass) return nullptr;

        jmethodID valueOf = env->GetStaticMethodID(longClass, "valueOf", "(J)Ljava/lang/Long;");
        if (!valueOf) {
            env->DeleteLocalRef(longClass);
            return nullptr;
        }

        jobject result = env->CallStaticObjectMethod(longClass, valueOf, (jlong)0);
        env->DeleteLocalRef(longClass);
        return result;
    }

    inline jobject ReturnLong(JNIEnv* env, jlong value) {
        jclass longClass = env->FindClass("java/lang/Long");
        if (!longClass) return nullptr;

        jmethodID valueOf = env->GetStaticMethodID(longClass, "valueOf", "(J)Ljava/lang/Long;");
        if (!valueOf) {
            env->DeleteLocalRef(longClass);
            return nullptr;
        }

        jobject result = env->CallStaticObjectMethod(longClass, valueOf, value);
        env->DeleteLocalRef(longClass);
        return result;
    }

    inline jobject ReturnByteZero(JNIEnv* env) {
        jclass byteClass = env->FindClass("java/lang/Byte");
        if (!byteClass) return nullptr;

        jmethodID valueOf = env->GetStaticMethodID(byteClass, "valueOf", "(B)Ljava/lang/Byte;");
        if (!valueOf) {
            env->DeleteLocalRef(byteClass);
            return nullptr;
        }

        jobject result = env->CallStaticObjectMethod(byteClass, valueOf, (jbyte)0);
        env->DeleteLocalRef(byteClass);
        return result;
    }

    inline jobject ReturnByte(JNIEnv* env, jbyte value) {
        jclass byteClass = env->FindClass("java/lang/Byte");
        if (!byteClass) return nullptr;

        jmethodID valueOf = env->GetStaticMethodID(byteClass, "valueOf", "(B)Ljava/lang/Byte;");
        if (!valueOf) {
            env->DeleteLocalRef(byteClass);
            return nullptr;
        }

        jobject result = env->CallStaticObjectMethod(byteClass, valueOf, value);
        env->DeleteLocalRef(byteClass);
        return result;
    }

    inline jobject ReturnShortZero(JNIEnv* env) {
        jclass shortClass = env->FindClass("java/lang/Short");
        if (!shortClass) return nullptr;

        jmethodID valueOf = env->GetStaticMethodID(shortClass, "valueOf", "(S)Ljava/lang/Short;");
        if (!valueOf) {
            env->DeleteLocalRef(shortClass);
            return nullptr;
        }

        jobject result = env->CallStaticObjectMethod(shortClass, valueOf, (jshort)0);
        env->DeleteLocalRef(shortClass);
        return result;
    }

    inline jobject ReturnShort(JNIEnv* env, jshort value) {
        jclass shortClass = env->FindClass("java/lang/Short");
        if (!shortClass) return nullptr;

        jmethodID valueOf = env->GetStaticMethodID(shortClass, "valueOf", "(S)Ljava/lang/Short;");
        if (!valueOf) {
            env->DeleteLocalRef(shortClass);
            return nullptr;
        }

        jobject result = env->CallStaticObjectMethod(shortClass, valueOf, value);
        env->DeleteLocalRef(shortClass);
        return result;
    }

    inline jobject ReturnObject(JNIEnv* env, jobject value) {
        return value;
    }

}
