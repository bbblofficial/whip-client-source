#pragma once
#include <vector>
#include <array>
#include "../../../../../includes/wrapper/primitive/JavaObject.h"
#include "../../../../../includes/util/RenderMatrixSnapshot.h"

class ActiveRenderInfo : public JavaObject {
    static jclass activeRenderInfoClass;
    static jfieldID modelviewId;
    static jfieldID projectionId;

public:
    ActiveRenderInfo(JNIEnv* env, jobject obj) : JavaObject(env, obj) {}

    static jobject getModelview(JNIEnv* env) {
        if (!activeRenderInfoClass) activeRenderInfoClass = mappings->getClass("ActiveRenderInfo");
        if (!modelviewId) modelviewId = mappings->getField("ActiveRenderInfo#MODELVIEW");
        return env->GetStaticObjectField(activeRenderInfoClass, modelviewId);
    }

    static jobject getProjection(JNIEnv* env) {
        if (!activeRenderInfoClass) activeRenderInfoClass = mappings->getClass("ActiveRenderInfo");
        if (!projectionId) projectionId = mappings->getField("ActiveRenderInfo#PROJECTION");
        return env->GetStaticObjectField(activeRenderInfoClass, projectionId);
    }

    static std::vector<float> GetProjectionMatrix(JNIEnv* env) {
        std::array<float, 16> snap{};
        if (RenderMatrixSnapshot::get().getProjection(snap)) {
            return std::vector<float>(snap.begin(), snap.end());
        }

        jobject projectionObject = getProjection(env);
        if (!projectionObject) {
            if (env->ExceptionCheck()) env->ExceptionClear();
            return {};
        }

        jclass floatBufferClass = env->FindClass("java/nio/FloatBuffer");
        jmethodID getMethod = env->GetMethodID(floatBufferClass, "get", "(I)F");

        std::vector<float> ret;
        for (int i = 0; i < 16; i++) {
            ret.push_back(env->CallFloatMethod(projectionObject, getMethod, i));
        }

        env->DeleteLocalRef(projectionObject);
        env->DeleteLocalRef(floatBufferClass);
        return ret;
    }

    static std::vector<float> GetModelViewMatrix(JNIEnv* env) {
        std::array<float, 16> snap{};
        if (RenderMatrixSnapshot::get().getModelView(snap)) {
            return std::vector<float>(snap.begin(), snap.end());
        }

        jobject modelViewObject = getModelview(env);
        if (!modelViewObject) {
            if (env->ExceptionCheck()) env->ExceptionClear();
            return {};
        }

        jclass floatBufferClass = env->FindClass("java/nio/FloatBuffer");
        jmethodID getMethod = env->GetMethodID(floatBufferClass, "get", "(I)F");

        std::vector<float> ret;
        for (int i = 0; i < 16; i++) {
            ret.push_back(env->CallFloatMethod(modelViewObject, getMethod, i));
        }

        env->DeleteLocalRef(modelViewObject);
        env->DeleteLocalRef(floatBufferClass);
        return ret;
    }
};
