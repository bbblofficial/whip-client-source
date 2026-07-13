#pragma once

#include "../../../../../includes/wrapper/primitive/JavaObject.h"
#include <array>

class ActiveRenderInfo2 : public JavaObject {
    static jclass activeRenderInfoClass;

    static jfieldID rotationXId;
    static jfieldID rotationZId;
    static jfieldID rotationYZId;
    static jfieldID rotationXYId;
    static jfieldID rotationXZId;

    static jfieldID modelviewId;
    static jfieldID projectionId;
    static jfieldID viewportId;

public:
    ActiveRenderInfo2(JNIEnv* env, jobject obj) : JavaObject(env, obj) {}

    static ActiveRenderInfo2 getInstance(JNIEnv* env) {
        if (!env) return { nullptr, nullptr };
        if (!activeRenderInfoClass) {
            activeRenderInfoClass = mappings->getClass("ActiveRenderInfo");
        }

        ActiveRenderInfo2 result{ env, reinterpret_cast<jobject>(activeRenderInfoClass) };
        result.setDeleteRef(false);
        return result;
    }

    [[nodiscard]] float getRotationX() const {
        if (!activeRenderInfoClass) activeRenderInfoClass = mappings->getClass("ActiveRenderInfo");
        if (!rotationXId) rotationXId = mappings->getField("ActiveRenderInfo#rotationX");

        return env->GetStaticFloatField(activeRenderInfoClass, rotationXId);
    }

    [[nodiscard]] float getRotationZ() const {
        if (!activeRenderInfoClass) activeRenderInfoClass = mappings->getClass("ActiveRenderInfo");
        if (!rotationZId) rotationZId = mappings->getField("ActiveRenderInfo#rotationZ");

        return env->GetStaticFloatField(activeRenderInfoClass, rotationZId);
    }

    [[nodiscard]] float getRotationYZ() const {
        if (!activeRenderInfoClass) activeRenderInfoClass = mappings->getClass("ActiveRenderInfo");
        if (!rotationYZId) rotationYZId = mappings->getField("ActiveRenderInfo#rotationYZ");

        return env->GetStaticFloatField(activeRenderInfoClass, rotationYZId);
    }

    [[nodiscard]] float getRotationXY() const {
        if (!activeRenderInfoClass) activeRenderInfoClass = mappings->getClass("ActiveRenderInfo");
        if (!rotationXYId) rotationXYId = mappings->getField("ActiveRenderInfo#rotationXY");

        return env->GetStaticFloatField(activeRenderInfoClass, rotationXYId);
    }

    [[nodiscard]] float getRotationXZ() const {
        if (!activeRenderInfoClass) activeRenderInfoClass = mappings->getClass("ActiveRenderInfo");
        if (!rotationXZId) rotationXZId = mappings->getField("ActiveRenderInfo#rotationXZ");

        return env->GetStaticFloatField(activeRenderInfoClass, rotationXZId);
    }

    void getModelView(std::array<double, 16>& arr) const;
    void getProjection(std::array<double, 16>& arr) const;
    void getModelViewF(std::array<float, 16>& arr) const;
    void getProjectionF(std::array<float, 16>& arr) const;
    void getViewport(std::array<int, 4>& arr) const;
};
