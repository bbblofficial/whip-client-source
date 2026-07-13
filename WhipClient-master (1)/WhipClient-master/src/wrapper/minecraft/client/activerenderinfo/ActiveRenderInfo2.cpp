#include "wrapper/minecraft/client/activerenderinfo/ActiveRenderInfo2.h"
#include "util/RenderMatrixSnapshot.h"

jclass ActiveRenderInfo2::activeRenderInfoClass = nullptr;

jfieldID ActiveRenderInfo2::rotationXId = nullptr;
jfieldID ActiveRenderInfo2::rotationZId = nullptr;
jfieldID ActiveRenderInfo2::rotationYZId = nullptr;
jfieldID ActiveRenderInfo2::rotationXYId = nullptr;
jfieldID ActiveRenderInfo2::rotationXZId = nullptr;

jfieldID ActiveRenderInfo2::modelviewId = nullptr;
jfieldID ActiveRenderInfo2::projectionId = nullptr;
jfieldID ActiveRenderInfo2::viewportId = nullptr;

void ActiveRenderInfo2::getModelView(std::array<double, 16>& arr) const {
    if (!env) return;

    std::array<float, 16> snap{};
    if (RenderMatrixSnapshot::get().getModelView(snap)) {
        for (int i = 0; i < 16; i++) arr[i] = static_cast<double>(snap[i]);
        return;
    }

    if (!activeRenderInfoClass) activeRenderInfoClass = mappings->getClass("ActiveRenderInfo");
    if (!modelviewId) modelviewId = mappings->getField("ActiveRenderInfo#MODELVIEW");
    if (!activeRenderInfoClass || !modelviewId) return;

    jobject buffer = env->GetStaticObjectField(activeRenderInfoClass, modelviewId);
    if (!buffer) return;

    jclass bufferClass = env->GetObjectClass(buffer);
    jmethodID getMethod = env->GetMethodID(bufferClass, "get", "(I)F");

    for (int i = 0; i < 16; i++) {
        arr[i] = static_cast<double>(env->CallFloatMethod(buffer, getMethod, i));
    }

    env->DeleteLocalRef(buffer);
    env->DeleteLocalRef(bufferClass);
}

void ActiveRenderInfo2::getProjection(std::array<double, 16>& arr) const {
    if (!env) return;

    std::array<float, 16> snap{};
    if (RenderMatrixSnapshot::get().getProjection(snap)) {
        for (int i = 0; i < 16; i++) arr[i] = static_cast<double>(snap[i]);
        return;
    }

    if (!activeRenderInfoClass) activeRenderInfoClass = mappings->getClass("ActiveRenderInfo");
    if (!projectionId) projectionId = mappings->getField("ActiveRenderInfo#PROJECTION");
    if (!activeRenderInfoClass || !projectionId) return;

    jobject buffer = env->GetStaticObjectField(activeRenderInfoClass, projectionId);
    if (!buffer) return;

    jclass bufferClass = env->GetObjectClass(buffer);
    jmethodID getMethod = env->GetMethodID(bufferClass, "get", "(I)F");

    for (int i = 0; i < 16; i++) {
        arr[i] = static_cast<double>(env->CallFloatMethod(buffer, getMethod, i));
    }

    env->DeleteLocalRef(buffer);
    env->DeleteLocalRef(bufferClass);
}

void ActiveRenderInfo2::getModelViewF(std::array<float, 16>& arr) const {
    if (!env) return;

    if (RenderMatrixSnapshot::get().getModelView(arr)) return;

    if (!activeRenderInfoClass) activeRenderInfoClass = mappings->getClass("ActiveRenderInfo");
    if (!modelviewId) modelviewId = mappings->getField("ActiveRenderInfo#MODELVIEW");
    if (!activeRenderInfoClass || !modelviewId) return;

    jobject buffer = env->GetStaticObjectField(activeRenderInfoClass, modelviewId);
    if (!buffer) return;

    jclass bufferClass = env->GetObjectClass(buffer);
    jmethodID getMethod = env->GetMethodID(bufferClass, "get", "(I)F");

    for (int i = 0; i < 16; i++) {
        arr[i] = env->CallFloatMethod(buffer, getMethod, i);
    }

    env->DeleteLocalRef(buffer);
    env->DeleteLocalRef(bufferClass);
}

void ActiveRenderInfo2::getProjectionF(std::array<float, 16>& arr) const {
    if (!env) return;

    if (RenderMatrixSnapshot::get().getProjection(arr)) return;

    if (!activeRenderInfoClass) activeRenderInfoClass = mappings->getClass("ActiveRenderInfo");
    if (!projectionId) projectionId = mappings->getField("ActiveRenderInfo#PROJECTION");
    if (!activeRenderInfoClass || !projectionId) return;

    jobject buffer = env->GetStaticObjectField(activeRenderInfoClass, projectionId);
    if (!buffer) return;

    jclass bufferClass = env->GetObjectClass(buffer);
    jmethodID getMethod = env->GetMethodID(bufferClass, "get", "(I)F");

    for (int i = 0; i < 16; i++) {
        arr[i] = env->CallFloatMethod(buffer, getMethod, i);
    }

    env->DeleteLocalRef(buffer);
    env->DeleteLocalRef(bufferClass);
}

void ActiveRenderInfo2::getViewport(std::array<int, 4>& arr) const {
    if (!env) return;

    if (!activeRenderInfoClass) activeRenderInfoClass = mappings->getClass("ActiveRenderInfo");
    if (!viewportId) viewportId = mappings->getField("ActiveRenderInfo#VIEWPORT");
    if (!activeRenderInfoClass || !viewportId) return;

    jobject buffer = env->GetStaticObjectField(activeRenderInfoClass, viewportId);
    if (!buffer) return;

    jclass bufferClass = env->GetObjectClass(buffer);
    jmethodID getMethod = env->GetMethodID(bufferClass, "get", "(I)I");

    for (int i = 0; i < 4; i++) {
        arr[i] = env->CallIntMethod(buffer, getMethod, i);
    }

    env->DeleteLocalRef(buffer);
    env->DeleteLocalRef(bufferClass);
}
