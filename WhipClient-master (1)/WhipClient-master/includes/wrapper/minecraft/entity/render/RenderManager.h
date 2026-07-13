#pragma once

#include "../../../../../includes/wrapper/primitive/JavaObject.h"
#include "../../../../../includes/util/mathutils.h"
#include "wrapper/minecraft/entity/player/EntityPlayer.h"

class RenderManager : public JavaObject {
private:
    static jfieldID RenderPosXId;
    static jfieldID RenderPosYId;
    static jfieldID RenderPosZId;
    static jfieldID RenderManagerInstanceId;
    static jclass RenderManagerClass;
    static jmethodID RenderEntitySimpleId;
    static jmethodID RenderEntityStaticId;

public:
    RenderManager(JNIEnv* env, jobject obj) : JavaObject(env, obj) {}

    Vec3D getRenderPos() {
        if (MinecraftSession::getInstance().version == MinecraftVersion::V1_8_9) {
            Vec3D pos;

            if (!RenderPosXId) {
                RenderPosXId = mappings->getField("RenderManager#renderPosX");
            }
            if (!RenderPosYId) {
                RenderPosYId = mappings->getField("RenderManager#renderPosY");
            }
            if (!RenderPosZId) {
                RenderPosZId = mappings->getField("RenderManager#renderPosZ");
            }

            if (RenderPosXId && RenderPosYId && RenderPosZId) {
                pos.x = static_cast<float>(env->GetDoubleField(obj, RenderPosXId));
                pos.y = static_cast<float>(env->GetDoubleField(obj, RenderPosYId));
                pos.z = static_cast<float>(env->GetDoubleField(obj, RenderPosZId));
            }
            return pos;
        }
        if (MinecraftSession::getInstance().version == MinecraftVersion::V1_7_10) {
            Vec3D pos;
            if (!RenderManagerClass) RenderManagerClass = mappings->getClass("RenderManager");

            if (!RenderPosXId) {
                RenderPosXId = mappings->getField("RenderManager#renderPosX");
            }
            if (!RenderPosYId) {
                RenderPosYId = mappings->getField("RenderManager#renderPosY");
            }
            if (!RenderPosZId) {
                RenderPosZId = mappings->getField("RenderManager#renderPosZ");
            }

            if (RenderPosXId && RenderPosYId && RenderPosZId) {
                pos.x = static_cast<float>(env->GetStaticDoubleField(RenderManagerClass, RenderPosXId));
                pos.y = static_cast<float>(env->GetStaticDoubleField(RenderManagerClass, RenderPosYId));
                pos.z = static_cast<float>(env->GetStaticDoubleField(RenderManagerClass, RenderPosZId));
            }
            return pos;
        }
        return Vec3D();
    }

    bool renderEntitySimple(EntityPlayer& entity, float partialTicks) {
        if (!RenderEntitySimpleId) {
            RenderEntitySimpleId = mappings->getMethod("RenderManager#renderEntitySimple");
        }

        if (!RenderEntitySimpleId || !obj || !entity.getObj()) {
            return false;
        }

        return env->CallBooleanMethod(obj, RenderEntitySimpleId, entity.getObj(), partialTicks);
    }

    bool renderEntityStatic(EntityPlayer& entity, float partialTicks, bool hideDebugBox) {
        if (!RenderEntityStaticId) {
            RenderEntityStaticId = mappings->getMethod("RenderManager#renderEntityStatic");
        }

        if (!RenderEntityStaticId || !obj || !entity.getObj()) {
            return false;
        }

        return env->CallBooleanMethod(obj, RenderEntityStaticId, entity.getObj(), partialTicks, hideDebugBox);
    }

    static RenderManager getInstance(JNIEnv* env) {
        if (!RenderManagerClass) RenderManagerClass = mappings->getClass("RenderManager");
        if (!RenderManagerInstanceId) RenderManagerInstanceId = mappings->getField("RenderManager#instance");

        jobject obj = env->GetStaticObjectField(RenderManagerClass, RenderManagerInstanceId);
        if (!obj) return { env, nullptr };

        return { env, obj };
    }
};
