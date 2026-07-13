#pragma once
#include "../../../../includes/wrapper/primitive/JavaObject.h"
#include "../util/Vec3.h"

class BlockPos : public JavaObject {
private:
    static jmethodID blockPosConstructorId;
    static jmethodID blockPosVec3ConstructorId;

public:
    BlockPos(JNIEnv* env, jobject obj) : JavaObject::JavaObject(env, obj) {}

    static BlockPos fromVec3(JNIEnv* env, Vec3MC source) {
        jclass blockPosClass = mappings->getClass("BlockPos");

        jmethodID constructor = env->GetMethodID(blockPosClass, "<init>", "(Lnet/minecraft/util/Vec3;)V");

        jobject newObj = env->NewObject(blockPosClass, constructor, source.getObj());

        if (!newObj) return BlockPos(NULL, NULL);
        return BlockPos(env, newObj);
    }

    static BlockPos create(JNIEnv* env, int x, int y, int z) {
        jclass blockPosClass = mappings->getClass("BlockPos");

        jmethodID constructor = env->GetMethodID(blockPosClass, "<init>", "(III)V");

        jobject newObj = env->NewObject(blockPosClass, constructor, x, y, z);

        if (!newObj) return BlockPos(NULL, NULL);
        return BlockPos(env, newObj);
    }

    int getX() {
        static jmethodID getXId = nullptr;
        if (!getXId) getXId = mappings->getMethod("Vec3i#getX");
        return this->env->CallIntMethod(this->obj, getXId);
    }

    int getY() {
        static jmethodID getYId = nullptr;
        if (!getYId) getYId = mappings->getMethod("Vec3i#getY");
        return this->env->CallIntMethod(this->obj, getYId);
    }

    int getZ() {
        static jmethodID getZId = nullptr;
        if (!getZId) getZId = mappings->getMethod("Vec3i#getZ");
        return this->env->CallIntMethod(this->obj, getZId);
    }
};
