#pragma once

#include "../../../../primitive/JavaObject.h"

class S0CPacketSpawnPlayer : public JavaObject {
private:
    static jclass spawnPacketClass;
    static jmethodID getEntityIDId;

public:
    S0CPacketSpawnPlayer(JNIEnv* env, jobject obj) : JavaObject(env, obj) {}

    static bool isInstance(JNIEnv* env, jobject obj) {
        if (!obj) return false;
        if (!spawnPacketClass) {
            spawnPacketClass = mappings->getClass("S0CPacketSpawnPlayer");
            if (!spawnPacketClass) return false;
        }
        return env->IsInstanceOf(obj, spawnPacketClass);
    }

    int getEntityID() {
        if (!getEntityIDId) getEntityIDId = mappings->getMethod("S0CPacketSpawnPlayer#getEntityID");
        if (!getEntityIDId) return -1;
        int v = this->env->CallIntMethod(this->obj, getEntityIDId);
        if (this->env->ExceptionCheck()) { this->env->ExceptionClear(); return -1; }
        return v;
    }
};
