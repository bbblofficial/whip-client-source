#pragma once

#include "../../../../primitive/JavaObject.h"

class C05PacketPlayerLook : public JavaObject {
private:
    static jclass packetClass;
    static jmethodID ctorFFZ;

public:
    C05PacketPlayerLook(JNIEnv* env, jobject obj) : JavaObject(env, obj) {}

    static C05PacketPlayerLook create(JNIEnv* env, float yaw, float pitch, bool onGround) {
        if (!packetClass) {
            packetClass = mappings->getClass("C03PacketPlayer$C05PacketPlayerLook");
            if (!packetClass) {

                packetClass = mappings->getClass("C03PacketPlayer_C05PacketPlayerLook");
            }
        }
        if (!packetClass) return { env, NULL };
        if (!ctorFFZ) {
            ctorFFZ = mappings->getMethod("C03PacketPlayer$C05PacketPlayerLook#<init>");
            if (!ctorFFZ) ctorFFZ = mappings->getMethod("C03PacketPlayer_C05PacketPlayerLook#<init>");
        }
        if (!ctorFFZ) return { env, NULL };
        jobject obj = env->NewObject(packetClass, ctorFFZ, yaw, pitch, (jboolean)onGround);
        if (env->ExceptionCheck()) {
            env->ExceptionClear();
            return { env, NULL };
        }
        return { env, obj };
    }
};
