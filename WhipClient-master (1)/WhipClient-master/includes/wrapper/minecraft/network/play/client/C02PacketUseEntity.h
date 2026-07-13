#pragma once
#include "../../../../../../includes/wrapper/primitive/JavaObject.h"
#include "../../Packet.h"

class C02PacketUseEntity : public Packet {
    static jobject attackObj;
    static jobject interactObj;

public:
    C02PacketUseEntity(JNIEnv* env, jobject obj) : Packet(env, obj) {
        if (!env || !obj) return;

        jclass expectedClass = mappings->getClass("C02PacketUseEntity");
        if (!expectedClass || !env->IsInstanceOf(obj, expectedClass)) return;
    }

    int entityId() {
        return env->GetIntField(obj, mappings->getField("C02PacketUseEntity#entityId"));
    }

    bool isAttack() {
        if (!attackObj) attackObj = mappings->getObject("C02PacketUseEntity$Action#ATTACK");

        jfieldID actionField = mappings->getField("C02PacketUseEntity#action");
        if (!actionField || !attackObj) return false;

        jobject action = env->GetObjectField(obj, actionField);
        if (!action) return false;

        bool result = env->IsSameObject(action, attackObj);
        env->DeleteLocalRef(action);
        return result;
    }

    bool isInteract() {
        if (!interactObj) interactObj = mappings->getObject("C02PacketUseEntity$Action#INTERACT");

        jfieldID actionField = mappings->getField("C02PacketUseEntity#action");
        if (!actionField || !interactObj) return false;

        jobject action = env->GetObjectField(obj, actionField);
        if (!action) return false;

        bool result = env->IsSameObject(action, interactObj);
        env->DeleteLocalRef(action);
        return result;
    }
};
