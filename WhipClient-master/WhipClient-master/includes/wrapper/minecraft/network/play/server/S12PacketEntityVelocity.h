#pragma once
#include "../../../../../../includes/wrapper/primitive/JavaObject.h"
#include "../../../entity/Entity.h"
#include "../../Packet.h"

class S12PacketEntityVelocity : public Packet {
    static jfieldID entityIdId;
    static jfieldID motionXId;
    static jfieldID motionYId;
    static jfieldID motionZId;

public:
    S12PacketEntityVelocity(JNIEnv* env, jobject obj) : Packet(env, obj) {
        if (!env || !obj) {
            return;
        }

        jclass expectedClass = mappings->getClass("S12PacketEntityVelocity");
        if (!expectedClass) {
            return;
        }
        if (!env->IsInstanceOf(obj, expectedClass)) {
	        return;
        }
    }

    static S12PacketEntityVelocity createFromEntity(JNIEnv* env, Entity& entity) {
        jclass packetClass = mappings->getClass("S12PacketEntityVelocity");
        jmethodID constructor = env->GetMethodID(packetClass, "<init>", "(Lnet/minecraft/entity/Entity;)V");

        jobject packetObj = env->NewObject(packetClass, constructor, entity.GetInstanceObject());

        S12PacketEntityVelocity result(env, packetObj);

        env->DeleteLocalRef(packetObj);

        return result;
    }

    operator Packet() const {
        return Packet(this->env, this->obj);
    }

    int pVelocity_entityId() {
        if (!entityIdId) entityIdId = mappings->getField("S12PacketEntityVelocity#entityID");
        return this->env->GetIntField(this->obj, entityIdId);
    }
	int pVelocity_motionX() {
		if (!motionXId) motionXId = mappings->getField("S12PacketEntityVelocity#motionX");

		return this->env->GetIntField(this->obj, motionXId);
	}
	int pVelocity_motionY() {
		if (!motionYId) motionYId = mappings->getField("S12PacketEntityVelocity#motionY");

		return this->env->GetIntField(this->obj, motionYId);
	}
	int pVelocity_motionZ() {
		if (!motionZId) motionZId = mappings->getField("S12PacketEntityVelocity#motionZ");

		return this->env->GetIntField(this->obj, motionZId);
	}
	void setMotionX(const int velo) {
		if (!motionXId) motionXId = mappings->getField("S12PacketEntityVelocity#motionX");

		this->env->SetIntField(this->obj, motionXId, velo);
	}
	void setMotionY(const int velo) {
		if (!motionYId) motionYId = mappings->getField("S12PacketEntityVelocity#motionY");

		this->env->SetIntField(this->obj, motionYId, velo);
	}
	void setMotionZ(const int velo) {
		if (!motionZId) motionZId = mappings->getField("S12PacketEntityVelocity#motionZ");

		this->env->SetIntField(this->obj, motionZId, velo);
	}

};
