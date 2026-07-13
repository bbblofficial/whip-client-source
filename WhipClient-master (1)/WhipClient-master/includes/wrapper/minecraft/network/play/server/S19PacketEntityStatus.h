#pragma once
#include "../../../../../../includes/wrapper/primitive/javaobject.h"
#include "../../../../../../includes/util/mathutils.h"

class S19PacketEntityStatus : public JavaObject {
private:
	static jfieldID entityIdId;
	static jfieldID logicOpcodeId;

	static constexpr jbyte STATUS_HURT = 2;
	static constexpr jbyte STATUS_DEAD = 3;

public:
	S19PacketEntityStatus(JNIEnv* env, jobject obj) : JavaObject(env, obj) {
		if (!env || !obj) {
			return;
		}

		jclass expectedClass = mappings->getClass("S19PacketEntityStatus");
		if (!expectedClass) {
			return;
		}

		if (!env->IsInstanceOf(obj, expectedClass)) {
			return;
		}

	}

	~S19PacketEntityStatus() {

	}

	int entityId() {
		if (!entityIdId) entityIdId = mappings->getField("S19PacketEntityStatus#entityId");

		return this->env->GetIntField(this->obj, entityIdId);
	}

	jbyte getLogicOpcode() {
		if (!logicOpcodeId) logicOpcodeId = mappings->getField("S19PacketEntityStatus#logicOpcode");

		return this->env->GetByteField(this->obj, logicOpcodeId);
	}

	bool isDeath() {
		return getLogicOpcode() == STATUS_DEAD;
	}

	bool isHurt() {
		return getLogicOpcode() == STATUS_HURT;
	}

};
