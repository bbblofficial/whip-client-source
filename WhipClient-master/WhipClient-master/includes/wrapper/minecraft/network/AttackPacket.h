#pragma once
#include "../../../../includes/wrapper/primitive/JavaObject.h"

class AttackPacket : public JavaObject {
private:

	static jfieldID GetLogicOpCodeId;
	static jfieldID entityIdId;

public:
	AttackPacket(JNIEnv* env, jobject obj) : JavaObject::JavaObject(env, obj) {}

	jbyte GetLogicOpCode() {

		if (!GetLogicOpCodeId) {
			GetLogicOpCodeId = mappings->getField("S19PacketEntityStatus#logicOpcode");
		}

		return env->GetByteField(this->obj, GetLogicOpCodeId);
	}

	int entityId() {
		if (!entityIdId) entityIdId = mappings->getField("S19PacketEntityStatus#entityId");

		return this->env->GetIntField(this->obj, entityIdId);
	}

	void setEntityId(int id) {
		if (!entityIdId) entityIdId = mappings->getField("S19PacketEntityStatus#entityId");
		this->env->SetIntField(this->obj, entityIdId, id);
	}

};
