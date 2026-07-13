#pragma once
#include "../../../../../../includes/wrapper/primitive/javaobject.h"
#include "../../../../../../includes/util/mathutils.h"

class S18PacketEntityTeleport : public JavaObject {
private:
	static jfieldID entityIdId;
	static jfieldID posXId;
	static jfieldID posYId;
	static jfieldID posZId;

public:
	S18PacketEntityTeleport(JNIEnv* env, jobject obj) : JavaObject(env, obj) {
		if (!env || !obj) {
			return;
		}

		jclass expectedClass = mappings->getClass("S18PacketEntityTeleport");
		if (!expectedClass) {
			return;
		}

		if (!env->IsInstanceOf(obj, expectedClass)) {
			return;
		}

	}

	~S18PacketEntityTeleport() {

	}

	int entityId() {
		if (!entityIdId) entityIdId = mappings->getField("S18PacketEntityTeleport#entityId");

		return this->env->GetIntField(this->obj, entityIdId);
	}

	int posX() {
		if (!posXId) posXId = mappings->getField("S18PacketEntityTeleport#posX");

		return this->env->GetIntField(this->obj, posXId);
	}

	int posY() {
		if (!posYId) posYId = mappings->getField("S18PacketEntityTeleport#posY");

		return this->env->GetIntField(this->obj, posYId);
	}

	int posZ() {
		if (!posZId) posZId = mappings->getField("S18PacketEntityTeleport#posZ");

		return this->env->GetIntField(this->obj, posZId);
	}

	Vector3<double> GetPosition() const {
		Vector3 pos(0, 0, 0);

		if (!posXId) {
			posXId = mappings->getField("S18PacketEntityTeleport#posX");
		}
		if (!posYId) {
			posYId = mappings->getField("S18PacketEntityTeleport#posY");
		}
		if (!posZId) {
			posZId = mappings->getField("S18PacketEntityTeleport#posZ");
		}

		if (posXId && posYId && posZId) {
			pos.X = static_cast<float>(env->GetDoubleField(obj, posXId));
			pos.Y = static_cast<float>(env->GetDoubleField(obj, posYId));
			pos.Z = static_cast<float>(env->GetDoubleField(obj, posZId));
		}
		return pos;
	}

};
