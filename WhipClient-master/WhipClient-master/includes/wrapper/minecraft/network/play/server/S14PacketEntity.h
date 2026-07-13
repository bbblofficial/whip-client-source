#pragma once
#include "../../../../../../includes/wrapper/primitive/javaobject.h"
#include "../../../../../../includes/util/mathutils.h"

class S14PacketEntity : public JavaObject {
private:
	static jfieldID entityIdId;
	static jfieldID posXId;
	static jfieldID posYId;
	static jfieldID posZId;

public:
	S14PacketEntity(JNIEnv* env, jobject obj) : JavaObject(env, obj) {

		if (!env || !obj) {
			return;
		}

		jclass expectedClass = mappings->getClass("S14PacketEntity");
		if (!expectedClass) {
			return;
		}

		if (!env->IsInstanceOf(obj, expectedClass)) {
			return;
		}

	}

	~S14PacketEntity() {

	}

	int entityId() {
		if (!entityIdId) entityIdId = mappings->getField("S14PacketEntity#entityId");

		return this->env->GetIntField(this->obj, entityIdId);
	}

	int posX() {
		if (!posXId) posXId = mappings->getField("S14PacketEntity#posX");

		jbyte value = this->env->GetByteField(this->obj, posXId);
		return static_cast<int>(value);
	}

	int posY() {
		if (!posYId) posYId = mappings->getField("S14PacketEntity#posY");

		jbyte value = this->env->GetByteField(this->obj, posYId);
		return static_cast<int>(value);
	}

	int posZ() {
		if (!posZId) posZId = mappings->getField("S14PacketEntity#posZ");

		jbyte value = this->env->GetByteField(this->obj, posZId);
		return static_cast<int>(value);
	}

	Vector3<double> GetPosition() const {
		Vector3 pos(0, 0, 0);

		if (!posXId) {
			posXId = mappings->getField("S14PacketEntity#posX");
		}
		if (!posYId) {
			posYId = mappings->getField("S14PacketEntity#posY");
		}
		if (!posZId) {
			posZId = mappings->getField("S14PacketEntity#posZ");
		}

		if (posXId && posYId && posZId) {
			pos.X = static_cast<float>(env->GetDoubleField(obj, posXId));
			pos.Y = static_cast<float>(env->GetDoubleField(obj, posYId));
			pos.Z = static_cast<float>(env->GetDoubleField(obj, posZId));
		}
		return pos;
	}

};
