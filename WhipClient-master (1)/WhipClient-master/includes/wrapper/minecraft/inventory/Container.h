#pragma once
#include "../../../../includes/wrapper/primitive/JavaObject.h"
#include "../../java/util/ArrayList.h"

class Container : public JavaObject {
private:
	static jfieldID windowIdId;
	static jfieldID inventorySlotsId;

public:
	Container(JNIEnv* env, jobject obj) : JavaObject::JavaObject(env, obj) {}

	int windowId() {
		if (!windowIdId) windowIdId = mappings->getField("Container#windowId");
		return this->env->GetIntField(this->obj, windowIdId);
	}

	ArrayList inventorySlots() {
		if (!inventorySlotsId) inventorySlotsId = mappings->getField("Container#inventorySlots");
		jobject obj = this->env->GetObjectField(this->obj, inventorySlotsId);
		if (!obj) return { nullptr, nullptr };
		return { this->env, obj };
	}
};
