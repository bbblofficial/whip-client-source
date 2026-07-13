#pragma once
#include "../../../../includes/wrapper/primitive/javaobject.h"

class EntityFishHook : public JavaObject {
private:

	static jfieldID onGroundId;
	static jfieldID caughtEntityFieldId;
	static jfieldID anglerFieldId;

public:
	EntityFishHook(JNIEnv* env, jobject obj) : JavaObject::JavaObject(env, obj) {
		if (!env || !obj) {
			return;
		}

		this->makeGlobalRef();
	}

	bool InGround() {
		if (!onGroundId) onGroundId = mappings->getField("EntityFishHook#inGround");
		return this->env->GetBooleanField(this->obj, onGroundId);
	}

	jobject GetAngler() {
		if (!anglerFieldId) anglerFieldId = mappings->getField("EntityFishHook#angler");
		return env->GetObjectField(obj, anglerFieldId);
	}

	jobject GetCaughtEntity() {
		if (!caughtEntityFieldId) caughtEntityFieldId = mappings->getField("EntityFishHook#caughtEntity");
		return env->GetObjectField(obj, caughtEntityFieldId);
	}
};
