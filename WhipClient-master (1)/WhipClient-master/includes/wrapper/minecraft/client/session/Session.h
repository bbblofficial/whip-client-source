#pragma once

#include "../../../../../includes/wrapper/primitive/JavaObject.h"
#include "../../../java/lang/String.h"

class Session : public JavaObject {
private:
	static jmethodID getPlayerId;
	static jmethodID getUsernameId;

public:
	Session(JNIEnv* env, jobject obj) : JavaObject(env, obj) {}

	JavaString getPlayerID() {
		if (!getPlayerId) getPlayerId = mappings->getMethod("Session#getPlayerID");

		jobject obj = this->env->CallObjectMethod(this->obj, getPlayerId);
		if (!obj) return { NULL, NULL };

		return { this->env, obj };
	}

	JavaString getUsername() {
		if (!getUsernameId) getUsernameId = mappings->getMethod("Session#getUsername");

		jobject obj = this->env->CallObjectMethod(this->obj, getUsernameId);
		if (!obj) return { NULL, NULL };

		return { this->env, obj };
	}

};
