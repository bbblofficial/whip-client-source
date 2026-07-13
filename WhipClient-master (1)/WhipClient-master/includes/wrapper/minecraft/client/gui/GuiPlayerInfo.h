#pragma once

#include "../../../../../includes/wrapper/primitive/JavaObject.h"
#include "../../../../../includes/util/Debug.h"

class GuiPlayerInfo : public JavaObject {
private:
	static jfieldID responseTimeId;
	static jfieldID nameId;

public:
	GuiPlayerInfo(JNIEnv* env, jobject obj) : JavaObject(env, obj) {
	}

	int getResponseTime() {
		if (!responseTimeId) {
			responseTimeId = mappings->getField("NetworkPlayerInfo#responseTime");
		}
		if (!responseTimeId) {
			return -1;
		}
		int ping = this->env->GetIntField(this->obj, responseTimeId);
		return ping;
	}

	std::string getName() {
		if (!nameId) nameId = mappings->getField("NetworkPlayerInfo#gameProfile");
		jobject nameObj = this->env->GetObjectField(this->obj, nameId);
		if (!nameObj) {
			return "";
		}

		const char* nameStr = this->env->GetStringUTFChars((jstring)nameObj, nullptr);
		std::string result(nameStr);
		this->env->ReleaseStringUTFChars((jstring)nameObj, nameStr);
		return result;
	}
};
