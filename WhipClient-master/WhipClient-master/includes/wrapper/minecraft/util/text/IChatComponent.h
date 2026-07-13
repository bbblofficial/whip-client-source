#pragma once
#include "../../../../../includes/wrapper/primitive/JavaObject.h"
#include "../../../java/lang/String.h"

class IChatComponent : public JavaObject {
private:
	static jmethodID getFormattedTextId;

public:
	IChatComponent(JNIEnv* env, jobject obj) : JavaObject(env, obj) {}

	JavaString getFormattedText() {
		if (!getFormattedTextId) getFormattedTextId = mappings->getMethod("IChatComponent#getFormattedText");

		jobject obj = this->env->CallObjectMethod(this->obj, getFormattedTextId);
		if (!obj) return { NULL, NULL };

		return { this->env, obj };
	}
};
