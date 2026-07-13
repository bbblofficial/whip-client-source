#pragma once

#include "../../../../includes/wrapper/primitive/JavaObject.h"

class JavaString : public JavaObject {
public:
	JavaString(JNIEnv* env, const jobject obj) : JavaObject(env, obj) {}

	int size() const {
		return this->env->GetStringLength(static_cast<jstring>(this->obj));
	}
	wchar_t* get() const {
		return (wchar_t*) this->env->GetStringChars(static_cast<jstring>(this->obj), NULL);
	}

	void release(wchar_t* buff) {
		this->env->ReleaseStringChars((jstring)this->obj, (jchar*)buff);
	}

	static std::string jstringToString(JNIEnv* env, jstring jStr) {
		if (jStr == nullptr) return "";

		const char* chars = env->GetStringUTFChars(jStr, nullptr);
		if (chars == nullptr) return "";

		std::string result(chars);
		env->ReleaseStringUTFChars(jStr, chars);
		return result;
	}
};
