#pragma once
#include "../../../../includes/wrapper/primitive/JavaObject.h"

class Profiler : public JavaObject {
private:

	static jmethodID startSectionId;
	static jmethodID endSectionId;

public:
    Profiler(JNIEnv* env, jobject obj) : JavaObject::JavaObject(env, obj) {}

	void startSection(jstring string) {
		if (!startSectionId) startSectionId = mappings->getMethod("Profiler#startSection");

		this->env->CallVoidMethod(this->obj, startSectionId, string);
	}

	void endSection() {
		if (!endSectionId) endSectionId = mappings->getMethod("Profiler#endSection");
		this->env->CallVoidMethod(this->obj, endSectionId);
	}

};
