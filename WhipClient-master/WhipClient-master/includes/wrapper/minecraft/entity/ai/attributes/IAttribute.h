#pragma once
#include "../../../../../../includes/wrapper/primitive/JavaObject.h"

class IAttribute : public JavaObject {
private:

public:
	IAttribute(JNIEnv* env, jobject obj) : JavaObject::JavaObject(env, obj) {}

};
