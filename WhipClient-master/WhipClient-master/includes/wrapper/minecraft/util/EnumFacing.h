#pragma once
#include "../../../../includes/wrapper/primitive/javaobject.h"

class EnumFacing : public JavaObject {
private:

public:
	EnumFacing(JNIEnv* env, jobject obj) : JavaObject::JavaObject(env, obj) {}

};
