#pragma once
#include "../../../../includes/wrapper/primitive/JavaObject.h"

class Chunk : public JavaObject {
private:

public:
	Chunk(JNIEnv* env, jobject obj) : JavaObject::JavaObject(env, obj) {}

};
