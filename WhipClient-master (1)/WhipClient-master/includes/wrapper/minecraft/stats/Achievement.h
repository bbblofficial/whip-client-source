#pragma once
#include "../../../../includes/wrapper/primitive/JavaObject.h"

class Achievement : public JavaObject {
public:
    Achievement(JNIEnv* env, jobject obj) : JavaObject::JavaObject(env, obj) {}
};
