#pragma once
#include "../../../../includes/wrapper/primitive/JavaObject.h"

class StatBase : public JavaObject {
public:
    StatBase(JNIEnv* env, jobject obj) : JavaObject::JavaObject(env, obj) {}
};
