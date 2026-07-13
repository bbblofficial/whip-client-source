#pragma once
#include "../../../../includes/wrapper/primitive/javaobject.h"

class IEntityMultiPart : public JavaObject {
public:
    IEntityMultiPart(JNIEnv* env, jobject obj) : JavaObject::JavaObject(env, obj) {}
};
