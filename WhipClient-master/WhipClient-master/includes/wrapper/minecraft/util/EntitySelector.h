#pragma once
#include "../../../../includes/wrapper/primitive/javaobject.h"
#include <functional>

class EntitySelectors : public JavaObject {
private:
    static jclass entitySelectorsClass;
    static jfieldID isStandaloneId;
    static jfieldID notSpectatingId;

public:
    EntitySelectors(JNIEnv* env, jobject obj) : JavaObject::JavaObject(env, obj) {}

    static const jobject IS_STANDALONE;
    static const jobject NOT_SPECTATING;
};
