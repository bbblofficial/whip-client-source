#pragma once
#include "../../../../../../includes/wrapper/primitive/JavaObject.h"

class IAttributeInstance : public JavaObject {
    static jmethodID getAttributeValueId;

public:
	IAttributeInstance(JNIEnv* env, jobject obj) : JavaObject(env, obj) {}

    double getAttributeValue() {
        if (!getAttributeValueId) getAttributeValueId = mappings->getMethod("IAttributeInstance#getAttributeValue");

        return this->env->CallDoubleMethod(this->obj, getAttributeValueId);
    }

};
