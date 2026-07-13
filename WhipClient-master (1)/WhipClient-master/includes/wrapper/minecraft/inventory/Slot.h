#pragma once
#include "../../../../includes/wrapper/primitive/JavaObject.h"

class ItemStack;

class Slot : public JavaObject {
private:
    static jfieldID xDisplayPositionId;
    static jfieldID yDisplayPositionId;
    static jmethodID stackMethodId;

public:
    Slot(JNIEnv* env, jobject obj) : JavaObject(env, obj) {}

    int xDisplayPosition();
    int yDisplayPosition();
    ItemStack getStack();
};
