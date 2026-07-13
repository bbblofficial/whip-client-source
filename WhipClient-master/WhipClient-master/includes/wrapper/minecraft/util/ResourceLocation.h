#pragma once

#include "../../primitive/JavaObject.h"
#include <string>

class ResourceLocation : public JavaObject {
private:
    static jclass resourceLocationClass;
    static jmethodID constructorId;

public:
    ResourceLocation(JNIEnv* env, const char* path) : JavaObject(env, nullptr) {
        if (!resourceLocationClass) {
            resourceLocationClass = mappings->getClass("ResourceLocation");
            if (resourceLocationClass) {
                resourceLocationClass = (jclass)env->NewGlobalRef(resourceLocationClass);
            }
        }

        if (!constructorId && resourceLocationClass) {
            constructorId = env->GetMethodID(resourceLocationClass, "<init>", "(Ljava/lang/String;)V");
        }

        if (constructorId && resourceLocationClass) {
            jstring jpath = env->NewStringUTF(path);
            jobject localObj = env->NewObject(resourceLocationClass, constructorId, jpath);
            env->DeleteLocalRef(jpath);

            if (localObj) {
                this->obj = localObj;
                this->deleteRef = true;
                this->isGlobalRef = false;
            }
        }
    }

    ~ResourceLocation() {
        if (env && obj && deleteRef) {
            if (isGlobalRef) {
                env->DeleteGlobalRef(obj);
            } else {
                env->DeleteLocalRef(obj);
            }
        }
    }
};
