#pragma once

#include "../../primitive/JavaObject.h"

class GameProfile : public JavaObject {
    static jfieldID nameId;
public:
    GameProfile(JNIEnv* env, jobject obj) : JavaObject(env, obj) {}

    jstring name() const {
        if (!nameId) nameId = mappings->getField("GameProfile#name");
        return (jstring) this->env->GetObjectField(this->obj, nameId);
    }
};
