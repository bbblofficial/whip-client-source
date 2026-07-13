#pragma once

#include "../../../../wrapper/primitive/JavaObject.h"
#include "../../util/ResourceLocation.h"

class TextureManager : public JavaObject {
private:
    static jmethodID bindTextureId;

public:
    TextureManager(JNIEnv* env, jobject obj) : JavaObject(env, obj) {}

    void bindTexture(ResourceLocation& location) {
        if (!bindTextureId) bindTextureId = Mappings::getInstance().getMethod("TextureManager#bindTexture");
        if (!bindTextureId || !location.getObj()) return;

        this->env->CallVoidMethod(this->obj, bindTextureId, location.getObj());
    }
};
