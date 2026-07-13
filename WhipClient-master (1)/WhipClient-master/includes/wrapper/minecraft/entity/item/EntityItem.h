#pragma once
#include "../../../../../includes/wrapper/primitive/JavaObject.h"
#include "../../item/ItemStack.h"

class EntityItem : public JavaObject {
private:
    static jclass entityItemClass;
    static jmethodID getEntityItemId;

public:
    EntityItem(JNIEnv* env, jobject obj) : JavaObject::JavaObject(env, obj) {}

    static bool isInstance(JNIEnv* env, jobject obj) {
        if (!obj) return false;
        if (!entityItemClass) {
            entityItemClass = mappings->getClass("EntityItem");
            if (!entityItemClass) return false;
        }
        return env->IsInstanceOf(obj, entityItemClass);
    }

    ItemStack getEntityItem() {
        if (!getEntityItemId) getEntityItemId = mappings->getMethod("EntityItem#getEntityItem");
        if (!getEntityItemId) return { env, NULL };

        jobject obj = this->env->CallObjectMethod(this->obj, getEntityItemId);
        if (this->env->ExceptionCheck()) {
            this->env->ExceptionClear();
            return { env, NULL };
        }
        if (!obj) return { env, NULL };
        return { this->env, obj };
    }
};
