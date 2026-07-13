#pragma once
#include "../../../../../includes/wrapper/primitive/JavaObject.h"
#include "../../util/BlockPos.h"

class WorldBorder : public JavaObject {
private:
    static jmethodID containsId;

public:
    WorldBorder(JNIEnv* env, jobject obj) : JavaObject::JavaObject(env, obj) {}

    bool contains(BlockPos blockPos) {
        if (blockPos.isNull()) {
            return false;
        }

        if (!this->obj) {
            return false;
        }

        if (!this->env) {
            return false;
        }

        if (!containsId) {
            if (!mappings) {
                return false;
            }

            containsId = mappings->getMethod("WorldBorder#contains");

            if (!containsId) {
                return false;
            }
        }

        if (this->env->ExceptionCheck()) {
            this->env->ExceptionDescribe();
            this->env->ExceptionClear();
        }

        jboolean result = this->env->CallBooleanMethod(this->obj, containsId, blockPos.getObj());

        if (this->env->ExceptionCheck()) {
            this->env->ExceptionDescribe();
            this->env->ExceptionClear();
            return false;
        }

        return static_cast<bool>(result);
    }
};
