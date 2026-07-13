#pragma once
#include "../../../../includes/wrapper/primitive/JavaObject.h"

class ChannelHandlerContext : public JavaObject {
private:
    static jclass channelHandlerContextClass;

public:
    ChannelHandlerContext(JNIEnv* env, jobject obj) : JavaObject(env, obj) {

        if (!env || !obj) {
            return;
        }

        jclass expectedClass = mappings->getClass("ChannelHandlerContext");
        if (!expectedClass) {
            return;
        }

        if (!env->IsInstanceOf(obj, expectedClass)) {
            return;
        }

        makeGlobalRef();

        this->UpdateInstanceObject(this->obj);
    }

    ~ChannelHandlerContext() {
        if (this->obj && this->env) {
            this->unmakeGlobalRef();
        }
    }

    bool isChannelHandlerContext() {
        if (!channelHandlerContextClass) {
            channelHandlerContextClass = mappings->getClass("ChannelHandlerContext");
        }
        return this->env->IsInstanceOf(this->obj, channelHandlerContextClass);
    }
};
