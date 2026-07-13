#pragma once

#include "../base/BaseEvent.h"
#include <jni.h>

class PostRayTraceEvent final : public EventBase {
public:
    explicit PostRayTraceEvent(JNIEnv* env) : EventBase(env) {}

    std::type_index getType() const override {
        return typeid(PostRayTraceEvent);
    }
};
