#pragma once

#include "../base/BaseEvent.h"
#include <jni.h>

class PreRayTraceEvent final : public EventBase {
public:
    explicit PreRayTraceEvent(JNIEnv* env) : EventBase(env) {}

    std::type_index getType() const override {
        return typeid(PreRayTraceEvent);
    }
};
