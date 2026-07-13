#pragma once

#include "../base/BaseEvent.h"
#include <jni.h>

class PreOrientCameraEvent final : public EventBase {
public:
    explicit PreOrientCameraEvent(JNIEnv* env) : EventBase(env) {}

    std::type_index getType() const override {
        return typeid(PreOrientCameraEvent);
    }
};
