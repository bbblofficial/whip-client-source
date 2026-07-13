#pragma once

#include "../base/BaseEvent.h"
#include <jni.h>

class PostOrientCameraEvent final : public EventBase {
public:
    explicit PostOrientCameraEvent(JNIEnv* env) : EventBase(env) {}

    std::type_index getType() const override {
        return typeid(PostOrientCameraEvent);
    }
};
