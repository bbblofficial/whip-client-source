#pragma once

#include "../base/BaseEvent.h"
#include <jni.h>

class PostMotionEvent final : public EventBase {
public:
    explicit PostMotionEvent(JNIEnv* env) : EventBase(env) {}

    std::type_index getType() const override {
        return typeid(PostMotionEvent);
    }
};
