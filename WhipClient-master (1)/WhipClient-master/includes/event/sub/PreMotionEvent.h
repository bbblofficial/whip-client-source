#pragma once

#include "../base/BaseEvent.h"
#include <jni.h>

class PreMotionEvent final : public EventBase {
public:
    explicit PreMotionEvent(JNIEnv* env) : EventBase(env) {}

    std::type_index getType() const override {
        return typeid(PreMotionEvent);
    }
};
