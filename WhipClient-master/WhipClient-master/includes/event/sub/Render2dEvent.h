#pragma once
#include "../base/RenderBaseEvent.h"
#include <typeindex>

class Render2dEvent : public RenderBaseEvent {
public:
    Render2dEvent(JNIEnv* env, float partialTicks)
        : RenderBaseEvent(env, partialTicks) {}

    std::type_index getType() const override {
        return std::type_index(typeid(Render2dEvent));
    }

};
