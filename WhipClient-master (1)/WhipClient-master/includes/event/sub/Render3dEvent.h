#pragma once
#include "../base/RenderBaseEvent.h"
#include <typeindex>

class Render3dEvent : public RenderBaseEvent {
public:
    Render3dEvent(JNIEnv* env, float partialTicks)
        : RenderBaseEvent(env, partialTicks) {}

    std::type_index getType() const override {
        return std::type_index(typeid(Render3dEvent));
    }

};
