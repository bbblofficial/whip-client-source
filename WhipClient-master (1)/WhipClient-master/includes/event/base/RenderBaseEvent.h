#pragma once
#include "BaseEvent.h"

class RenderBaseEvent : public EventBase {
protected:
    float partialTicks;

public:
    RenderBaseEvent(JNIEnv* env, float partialTicks)
        : EventBase(env), partialTicks(partialTicks) {}

    float getPartialTicks() const { return partialTicks; }
};
