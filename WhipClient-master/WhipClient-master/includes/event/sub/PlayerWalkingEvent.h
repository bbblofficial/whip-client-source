#pragma once
#ifndef PLAYER_WALKING_EVENT_H
#define PLAYER_WALKING_EVENT_H

#include <typeindex>
#include "../base/BaseEvent.h"
#include <jni.h>

class PlayerWalkingEvent final : public EventBase {
    float retainedSpeed;

public:
    PlayerWalkingEvent(JNIEnv* env);

    std::type_index getType() const override;

};

#endif
