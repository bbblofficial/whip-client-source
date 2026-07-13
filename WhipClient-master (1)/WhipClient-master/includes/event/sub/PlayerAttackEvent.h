#pragma once
#ifndef PLAYER_ATTACK_EVENT_H
#define PLAYER_ATTACK_EVENT_H

#include <typeindex>
#include "../base/BaseEvent.h"
#include <jni.h>

#include "event/Cancellable.h"

class PlayerAttackEvent final : public EventBase, public Cancellable {
    int targetId_;

public:
    PlayerAttackEvent(JNIEnv* env, int targetId);

    std::type_index getType() const override;

    int getTargetEntityId() const;
};

#endif
