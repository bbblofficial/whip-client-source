#pragma once
#ifndef ATTACK_ENTITY_EVENT_H
#define ATTACK_ENTITY_EVENT_H

#include <typeindex>
#include "../base/BaseEvent.h"
#include <jni.h>

#include "event/Cancellable.h"

class AttackEntityEvent final : public EventBase, public Cancellable {
    float retainedSpeed;
    jobject target;

public:
    AttackEntityEvent(JNIEnv* env, float retainedSpeed, jobject target = nullptr);

    std::type_index getType() const override;

    float getRetainedSpeed() const;

    void setRetainedSpeed(float retainedSpeed);

    jobject getTarget() const { return target; }
};

#endif
