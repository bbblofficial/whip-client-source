#pragma once
#ifndef CANBECOLLIDEDWITHEVENT_H
#define CANBECOLLIDEDWITHEVENT_H

#include <typeindex>
#include "../base/BaseEvent.h"
#include "event/Cancellable.h"
#include "wrapper/minecraft/entity/Entity.h"

class CanBeCollidedWithEvent : public EventBase, public Cancellable {
    Entity p_apply_1_;
    bool value;

public:
    CanBeCollidedWithEvent(JNIEnv* env, Entity& p_apply_1_, bool value);

    Entity& getApply();
    void setApply(Entity& apply);

    bool getValue();
    void setValue(bool val);

    std::type_index getType() const override;

};

#endif
