#pragma once
#ifndef APPLY_EVENT_H
#define APPLY_EVENT_H

#include <typeindex>
#include "../base/BaseEvent.h"
#include "event/Cancellable.h"
#include "wrapper/minecraft/entity/Entity.h"

class ApplyEvent : public EventBase, public Cancellable {
    Entity p_apply_1_;
    bool value;

public:
    ApplyEvent(JNIEnv* env, Entity& p_apply_1_, bool value);

    Entity& getApply();
    void setApply(Entity& apply);

    bool getValue();
    void setValue(bool val);

    std::type_index getType() const override;

};

#endif
