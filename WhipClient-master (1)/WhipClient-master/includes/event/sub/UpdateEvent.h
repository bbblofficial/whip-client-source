#pragma once
#ifndef UPDATE_EVENT_H
#define UPDATE_EVENT_H

#include <typeindex>
#include "../base/BaseEvent.h"

class UpdateEvent final : public EventBase {
public:
    explicit UpdateEvent(JNIEnv* env) : EventBase(env) {}

    std::type_index getType() const override;
};

#endif
