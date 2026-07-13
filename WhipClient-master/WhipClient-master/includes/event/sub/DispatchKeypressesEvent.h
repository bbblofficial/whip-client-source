#pragma once

#include <typeindex>
#include "../base/BaseEvent.h"
#include "event/Cancellable.h"

class OnRunTickEvent final : public EventBase, public Cancellable {
public:
    OnRunTickEvent(JNIEnv* env);

    std::type_index getType() const override;

};
