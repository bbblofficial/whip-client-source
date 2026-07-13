#pragma once
#ifndef ONTICKEVENT_H
#define ONTICKEVENT_H

#include "event/Cancellable.h"
#include "event/base/BaseEvent.h"
#include <jni.h>

class OnTickEvent final : public EventBase, public Cancellable {
public:
    OnTickEvent(JNIEnv* env);

    std::type_index getType() const override;

};

#endif
