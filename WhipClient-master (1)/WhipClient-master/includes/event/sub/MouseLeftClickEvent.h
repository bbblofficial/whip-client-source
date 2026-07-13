#pragma once
#ifndef MOUSE_LEFT_CLICK_EVENT_H
#define MOUSE_LEFT_CLICK_EVENT_H

#include "event/Cancellable.h"
#include "event/base/BaseEvent.h"
#include <jni.h>

class MouseLeftClickEvent final : public EventBase, public Cancellable {
public:
    MouseLeftClickEvent(JNIEnv* env);

    std::type_index getType() const override;

};

#endif
