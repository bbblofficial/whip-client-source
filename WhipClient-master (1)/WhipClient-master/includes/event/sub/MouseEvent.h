#pragma once
#ifndef MOUSE_EVENT_H
#define MOUSE_EVENT_H

#include <typeindex>
#include "../base/BaseEvent.h"
#include <jni.h>

#include "event/Cancellable.h"
#include "wrapper/minecraft/util/MovingObjectPosition.h"

class MouseEvent : public EventBase, public Cancellable {
    MovingObjectPosition mouseOver;

public:
    MouseEvent(JNIEnv* env, MovingObjectPosition mouseOver);

    MovingObjectPosition getMouseOver();
    void setMouseOver(MovingObjectPosition mouseOver);

    std::type_index getType() const override;

};

#endif
