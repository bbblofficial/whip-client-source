#pragma once
#ifndef MOUSE_CLICK_EVENT_H
#define MOUSE_CLICK_EVENT_H

#include <typeindex>
#include "../base/BaseEvent.h"
#include <jni.h>
#include "event/Cancellable.h"

class MouseBlockClickEvent final : public EventBase, public Cancellable {
public:
    struct BlockPosition {
        int x = 0;
        int y = 0;
        int z = 0;
        bool isValid = false;
    };

private:
    BlockPosition blockPos;

public:
    MouseBlockClickEvent(JNIEnv* env, int x, int y, int z, bool valid);
    MouseBlockClickEvent(JNIEnv* env);

    std::type_index getType() const override;

    const BlockPosition& getBlockPosition() const { return blockPos; }
    bool hasBlockPosition() const { return blockPos.isValid; }

};

#endif
