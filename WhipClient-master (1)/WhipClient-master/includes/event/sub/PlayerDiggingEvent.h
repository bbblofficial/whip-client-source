#pragma once
#ifndef PLAYERDIGGINGEVENT_H
#define PLAYERDIGGINGEVENT_H

#include <typeindex>
#include "../base/BaseEvent.h"
#include <jni.h>

#include "event/Cancellable.h"
#include "wrapper/minecraft/network/play/client/c07packetplayerdigging.h"

class PlayerDiggingEvent : public EventBase, public Cancellable {
    C07PacketPlayerDigging playerDigging;

public:
    PlayerDiggingEvent(JNIEnv* env, C07PacketPlayerDigging& entityVelo);

    C07PacketPlayerDigging getVeloPacket();

    std::type_index getType() const override;

};

#endif
