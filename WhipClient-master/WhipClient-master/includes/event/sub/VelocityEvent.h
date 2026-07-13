#pragma once
#ifndef VELOCITY_EVENT_EVENT_H
#define VELOCITY_EVENT_EVENT_H

#include <typeindex>
#include "../base/BaseEvent.h"
#include <jni.h>

#include "../Cancellable.h"
#include "wrapper/minecraft/network/play/server/s12packetentityvelocity.h"

class VelocityEvent final : public EventBase, public Cancellable {
    S12PacketEntityVelocity entityVelo;

public:
    VelocityEvent(JNIEnv* env, S12PacketEntityVelocity& entityVelo);

    S12PacketEntityVelocity getVeloPacket();

    S12PacketEntityVelocity setVeloPacket(const S12PacketEntityVelocity& packet);

    std::type_index getType() const override;

};

#endif
