#pragma once
#ifndef CHANNEL_READ_H
#define CHANNEL_READ_H

#include <typeindex>
#include "../base/BaseEvent.h"
#include <jni.h>
#include "../Cancellable.h"

class ChannelReadEvent final : public EventBase, public Cancellable {
    jobject packetObj;

public:
    ChannelReadEvent(JNIEnv* env, jobject packetObj);

    [[nodiscard]] jobject getPacketObject() const;

    [[nodiscard]] void setPacketObject(jobject packetObj);

    [[nodiscard]] std::type_index getType() const override;

};

#endif
