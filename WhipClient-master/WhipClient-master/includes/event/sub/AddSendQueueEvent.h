#pragma once
#ifndef ADDSENDQUEUE_EVENT_H
#define ADDSENDQUEUE_EVENT_H

#include <typeindex>
#include "../base/BaseEvent.h"
#include "event/Cancellable.h"

class AddSendQueueEvent final : public EventBase, public Cancellable {
    const char* packetName;
    jobject packetObj;

public:
    AddSendQueueEvent(JNIEnv* env, const char* packetName, jobject packetObj)
        : EventBase(env), packetName(packetName), packetObj(packetObj) {
    }

    const char* getPacketName() const {
        return packetName;
    }

    void setPacketName(const char* packetName) {
        this->packetName = packetName;
    }

    jobject getPacketObject() const {
        return packetObj;
    }

    std::type_index getType() const override {
        return typeid(AddSendQueueEvent);
    }

};

#endif
