#pragma once
#ifndef STATUS_UPDATE_EVENT_H
#define STATUS_UPDATE_EVENT_H

#include <typeindex>
#include "../base/BaseEvent.h"
#include <jni.h>

#include "../Cancellable.h"

class StatusUpdateEvent final : public EventBase, public Cancellable {
    jbyte status;

public:
    StatusUpdateEvent(JNIEnv* env, jbyte status);

    jbyte getStatus() const;

    void setStatus(jbyte newStatus);

    std::type_index getType() const override;
};

#endif
