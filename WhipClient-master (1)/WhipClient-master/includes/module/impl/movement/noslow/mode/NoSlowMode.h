#pragma once

#include <vector>

#include "event/sub/AddSendQueueEvent.h"
#include "event/sub/EntityLivingUpdateEvent.h"

class NoSlowMode {
public:
    virtual ~NoSlowMode() = default;

    virtual void handlePacketSend(const AddSendQueueEvent& event, std::vector<bool> itemMode) = 0;

    virtual void handleEntityLivingUpdate(
        const EntityLivingUpdateEvent& event,
        std::vector<bool> itemMode,
        float powerMultiplier
    ) = 0;
};
