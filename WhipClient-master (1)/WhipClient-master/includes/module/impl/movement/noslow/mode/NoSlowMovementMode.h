#pragma once

#include "NoSlowMode.h"

class NoSlowMovementMode final : public NoSlowMode {
public:
    NoSlowMovementMode() = default;
    ~NoSlowMovementMode() override = default;

    void handlePacketSend(const AddSendQueueEvent& event, std::vector<bool> itemMode) override;

    void handleEntityLivingUpdate(
        const EntityLivingUpdateEvent &event,
        std::vector<bool> itemMode,
        float powerMultiplier
    ) override;
};
