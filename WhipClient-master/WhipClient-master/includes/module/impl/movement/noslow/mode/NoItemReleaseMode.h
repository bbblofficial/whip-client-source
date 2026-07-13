#pragma once

#include "NoSlowMode.h"

class NoItemReleaseMode final : public NoSlowMode {
public:
    NoItemReleaseMode() = default;
    ~NoItemReleaseMode() override = default;

    void handlePacketSend(const AddSendQueueEvent &event, std::vector<bool> itemMode) override;

    void handleEntityLivingUpdate(
        const EntityLivingUpdateEvent& event,
        std::vector<bool> itemMode,
        float powerMultiplier
    ) override;
};
