#pragma once
#include "AutoRefillMode.h"

class AutoRefillBlatantMode : public AutoRefillMode {
public:
    void performClick(
        int slot,
        int speed,
        int distance,
        Container& container,
        EntityClientPlayerMP& player,
        Minecraft& mc,
        bool dynamicSpeed,
        bool transition
        ) override;

    bool isInstant() const override {
        return true;
    }

    int dynamicDistanceSpeed(int baseSpeed, int distance, bool active) override;

    void onEnable() override;
    void onDisable() override;
};
