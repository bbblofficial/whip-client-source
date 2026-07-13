#pragma once

#include "wrapper/minecraft/client/minecraft.h"
#include "wrapper/minecraft/client/entity/EntityClientPlayerMP.h"

class AutoRefillMode {
public:
    virtual ~AutoRefillMode() = default;

    void handleClick(int slot,
        int speed,
        int distance,
        Container& container,
        EntityClientPlayerMP& player,
        Minecraft& mc,
        const bool dynamicSpeed,
        bool transition
    ) {
        performClick(slot, speed, distance, container, player, mc, dynamicSpeed, transition);
    }

    virtual void onEnable() = 0;

    virtual void onDisable() = 0;

    virtual int dynamicDistanceSpeed(int baseSpeed, int distance, bool active) = 0;

    virtual bool isInstant() const = 0;

    virtual void performClick(
        int slot,
        int speed,
        int distance,
        Container& container,
        EntityClientPlayerMP& player,
        Minecraft& mc,
        bool dynamicSpeed,
        bool transition
    ) = 0;
};
