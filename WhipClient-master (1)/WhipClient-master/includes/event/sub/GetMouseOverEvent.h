#pragma once
#ifndef GET_MOUSE_OVER_EVENT_H
#define GET_MOUSE_OVER_EVENT_H

#include <typeindex>
#include "../base/BaseEvent.h"

class GetMouseOverEvent final : public EventBase {
    double blockDist;
    double entityReachCap;
    bool bypassBlock = false;
    bool hitThroughBlock = false;
    bool playersOnlyThroughBlock = false;

public:
    GetMouseOverEvent(JNIEnv* env, double blockDist, double entityReachCap)
        : EventBase(env), blockDist(blockDist), entityReachCap(entityReachCap) {}

    std::type_index getType() const override { return std::type_index(typeid(GetMouseOverEvent)); }

    double getBlockDist() const { return blockDist; }
    double getEntityReachCap() const { return entityReachCap; }

    bool shouldBypassBlock() const { return bypassBlock; }
    void setBypassBlock(bool value) { bypassBlock = value; }

    bool isHitThroughBlock() const { return hitThroughBlock; }
    void setHitThroughBlock(bool value) { hitThroughBlock = value; }

    bool isPlayersOnlyThroughBlock() const { return playersOnlyThroughBlock; }
    void setPlayersOnlyThroughBlock(bool value) { playersOnlyThroughBlock = value; }

    double getEffectiveReach() const {
        double reach = (blockDist < entityReachCap) ? blockDist : entityReachCap;
        if (bypassBlock && reach < entityReachCap) reach = entityReachCap;
        return reach;
    }
};

#endif
