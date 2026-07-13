#pragma once

#include "event/sub/ChannelReadEvent.h"
#include "event/sub/AddSendQueueEvent.h"
#include "event/sub/DispatchKeypressesEvent.h"
#include "event/sub/PlayerAttackEvent.h"
#include "event/sub/MouseLeftClickEvent.h"
#include "event/sub/Render3dEvent.h"

class BacktrackModule;

class IBacktrackMode {
public:
    virtual ~IBacktrackMode() = default;
    virtual void onEnable(JNIEnv* env) = 0;
    virtual void onDisable(JNIEnv* env) = 0;
    virtual void onPacketReceived(const ChannelReadEvent& event) = 0;
    virtual void onPacketSend(const AddSendQueueEvent& event) {}
    virtual void onTick(const OnRunTickEvent& event) = 0;
    virtual void onPlayerAttack(const PlayerAttackEvent& event) = 0;
    virtual void onMouseLeftClick(const MouseLeftClickEvent& event) {}
    virtual void onRender3d(const Render3dEvent& event) = 0;
};
