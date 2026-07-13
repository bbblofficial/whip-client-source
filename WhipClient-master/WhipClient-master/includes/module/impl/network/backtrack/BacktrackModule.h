#pragma once

#include <imgui.h>
#include <chrono>
#include <memory>

#include "event/sub/PlayerAttackEvent.h"
#include "event/sub/ChannelReadEvent.h"
#include "event/sub/MouseLeftClickEvent.h"
#include "event/sub/DispatchKeypressesEvent.h"
#include "event/sub/OnTickEvent.h"
#include "event/sub/AddSendQueueEvent.h"

#include "../../../base/Render3dBaseModule.h"
#include "mode/IBacktrackMode.h"

class BacktrackModule final : public Render3dBaseModule<BacktrackModule, ModuleType::BACKTRACK, CategoryType::NETWORK> {

    int mode = 0;


    int delayInTicks = 4;
    int cooldown = 500;


    bool distanceCheck = true;
    float distance = 1.0f;
    float distanceMax = 4.0f;


    int smoothDelayMs = 200;
    int forceFlushMs = 500;


    int maxDelayMs = 500;
    int cooldownTime = 500;
    bool dynamicDelay = true;
    float desiredOffset = 2.0f;


    bool onlySprinting = false;


    int  maxDelay           = 200;
    int  minDelay           = 0;
    int  delayBetweenLags   = 0;
    int  stopAtHurt         = 10;
    int  disableOn          = 0;
    float stopOnAttackRange = 3.0f;
    bool onlyWhenNeeded     = true;
    bool continueAtHurtTime = false;
    bool fixPacketOrder     = true;


    bool drawBox = true;
    ImColor boxColor = ImColor(0.14f, 0.12f, 0.58f, 0.34f);
    ImColor outlineColor = ImColor(1.0f, 1.0f, 1.0f, 1.0f);


    std::unique_ptr<IBacktrackMode> currentMode_;

    std::unique_ptr<IBacktrackMode> createMode(int modeIndex);

public:
    BacktrackModule() : Render3dBaseModule(BindType::TOGGLE, 0) {}
    ~BacktrackModule() override = default;

    void onLoad() override;
    void onEnable() override;
    void onDisable() override;
    void onCleanup() override {
        currentMode_.reset();
        clearInstanceBuffer();
    }

protected:
    void registerEvents() override;
    void onRender3d(const Render3dEvent& event) override;

public:

    int getDelayInTicks() const { return delayInTicks; }
    int getCooldown() const { return cooldown; }
    bool isDistanceCheck() const { return distanceCheck; }
    float getDistance() const { return distance; }
    float getDistanceMax() const { return distanceMax; }

    int getSmoothDelayMs() const { return smoothDelayMs; }
    int getForceFlushMs() const { return forceFlushMs; }

    int getMaxDelayMs() const { return maxDelayMs; }
    int getCooldownTime() const { return cooldownTime; }
    bool isDynamicDelay() const { return dynamicDelay; }
    float getDesiredOffset() const { return desiredOffset; }

    bool isOnlySprinting() const { return onlySprinting; }

    bool isDrawBox() const { return drawBox; }
    ImColor getBoxColor() const { return boxColor; }
    ImColor getOutlineColor() const { return outlineColor; }

    int getAdvMaxDelay() const { return maxDelay; }
    int getAdvMinDelay() const { return minDelay; }
    int getAdvDelayBetweenLags() const { return delayBetweenLags; }
    int getAdvStopAtHurt() const { return stopAtHurt; }
    int getAdvAbortCriterion() const { return disableOn; }
    float getAdvStopOnAttackRange() const { return stopOnAttackRange; }
    bool isAdvOnlyWhenNeeded() const { return onlyWhenNeeded; }
    bool isAdvContinueAtHurtTime() const { return continueAtHurtTime; }
    bool isAdvFixPacketOrder() const { return fixPacketOrder; }

    const char* getDisplayFlags() const override {
        SecureZeroMemory(instanceBuffer, sizeof(instanceBuffer));
        if (mode == 0)
            snprintf(instanceBuffer, 63, "Lag %dt", delayInTicks);
        else if (mode == 1)
            snprintf(instanceBuffer, 63, forceFlushMs >= 1001 ? "Smooth Never" : "Smooth %dms", forceFlushMs);
        else if (mode == 2)
            snprintf(instanceBuffer, 63, "Advanced %dms", maxDelay);
        return instanceBuffer;
    }
};
