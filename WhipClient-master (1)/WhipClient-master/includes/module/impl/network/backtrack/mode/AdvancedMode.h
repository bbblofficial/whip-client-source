#pragma once

#include "IBacktrackMode.h"
#include "../BacktrackStructs.h"

#include <chrono>

class AdvancedMode : public IBacktrackMode {
    BacktrackModule& module_;

    BacktrackTarget target_;
    bool       inBacktrackWindow_ = false;
    long long  windowStartMs_     = 0;
    long long  lastFlushMs_       = 0;
    long long  lastAttackMs_      = 0;
    bool       wasHoldingSword_   = false;
    float      renderAlpha_       = 0.0f;
    bool       clickedThisTick_   = false;

public:
    explicit AdvancedMode(BacktrackModule& m) : module_(m) {}

    void onEnable(JNIEnv* env) override;
    void onDisable(JNIEnv* env) override;
    void onPacketReceived(const ChannelReadEvent& event) override;
    void onTick(const OnRunTickEvent& event) override;
    void onPlayerAttack(const PlayerAttackEvent& event) override;
    void onMouseLeftClick(const MouseLeftClickEvent& event) override;
    void onRender3d(const Render3dEvent& event) override;

private:
    void setTarget(JNIEnv* env, int entityId);
    void flushAndClear(JNIEnv* env);
    bool targetInRange(JNIEnv* env, int entityId, float maxRange) const;

    static long long now() {
        return std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();
    }
};
