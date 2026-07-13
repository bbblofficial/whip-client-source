#pragma once

#include "IBacktrackMode.h"
#include "../BacktrackStructs.h"

class LagMode : public IBacktrackMode {
    BacktrackModule& module_;

    BacktrackTarget target_;
    long long lastAttackTime_ = 0;
    bool wasHoldingSword_ = false;
    float renderAlpha_ = 0.0f;

public:
    explicit LagMode(BacktrackModule& m) : module_(m) {}

    void onEnable(JNIEnv* env) override;
    void onDisable(JNIEnv* env) override;
    void onPacketReceived(const ChannelReadEvent& event) override;
    void onTick(const OnRunTickEvent& event) override;
    void onPlayerAttack(const PlayerAttackEvent& event) override;
    void onRender3d(const Render3dEvent& event) override;

private:
    static bool isInstanceOf(JNIEnv* env, jobject obj, const char* className);
    bool isIgnoredPacket(JNIEnv* env, jobject packet) const;
    bool isVelocityForSelf(JNIEnv* env, jobject packet) const;
    void setTarget(JNIEnv* env, int entityId);
    void clearTarget(JNIEnv* env);
    void flushAndClear(JNIEnv* env);

    [[nodiscard]] long long now() const;
};
