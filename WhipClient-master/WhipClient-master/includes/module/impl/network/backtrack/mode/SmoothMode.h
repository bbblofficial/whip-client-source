#pragma once

#include "IBacktrackMode.h"
#include "../BacktrackStructs.h"
#include "../MotionSimulator.h"
#include <queue>
#include <mutex>

class SmoothMode : public IBacktrackMode {
    BacktrackModule& module_;

    BacktrackTarget target_;
    long long lastAttackTime_ = 0;
    float renderAlpha_ = 0.0f;
    int nonSprintTicks_ = 0;


    int delayedServerPosX_ = 0;
    int delayedServerPosY_ = 0;
    int delayedServerPosZ_ = 0;

    std::queue<SmoothQueuedPacket> packetQueue_;
    std::mutex queueMutex_;

    jmethodID processPacketMethod_ = nullptr;
    bool processPacketCached_ = false;


    MotionSimulator simState_;
    bool simActive_ = false;
    int ticksSinceLastServerPos_ = 0;

public:
    explicit SmoothMode(BacktrackModule& m) : module_(m) {}

    void onEnable(JNIEnv* env) override;
    void onDisable(JNIEnv* env) override;
    void onPacketReceived(const ChannelReadEvent& event) override;
    void onTick(const OnRunTickEvent& event) override;
    void onPlayerAttack(const PlayerAttackEvent& event) override;
    void onRender3d(const Render3dEvent& event) override;

private:
    static bool isInstanceOf(JNIEnv* env, jobject obj, const char* className);
    bool isVelocityForSelf(JNIEnv* env, jobject packet) const;
    bool isSmoothDelayedPacket(JNIEnv* env, jobject packet) const;
    bool shouldDisable(JNIEnv* env) const;
    void setTarget(JNIEnv* env, int entityId);
    void reset(JNIEnv* env);
    void processQueue(JNIEnv* env);
    void releaseAll(JNIEnv* env);
    void processPacket(JNIEnv* env, jobject packet);
    void cacheProcessPacketMethod(JNIEnv* env);

    [[nodiscard]] long long now() const;
};
