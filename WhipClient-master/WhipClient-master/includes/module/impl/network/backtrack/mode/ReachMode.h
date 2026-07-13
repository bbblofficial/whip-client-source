#pragma once

#include "IBacktrackMode.h"
#include "../BacktrackStructs.h"
#include <deque>
#include <queue>
#include <mutex>

class ReachMode : public IBacktrackMode {
    BacktrackModule& module_;

    int targetEntityId_ = -1;
    bool tracking_ = false;
    long long lastAttackTime_ = 0;
    std::deque<BTPositionSample> positionHistory_;


    std::queue<std::pair<jobject, long long>> keepAliveQueue_;
    std::mutex keepAliveMutex_;
    bool flushing_ = false;


    double effectiveDelayMs_ = 500.0;


    double ghostTargetX_ = 0, ghostTargetY_ = 0, ghostTargetZ_ = 0;
    double ghostPosX_ = 0, ghostPosY_ = 0, ghostPosZ_ = 0;
    double ghostLastTickPosX_ = 0, ghostLastTickPosY_ = 0, ghostLastTickPosZ_ = 0;
    int ghostPosIncrements_ = 0;
    bool ghostValid_ = false;


    int lastServerPosX_ = 0, lastServerPosY_ = 0, lastServerPosZ_ = 0;
    bool lastPosWasTeleport_ = false;

    bool wasHoldingSword_ = false;
    float renderAlpha_ = 0.0f;
    int nonSprintTicks_ = 0;


    static jclass C00KeepAliveClass_;
    static jclass C0FConfirmTransactionClass_;
    static jclass S14PacketEntityClass_;
    static jclass S18PacketEntityTeleportClass_;
    static jclass S12VelocityClass_;

public:
    explicit ReachMode(BacktrackModule& m) : module_(m) {}

    void onEnable(JNIEnv* env) override;
    void onDisable(JNIEnv* env) override;
    void onPacketReceived(const ChannelReadEvent& event) override;
    void onPacketSend(const AddSendQueueEvent& event) override;
    void onTick(const OnRunTickEvent& event) override;
    void onPlayerAttack(const PlayerAttackEvent& event) override;
    void onMouseLeftClick(const MouseLeftClickEvent& event) override;
    void onRender3d(const Render3dEvent& event) override;

private:
    bool findHittableGhost(JNIEnv* env, double& hitDist);
    bool rayIntersectsBoxAt(double bx, double by, double bz,
                            double eyeX, double eyeY, double eyeZ,
                            double dirX, double dirY, double dirZ,
                            double& hitDist);
    void sendAttack(JNIEnv* env, jobject targetEntity);
    void softReset(JNIEnv* env);
    void reset(JNIEnv* env = nullptr);
    void computeDynamicDelay(double playerX, double playerY, double playerZ,
                             double targetX, double targetY, double targetZ);

    void processKeepAliveQueue(JNIEnv* env);
    void flushKeepAliveQueue(JNIEnv* env);
    static bool cachedIsInstanceOf(JNIEnv* env, jobject obj, jclass& cached, const char* className);
    static bool isInstanceOf(JNIEnv* env, jobject obj, const char* className);
    bool isVelocityForSelf(JNIEnv* env, jobject packet) const;

    [[nodiscard]] long long now() const;
};
