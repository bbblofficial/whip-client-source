#pragma once

#include <imgui.h>
#include <chrono>
#include <deque>

#include "event/sub/AddSendQueueEvent.h"
#include "event/sub/ChannelReadEvent.h"
#include "event/sub/OnTickEvent.h"
#include "util/MathUtils.h"

#include "../../base/Render3dBaseModule.h"

class LagRangeModule final : public Render3dBaseModule<LagRangeModule, ModuleType::LAG_RANGE, CategoryType::NETWORK> {
    int mode = 0;
    int delay = 300;
    float activationDistance = 6.0f;
    float flushDistance = 4.0f;
    bool sprintReset = true;
    bool usedSplashPotion = true;
    bool onlyWeapon = true;
    bool onlySprinting = false;
    bool fixPing = false;
    bool drawBox = true;
    ImColor boxColor = ImColor(0.58f, 0.12f, 0.14f, 0.34f);
    ImColor outlineColor = ImColor(1.0f, 0.3f, 0.3f, 1.0f);

    Vector3d lastServerPosition_;
    Vector3d lastLocalPosition_;
    Vector3d dynamicServerPosition_;
    Vector3d lastDrawPosition_;
    Vector3d currentDrawPosition_;

    struct TimedPosition {
        long long timestamp;
        Vector3d position;
    };
    std::deque<TimedPosition> positionHistory_;

    int ticksSinceRespawn_ = 0;
    bool isLagging_ = false;
    long long lastQueueTime_ = 0;
    long long lagStartTime_ = 0;
    float renderAlpha_ = 0.0f;
    bool wasSprinting_ = false;

    static jclass C02PacketUseEntityClass_;
    static jclass C08PacketBlockPlacementClass_;
    static jclass C17PacketCustomPayloadClass_;
    static jclass C00PacketKeepAliveClass_;
    static jclass C0FPacketConfirmTransactionClass_;
    static jclass S07PacketRespawnClass_;
    static jclass S08PacketPlayerPosLookClass_;

    std::vector<float> projectionMatrix;
    std::vector<float> modelViewMatrix;

public:
    LagRangeModule() : Render3dBaseModule(BindType::TOGGLE, 0) {
        projectionMatrix.resize(16, 0.0f);
        modelViewMatrix.resize(16, 0.0f);
    }

    void onLoad() override;
    void onEnable() override;
    void onDisable() override;

protected:
    void registerEvents() override;
    void onRender3d(const Render3dEvent& event) override;

private:
    void onPacketSend(const AddSendQueueEvent& event);
    void onPacketReceived(const ChannelReadEvent& event);
    void onTick(const OnTickEvent& event);

    bool shouldActivateLag(JNIEnv* env) const;
    bool isFlushTrigger(JNIEnv* env, jobject packet) const;
    bool isSkippedPacket(JNIEnv* env, jobject packet) const;
    bool isHoldingSplashPotion(JNIEnv* env) const;
    void flushQueue(JNIEnv* env);
    void resetState();

    static bool isInstanceOf(JNIEnv* env, jobject obj, jclass& cached, const char* className);

    [[nodiscard]] long long getCurrentTime() const {
        return std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();
    }

private:
    mutable char instanceBuffer[64] = {0};

public:
    FORMAT_FLAGS("%s", this->mode == 0 ? "Static" : "Dynamic")
};
