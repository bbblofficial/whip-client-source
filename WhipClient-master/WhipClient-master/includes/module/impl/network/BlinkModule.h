#pragma once

#include <deque>
#include <mutex>
#include <atomic>
#include <chrono>

#include "event/sub/AddSendQueueEvent.h"
#include "event/sub/ChannelReadEvent.h"
#include "event/sub/DispatchKeypressesEvent.h"
#include "event/sub/PlayerAttackEvent.h"
#include "event/sub/Render2dEvent.h"
#include "event/sub/Render3dEvent.h"

#include "../../base/ListenedBaseModule.h"

struct BlinkSendData {
    jobject packet;
};

struct BlinkReceiveData {
    jobject packet;
};

class BlinkModule final : public ListenedBaseModule<BlinkModule, ModuleType::BLINK, CategoryType::NETWORK> {
    friend class BaseModule;

    int direction = 0;
    int autoSendDelay = 5000;
    bool disableOnLocalDamage = false;
    bool disableOnTargetDamage = false;
    bool drawEsp = true;
    ImColor espColor = ImColor(0.08f, 0.47f, 0.90f, 0.55f);

    std::deque<BlinkSendData> sendQueue_;
    std::deque<BlinkReceiveData> receiveQueue_;
    std::mutex mutex_;

    std::atomic<bool> doBlink_ = false;
    std::atomic<bool> pendingDisable_ = false;
    bool fired_ = false;
    long long timer_ = 0;

    double blinkStartX_ = 0, blinkStartY_ = 0, blinkStartZ_ = 0;
    bool hasBlinkPos_ = false;

    static jclass C03PacketPlayerClass_;
    static jclass C00PacketKeepAliveClass_;
    static jclass C0FPacketConfirmTransactionClass_;
    static jclass S00PacketKeepAliveClass_;
    static jclass S32PacketConfirmTransactionClass_;
    static jclass C02PacketUseEntityClass_;
    static jclass S06PacketUpdateHealthClass_;

    jmethodID processPacketMethod_ = nullptr;
    bool processPacketCached_ = false;

    ImFont* blinkFont_ = nullptr;
    bool fontInitialized_ = false;
    void initFont();

public:
    BlinkModule() : ListenedBaseModule(BindType::TOGGLE, 0) {}

    void onLoad() override;
    void onEnable() override;
    void onDisable() override;

protected:
    void registerEvents() override;

private:
    void onPacketSend(const AddSendQueueEvent& event);
    void onPacketReceive(const ChannelReadEvent& event);
    void onTick(const OnRunTickEvent& event);
    void onPlayerAttack(const PlayerAttackEvent& event);
    void onRender2d(const Render2dEvent& event);
    void onRender3d(const Render3dEvent& event);

    void forceDisable();

    void releasePackets(JNIEnv* env);
    void clearQueues(JNIEnv* env);

    bool isConnectionPacket(JNIEnv* env, jobject packet);
    bool isMovementPacket(JNIEnv* env, jobject packet);

    void cacheProcessPacketMethod(JNIEnv* env);

    static bool isInstanceOf(JNIEnv* env, jobject obj, jclass& cached, const char* className);

    [[nodiscard]] long long getCurrentTime() const {
        return std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();
    }
};
