#pragma once

#include <jni.h>
#include <chrono>

#include "../../base/ListenedBaseModule.h"
#include "../../ModuleType.h"
#include "../../CategoryType.h"

#include "event/sub/AddSendQueueEvent.h"
#include "event/sub/ChannelReadEvent.h"
#include "event/sub/DispatchKeypressesEvent.h"

#include "hud/renderer/IArraylistRenderer.h"
#include "util/ClientStrings.h"
#include "util/xor.h"

class CriticalsModule final : public ListenedBaseModule<CriticalsModule, ModuleType::CRITICALS, CategoryType::COMBAT> {
    friend class BaseModule;

    int mode = 0;
    int chance = 100;
    float timerSpeed = 0.5f;
    int maxQueueTime = 500;

    bool isLagging_ = false;
    long long lagStartTime_ = 0;

    bool timerActive_ = false;
    bool wasHitAirborne_ = false;
    int lastHurtTime_ = 0;

    static jclass C02PacketUseEntityClass_;
    static jclass S07PacketRespawnClass_;
    static jclass S08PacketPlayerPosLookClass_;

    static bool isAttackPacket(JNIEnv* env, jobject obj);
    static bool isInstanceOf(JNIEnv* env, jobject obj, jclass& cached, const char* className);

public:
    CriticalsModule() : ListenedBaseModule(BindType::TOGGLE, 0) {}

    void onLoad() override;
    void onEnable() override;
    void onDisable() override;

protected:
    void registerEvents() override;

private:
    void onPacketSend(const AddSendQueueEvent& event);
    void onPacketReceived(const ChannelReadEvent& event);
    void onTick(const OnRunTickEvent& event);

    bool canQueueForCrit(JNIEnv* env);
    void flushQueue(JNIEnv* env);

    [[nodiscard]] long long getCurrentTime() const {
        return std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();
    }

    FORMAT_FLAGS("%s", mode == 0 ? Strings::modePacket() : Strings::modeTimer())
};
