#pragma once

#include "../../base/ListenedBaseModule.h"
#include "../../ModuleType.h"
#include "../../CategoryType.h"
#include "../../../setting/SettingMacros.h"
#include "../../../event/sub/ChannelReadEvent.h"
#include "../../../event/sub/OnTickEvent.h"
#include "../../../event/sub/DispatchKeypressesEvent.h"
#include "wrapper/minecraft/entity/Entity.h"

#include <unordered_set>
#include <unordered_map>
#include <mutex>

class AntiBotModule final
    : public ListenedBaseModule<AntiBotModule, ModuleType::ANTI_BOT, CategoryType::MISC> {

    int minTicksExisted = 20;
    bool checkTabList = true;
    bool checkServerPackets = true;
    int packetGraceTicks = 40;

    std::unordered_set<int> spawnedPlayerIds_;
    std::unordered_set<int> confirmedBotIds_;

    std::unordered_set<int> receivedMovementPacket_;

    mutable std::mutex mutex_;
    bool populated_ = false;

    static inline jclass clsS14Packet_ = nullptr;
    static inline jclass clsS18Packet_ = nullptr;
    static inline jclass clsNetHandler_ = nullptr;
    static inline bool jniResolved_ = false;

    void resolveJni(JNIEnv* env);
    void populateExistingPlayers(JNIEnv* env);
    bool isInTabList(JNIEnv* env, jobject entityObj);

protected:
    void registerEvents() override;

public:
    AntiBotModule() = default;

    void onLoad() override {
        ListenedBaseModule::onLoad();
    }

    void onEnable() override {
        ListenedBaseModule::onEnable();
        std::lock_guard lock(mutex_);
        spawnedPlayerIds_.clear();
        confirmedBotIds_.clear();
        receivedMovementPacket_.clear();
        populated_ = false;
    }

    void onDisable() override {
        std::lock_guard lock(mutex_);
        spawnedPlayerIds_.clear();
        confirmedBotIds_.clear();
        receivedMovementPacket_.clear();
        populated_ = false;
        ListenedBaseModule::onDisable();
    }

    void onCleanup() override { clearInstanceBuffer(); }

    bool isBot(JNIEnv* env, jobject entityObj);
    bool isBot(JNIEnv* env, Entity& entity);

    static AntiBotModule* getInstancePtr() {
        return &BaseModule::getInstance();
    }

private:
    void onPacketReceived(const ChannelReadEvent& event);
    void onTick(const OnRunTickEvent& event);

    mutable char instanceBuffer[64] = {0};

public:
    FORMAT_FLAGS("%s", "")
};
