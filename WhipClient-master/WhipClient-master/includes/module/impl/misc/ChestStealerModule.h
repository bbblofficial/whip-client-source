#pragma once

#include "../../base/DedicatedThreadBaseModule.h"
#include "../../ModuleType.h"
#include "../../CategoryType.h"
#include "../../../util/JniScope.h"
#include "util/ClientStrings.h"
#include "event/sub/DispatchKeypressesEvent.h"
#include "event/sub/AddSendQueueEvent.h"

#include <random>

class Container;
class EntityClientPlayerMP;
class Minecraft;

class ChestStealerModule final : public DedicatedThreadBaseModule<ChestStealerModule, ModuleType::CHEST_STEALER, CategoryType::MISC> {
    int mode = 0;
    int speed = 5;
    bool autoOpen = false;
    bool closeAfterSteal = true;

    bool stealing_ = false;
    bool closing_ = false;

    int blatantSlotIndex_ = 0;
    int blatantChestSlotCount_ = 0;
    bool blatantActive_ = false;
    int blatantTickDelay_ = 0;
    bool ourClick_ = false;

    static std::random_device rd_;
    static std::mt19937 gen_;

protected:
    void onUpdate(JniScope& scope) override;

    void registerEvents() override {
        subscribe<OnRunTickEvent>([this](const OnRunTickEvent& event) {
            this->onTick(event);
        }, EventPriority::DEFAULT, false);

        subscribe<AddSendQueueEvent>([this](const AddSendQueueEvent& event) {
            this->onPacketSend(event);
        }, EventPriority::HIGH, false);
    }

public:
    ChestStealerModule();

    void onLoad() override;
    void onEnable() override;
    void onDisable() override;
    void onCleanup() override { clearInstanceBuffer(); }

private:
    void onTick(const OnRunTickEvent& event);
    void onPacketSend(const AddSendQueueEvent& event);
    void tickBlatant(JNIEnv* env);
    void stealLegit(JNIEnv* env, Container& container, EntityClientPlayerMP& player, Minecraft& mc, int chestSlotCount);

    void calcGuiLayout(Minecraft& mc, int chestSlotCount, int& guiLeft, int& guiTop,
                       double& scaleX, double& scaleY, POINT& clientOrigin);
    void getSlotScreenPos(int slotIndex, int guiLeft, int guiTop, double scaleX, double scaleY,
                          const POINT& clientOrigin, int& outX, int& outY);
    void smoothMouseMove(int targetX, int targetY);
    int getChestGuiHeight(int chestSlotCount);

    int getInternalSpeed() const { return ((speed - 1) * 50) / 9; }

    mutable char instanceBuffer[64] = {};
    void clearInstanceBuffer() const { memset(instanceBuffer, 0, sizeof(instanceBuffer)); }

public:
    FORMAT_FLAGS("%s %d", (this->mode == 0 ? Strings::modeBlatant() : Strings::modeLegit()), this->speed)
};
