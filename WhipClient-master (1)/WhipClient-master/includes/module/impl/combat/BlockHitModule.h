#pragma once
#include "../../../hud/renderer/IArraylistRenderer.h"

#include "../../base/DedicatedThreadBaseModule.h"
#include "../../ModuleType.h"
#include "../../CategoryType.h"
#include "../../../util/JniScope.h"
#include "event/sub/MouseLeftClickEvent.h"
#include "util/xor.h"
#include "util/ClientStrings.h"
#include "wrapper/minecraft/client/entity/EntityClientPlayerMP.h"
#include <chrono>

class Minecraft;

class BlockHitModule final : public DedicatedThreadBaseModule<BlockHitModule, ModuleType::BLOCK_HIT, CategoryType::COMBAT> {

    int mode = 0;

    int minDuration   = 0;
    int maxDuration   = 2;
    int chance        = 100;
    bool disableOnBehind = true;

    int currentPID    = 0;
    int playingDuration = -1;

    int  prevTargetHurtTime_ = 0;
    bool isBlocking_         = false;
    std::chrono::steady_clock::time_point blockStart_;
    int  blockDurationMs_    = 0;

    int  smoothedPingMs_     = 0;
    int  prevMyHurtTime_     = 0;

    static bool isTargetBehind(EntityClientPlayerMP& player, EntityLivingBase& target);
    void onMouseClick(const MouseLeftClickEvent& event);

    void updatePredict(JNIEnv* env, Minecraft& mc);
    void startBlock(JNIEnv* env, Minecraft& mc);
    void stopBlock(JNIEnv* env, Minecraft& mc);
    int  getRawPingMs(Minecraft& mc);
    int  getSmoothedPingMs(Minecraft& mc);

protected:
    void onUpdate(JniScope& scope) override;
    void registerEvents() override;

public:
    BlockHitModule() = default;

    void onLoad() override {
        DedicatedThreadBaseModule::onLoad();
        this->currentPID = GetCurrentProcessId();

        COMBO_SETTING(mode, "Normal", "Predict");

        INT_SLIDER_OPTIONAL(minDuration, 0, 0, 10, SETTING_VISIBILITY(mode == 0));
        INT_SLIDER_OPTIONAL(maxDuration, 2, 0, 10, SETTING_VISIBILITY(mode == 0));
        INT_SLIDER_OPTIONAL(chance, 100, 0, 100,   SETTING_VISIBILITY(mode == 0));
        BOOL_SETTING_CONDITIONAL_OPTIONAL(disableOnBehind, true, [this]() -> bool {
            return mode == 0;
        });
    }

    void onEnable() override {
        DedicatedThreadBaseModule::onEnable();
        playingDuration      = -1;
        prevTargetHurtTime_  = 0;
        isBlocking_          = false;
        blockDurationMs_     = 0;
        smoothedPingMs_      = 0;
    }

private:
    mutable char instanceBuffer[64] = {0};

public:
    FORMAT_FLAGS("%s", this->mode == 0 ? "Normal" : "Predict")
};
