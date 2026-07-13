#pragma once

#include <imgui.h>
#include <chrono>

#include "../../../hud/renderer/IArraylistRenderer.h"
#include "../../base/Render3dBaseModule.h"
#include "../../ModuleType.h"
#include "../../CategoryType.h"

#include "event/sub/OnTickEvent.h"
#include "event/sub/DispatchKeypressesEvent.h"
#include "event/sub/Render3dEvent.h"
#include "util/ClientStrings.h"

class EntityClientPlayerMP;

class AutoRodModule final : public Render3dBaseModule<
    AutoRodModule, ModuleType::THROW_ROD, CategoryType::TEST> {

    float fov                  = 180.0f;
    float maxTargetLookFovDiff = 90.0f;
    float maxRodRange          = 10.0f;
    int   throwCooldownMs      = 250;

    bool ignoreEatingTargets   = true;
    bool moveFix               = true;
    bool disableWhileScaffold  = false;
    bool onlyRodIfNotInReach   = true;
    float meleeReach           = 3.0f;
    bool click                 = true;
    bool rotations             = true;
    bool luckyThrow            = false;
    bool targetPlayers         = true;
    bool targetMobs            = false;

    bool esp = true;
    ImColor espColor = ImColor(0.0f, 1.0f, 0.0f, 1.0f);

    enum class RodState { IDLE, AIM, THROW, SWAP_BACK };

    long long lastThrowMs_       = 0;
    int       currentTargetId_   = -1;
    float     currentTargetYaw_  = 0.0f;
    float     currentTargetPitch_= 0.0f;
    RodState  state_             = RodState::IDLE;
    int       pendingRodSlot_    = -1;
    int       pendingOrigSlot_   = -1;
    float     savedYaw_          = 0.0f;
    float     savedPitch_        = 0.0f;
    float     savedPrevYaw_      = 0.0f;
    float     savedPrevPitch_    = 0.0f;

public:
    AutoRodModule() : Render3dBaseModule(BindType::TOGGLE, 0) {}
    ~AutoRodModule() override = default;

    void onLoad() override;
    void onEnable() override {
        Render3dBaseModule::onEnable();
        lastThrowMs_     = 0;
        currentTargetId_ = -1;
        state_           = RodState::IDLE;
    }
    void onDisable() override {
        Render3dBaseModule::onDisable();
        currentTargetId_ = -1;
        state_           = RodState::IDLE;
    }
    void onCleanup() override { clearInstanceBuffer(); }

protected:
    void registerEvents() override;
    void onRender3d(const Render3dEvent& event) override;

private:
    mutable char instanceBuffer[64] = {0};

    void onTick(const OnRunTickEvent& event);

    int  findRodSlot(EntityClientPlayerMP& player) const;
    bool findClosestTarget(JNIEnv* env, int& outId,
                            float& outYaw, float& outPitch, double& outDist) const;
    void throwRod(JNIEnv* env, int rodSlot, float yaw, float pitch);

    static long long now() {
        return std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();
    }

public:
    FORMAT_FLAGS("%.1fm", this->maxRodRange)
};
