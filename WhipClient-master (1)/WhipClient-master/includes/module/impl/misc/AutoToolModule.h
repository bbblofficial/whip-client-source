#pragma once

#include "../../base/DedicatedThreadBaseModule.h"
#include "../../ModuleType.h"
#include <chrono>

class AutoToolModule final : public DedicatedThreadBaseModule<AutoToolModule, ModuleType::AUTO_TOOL, CategoryType::MISC> {
    int delayTicks = 4;
    bool instantOnShift = false;

    bool isAimingBlock_ = false;
    bool hasSwitched_ = false;
    bool hasEverSwitchedSlot_ = false;

    int lastBlockX_ = 0;
    int lastBlockY_ = 0;
    int lastBlockZ_ = 0;

    std::chrono::steady_clock::time_point lastBlockAimTime_;

    int originalSlot_ = 0;

    void switchToSword(JNIEnv* env);
    static int findBestSwordSlot(JNIEnv* env);

protected:
    void onUpdate(JniScope& scope) override;

public:
    AutoToolModule() : DedicatedThreadBaseModule(BindType::TOGGLE, 0, 1) {}

    void onLoad() override;
    void onCleanup() override { clearInstanceBuffer(); }

private:
    mutable char instanceBuffer[64] = {0};
    void clearInstanceBuffer() const { memset(instanceBuffer, 0, sizeof(instanceBuffer)); }
};
