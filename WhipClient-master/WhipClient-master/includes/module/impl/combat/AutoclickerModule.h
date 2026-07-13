#pragma once
#include "../../../hud/renderer/IArraylistRenderer.h"

#include <vector>
#include <random>
#include "../../base/DedicatedThreadBaseModule.h"
#include "../../ModuleType.h"
#include "../../CategoryType.h"
#include "../../../util/JniScope.h"
#include "util/ClientStrings.h"

class AutoClickerModule final : public DedicatedThreadBaseModule<AutoClickerModule, ModuleType::AUTOCLICKER, CategoryType::COMBAT> {
    int mode = 2;
    float average = 17.5f;
    float multiplier = 1.0f;
    bool holdToClick = true;
    bool inventoryClick = true;
    bool fastRefill = false;
    bool preventUnrefill = true;
    bool weaponsOnly = true;
    bool exhaust = true;
    bool breakBlock = false;
    bool blatant = false;
    bool noHitDelay = false;
    bool cpsUnlocker = false;

    int currentPId = 0;
    int recordIndex = 0;
    DWORD lastDoubleClickTime = 0;
    float minDoubleClickDelay = 1.5f;
    float maxDoubleClickDelay = 4.0f;
    int currentConfig = 0;
    int lastRandomIndex = 0;
    int cpsbb = 20;
    int cpsj = 25;

    LARGE_INTEGER qpcFreq{};
    LARGE_INTEGER nextClickTick{};
    LARGE_INTEGER pendingUpTick{};
    bool buttonHeld = false;

protected:
    void onUpdate(JniScope& scope) override;
    void flushPendingUp(HWND hWnd);
    void handlePreciseBlatant(HWND hWnd, float cps);
    void resetPreciseState();

public:
    AutoClickerModule() = default;

    void onLoad() override {
        DedicatedThreadBaseModule::onLoad();

        setDelayMs(2);

        COMBO_SETTING_CALLBACK(mode, [this](const int value) {
            if (value == 1) exhaust = false;
            else exhaust = true;
        }, Strings::modeJitter(), Strings::modeBlatant(), Strings::modeButterfly());
        FLOAT_SLIDER(average, 17.5f, 1.0f, 25.0f);

        BOOL_SETTING_CONDITIONAL(holdToClick, true);
        BOOL_SETTING_CONDITIONAL(preventUnrefill, true);
        BOOL_SETTING_CONDITIONAL(inventoryClick, true);
        BOOL_SETTING_CONDITIONAL_OPTIONAL(fastRefill, false, SETTING_VISIBILITY(inventoryClick));
        BOOL_SETTING_CONDITIONAL(weaponsOnly, true);
        BOOL_SETTING_CONDITIONAL(breakBlock, false);
        BOOL_SETTING_CONDITIONAL_OPTIONAL(exhaust, true, [this]() -> bool {
            return mode != 1;
        });
        if (MinecraftSession::getInstance().version == MinecraftVersion::V1_8_9) {
            BOOL_SETTING_CONDITIONAL(noHitDelay, false);
        }

        currentPId = GetCurrentProcessId();
        recordIndex = 0;
        lastDoubleClickTime = GetTickCount64();
        QueryPerformanceFrequency(&qpcFreq);
    }

    void onEnable() override {
        DedicatedThreadBaseModule::onEnable();
        resetPreciseState();
    }

    void onDisable() override {
        resetPreciseState();
        DedicatedThreadBaseModule::onDisable();
    }

    void onCleanup() override { clearInstanceBuffer(); }

private:
	mutable char instanceBuffer[64] = {0};

public:

    FORMAT_FLAGS("%s %.1f", (this->mode == 0 ? Strings::modeJitter() : this->mode == 1 ? Strings::modeBlatant() : Strings::modeButterfly()), this->average)
};
