#pragma once

#include "../../../hud/renderer/IArraylistRenderer.h"
#include "../../base/ListenedBaseModule.h"
#include "../../ModuleType.h"
#include "../../CategoryType.h"

#include "event/sub/ChannelReadEvent.h"
#include "event/sub/DispatchKeypressesEvent.h"
#include "event/sub/StatusUpdateEvent.h"
#include "event/sub/OnTickEvent.h"
#include "hook/sub/AddSendQueueHook.h"
#include "util/ClientStrings.h"
#include "wrapper/minecraft/client/minecraft.h"

class VelocityModule final : public ListenedBaseModule<VelocityModule, ModuleType::VELOCITY, CategoryType::COMBAT> {
    int chance = 100;
    float horizontal = 50.0f;
    float vertical = 100.0f;
    float reverseStrength = 100.0f;
    float reduceH = 60.0f;
    bool agcBypass = false;
    int mode = 0;
    bool weaponsOnly = true;
    bool onAirOnly = false;
    bool onGroundOnly = false;
    bool onlyWhenMovingForward = false;
    bool onlyLookingAtPlayer = false;
    bool onlyMousePressed = false;
    int jumpDelayMs = 0;

    bool pendingJumpReset = false;
    bool pendingJumpDelay = false;
    long long jumpDelayStart_ = 0;

protected:
    int inverse(int value);

public:
    VelocityModule() {}

    void registerEvents() override {
        subscribe<ChannelReadEvent>([this](const ChannelReadEvent& event) {
            onChannelRead(event);
        }, EventPriority::HIGH, false);

        subscribe<OnRunTickEvent>([this](const OnRunTickEvent& event) {
            onTick(event);
        }, EventPriority::HIGH, false);
    }

    void onChannelRead(const ChannelReadEvent& event);

    void onTick(const OnRunTickEvent& event);

    void onEnable() override {
        ListenedBaseModule::onEnable();
        pendingJumpReset = false;
        pendingJumpDelay = false;
        jumpDelayStart_ = 0;
    }

    void onDisable() override {
        ListenedBaseModule::onDisable();
        pendingJumpReset = false;
        pendingJumpDelay = false;
    }

    void onCleanup() override { clearInstanceBuffer(); }

    void onLoad() override {
        ListenedBaseModule::onLoad();

        COMBO_SETTING(mode, Strings::modeBlatant(), Strings::modeReverse(), Strings::modeJump(), "Reduce");
        FLOAT_SLIDER_OPTIONAL(horizontal, 50.0f, 0.0f, 100.0f, SETTING_VISIBILITY(mode == 0));
        FLOAT_SLIDER_OPTIONAL(vertical, 100.0f, 0.0f, 100.0f, SETTING_VISIBILITY(mode == 0));
        FLOAT_SLIDER_OPTIONAL(reverseStrength, 100.0f, 0.0f, 100.0f, SETTING_VISIBILITY(mode == 1));
        do {
            auto setting = SettingsHandler::getInstance().createFloatSliderSetting("Strength", &reduceH, 60.0f, 0.0f, 100.0f, SETTING_VISIBILITY(mode == 3));
            SettingsHandler::getInstance().addSetting(this, setting);
        } while(0);
        do {
            auto setting = SettingsHandler::getInstance().createBoolSetting("AGC Bypass", &agcBypass, false, SETTING_VISIBILITY(mode == 3), true);
            SettingsHandler::getInstance().addSetting(this, setting);
        } while(0);
        INT_SLIDER_OPTIONAL(jumpDelayMs, 0, 0, 50, SETTING_VISIBILITY(mode == 2));
        INT_SLIDER(chance, 100, 0, 100);

        BOOL_SETTING_CONDITIONAL(weaponsOnly, true);
        BOOL_SETTING_CONDITIONAL(onlyWhenMovingForward, false);
        BOOL_SETTING_CONDITIONAL(onlyLookingAtPlayer, false);
        BOOL_SETTING_CONDITIONAL(onlyMousePressed, false);
    }

    bool isPlayerMovingForward(JNIEnv* env);

    bool isPlayerSprinting(JNIEnv* env);

private:
    mutable char instanceBuffer[64] = {};

public:

    FORMAT_FLAGS(mode == 2 ? "%s" : mode == 3 ? "%s %.0f%%" : mode == 0 ? "%s %.0f-%.0f" : "%s %.0f",
        mode == 0 ? Strings::modeBlatant() : mode == 1 ? Strings::modeReverse() : mode == 3 ? "Reduce" : Strings::modeJump(),
        mode == 0 ? horizontal : mode == 1 ? reverseStrength : mode == 3 ? reduceH : (float)10,
        mode == 0 ? vertical : (float)0)
};
