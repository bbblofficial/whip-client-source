#include "../../../../../includes/module/impl/network/backtrack/BacktrackModule.h"
#include "../../../../../includes/module/impl/network/backtrack/mode/LagMode.h"

#include "../../../../../includes/module/impl/network/backtrack/mode/SmoothMode.h"
#include "../../../../../includes/module/impl/network/backtrack/mode/AdvancedMode.h"

#include "setting/SettingMacros.h"


std::unique_ptr<IBacktrackMode> BacktrackModule::createMode(int modeIndex) {
    switch (modeIndex) {
        case 0:  return std::make_unique<LagMode>(*this);
        case 1:  return std::make_unique<SmoothMode>(*this);
        case 2:  return std::make_unique<AdvancedMode>(*this);
        default: return std::make_unique<LagMode>(*this);
    }
}


void BacktrackModule::onLoad() {
    Render3dBaseModule::onLoad();

    COMBO_SETTING_CALLBACK(mode, [this](int) {
        JNIEnv* env = nullptr;
        JavaVM* jvm = nullptr;
        if (JNI_GetCreatedJavaVMs(&jvm, 1, nullptr) == JNI_OK && jvm)
            jvm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_8);
        if (currentMode_ && env) currentMode_->onDisable(env);
        currentMode_ = createMode(this->mode);
        if (currentMode_ && env && this->enable) currentMode_->onEnable(env);
    }, "Lag", "Smooth", "Advanced");


    INT_SLIDER_OPTIONAL(delayInTicks, 4, 1, 15, SETTING_VISIBILITY(mode == 0));
    INT_SLIDER_OPTIONAL(cooldown, 500, 100, 1000, SETTING_VISIBILITY(mode == 0));


    INT_SLIDER_OPTIONAL(smoothDelayMs, 200, 0, 1000, SETTING_VISIBILITY(mode == 1));
    do {
        auto setting = SettingsHandler::getInstance().createIntSliderSetting("forceFlushMs", &forceFlushMs, 500, 100, 1001, SETTING_VISIBILITY(mode == 1), false);
        setting->setFormatFn([](int v) -> const char* { return v >= 1001 ? "Never" : "%d"; });
        SettingsHandler::getInstance().addSetting(this, setting);
    } while(0);
    BOOL_SETTING_CONDITIONAL_OPTIONAL(onlySprinting, false, SETTING_VISIBILITY(mode == 1));


    BOOL_SETTING_CONDITIONAL_OPTIONAL(distanceCheck, true, SETTING_VISIBILITY(mode == 0));
    do {
        auto setting = SettingsHandler::getInstance().createFloatRangeSliderSetting(
            "Distance", &distance, &distanceMax, 1.0f, 4.0f, 0.0f, 10.0f,
            SETTING_VISIBILITY(distanceCheck && mode == 0));
        SettingsHandler::getInstance().addSetting(this, setting);
    } while(0);


    INT_SLIDER_OPTIONAL(maxDelay, 200, 0, 5000, SETTING_VISIBILITY(mode == 2));
    INT_SLIDER_OPTIONAL(minDelay, 0, 0, 5000, SETTING_VISIBILITY(mode == 2));
    INT_SLIDER_OPTIONAL(delayBetweenLags, 0, 0, 4000, SETTING_VISIBILITY(mode == 2));
    INT_SLIDER_OPTIONAL(stopAtHurt, 10, 0, 10, SETTING_VISIBILITY(mode == 2));
    COMBO_SETTING_OPTIONAL(disableOn, SETTING_VISIBILITY(mode == 2), "None", "OnAttack", "OnRange", "ClickCheck");
    FLOAT_SLIDER_OPTIONAL(stopOnAttackRange, 3.0f, 0.0f, 10.0f, SETTING_VISIBILITY(mode == 2 && disableOn == 2));
    BOOL_SETTING_CONDITIONAL_OPTIONAL(onlyWhenNeeded, true, SETTING_VISIBILITY(mode == 2));
    BOOL_SETTING_CONDITIONAL_OPTIONAL(continueAtHurtTime, false, SETTING_VISIBILITY(mode == 2));
    BOOL_SETTING_CONDITIONAL_OPTIONAL(fixPacketOrder, true, SETTING_VISIBILITY(mode == 2));


    BOOL_SETTING_CONDITIONAL(drawBox, true);
    COLOR_SETTING_CONDITIONAL_OPTIONAL(boxColor, ImColor(0.14f, 0.12f, 0.58f, 0.34f), SETTING_VISIBILITY(drawBox));
    COLOR_SETTING_CONDITIONAL_OPTIONAL(outlineColor, ImColor(1.0f, 1.0f, 1.0f, 1.0f), SETTING_VISIBILITY(drawBox));

    currentMode_ = createMode(mode);
}

void BacktrackModule::onEnable() {
    Render3dBaseModule::onEnable();

    JNIEnv* env = nullptr;
    JavaVM* jvm = nullptr;
    if (JNI_GetCreatedJavaVMs(&jvm, 1, nullptr) == JNI_OK && jvm)
        jvm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_8);

    if (currentMode_) currentMode_->onEnable(env);
}

void BacktrackModule::onDisable() {
    Render3dBaseModule::onDisable();

    JNIEnv* env = nullptr;
    JavaVM* jvm = nullptr;
    if (JNI_GetCreatedJavaVMs(&jvm, 1, nullptr) == JNI_OK && jvm)
        jvm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_8);

    if (currentMode_) currentMode_->onDisable(env);
}


void BacktrackModule::registerEvents() {
    Render3dBaseModule::registerEvents();

    subscribe<ChannelReadEvent>([this](const ChannelReadEvent& event) {
        if (this->enable && currentMode_) currentMode_->onPacketReceived(event);
    }, EventPriority::HIGH, false);

    subscribe<AddSendQueueEvent>([this](const AddSendQueueEvent& event) {
        if (this->enable && currentMode_) currentMode_->onPacketSend(event);
    }, EventPriority::HIGH, false);

    subscribe<OnRunTickEvent>([this](const OnRunTickEvent& event) {
        if (this->enable && currentMode_) currentMode_->onTick(event);
    });

    subscribe<PlayerAttackEvent>([this](const PlayerAttackEvent& event) {
        if (this->enable && currentMode_) currentMode_->onPlayerAttack(event);
    });

    subscribe<MouseLeftClickEvent>([this](const MouseLeftClickEvent& event) {
        if (this->enable && currentMode_) currentMode_->onMouseLeftClick(event);
    }, EventPriority::HIGH, false);
}

void BacktrackModule::onRender3d(const Render3dEvent& event) {
    if (this->enable && currentMode_) currentMode_->onRender3d(event);
}

REGISTER_MODULE(BacktrackModule, ModuleType::BACKTRACK)
