#pragma once

#include "../../../base/DedicatedThreadBaseModule.h"
#include "../../../ModuleType.h"
#include "../../../CategoryType.h"
#include "../../../../util/JniScope.h"
#include "../../../../util/Debug.h"
#include "../../../../setting/SettingMacros.h"
#include "../../../../manager/BindManager.h"
#include "mode/ThrowMode.h"
#include <memory>
#include <atomic>

#include "mode/ThrowDebuffMode.h"
#include "mode/ThrowPearlMode.h"
#include "mode/ThrowPotMode.h"
#include "mode/ThrowSoupMode.h"

#include "widgets.h"
#include "util/ClientStrings.h"
#include "functions.h"

#define SCALE(x) (x)

class ThrowModule final : public DedicatedThreadBaseModule<ThrowModule, ModuleType::THROW_MODULE, CategoryType::COMBAT> {
    std::unique_ptr<ThrowMode> potMode;
    std::unique_ptr<ThrowMode> soupMode;
    std::unique_ptr<ThrowMode> debuffMode;
    std::unique_ptr<ThrowMode> pearlMode;

    static constexpr float MIN_SPEED = 0.0f;
    static constexpr float MAX_SPEED = 10.0f;

    static inline std::atomic<bool> throwing_ = false;

    bool potKeyPressed = false;
    bool soupKeyPressed = false;
    bool debuffKeyPressed = false;
    bool pearlKeyPressed = false;

    bool potEnabled = false;
    bool soupEnabled = false;
    bool debuffEnabled = false;
    bool pearlEnabled = false;

    bool potShowInArrayList = false;
    bool soupShowInArrayList = false;
    bool debuffShowInArrayList = false;
    bool pearlShowInArrayList = false;

    int potSpeed = 1;
    float potDisplaySpeed = 10.0f;
    bool smartMod = false;
    bool doubleThrow = false;
    int potKeybind = 0;

    int soupSpeed = 1;
    float soupDisplaySpeed = 10.0f;
    bool smartModSoup = false;
    bool doubleUse = false;
    bool autoDrop = false;
    int soupKeybind = 0;

    int debuffSpeed = 1;
    float debuffDisplaySpeed = 10.0f;
    bool doubleThrowDebuff = false;
    int debuffKeybind = 0;

    int pearlSpeed = 1;
    float pearlDisplaySpeed = 10.0f;
    int pearlKeybind = 0;

protected:
    void onUpdate(JniScope& scope) override;

public:
    ThrowModule() = default;

    void onLoad() override {
        DedicatedThreadBaseModule::onLoad();

        potMode = std::make_unique<ThrowPotMode>();
        soupMode = std::make_unique<ThrowSoupMode>();
        debuffMode = std::make_unique<ThrowDebuffMode>();
        pearlMode = std::make_unique<ThrowPearlMode>();

        REGISTER_BOOL(potEnabled, false);
        REGISTER_INT(potSpeed, 10);
        REGISTER_BOOL(smartMod, false);
        REGISTER_BOOL(doubleThrow, false);
        REGISTER_KEYBIND(potKeybind, 0);

        REGISTER_BOOL(soupEnabled, false);
        REGISTER_INT(soupSpeed, 10);
        REGISTER_BOOL(smartModSoup, false);
        REGISTER_BOOL(doubleUse, false);
        REGISTER_BOOL(autoDrop, false);
        REGISTER_KEYBIND(soupKeybind, 0);

        REGISTER_BOOL(debuffEnabled, false);
        REGISTER_INT(debuffSpeed, 10);
        REGISTER_BOOL(doubleThrowDebuff, false);
        REGISTER_KEYBIND(debuffKeybind, 0);

        REGISTER_BOOL(pearlEnabled, false);
        REGISTER_INT(pearlSpeed, 10);
        REGISTER_KEYBIND(pearlKeybind, 0);

    }

    void syncDisplaySpeeds() {
        potDisplaySpeed = MAX_SPEED - static_cast<float>(potSpeed);
        soupDisplaySpeed = MAX_SPEED - static_cast<float>(soupSpeed);
        debuffDisplaySpeed = MAX_SPEED - static_cast<float>(debuffSpeed);
        pearlDisplaySpeed = MAX_SPEED - static_cast<float>(pearlSpeed);
    }

    ~ThrowModule() override = default;

    void onRender(const std::unique_ptr<c_widgets>& widgets) override {

        syncDisplaySpeeds();

        widgets->child(Strings::secThrowHealth());
        {
            if (widgets->checkbox(Strings::lblEnableHealth(), &potEnabled)) {
                processPotEnable(potEnabled);
            }
            widgets->tooltip_bind(Strings::lblBind(), "", &potKeybind, nullptr);

            if (widgets->slider_float(Strings::lblSpeed(), &potDisplaySpeed, MIN_SPEED, MAX_SPEED, "%.1f")) {
                this->potSpeed = MAX_SPEED - potDisplaySpeed;
                this->potSpeed = std::min(10, std::max(0, this->potSpeed));
            }
        }
        widgets->end_child();

        gui->sameline();

        widgets->child(Strings::secSettings2());
        {
            widgets->checkbox(Strings::lblSmartMode(), &this->smartMod);
            widgets->checkbox(Strings::lblDoubleThrow(), &this->doubleThrow);
        }
        widgets->end_child();

        widgets->child(Strings::secThrowSoup());
        {
            if (widgets->checkbox(Strings::lblEnableSoup(), &soupEnabled)) {
                processSoupEnable(soupEnabled);
            }
            widgets->tooltip_bind(Strings::lblBind(), "", &soupKeybind, nullptr);

            if (widgets->slider_float(Strings::lblSpeed(), &soupDisplaySpeed, MIN_SPEED, MAX_SPEED, "%.1f")) {
                this->soupSpeed = MAX_SPEED - soupDisplaySpeed;
                this->soupSpeed = std::min(10, std::max(0, this->soupSpeed));
            }
        }
        widgets->end_child();

        gui->sameline();

        widgets->child(Strings::secSettings1());
        {
            widgets->checkbox(Strings::lblSmartMode(), &this->smartModSoup);
            widgets->checkbox(Strings::lblDoubleUse(), &this->doubleUse);
            widgets->checkbox(Strings::lblAutoDrop(), &this->autoDrop);
        }
        widgets->end_child();

        widgets->child(Strings::secThrowDebuff());
        {
            if (widgets->checkbox(Strings::lblEnableDebuff(), &debuffEnabled)) {
                processDebuffEnable(debuffEnabled);
            }
            widgets->tooltip_bind(Strings::lblBind(), "", &debuffKeybind, nullptr);

            if (widgets->slider_float(Strings::lblSpeed(), &debuffDisplaySpeed, MIN_SPEED, MAX_SPEED, "%.1f")) {
                this->debuffSpeed = MAX_SPEED - debuffDisplaySpeed;
                this->debuffSpeed = std::min(10, std::max(0, this->debuffSpeed));
            }
        }
        widgets->end_child();

        gui->sameline();

        widgets->child(Strings::secSettings3());
        {
            widgets->checkbox(Strings::lblDoubleThrow(), &this->doubleThrowDebuff);
        }
        widgets->end_child();

        widgets->child(Strings::secThrowPearl());
        {
            if (widgets->checkbox(Strings::lblEnablePearl(), &pearlEnabled)) {
                processPearlEnable(pearlEnabled);
            }
            widgets->tooltip_bind(Strings::lblBind(), "", &pearlKeybind, nullptr);

            if (widgets->slider_float(Strings::lblSpeed(), &pearlDisplaySpeed, MIN_SPEED, MAX_SPEED, "%.1f")) {
                this->pearlSpeed = MAX_SPEED - pearlDisplaySpeed;
                this->pearlSpeed = std::min(10, std::max(0, this->pearlSpeed));
            }
        }
        widgets->end_child();

        gui->sameline();

        widgets->child(Strings::secSettings4());
        {
        }
        widgets->end_child();

        registerThrowKeybinds();
    }

    bool forceRender() const override {
        return isThrowModuleEnabled();
    }

    void onRenderConditional(const std::unique_ptr<c_widgets>& widgets) override {}

    void processPotEnable(const bool value) {
        potEnabled = value;
        if (value) {
            if (!soupEnabled && !debuffEnabled && !pearlEnabled) {
                DedicatedThreadBaseModule::setEnabled(true);
            }
        } else {
            if (!soupEnabled && !debuffEnabled && !pearlEnabled) {
                DedicatedThreadBaseModule::setEnabled(false);
            }
        }
    }

    void processSoupEnable(const bool value) {
        soupEnabled = value;
        if (value) {
            if (!potEnabled && !debuffEnabled && !pearlEnabled) {
                DedicatedThreadBaseModule::setEnabled(true);
            }
        } else {
            if (!potEnabled && !debuffEnabled && !pearlEnabled) {
                DedicatedThreadBaseModule::setEnabled(false);
            }
        }
    }

    void processDebuffEnable(const bool value) {
        debuffEnabled = value;
        if (value) {
            if (!potEnabled && !soupEnabled && !pearlEnabled) {
                DedicatedThreadBaseModule::setEnabled(true);
            }
        } else {
            if (!potEnabled && !soupEnabled && !pearlEnabled) {
                DedicatedThreadBaseModule::setEnabled(false);
            }
        }
    }

    void processPearlEnable(const bool value) {
        pearlEnabled = value;
        if (value) {
            if (!potEnabled && !soupEnabled && !debuffEnabled) {
                DedicatedThreadBaseModule::setEnabled(true);
            }
        } else {
            if (!potEnabled && !soupEnabled && !debuffEnabled) {
                DedicatedThreadBaseModule::setEnabled(false);
            }
        }
    }

    bool isThrowModuleEnabled() const {
        return soupEnabled || potEnabled || debuffEnabled || pearlEnabled;
    }

    static bool isThrowing() { return throwing_.load(std::memory_order_acquire); }

    const char* getDisplayFlags() const override {
        static char buffer[64];
        buffer[0] = {};
        buffer[1] = '\0';

        if (potEnabled) strcat(buffer, Strings::flagHealth());
        if (soupEnabled) strcat(buffer, Strings::flagSoup());
        if (debuffEnabled) strcat(buffer, Strings::flagDebuff());
        if (pearlEnabled) strcat(buffer, Strings::flagPearl());

        return buffer;
    }

    IGuiCustomRenderType getRenderType() const override {
        return OVERRIDE;
    }

private:
    void executeThrowMode(std::unique_ptr<ThrowMode>& mode, int speed, bool enabled, int keybind, bool doubleOption, bool smartMode, bool& keyPressed, JniScope& scope);

    void registerThrowKeybinds() {
        static int lastPotKeybind = 0;
        static int lastSoupKeybind = 0;
        static int lastDebuffKeybind = 0;
        static int lastPearlKeybind = 0;

        void* potOwner = (void*)&potKeybind;
        void* soupOwner = (void*)&soupKeybind;
        void* debuffOwner = (void*)&debuffKeybind;
        void* pearlOwner = (void*)&pearlKeybind;

        if (potKeybind != lastPotKeybind) {

            if (lastPotKeybind != 0) {
                BindManager::getInstance().removeCallbackForOwner(potOwner, lastPotKeybind);
            }

            if (potKeybind != 0) {
                BindManager::getInstance().registerCallbackForOwner(potOwner, potKeybind, []() {}, []() {});
            }
            lastPotKeybind = potKeybind;
        }

        if (soupKeybind != lastSoupKeybind) {

            if (lastSoupKeybind != 0) {
                BindManager::getInstance().removeCallbackForOwner(soupOwner, lastSoupKeybind);
            }

            if (soupKeybind != 0) {
                BindManager::getInstance().registerCallbackForOwner(soupOwner, soupKeybind, []() {}, []() {});
            }
            lastSoupKeybind = soupKeybind;
        }

        if (debuffKeybind != lastDebuffKeybind) {

            if (lastDebuffKeybind != 0) {
                BindManager::getInstance().removeCallbackForOwner(debuffOwner, lastDebuffKeybind);
            }

            if (debuffKeybind != 0) {
                BindManager::getInstance().registerCallbackForOwner(debuffOwner, debuffKeybind, []() {}, []() {});
            }
            lastDebuffKeybind = debuffKeybind;
        }

        if (pearlKeybind != lastPearlKeybind) {

            if (lastPearlKeybind != 0) {
                BindManager::getInstance().removeCallbackForOwner(pearlOwner, lastPearlKeybind);
            }

            if (pearlKeybind != 0) {
                BindManager::getInstance().registerCallbackForOwner(pearlOwner, pearlKeybind, []() {}, []() {});
            }
            lastPearlKeybind = pearlKeybind;
        }
    }
};
