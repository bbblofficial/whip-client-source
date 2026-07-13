#pragma once

#include "BaseModule.h"
#include "../../DllMain.h"
#include "../../handler/SettingsHandler.h"
#include "../../setting/SettingMacros.h"
#include "../../setting/Setting.h"
#include "../IGuiCustomRender.h"
#include "../../bus/EventBus.h"
#include "../../bus/Subscriber.h"
#include "../../util/Debug.h"
#include <vector>
#include <string>
#include <memory>

template<typename Derived, ModuleType Type = ModuleType::SETTINGS, CategoryType Category = CategoryType::SETTING>
class SettingBaseModule : public BaseModule<Derived, Type, Category>, public IGuiCustomRender {
    struct SettingGroup {
        std::string name;
        bool collapsed = false;
        std::function<bool()> visibility = nullptr;
        std::vector<std::shared_ptr<ISetting>> settings;
    };

    std::vector<SettingGroup> m_settingGroups;
    std::string m_currentGroup;
    bool m_autoSave = true;
    bool m_showAdvanced = false;

protected:
    EventBus* eventBus;

public:
    explicit SettingBaseModule() : BaseModule<Derived, Type, Category>(), eventBus(&EventBus::getInstance()) {

    }

    ~SettingBaseModule() override {
        unregisterEvents();
    }

    void onLoad() override {
        SettingsHandler::getInstance().initializeModuleSettings(this);
        registerEvents();
    }

    void onEnable() override {
        BaseModule<Derived, Type, Category>::onEnable();
    }

    void onDisable() override {
        BaseModule<Derived, Type, Category>::onDisable();
    }

protected:
    template<typename EventType>
    void subscribe(std::function<void(const EventType&)> callback, const int priority = EventPriority::DEFAULT, const bool ignoreCancelled = true) {
        eventBus->subscribe<EventType>(this, std::move(callback), priority, ignoreCancelled);
    }

    virtual void registerEvents() {

    }

    virtual void onSettingChanged(const std::string& settingName, const void* newValue) {}

    bool updateFloatSliderMaxValue(const std::string& settingName, const float newMaxValue) {

        const auto* settingsHandler = &SettingsHandler::getInstance();
        if (!settingsHandler) {
            return false;
        }

        for (const auto& setting : settingsHandler->getModuleSettings(this)) {
            if (setting->getName() == settingName && setting->getType() == SettingType::FLOAT_SLIDER) {
                auto* floatSetting = static_cast<FloatSliderSetting*>(setting.get());
                float oldMax = floatSetting->getMaxValue();
                float currentValue = floatSetting->getValue();
                floatSetting->setMaxValue(newMaxValue);
                return true;
            }
        }
        return false;
    }

    bool updateFloatSliderMinValue(const std::string& settingName, const float newMinValue) {
        const auto* settingsHandler = &SettingsHandler::getInstance();
        if (!settingsHandler) return false;

        for (const auto& setting : settingsHandler->getModuleSettings(this)) {
            if (setting->getName() == settingName && setting->getType() == SettingType::FLOAT_SLIDER) {
                auto* floatSetting = static_cast<FloatSliderSetting*>(setting.get());
                floatSetting->setMinValue(newMinValue);
                return true;
            }
        }
        return false;
    }

    bool updateFloatSliderRange(const std::string& settingName, const float newMinValue, const float newMaxValue) {
        const auto* settingsHandler = &SettingsHandler::getInstance();
        if (!settingsHandler) return false;

        for (const auto& setting : settingsHandler->getModuleSettings(this)) {
            if (setting->getName() == settingName && setting->getType() == SettingType::FLOAT_SLIDER) {
                auto* floatSetting = static_cast<FloatSliderSetting*>(setting.get());
                floatSetting->setMinValue(newMinValue);
                floatSetting->setMaxValue(newMaxValue);
                return true;
            }
        }
        return false;
    }

    void onRender(const std::unique_ptr<c_widgets>& widgets) override {
        SettingsHandler::getInstance().renderNormalSettings(widgets, this);
    }

    void onRenderConditional(const std::unique_ptr<c_widgets>& widgets) override {
       SettingsHandler::getInstance().renderConditionalSettings(widgets, this);
    }

    void onFullRender(const std::unique_ptr<c_widgets>& widgets) override {

    }

    IGuiCustomRenderType getRenderType() const override {
        return NONE;
    }

private:
    void unregisterEvents() {
        eventBus->unsubscribe(this);
    }
};
