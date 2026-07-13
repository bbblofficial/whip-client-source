#pragma once

#include <unordered_map>
#include <vector>
#include <memory>
#include "../setting/Setting.h"
#include "../module/IModule.h"

class SettingsHandler {
    std::unordered_map<IModule*, std::vector<std::shared_ptr<ISetting>>> m_moduleSettings;

public:
    SettingsHandler() = default;
    ~SettingsHandler() = default;

    SettingsHandler(const SettingsHandler&) = delete;
    SettingsHandler& operator=(const SettingsHandler&) = delete;

    void addSetting(IModule* module, std::shared_ptr<ISetting> setting);
    const std::vector<std::shared_ptr<ISetting>>& getModuleSettings(IModule* module) const;
    void initializeModuleSettings(IModule* module);
    void removeModuleSettings(const IModule* module);
    void renderNormalSettings(const std::unique_ptr<c_widgets> &widgets, IModule* module);
    void renderConditionalSettings(const std::unique_ptr<c_widgets> &widgets, IModule* module);
    bool hasSettings(IModule* module) const;
    const char* getModuleName(IModule* module) const;

    std::shared_ptr<BoolSetting> createBoolSetting(const char* name, bool* value, bool defaultValue, std::function<bool()> visibility = nullptr, bool isConditional = false, std::function<void(bool)> callback = nullptr, bool callbackOnVisibilityChange = false);
    std::shared_ptr<IntSliderSetting> createIntSliderSetting(const char* name, int* value, int defaultValue, int minValue, int maxValue, std::function<bool()> visibility = nullptr, bool isConditional = false, std::function<void(int)> callback = nullptr);
    std::shared_ptr<FloatSliderSetting> createFloatSliderSetting(const char* name, float* value, float defaultValue, float minValue, float maxValue, std::function<bool()> visibility = nullptr, bool isConditional = false, std::function<void(float)> callback = nullptr);
    std::shared_ptr<IntRangeSliderSetting> createIntRangeSliderSetting(const char* name, int* minValue, int* maxValue, int defaultMin, int defaultMax, int rangeMin, int rangeMax, std::function<bool()> visibility = nullptr, bool isConditional = false, std::function<void(int, int)> callback = nullptr);
    std::shared_ptr<FloatRangeSliderSetting> createFloatRangeSliderSetting(const char* name, float* minValue, float* maxValue, float defaultMin, float defaultMax, float rangeMin, float rangeMax, std::function<bool()> visibility = nullptr, bool isConditional = false, std::function<void(float, float)> callback = nullptr);
    std::shared_ptr<ComboSetting> createComboSetting(const char* name, int* selectedIndex, const std::vector<const char*>& options, std::function<bool()> visibility = nullptr, bool isConditional = false, std::function<void(int)> callback = nullptr);
    std::shared_ptr<MultiComboSetting> createMultiComboSetting(const char* name, std::vector<bool>* selectedItems, const std::vector<const char*>& options, const std::vector<bool>& defaultValues = {}, std::function<bool()> visibility = nullptr, bool isConditional = false, std::function<void(const std::vector<bool>&)> callback = nullptr);
    std::shared_ptr<KeybindSetting> createKeybindSetting(const char* name, int* keyCode, int defaultValue, std::function<bool()> visibility = nullptr, bool isConditional = false, std::function<void(int)> callback = nullptr, std::function<void()> pressCallback = nullptr);
    std::shared_ptr<ColorSetting> createColorSetting(const char* name, ImColor* value, const ImColor& defaultValue, std::function<bool()> visibility = nullptr, bool isConditional = false, std::function<void(const ImVec4&)> callback = nullptr);
    std::shared_ptr<TextSetting> createTextSetting(const char* name, std::string* text, std::function<bool()> visibility = nullptr, bool isConditional = false);
    std::shared_ptr<TextInputSetting> createTextInputSetting(const char* name, std::string* text, const char* defaultValue = "", int maxLength = 256, std::function<bool()> visibility = nullptr, bool isConditional = false, std::function<void(const std::string&)> callback = nullptr);

    std::shared_ptr<BoolSetting> registerBoolValue(const char* name, bool* value, bool defaultValue);
    std::shared_ptr<IntSliderSetting> registerIntValue(const char* name, int* value, int defaultValue, int minValue = 0, int maxValue = 100);
    std::shared_ptr<FloatSliderSetting> registerFloatValue(const char* name, float* value, float defaultValue, float minValue = 0.0f, float maxValue = 100.0f);
    std::shared_ptr<ComboSetting> registerComboValue(const char* name, int* selectedIndex, const std::vector<const char*>& options);
    std::shared_ptr<KeybindSetting> registerKeybindValue(const char* name, int* keyCode, int defaultValue);
    std::shared_ptr<ColorSetting> registerColorValue(const char* name, ImColor* value, const ImColor& defaultValue);

    void resetAllToDefaults() {
        for (auto& [module, settings] : m_moduleSettings) {
            if (module) {
                auto cat = module->getCategory();
                if (cat == CategoryType::SETTING || cat == CategoryType::BACKEND)
                    continue;
            }
            for (auto& setting : settings) {
                if (setting) setting->resetToDefault();
            }
        }
    }

    void cleanup() {
        m_moduleSettings.clear();
    }

    static SettingsHandler& getInstance();
};
