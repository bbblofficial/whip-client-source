#include "../../includes/handler/SettingsHandler.h"
#include "../../includes/module/IModule.h"
#include "../../includes/util/TrackedString.h"
#include <cctype>
#include <cstring>

namespace {

    const char* toPascalCaseTracked(const char* input) {
        if (!input || input[0] == '\0') return input;

        size_t inputLen = strlen(input);

        size_t bufSize = inputLen * 2 + 1;
        char* out = static_cast<char*>(TrackedStringRegistry::instance().allocate(bufSize));
        if (!out) return input;

        size_t j = 0;
        for (size_t i = 0; i < inputLen && j < bufSize - 2; ++i) {
            char c = input[i];
            if (i > 0 && (std::isupper(c) || std::isdigit(c))) {
                out[j++] = ' ';
            }
            if (j < bufSize - 1) {
                out[j++] = c;
            }
        }
        out[j] = '\0';

        bool capitalizeNext = true;
        for (size_t i = 0; i < j; ++i) {
            if (out[i] == ' ') { capitalizeNext = true; continue; }
            if (capitalizeNext) { out[i] = static_cast<char>(std::toupper(static_cast<unsigned char>(out[i]))); capitalizeNext = false; }
        }

        TrackedStringRegistry::instance().track(out, j + 1, true);
        return out;
    }
}

void SettingsHandler::addSetting(IModule* module, std::shared_ptr<ISetting> setting) {
    if (!module || !setting) return;

    m_moduleSettings[module].push_back(setting);
}

const std::vector<std::shared_ptr<ISetting>>& SettingsHandler::getModuleSettings(IModule* module) const {
    static std::vector<std::shared_ptr<ISetting>> empty;

    if (const auto it = m_moduleSettings.find(module); it != m_moduleSettings.end()) {
        return it->second;
    }

    return empty;
}

void SettingsHandler::initializeModuleSettings(IModule* module) {
    if (!module) return;

    if (!m_moduleSettings.contains(module)) {
        m_moduleSettings[module] = std::vector<std::shared_ptr<ISetting>>();
    }
}

void SettingsHandler::removeModuleSettings(const IModule* module) {
    if (!module) return;

    m_moduleSettings.clear();
}

const char* SettingsHandler::getModuleName(IModule* module) const {
    if (!module) return "unknown";
    const char* name = module->getDisplayName();
    return name ? name : "unknown";
}

bool SettingsHandler::hasSettings(IModule* module) const {
    const auto it = m_moduleSettings.find(module);
    return it != m_moduleSettings.end() && !it->second.empty();
}

void SettingsHandler::renderNormalSettings(const std::unique_ptr<c_widgets> &widgets, IModule* module) {
    if (!module) return;

    const auto it = m_moduleSettings.find(module);
    if (it == m_moduleSettings.end()) return;

    for (const auto& setting : it->second) {
        if (setting && setting->isVisible() && !setting->isConditional()) {
            setting->render(widgets);

            if (setting->getType() == SettingType::KEYBIND) {
                auto* keybindSetting = static_cast<KeybindSetting*>(setting.get());
                keybindSetting->checkKeyPress();
            }
        }
    }
}

void SettingsHandler::renderConditionalSettings(const std::unique_ptr<c_widgets> &widgets, IModule* module) {
    if (!module) return;

    const auto it = m_moduleSettings.find(module);
    if (it == m_moduleSettings.end()) return;

    for (const auto& setting : it->second) {
        if (setting && setting->isVisible() && setting->isConditional()) {
            setting->render(widgets);

            if (setting->getType() == SettingType::KEYBIND) {
                auto* keybindSetting = static_cast<KeybindSetting*>(setting.get());
                keybindSetting->checkKeyPress();
            }
        }
    }
}

std::shared_ptr<BoolSetting> SettingsHandler::createBoolSetting(const char* name, bool* value, bool defaultValue, std::function<bool()> visibility, bool isConditional, std::function<void(bool)> callback, bool callbackOnVisibilityChange) {
    return std::allocate_shared<BoolSetting>(TrackedAllocator<BoolSetting>{},toPascalCaseTracked(name), value, defaultValue, std::move(visibility), isConditional, std::move(callback), callbackOnVisibilityChange);
}

std::shared_ptr<IntSliderSetting> SettingsHandler::createIntSliderSetting(const char* name, int* value, int defaultValue, int minValue, int maxValue, std::function<bool()> visibility, bool isConditional, std::function<void(int)> callback) {
    return std::allocate_shared<IntSliderSetting>(TrackedAllocator<IntSliderSetting>{},toPascalCaseTracked(name), value, defaultValue, minValue, maxValue, std::move(visibility), isConditional, std::move(callback));
}

std::shared_ptr<FloatSliderSetting> SettingsHandler::createFloatSliderSetting(const char* name, float* value, float defaultValue, float minValue, float maxValue, std::function<bool()> visibility, bool isConditional, std::function<void(float)> callback) {
    return std::allocate_shared<FloatSliderSetting>(TrackedAllocator<FloatSliderSetting>{},toPascalCaseTracked(name), value, defaultValue, minValue, maxValue, std::move(visibility), isConditional, std::move(callback));
}

std::shared_ptr<IntRangeSliderSetting> SettingsHandler::createIntRangeSliderSetting(const char* name, int* minValue, int* maxValue, int defaultMin, int defaultMax, int rangeMin, int rangeMax, std::function<bool()> visibility, bool isConditional, std::function<void(int, int)> callback) {
    return std::allocate_shared<IntRangeSliderSetting>(TrackedAllocator<IntRangeSliderSetting>{},toPascalCaseTracked(name), minValue, maxValue, defaultMin, defaultMax, rangeMin, rangeMax, std::move(visibility), isConditional, std::move(callback));
}

std::shared_ptr<FloatRangeSliderSetting> SettingsHandler::createFloatRangeSliderSetting(const char* name, float* minValue, float* maxValue, float defaultMin, float defaultMax, float rangeMin, float rangeMax, std::function<bool()> visibility, bool isConditional, std::function<void(float, float)> callback) {
    return std::allocate_shared<FloatRangeSliderSetting>(TrackedAllocator<FloatRangeSliderSetting>{},toPascalCaseTracked(name), minValue, maxValue, defaultMin, defaultMax, rangeMin, rangeMax, std::move(visibility), isConditional, std::move(callback));
}

std::shared_ptr<ComboSetting> SettingsHandler::createComboSetting(const char* name, int* selectedIndex, const std::vector<const char*>& options, std::function<bool()> visibility, bool isConditional, std::function<void(int)> callback) {
    return std::allocate_shared<ComboSetting>(TrackedAllocator<ComboSetting>{},toPascalCaseTracked(name), selectedIndex, options, std::move(visibility), isConditional, std::move(callback));
}

std::shared_ptr<MultiComboSetting> SettingsHandler::createMultiComboSetting(const char* name, std::vector<bool>* selectedItems, const std::vector<const char*>& options, const std::vector<bool>& defaultValues, std::function<bool()> visibility, bool isConditional, std::function<void(const std::vector<bool>&)> callback) {
    return std::allocate_shared<MultiComboSetting>(TrackedAllocator<MultiComboSetting>{},toPascalCaseTracked(name), selectedItems, options, defaultValues, std::move(visibility), isConditional, std::move(callback));
}

std::shared_ptr<KeybindSetting> SettingsHandler::createKeybindSetting(const char* name, int* keyCode, int defaultValue, std::function<bool()> visibility, bool isConditional, std::function<void(int)> callback, std::function<void()> pressCallback) {
    return std::allocate_shared<KeybindSetting>(TrackedAllocator<KeybindSetting>{},toPascalCaseTracked(name), keyCode, defaultValue, std::move(visibility), isConditional, std::move(callback), std::move(pressCallback));
}

std::shared_ptr<ColorSetting> SettingsHandler::createColorSetting(const char* name, ImColor* value, const ImColor& defaultValue, std::function<bool()> visibility, bool isConditional, std::function<void(const ImVec4&)> callback) {
    return std::allocate_shared<ColorSetting>(TrackedAllocator<ColorSetting>{},toPascalCaseTracked(name), value, defaultValue, std::move(visibility), isConditional, std::move(callback));
}

std::shared_ptr<TextSetting> SettingsHandler::createTextSetting(const char* name, std::string* text, std::function<bool()> visibility, bool isConditional) {
    return std::allocate_shared<TextSetting>(TrackedAllocator<TextSetting>{},toPascalCaseTracked(name), text, std::move(visibility), isConditional);
}

std::shared_ptr<TextInputSetting> SettingsHandler::createTextInputSetting(const char* name, std::string* text, const char* defaultValue, int maxLength, std::function<bool()> visibility, bool isConditional, std::function<void(const std::string&)> callback) {
    return std::allocate_shared<TextInputSetting>(TrackedAllocator<TextInputSetting>{},toPascalCaseTracked(name), text, defaultValue, maxLength, std::move(visibility), isConditional, std::move(callback));
}

std::shared_ptr<BoolSetting> SettingsHandler::registerBoolValue(const char* name, bool* value, bool defaultValue) {
    return std::allocate_shared<BoolSetting>(TrackedAllocator<BoolSetting>{},name, value, defaultValue, +[]() { return false; }, false, nullptr, false);
}

std::shared_ptr<IntSliderSetting> SettingsHandler::registerIntValue(const char* name, int* value, int defaultValue, int minValue, int maxValue) {
    return std::allocate_shared<IntSliderSetting>(TrackedAllocator<IntSliderSetting>{},name, value, defaultValue, minValue, maxValue, +[]() { return false; }, false, nullptr);
}

std::shared_ptr<FloatSliderSetting> SettingsHandler::registerFloatValue(const char* name, float* value, float defaultValue, float minValue, float maxValue) {
    return std::allocate_shared<FloatSliderSetting>(TrackedAllocator<FloatSliderSetting>{},name, value, defaultValue, minValue, maxValue, +[]() { return false; }, false, nullptr);
}

std::shared_ptr<ComboSetting> SettingsHandler::registerComboValue(const char* name, int* selectedIndex, const std::vector<const char*>& options) {
    return std::allocate_shared<ComboSetting>(TrackedAllocator<ComboSetting>{},name, selectedIndex, options, +[]() { return false; }, false, nullptr);
}

std::shared_ptr<KeybindSetting> SettingsHandler::registerKeybindValue(const char* name, int* keyCode, int defaultValue) {
    return std::allocate_shared<KeybindSetting>(TrackedAllocator<KeybindSetting>{},name, keyCode, defaultValue, +[]() { return false; }, false, nullptr);
}

std::shared_ptr<ColorSetting> SettingsHandler::registerColorValue(const char* name, ImColor* value, const ImColor& defaultValue) {
    return std::allocate_shared<ColorSetting>(TrackedAllocator<ColorSetting>{},name, value, defaultValue, +[]() { return false; }, false, nullptr);
}

SettingsHandler& SettingsHandler::getInstance() {
    static SettingsHandler instance;
    return instance;
}
