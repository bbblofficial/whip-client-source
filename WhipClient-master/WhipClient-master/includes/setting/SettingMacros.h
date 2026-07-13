#pragma once

#include "Setting.h"
#include "../handler/SettingsHandler.h"
#include "imgui.h"
#include <string>

#define BOOL_SETTING(variable, defaultValue) \
    do { \
        auto setting = SettingsHandler::getInstance().createBoolSetting(#variable, &variable, defaultValue); \
        SettingsHandler::getInstance().addSetting(this, setting); \
    } while(0)

#define BOOL_SETTING_OPTIONAL(variable, defaultValue, visibility) \
    do { \
        auto setting = SettingsHandler::getInstance().createBoolSetting(#variable, &variable, defaultValue, visibility); \
        SettingsHandler::getInstance().addSetting(this, setting); \
    } while(0)

#define INT_SLIDER(variable, defaultValue, minValue, maxValue) \
    do { \
        auto setting = SettingsHandler::getInstance().createIntSliderSetting(#variable, &variable, defaultValue, minValue, maxValue); \
        SettingsHandler::getInstance().addSetting(this, setting); \
    } while(0)

#define INT_SLIDER_OPTIONAL(variable, defaultValue, minValue, maxValue, visibility) \
    do { \
        auto setting = SettingsHandler::getInstance().createIntSliderSetting(#variable, &variable, defaultValue, minValue, maxValue, visibility, false); \
        SettingsHandler::getInstance().addSetting(this, setting); \
    } while(0)

#define FLOAT_SLIDER(variable, defaultValue, minValue, maxValue) \
    do { \
        auto setting = SettingsHandler::getInstance().createFloatSliderSetting(#variable, &variable, defaultValue, minValue, maxValue); \
        SettingsHandler::getInstance().addSetting(this, setting); \
    } while(0)

#define FLOAT_SLIDER_OPTIONAL(variable, defaultValue, minValue, maxValue, visibility) \
    do { \
        auto setting = SettingsHandler::getInstance().createFloatSliderSetting(#variable, &variable, defaultValue, minValue, maxValue, visibility); \
        SettingsHandler::getInstance().addSetting(this, setting); \
    } while(0)

#define FLOAT_SLIDER_CALLBACK(variable, defaultValue, minValue, maxValue, callback) \
    do { \
        auto setting = SettingsHandler::getInstance().createFloatSliderSetting(#variable, &variable, defaultValue, minValue, maxValue, true, false, callback); \
        SettingsHandler::getInstance().addSetting(this, setting); \
    } while(0)

#define INT_RANGE_SLIDER(minVar, maxVar, defaultMin, defaultMax, rangeMin, rangeMax) \
    do { \
        auto setting = SettingsHandler::getInstance().createIntRangeSliderSetting(#minVar "_" #maxVar, &minVar, &maxVar, defaultMin, defaultMax, rangeMin, rangeMax); \
        SettingsHandler::getInstance().addSetting(this, setting); \
    } while(0)

#define INT_RANGE_SLIDER_NAMED(name, minVar, maxVar, defaultMin, defaultMax, rangeMin, rangeMax) \
    do { \
        auto setting = SettingsHandler::getInstance().createIntRangeSliderSetting(name, &minVar, &maxVar, defaultMin, defaultMax, rangeMin, rangeMax); \
        SettingsHandler::getInstance().addSetting(this, setting); \
    } while(0)

#define INT_RANGE_SLIDER_OPTIONAL(minVar, maxVar, defaultMin, defaultMax, rangeMin, rangeMax, visibility) \
    do { \
        auto setting = SettingsHandler::getInstance().createIntRangeSliderSetting(#minVar "_" #maxVar, &minVar, &maxVar, defaultMin, defaultMax, rangeMin, rangeMax, visibility); \
        SettingsHandler::getInstance().addSetting(this, setting); \
    } while(0)

#define INT_RANGE_SLIDER_CALLBACK(minVar, maxVar, defaultMin, defaultMax, rangeMin, rangeMax, callback) \
    do { \
        auto setting = SettingsHandler::getInstance().createIntRangeSliderSetting(#minVar "_" #maxVar, &minVar, &maxVar, defaultMin, defaultMax, rangeMin, rangeMax, nullptr, false, callback); \
        SettingsHandler::getInstance().addSetting(this, setting); \
    } while(0)

#define INT_RANGE_SLIDER_CALLBACK_OPTIONAL(minVar, maxVar, defaultMin, defaultMax, rangeMin, rangeMax, visibility, callback) \
    do { \
        auto setting = SettingsHandler::getInstance().createIntRangeSliderSetting(#minVar "_" #maxVar, &minVar, &maxVar, defaultMin, defaultMax, rangeMin, rangeMax, visibility, false, callback); \
        SettingsHandler::getInstance().addSetting(this, setting); \
    } while(0)

#define FLOAT_RANGE_SLIDER(minVar, maxVar, defaultMin, defaultMax, rangeMin, rangeMax) \
    do { \
        auto setting = SettingsHandler::getInstance().createFloatRangeSliderSetting(#minVar "_" #maxVar, &minVar, &maxVar, defaultMin, defaultMax, rangeMin, rangeMax); \
        SettingsHandler::getInstance().addSetting(this, setting); \
    } while(0)

#define FLOAT_RANGE_SLIDER_NAMED(name, minVar, maxVar, defaultMin, defaultMax, rangeMin, rangeMax) \
    do { \
        auto setting = SettingsHandler::getInstance().createFloatRangeSliderSetting(name, &minVar, &maxVar, defaultMin, defaultMax, rangeMin, rangeMax); \
        SettingsHandler::getInstance().addSetting(this, setting); \
    } while(0)

#define FLOAT_RANGE_SLIDER_OPTIONAL(minVar, maxVar, defaultMin, defaultMax, rangeMin, rangeMax, visibility) \
    do { \
        auto setting = SettingsHandler::getInstance().createFloatRangeSliderSetting(#minVar "_" #maxVar, &minVar, &maxVar, defaultMin, defaultMax, rangeMin, rangeMax, visibility); \
        SettingsHandler::getInstance().addSetting(this, setting); \
    } while(0)

#define FLOAT_RANGE_SLIDER_CALLBACK(minVar, maxVar, defaultMin, defaultMax, rangeMin, rangeMax, callback) \
    do { \
        auto setting = SettingsHandler::getInstance().createFloatRangeSliderSetting(#minVar "_" #maxVar, &minVar, &maxVar, defaultMin, defaultMax, rangeMin, rangeMax, nullptr, false, callback); \
        SettingsHandler::getInstance().addSetting(this, setting); \
    } while(0)

#define FLOAT_RANGE_SLIDER_CALLBACK_OPTIONAL(minVar, maxVar, defaultMin, defaultMax, rangeMin, rangeMax, visibility, callback) \
    do { \
        auto setting = SettingsHandler::getInstance().createFloatRangeSliderSetting(#minVar "_" #maxVar, &minVar, &maxVar, defaultMin, defaultMax, rangeMin, rangeMax, visibility, false, callback); \
        SettingsHandler::getInstance().addSetting(this, setting); \
    } while(0)

#define INT_RANGE_SLIDER_CONDITIONAL(minVar, maxVar, defaultMin, defaultMax, rangeMin, rangeMax) \
    do { \
        auto setting = SettingsHandler::getInstance().createIntRangeSliderSetting(#minVar "_" #maxVar, &minVar, &maxVar, defaultMin, defaultMax, rangeMin, rangeMax, nullptr, true); \
        SettingsHandler::getInstance().addSetting(this, setting); \
    } while(0)

#define INT_RANGE_SLIDER_CONDITIONAL_OPTIONAL(minVar, maxVar, defaultMin, defaultMax, rangeMin, rangeMax, visibility) \
    do { \
        auto setting = SettingsHandler::getInstance().createIntRangeSliderSetting(#minVar "_" #maxVar, &minVar, &maxVar, defaultMin, defaultMax, rangeMin, rangeMax, visibility, true); \
        SettingsHandler::getInstance().addSetting(this, setting); \
    } while(0)

#define FLOAT_RANGE_SLIDER_CONDITIONAL(minVar, maxVar, defaultMin, defaultMax, rangeMin, rangeMax) \
    do { \
        auto setting = SettingsHandler::getInstance().createFloatRangeSliderSetting(#minVar "_" #maxVar, &minVar, &maxVar, defaultMin, defaultMax, rangeMin, rangeMax, nullptr, true); \
        SettingsHandler::getInstance().addSetting(this, setting); \
    } while(0)

#define FLOAT_RANGE_SLIDER_CONDITIONAL_OPTIONAL(minVar, maxVar, defaultMin, defaultMax, rangeMin, rangeMax, visibility) \
    do { \
        auto setting = SettingsHandler::getInstance().createFloatRangeSliderSetting(#minVar "_" #maxVar, &minVar, &maxVar, defaultMin, defaultMax, rangeMin, rangeMax, visibility, true); \
        SettingsHandler::getInstance().addSetting(this, setting); \
    } while(0)

#define COMBO_SETTING(selectedIndex, ...) \
    do { \
        static std::vector<const char*> options = {__VA_ARGS__}; \
        auto setting = SettingsHandler::getInstance().createComboSetting(#selectedIndex, &selectedIndex, options); \
        SettingsHandler::getInstance().addSetting(this, setting); \
    } while(0)

#define COMBO_SETTING_OPTIONAL(selectedIndex, visibility, ...) \
    do { \
        static std::vector<const char*> options = {__VA_ARGS__}; \
        auto setting = SettingsHandler::getInstance().createComboSetting(#selectedIndex, &selectedIndex, options, visibility); \
        SettingsHandler::getInstance().addSetting(this, setting); \
    } while(0)

#define MULTI_COMBO_SETTING(selectedItemsVec, ...) \
    do { \
        static std::vector<const char*> options = {__VA_ARGS__}; \
        auto setting = SettingsHandler::getInstance().createMultiComboSetting(#selectedItemsVec, &selectedItemsVec, options, {}); \
        SettingsHandler::getInstance().addSetting(this, setting); \
    } while(0)

#define MULTI_COMBO_SETTING_OPTIONAL(selectedItemsVec, visibility, ...) \
    do { \
        static std::vector<const char*> options = {__VA_ARGS__}; \
        auto setting = SettingsHandler::getInstance().createMultiComboSetting(#selectedItemsVec, &selectedItemsVec, options, {}, visibility); \
        SettingsHandler::getInstance().addSetting(this, setting); \
    } while(0)

#define MULTI_COMBO_SETTING_CALLBACK(selectedItemsVec, callback, ...) \
    do { \
        static std::vector<const char*> options = {__VA_ARGS__}; \
        auto setting = SettingsHandler::getInstance().createMultiComboSetting(#selectedItemsVec, &selectedItemsVec, options, {}, nullptr, false, callback); \
        SettingsHandler::getInstance().addSetting(this, setting); \
    } while(0)

#define MULTI_COMBO_SETTING_CALLBACK_OPTIONAL(selectedItemsVec, visibility, callback, ...) \
    do { \
        static std::vector<const char*> options = {__VA_ARGS__}; \
        auto setting = SettingsHandler::getInstance().createMultiComboSetting(#selectedItemsVec, &selectedItemsVec, options, {}, visibility, false, callback); \
        SettingsHandler::getInstance().addSetting(this, setting); \
    } while(0)

#define KEYBIND_SETTING(variable, defaultValue) \
    do { \
        auto setting = SettingsHandler::getInstance().createKeybindSetting(#variable, &variable, defaultValue); \
        SettingsHandler::getInstance().addSetting(this, setting); \
    } while(0)

#define KEYBIND_SETTING_CALLBACK(variable, defaultValue, callback) \
    do { \
        auto setting = SettingsHandler::getInstance().createKeybindSetting(#variable, &variable, defaultValue, nullptr, false, callback); \
        SettingsHandler::getInstance().addSetting(this, setting); \
    } while(0)

#define KEYBIND_SETTING_OPTIONAL(variable, defaultValue, visibility) \
    do { \
        auto setting = SettingsHandler::getInstance().createKeybindSetting(#variable, &variable, defaultValue, visibility); \
        SettingsHandler::getInstance().addSetting(this, setting); \
    } while(0)

#define SETTING_VISIBILITY(condition) [this]() { return condition; }

#define SETTING_CALLBACK(lambda) lambda

#define BOOL_SETTING_CALLBACK(variable, defaultValue, callback) \
    do { \
        auto setting = SettingsHandler::getInstance().createBoolSetting(#variable, &variable, defaultValue, nullptr, false, callback); \
        SettingsHandler::getInstance().addSetting(this, setting); \
    } while(0)

#define BOOL_SETTING_CALLBACK_OPTIONAL(variable, defaultValue, visibility, callback) \
    do { \
        auto setting = SettingsHandler::getInstance().createBoolSetting(#variable, &variable, defaultValue, visibility, false, callback); \
        SettingsHandler::getInstance().addSetting(this, setting); \
    } while(0)

#define INT_SLIDER_CALLBACK(variable, defaultValue, minValue, maxValue, callback) \
    do { \
        auto setting = SettingsHandler::getInstance().createIntSliderSetting(#variable, &variable, defaultValue, minValue, maxValue, nullptr, false, callback); \
        SettingsHandler::getInstance().addSetting(this, setting); \
    } while(0)

#define INT_SLIDER_CALLBACK_OPTIONAL(variable, defaultValue, minValue, maxValue, visibility, callback) \
    do { \
        auto setting = SettingsHandler::getInstance().createIntSliderSetting(#variable, &variable, defaultValue, minValue, maxValue, visibility, false, callback); \
        SettingsHandler::getInstance().addSetting(this, setting); \
    } while(0)

#define FLOAT_SLIDER_CALLBACK(variable, defaultValue, minValue, maxValue, callback) \
    do { \
        auto setting = SettingsHandler::getInstance().createFloatSliderSetting(#variable, &variable, defaultValue, minValue, maxValue, nullptr, false, callback); \
        SettingsHandler::getInstance().addSetting(this, setting); \
    } while(0)

#define FLOAT_SLIDER_CALLBACK_OPTIONAL(variable, defaultValue, minValue, maxValue, visibility, callback) \
    do { \
        auto setting = SettingsHandler::getInstance().createFloatSliderSetting(#variable, &variable, defaultValue, minValue, maxValue, visibility, false, callback); \
        SettingsHandler::getInstance().addSetting(this, setting); \
    } while(0)

#define COMBO_SETTING_CALLBACK(selectedIndex, callback, ...) \
    do { \
        static std::vector<const char*> options = {__VA_ARGS__}; \
        auto setting = SettingsHandler::getInstance().createComboSetting(#selectedIndex, &selectedIndex, options, nullptr, false, callback); \
        SettingsHandler::getInstance().addSetting(this, setting); \
    } while(0)

#define COMBO_SETTING_CALLBACK_OPTIONAL(selectedIndex, visibility, callback, ...) \
    do { \
        static std::vector<const char*> options = {__VA_ARGS__}; \
        auto setting = SettingsHandler::getInstance().createComboSetting(#selectedIndex, &selectedIndex, options, visibility, false, callback); \
        SettingsHandler::getInstance().addSetting(this, setting); \
    } while(0)

#define COLOR_SETTING(variable, defaultValue) \
    do { \
        auto setting = SettingsHandler::getInstance().createColorSetting(#variable, &variable, defaultValue); \
        SettingsHandler::getInstance().addSetting(this, setting); \
    } while(0)

#define COLOR_SETTING_OPTIONAL(variable, defaultValue, visibility) \
    do { \
        auto setting = SettingsHandler::getInstance().createColorSetting(#variable, &variable, defaultValue, visibility); \
        SettingsHandler::getInstance().addSetting(this, setting); \
    } while(0)

#define COLOR_SETTING_CALLBACK(variable, defaultValue, callback) \
    do { \
        auto setting = SettingsHandler::getInstance().createColorSetting(#variable, &variable, defaultValue, nullptr, false, callback); \
        SettingsHandler::getInstance().addSetting(this, setting); \
    } while(0)

#define COLOR_SETTING_CALLBACK_OPTIONAL(variable, defaultValue, visibility, callback) \
    do { \
        auto setting = SettingsHandler::getInstance().createColorSetting(#variable, &variable, defaultValue, visibility, false, callback); \
        SettingsHandler::getInstance().addSetting(this, setting); \
    } while(0)

#define COLOR_SETTING_CONDITIONAL_OPTIONAL(variable, defaultValue, visibility) \
    do { \
        auto setting = SettingsHandler::getInstance().createColorSetting(#variable, &variable, defaultValue, visibility, true); \
        SettingsHandler::getInstance().addSetting(this, setting); \
    } while(0)

#define BOOL_SETTING_CONDITIONAL(variable, defaultValue) \
    do { \
        auto setting = SettingsHandler::getInstance().createBoolSetting(#variable, &variable, defaultValue, nullptr, true); \
        SettingsHandler::getInstance().addSetting(this, setting); \
    } while(0)

#define BOOL_SETTING_CONDITIONAL_OPTIONAL(variable, defaultValue, visibility) \
    do { \
        auto setting = SettingsHandler::getInstance().createBoolSetting(#variable, &variable, defaultValue, visibility, true); \
        SettingsHandler::getInstance().addSetting(this, setting); \
    } while(0)

#define BOOL_SETTING_CONDITIONAL_CALLBACK(variable, defaultValue, callback) \
    do { \
        auto setting = SettingsHandler::getInstance().createBoolSetting(#variable, &variable, defaultValue, nullptr, true, callback); \
        SettingsHandler::getInstance().addSetting(this, setting); \
    } while(0)

#define BOOL_SETTING_CONDITIONAL_CALLBACK_OPTIONAL(variable, defaultValue, visibility, callback) \
    do { \
        auto setting = SettingsHandler::getInstance().createBoolSetting(#variable, &variable, defaultValue, visibility, true, callback); \
        SettingsHandler::getInstance().addSetting(this, setting); \
    } while(0)

#define BOOL_SETTING_CONDITIONAL_CALLBACK_REACTIVE(variable, defaultValue, visibility, callback) \
    do { \
        auto setting = SettingsHandler::getInstance().createBoolSetting(#variable, &variable, defaultValue, visibility, true, callback, true); \
        SettingsHandler::getInstance().addSetting(this, setting); \
    } while(0)

#define INT_SLIDER_CONDITIONAL(variable, defaultValue, minValue, maxValue) \
    do { \
        auto setting = SettingsHandler::getInstance().createIntSliderSetting(#variable, &variable, defaultValue, minValue, maxValue, nullptr, true); \
        SettingsHandler::getInstance().addSetting(this, setting); \
    } while(0)

#define INT_SLIDER_CONDITIONAL_OPTIONAL(variable, defaultValue, minValue, maxValue, visibility) \
    do { \
        auto setting = SettingsHandler::getInstance().createIntSliderSetting(#variable, &variable, defaultValue, minValue, maxValue, visibility, true); \
        SettingsHandler::getInstance().addSetting(this, setting); \
    } while(0)

#define FLOAT_SLIDER_CONDITIONAL(variable, defaultValue, minValue, maxValue) \
    do { \
        auto setting = SettingsHandler::getInstance().createFloatSliderSetting(#variable, &variable, defaultValue, minValue, maxValue, nullptr, true); \
        SettingsHandler::getInstance().addSetting(this, setting); \
    } while(0)

#define FLOAT_SLIDER_CONDITIONAL_OPTIONAL(variable, defaultValue, minValue, maxValue, visibility) \
    do { \
        auto setting = SettingsHandler::getInstance().createFloatSliderSetting(#variable, &variable, defaultValue, minValue, maxValue, visibility, true); \
        SettingsHandler::getInstance().addSetting(this, setting); \
    } while(0)

#define COMBO_SETTING_CONDITIONAL(selectedIndex, ...) \
    do { \
        static std::vector<const char*> options = {__VA_ARGS__}; \
        auto setting = SettingsHandler::getInstance().createComboSetting(#selectedIndex, &selectedIndex, options, nullptr, true); \
        SettingsHandler::getInstance().addSetting(this, setting); \
    } while(0)

#define COMBO_SETTING_CONDITIONAL_OPTIONAL(selectedIndex, visibility, ...) \
    do { \
        static std::vector<const char*> options = {__VA_ARGS__}; \
        auto setting = SettingsHandler::getInstance().createComboSetting(#selectedIndex, &selectedIndex, options, visibility, true); \
        SettingsHandler::getInstance().addSetting(this, setting); \
    } while(0)

#define MULTI_COMBO_SETTING_CONDITIONAL(selectedItemsVec, ...) \
    do { \
        static std::vector<const char*> options = {__VA_ARGS__}; \
        auto setting = SettingsHandler::getInstance().createMultiComboSetting(#selectedItemsVec, &selectedItemsVec, options, {}, nullptr, true); \
        SettingsHandler::getInstance().addSetting(this, setting); \
    } while(0)

#define MULTI_COMBO_SETTING_CONDITIONAL_OPTIONAL(selectedItemsVec, visibility, ...) \
    do { \
        static std::vector<const char*> options = {__VA_ARGS__}; \
        auto setting = SettingsHandler::getInstance().createMultiComboSetting(#selectedItemsVec, &selectedItemsVec, options, {}, visibility, true); \
        SettingsHandler::getInstance().addSetting(this, setting); \
    } while(0)

#define MULTI_COMBO_SETTING_DEFAULT(selectedItemsVec, defaultValues, ...) \
    do { \
        static std::vector<const char*> options = {__VA_ARGS__}; \
        std::vector<bool> defaultVec = defaultValues; \
        auto multiComboSetting = SettingsHandler::getInstance().createMultiComboSetting(#selectedItemsVec, &selectedItemsVec, options, defaultVec); \
        SettingsHandler::getInstance().addSetting(this, multiComboSetting); \
    } while(0)

#define MULTI_COMBO_SETTING_DEFAULT_OPTIONAL(selectedItemsVec, defaultValues, visibility, ...) \
    do { \
        static std::vector<const char*> options = {__VA_ARGS__}; \
        std::vector<bool> defaultVec = defaultValues; \
        auto multiComboSettingOpt = SettingsHandler::getInstance().createMultiComboSetting(#selectedItemsVec, &selectedItemsVec, options, defaultVec, visibility); \
        SettingsHandler::getInstance().addSetting(this, multiComboSettingOpt); \
    } while(0)

#define MULTI_COMBO_SETTING_DEFAULT_CONDITIONAL(selectedItemsVec, defaultValues, ...) \
    do { \
        static std::vector<const char*> options = {__VA_ARGS__}; \
        std::vector<bool> defaultVec = defaultValues; \
        auto multiComboSettingCond = SettingsHandler::getInstance().createMultiComboSetting(#selectedItemsVec, &selectedItemsVec, options, defaultVec, nullptr, true); \
        SettingsHandler::getInstance().addSetting(this, multiComboSettingCond); \
    } while(0)

#define MULTI_COMBO_SETTING_DEFAULT_CONDITIONAL_OPTIONAL(selectedItemsVec, defaultValues, visibility, ...) \
    do { \
        static std::vector<const char*> options = {__VA_ARGS__}; \
        std::vector<bool> defaultVec = defaultValues; \
        auto multiComboSettingCondOpt = SettingsHandler::getInstance().createMultiComboSetting(#selectedItemsVec, &selectedItemsVec, options, defaultVec, visibility, true); \
        SettingsHandler::getInstance().addSetting(this, multiComboSettingCondOpt); \
    } while(0)

#define MULTI_COMBO_SETTING_CONDITIONAL_CALLBACK(selectedItemsVec, callback, ...) \
    do { \
        static std::vector<const char*> options = {__VA_ARGS__}; \
        auto setting = SettingsHandler::getInstance().createMultiComboSetting(#selectedItemsVec, &selectedItemsVec, options, {}, nullptr, true, callback); \
        SettingsHandler::getInstance().addSetting(this, setting); \
    } while(0)

#define MULTI_COMBO_SETTING_CONDITIONAL_CALLBACK_OPTIONAL(selectedItemsVec, visibility, callback, ...) \
    do { \
        static std::vector<const char*> options = {__VA_ARGS__}; \
        auto setting = SettingsHandler::getInstance().createMultiComboSetting(#selectedItemsVec, &selectedItemsVec, options, {}, visibility, true, callback); \
        SettingsHandler::getInstance().addSetting(this, setting); \
    } while(0)

#define KEYBIND_SETTING_CONDITIONAL(variable, defaultValue) \
    do { \
        auto setting = SettingsHandler::getInstance().createKeybindSetting(#variable, &variable, defaultValue, nullptr, true); \
        SettingsHandler::getInstance().addSetting(this, setting); \
    } while(0)

#define KEYBIND_SETTING_CONDITIONAL_OPTIONAL(variable, defaultValue, visibility) \
    do { \
        auto setting = SettingsHandler::getInstance().createKeybindSetting(#variable, &variable, defaultValue, visibility, true); \
        SettingsHandler::getInstance().addSetting(this, setting); \
    } while(0)

#define KEYBIND_SETTING_CONDITIONAL_CALLBACK(variable, defaultValue, callback) \
    do { \
        auto setting = SettingsHandler::getInstance().createKeybindSetting(#variable, &variable, defaultValue, nullptr, true, callback); \
        SettingsHandler::getInstance().addSetting(this, setting); \
    } while(0)

#define KEYBIND_SETTING_PRESS_CALLBACK(variable, defaultValue, pressCallback) \
    do { \
        auto setting = SettingsHandler::getInstance().createKeybindSetting(#variable, &variable, defaultValue, nullptr, true, nullptr, pressCallback); \
        SettingsHandler::getInstance().addSetting(this, setting); \
    } while(0)

#define BOOL_CONDITIONAL(variable, defaultValue) BOOL_SETTING(variable, defaultValue)

#define ADD_BOOL_SETTING(name, description, variable, defaultValue, ...) \
    do { \
        auto setting = std::make_shared<Setting<bool>>(name, description, &variable, defaultValue, ##__VA_ARGS__); \
        SettingsHandler::getInstance().addSetting(this, setting); \
    } while(0)

#define ADD_INT_SLIDER(name, description, variable, defaultValue, minValue, maxValue, ...) \
    do { \
        auto setting = std::make_shared<Setting<int>>(name, description, &variable, defaultValue, minValue, maxValue, ##__VA_ARGS__); \
        SettingsHandler::getInstance().addSetting(this, setting); \
    } while(0)

#define ADD_FLOAT_SLIDER(name, description, variable, defaultValue, minValue, maxValue, ...) \
    do { \
        auto setting = std::make_shared<Setting<float>>(name, description, &variable, defaultValue, minValue, maxValue, ##__VA_ARGS__); \
        SettingsHandler::getInstance().addSetting(this, setting); \
    } while(0)

#define ADD_COMBO_SETTING(name, description, options, selectedIndex, ...) \
    do { \
        static std::vector<std::string> comboOptions = options; \
        auto setting = std::make_shared<Setting<std::vector<std::string>>>(name, description, &comboOptions, &selectedIndex, options, ##__VA_ARGS__); \
        SettingsHandler::getInstance().addSetting(this, setting); \
    } while(0)

#define INIT_MODULE_SETTINGS() \
    do { \
        SettingsHandler::getInstance().initializeModuleSettings(this); \
        initSettings(); \
    } while(0)

#define CLEANUP_MODULE_SETTINGS() \
    do { \
        SettingsHandler::getInstance().removeModuleSettings(this); \
    } while(0)

#define BUTTON_SETTING(label, callback) \
    do { \
        static bool button_dummy = false; \
        auto cb = callback; \
        auto setting = SettingsHandler::getInstance().createBoolSetting(label, &button_dummy, false, nullptr, false, [cb](bool value) { if (value) { cb(); } }); \
        setting->setIsButton(true); \
        SettingsHandler::getInstance().addSetting(this, setting); \
    } while(0)

#define BUTTON_SETTING_OPTIONAL(label, visibility, callback) \
    do { \
        static bool button_dummy_opt = false; \
        auto cb = callback; \
        auto setting = SettingsHandler::getInstance().createBoolSetting(label, &button_dummy_opt, false, visibility, false, [cb](bool value) { if (value) { cb(); } }); \
        setting->setIsButton(true); \
        SettingsHandler::getInstance().addSetting(this, setting); \
    } while(0)

#define BUTTON_SETTING_CONDITIONAL(label, callback) \
    do { \
        static bool button_dummy_cond = false; \
        auto cb = callback; \
        auto setting = SettingsHandler::getInstance().createBoolSetting(label, &button_dummy_cond, false, nullptr, true, [cb](bool value) { if (value) { cb(); } }); \
        setting->setIsButton(true); \
        SettingsHandler::getInstance().addSetting(this, setting); \
    } while(0)

#define BUTTON_SETTING_CONDITIONAL_OPTIONAL(label, visibility, callback) \
    do { \
        static bool button_dummy_cond_opt = false; \
        auto cb = callback; \
        auto setting = SettingsHandler::getInstance().createBoolSetting(label, &button_dummy_cond_opt, false, visibility, true, [cb](bool value) { if (value) { cb(); } }); \
        setting->setIsButton(true); \
        SettingsHandler::getInstance().addSetting(this, setting); \
    } while(0)

#define REGISTER_BOOL(variable, defaultValue) \
    do { \
        auto setting = SettingsHandler::getInstance().registerBoolValue(#variable, &variable, defaultValue); \
        SettingsHandler::getInstance().addSetting(this, setting); \
    } while(0)

#define REGISTER_INT(variable, defaultValue, ...) \
    do { \
        auto setting = SettingsHandler::getInstance().registerIntValue(#variable, &variable, defaultValue, ##__VA_ARGS__); \
        SettingsHandler::getInstance().addSetting(this, setting); \
    } while(0)

#define REGISTER_FLOAT(variable, defaultValue, ...) \
    do { \
        auto setting = SettingsHandler::getInstance().registerFloatValue(#variable, &variable, defaultValue, ##__VA_ARGS__); \
        SettingsHandler::getInstance().addSetting(this, setting); \
    } while(0)

#define REGISTER_KEYBIND(variable, defaultValue) \
    do { \
        auto setting = SettingsHandler::getInstance().registerKeybindValue(#variable, &variable, defaultValue); \
        SettingsHandler::getInstance().addSetting(this, setting); \
    } while(0)

#define REGISTER_COLOR(variable, defaultValue) \
    do { \
        auto setting = SettingsHandler::getInstance().registerColorValue(#variable, &variable, defaultValue); \
        SettingsHandler::getInstance().addSetting(this, setting); \
    } while(0)

#define TEXT_SETTING(variable) \
    do { \
        auto setting = SettingsHandler::getInstance().createTextSetting(#variable, &variable); \
        SettingsHandler::getInstance().addSetting(this, setting); \
    } while(0)

#define TEXT_SETTING_OPTIONAL(variable, visibility) \
    do { \
        auto setting = SettingsHandler::getInstance().createTextSetting(#variable, &variable, visibility); \
        SettingsHandler::getInstance().addSetting(this, setting); \
    } while(0)

#define TEXT_SETTING_CONDITIONAL(variable) \
    do { \
        auto setting = SettingsHandler::getInstance().createTextSetting(#variable, &variable, nullptr, true); \
        SettingsHandler::getInstance().addSetting(this, setting); \
    } while(0)

#define TEXT_SETTING_CONDITIONAL_OPTIONAL(variable, visibility) \
    do { \
        auto setting = SettingsHandler::getInstance().createTextSetting(#variable, &variable, visibility, true); \
        SettingsHandler::getInstance().addSetting(this, setting); \
    } while(0)

#define UPDATE_TEXT(variable, newText) \
    do { \
        variable = newText; \
    } while(0)

#define TEXT_INPUT_SETTING(variable, defaultValue, maxLength) \
    do { \
        auto setting = SettingsHandler::getInstance().createTextInputSetting(#variable, &variable, defaultValue, maxLength); \
        SettingsHandler::getInstance().addSetting(this, setting); \
    } while(0)

#define TEXT_INPUT_SETTING_OPTIONAL(variable, defaultValue, maxLength, visibility) \
    do { \
        auto setting = SettingsHandler::getInstance().createTextInputSetting(#variable, &variable, defaultValue, maxLength, visibility); \
        SettingsHandler::getInstance().addSetting(this, setting); \
    } while(0)

#define TEXT_INPUT_SETTING_CALLBACK(variable, defaultValue, maxLength, callback) \
    do { \
        auto setting = SettingsHandler::getInstance().createTextInputSetting(#variable, &variable, defaultValue, maxLength, nullptr, false, callback); \
        SettingsHandler::getInstance().addSetting(this, setting); \
    } while(0)

#define TEXT_INPUT_SETTING_CALLBACK_OPTIONAL(variable, defaultValue, maxLength, visibility, callback) \
    do { \
        auto setting = SettingsHandler::getInstance().createTextInputSetting(#variable, &variable, defaultValue, maxLength, visibility, false, callback); \
        SettingsHandler::getInstance().addSetting(this, setting); \
    } while(0)

#define TEXT_INPUT_SETTING_CONDITIONAL(variable, defaultValue, maxLength) \
    do { \
        auto setting = SettingsHandler::getInstance().createTextInputSetting(#variable, &variable, defaultValue, maxLength, nullptr, true); \
        SettingsHandler::getInstance().addSetting(this, setting); \
    } while(0)

#define TEXT_INPUT_SETTING_CONDITIONAL_OPTIONAL(variable, defaultValue, maxLength, visibility) \
    do { \
        auto setting = SettingsHandler::getInstance().createTextInputSetting(#variable, &variable, defaultValue, maxLength, visibility, true); \
        SettingsHandler::getInstance().addSetting(this, setting); \
    } while(0)

#define TEXT_INPUT_SETTING_CONDITIONAL_CALLBACK(variable, defaultValue, maxLength, callback) \
    do { \
        auto setting = SettingsHandler::getInstance().createTextInputSetting(#variable, &variable, defaultValue, maxLength, nullptr, true, callback); \
        SettingsHandler::getInstance().addSetting(this, setting); \
    } while(0)

#define TEXT_INPUT_SETTING_CONDITIONAL_CALLBACK_OPTIONAL(variable, defaultValue, maxLength, visibility, callback) \
    do { \
        auto setting = SettingsHandler::getInstance().createTextInputSetting(#variable, &variable, defaultValue, maxLength, visibility, true, callback); \
        SettingsHandler::getInstance().addSetting(this, setting); \
    } while(0)
