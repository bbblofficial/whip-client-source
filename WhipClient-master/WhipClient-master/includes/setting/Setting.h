#pragma once

#include <functional>
#include <vector>
#include "widgets.h"
#include "util/Debug.h"
#include "util/TrackedString.h"

class ConfigManager;

enum class SettingType {
    BOOL,
    INT_SLIDER,
    FLOAT_SLIDER,
    INT_RANGE_SLIDER,
    FLOAT_RANGE_SLIDER,
    COMBO,
    MULTI_COMBO,
    KEYBIND,
    COLOR,
    TEXT,
    TEXT_INPUT
};

class ISetting {
public:
    virtual ~ISetting() = default;

    virtual void render(const std::unique_ptr<c_widgets> &widgets) = 0;
    virtual const char* getName() const = 0;
    virtual SettingType getType() const = 0;
    virtual bool isVisible() const = 0;
    virtual bool isConditional() const = 0;
    virtual void* getValuePtr() const = 0;

    virtual void clearStrings() = 0;
    virtual void resetToDefault() = 0;
};

class BoolSetting final : public ISetting {
    const char* m_name;
    bool* m_value;
    bool m_defaultValue;
    std::function<bool()> m_visibility;
    bool m_isConditional;
    std::function<void(bool)> m_callback;
    bool m_callbackOnVisibilityChange;
    mutable bool m_lastVisibilityState;
    bool m_isButton = false;

public:
    BoolSetting(const char* name, bool *value, const bool defaultValue,
                std::function<bool()> visibility = nullptr, const bool isConditional = false,
                std::function<void(bool)> callback = nullptr, const bool callbackOnVisibilityChange = false)
        : m_name(name), m_value(value), m_defaultValue(defaultValue), m_visibility(std::move(visibility)),
          m_isConditional(isConditional), m_callback(std::move(callback)), m_callbackOnVisibilityChange(callbackOnVisibilityChange),
          m_lastVisibilityState(m_visibility ? m_visibility() : true) {
        *m_value = defaultValue;
    }

    ~BoolSetting() = default;

    void render(const std::unique_ptr<c_widgets> &widgets) override {
        if (m_callbackOnVisibilityChange && m_callback && m_visibility) {
            bool currentVisibility = m_visibility();
            if (currentVisibility != m_lastVisibilityState) {
                m_lastVisibilityState = currentVisibility;
                m_callback(*m_value);
            }
        }

        if (!isVisible()) return;

        if (m_isButton) {
            if (widgets->button2(m_name)) {
                *m_value = true;
                if (m_callback) {
                    m_callback(*m_value);
                }
                *m_value = false;
            }
        } else {
            bool oldValue = *m_value;
            if (widgets->checkbox(m_name, m_value)) {
                if (m_callback && oldValue != *m_value) {
                    m_callback(*m_value);
                }
            }
        }
    }

    const char* getName() const override {
        return m_name;
    }

    SettingType getType() const override { return SettingType::BOOL; }
    bool isVisible() const override { return m_visibility ? m_visibility() : true; }
    bool isConditional() const override { return m_isConditional; }
    void* getValuePtr() const override { return m_value; }

    bool getValue() const { return *m_value; }
    void setValue(const bool value) const;

    void triggerCallback() const {
        if (m_callback) {
            m_callback(*m_value);
        }
    }

    void setIsButton(bool isButton) { m_isButton = isButton; }
    bool isButton() const { return m_isButton; }

    void clearStrings() override {}
    void resetToDefault() override { *m_value = m_defaultValue; if (m_callback) m_callback(*m_value); }
};

class IntSliderSetting final : public ISetting {
    const char* m_name;
    int* m_value;
    int m_defaultValue;
    int m_minValue;
    int m_maxValue;
    std::function<bool()> m_visibility;
    bool m_isConditional;
    std::function<void(int)> m_callback;
    std::function<const char*(int)> m_formatFn;

public:
    IntSliderSetting(const char* name, int *value, const int defaultValue, const int minValue,
                     const int maxValue, std::function<bool()> visibility = nullptr,
                     const bool isConditional = false, std::function<void(int)> callback = nullptr)
        : m_name(name), m_value(value), m_defaultValue(defaultValue), m_minValue(minValue), m_maxValue(maxValue),
          m_visibility(std::move(visibility)), m_isConditional(isConditional), m_callback(std::move(callback)) {
        *m_value = defaultValue;
    }

    ~IntSliderSetting() = default;

    void setFormatFn(std::function<const char*(int)> fn) { m_formatFn = std::move(fn); }

    void render(const std::unique_ptr<c_widgets> &widgets) override {
        if (!isVisible()) return;
        int oldValue = *m_value;
        const char* fmt = m_formatFn ? m_formatFn(*m_value) : "%d";
        if (widgets->slider_int(m_name, m_value, m_minValue, m_maxValue, fmt)) {
            if (m_callback && oldValue != *m_value) {
                m_callback(*m_value);
            }
        }
    }

    const char* getName() const override { return m_name; }
    SettingType getType() const override { return SettingType::INT_SLIDER; }
    bool isVisible() const override { return m_visibility ? m_visibility() : true; }
    bool isConditional() const override { return m_isConditional; }
    void* getValuePtr() const override { return m_value; }

    int getValue() const { return *m_value; }
    void setValue(const int value) const {
        int oldValue = *m_value;
        *m_value = value;
        if (m_callback && oldValue != value) {
            m_callback(value);
        }
    }

public:
    void clearStrings() override {}
    void resetToDefault() override { setValue(m_defaultValue); }
};

class FloatSliderSetting final : public ISetting {
    const char* m_name;
    float* m_value;
    float m_defaultValue;
    float m_minValue;
    float m_maxValue;
    std::function<bool()> m_visibility;
    bool m_isConditional;
    std::function<void(float)> m_callback;

public:
    FloatSliderSetting(const char* name, float *value, const float defaultValue, const float minValue,
                       const float maxValue, std::function<bool()> visibility = nullptr,
                       const bool isConditional = false, std::function<void(float)> callback = nullptr)
        : m_name(name), m_value(value), m_defaultValue(defaultValue), m_minValue(minValue), m_maxValue(maxValue),
          m_visibility(std::move(visibility)), m_isConditional(isConditional), m_callback(std::move(callback)) {
        *m_value = defaultValue;
    }

    ~FloatSliderSetting() = default;

    void render(const std::unique_ptr<c_widgets> &widgets) override {
        if (!isVisible()) return;
        float oldValue = *m_value;
        if (widgets->slider_float(m_name, m_value, m_minValue, m_maxValue, "%.2f")) {
            if (m_callback && oldValue != *m_value) {
                m_callback(*m_value);
            }
        }
    }

    const char* getName() const override { return m_name; }
    SettingType getType() const override { return SettingType::FLOAT_SLIDER; }
    bool isVisible() const override { return m_visibility ? m_visibility() : true; }
    bool isConditional() const override { return m_isConditional; }
    void* getValuePtr() const override { return m_value; }

    float getValue() const { return *m_value; }
    void setValue(const float value) const {
        float oldValue = *m_value;
        *m_value = value;
        if (m_callback && oldValue != value) {
            m_callback(value);
        }
    }

    float getMinValue() const { return m_minValue; }
    float getMaxValue() const { return m_maxValue; }
    void setMinValue(const float minValue) {
        m_minValue = minValue;

        if (*m_value < minValue) {
            *m_value = minValue;
        }
    }
    void setMaxValue(const float maxValue) {
        m_maxValue = maxValue;

        if (*m_value > maxValue) {
            *m_value = maxValue;
        }
    }

public:
    void clearStrings() override {}
    void resetToDefault() override { setValue(m_defaultValue); }
};

class IntRangeSliderSetting final : public ISetting {
    const char* m_name;
    int* m_minValue;
    int* m_maxValue;
    int m_defaultMin;
    int m_defaultMax;
    int m_rangeMin;
    int m_rangeMax;
    std::function<bool()> m_visibility;
    bool m_isConditional;
    std::function<void(int, int)> m_callback;

public:
    IntRangeSliderSetting(const char* name, int *minValue, int *maxValue,
                          const int defaultMin, const int defaultMax,
                          const int rangeMin, const int rangeMax,
                          std::function<bool()> visibility = nullptr,
                          const bool isConditional = false,
                          std::function<void(int, int)> callback = nullptr)
        : m_name(name), m_minValue(minValue), m_maxValue(maxValue),
          m_defaultMin(defaultMin), m_defaultMax(defaultMax),
          m_rangeMin(rangeMin), m_rangeMax(rangeMax),
          m_visibility(std::move(visibility)), m_isConditional(isConditional),
          m_callback(std::move(callback)) {
        *m_minValue = defaultMin;
        *m_maxValue = defaultMax;
    }

    ~IntRangeSliderSetting() = default;

    void render(const std::unique_ptr<c_widgets> &widgets) override {
        if (!isVisible()) return;
        int oldMin = *m_minValue;
        int oldMax = *m_maxValue;
        if (widgets->range_slider_int(m_name, m_minValue, m_maxValue, m_rangeMin, m_rangeMax)) {
            if (m_callback && (oldMin != *m_minValue || oldMax != *m_maxValue)) {
                m_callback(*m_minValue, *m_maxValue);
            }
        }
    }

    const char* getName() const override { return m_name; }
    SettingType getType() const override { return SettingType::INT_RANGE_SLIDER; }
    bool isVisible() const override { return m_visibility ? m_visibility() : true; }
    bool isConditional() const override { return m_isConditional; }
    void* getValuePtr() const override { return m_minValue; }

    int getMinValue() const { return *m_minValue; }
    int getMaxValue() const { return *m_maxValue; }
    int getRangeMin() const { return m_rangeMin; }
    int getRangeMax() const { return m_rangeMax; }
    void setMinValue(const int value) const {
        int oldMin = *m_minValue;
        int oldMax = *m_maxValue;
        *m_minValue = value;
        if (m_callback && oldMin != value) {
            m_callback(*m_minValue, *m_maxValue);
        }
    }
    void setMaxValue(const int value) const {
        int oldMin = *m_minValue;
        int oldMax = *m_maxValue;
        *m_maxValue = value;
        if (m_callback && oldMax != value) {
            m_callback(*m_minValue, *m_maxValue);
        }
    }

    void clearStrings() override {}
    void resetToDefault() override { setMinValue(m_defaultMin); setMaxValue(m_defaultMax); }
};

class FloatRangeSliderSetting final : public ISetting {
    const char* m_name;
    float* m_minValue;
    float* m_maxValue;
    float m_defaultMin;
    float m_defaultMax;
    float m_rangeMin;
    float m_rangeMax;
    std::function<bool()> m_visibility;
    bool m_isConditional;
    std::function<void(float, float)> m_callback;

public:
    FloatRangeSliderSetting(const char* name, float *minValue, float *maxValue,
                            const float defaultMin, const float defaultMax,
                            const float rangeMin, const float rangeMax,
                            std::function<bool()> visibility = nullptr,
                            const bool isConditional = false,
                            std::function<void(float, float)> callback = nullptr)
        : m_name(name), m_minValue(minValue), m_maxValue(maxValue),
          m_defaultMin(defaultMin), m_defaultMax(defaultMax),
          m_rangeMin(rangeMin), m_rangeMax(rangeMax),
          m_visibility(std::move(visibility)), m_isConditional(isConditional),
          m_callback(std::move(callback)) {
        *m_minValue = defaultMin;
        *m_maxValue = defaultMax;
    }

    ~FloatRangeSliderSetting() = default;

    void render(const std::unique_ptr<c_widgets> &widgets) override {
        if (!isVisible()) return;
        float oldMin = *m_minValue;
        float oldMax = *m_maxValue;
        if (widgets->range_slider_float(m_name, m_minValue, m_maxValue, m_rangeMin, m_rangeMax, "%.2f")) {
            if (m_callback && (oldMin != *m_minValue || oldMax != *m_maxValue)) {
                m_callback(*m_minValue, *m_maxValue);
            }
        }
    }

    const char* getName() const override { return m_name; }
    SettingType getType() const override { return SettingType::FLOAT_RANGE_SLIDER; }
    bool isVisible() const override { return m_visibility ? m_visibility() : true; }
    bool isConditional() const override { return m_isConditional; }
    void* getValuePtr() const override { return m_minValue; }

    float getMinValue() const { return *m_minValue; }
    float getMaxValue() const { return *m_maxValue; }
    float getRangeMin() const { return m_rangeMin; }
    float getRangeMax() const { return m_rangeMax; }
    void setMinValue(const float value) const {
        float oldMin = *m_minValue;
        float oldMax = *m_maxValue;
        *m_minValue = value;
        if (m_callback && oldMin != value) {
            m_callback(*m_minValue, *m_maxValue);
        }
    }
    void setMaxValue(const float value) const {
        float oldMin = *m_minValue;
        float oldMax = *m_maxValue;
        *m_maxValue = value;
        if (m_callback && oldMax != value) {
            m_callback(*m_minValue, *m_maxValue);
        }
    }

    void clearStrings() override {}
    void resetToDefault() override { setMinValue(m_defaultMin); setMaxValue(m_defaultMax); }
};

class ComboSetting final : public ISetting {
    const char* m_name;
    int* m_selectedIndex;
    const std::vector<const char*>* m_options;
    std::function<bool()> m_visibility;
    bool m_isConditional;
    std::function<void(int)> m_callback;

public:
    ComboSetting(const char* name, int *selectedIndex, const std::vector<const char*> &options,
                 std::function<bool()> visibility = nullptr, const bool isConditional = false,
                 std::function<void(int)> callback = nullptr)
        : m_name(name), m_selectedIndex(selectedIndex), m_options(&options),
          m_visibility(std::move(visibility)), m_isConditional(isConditional), m_callback(std::move(callback)) {
        *m_selectedIndex = 0;
    }

    ~ComboSetting() = default;

    void render(const std::unique_ptr<c_widgets> &widgets) override {
        if (!isVisible()) return;
        int oldValue = *m_selectedIndex;
        if (widgets->dropdown(m_name, m_selectedIndex, *m_options)) {
            if (m_callback && oldValue != *m_selectedIndex) {
                m_callback(*m_selectedIndex);
            }
        }
    }

    const char* getName() const override { return m_name; }
    SettingType getType() const override { return SettingType::COMBO; }
    bool isVisible() const override { return m_visibility ? m_visibility() : true; }
    bool isConditional() const override { return m_isConditional; }
    void* getValuePtr() const override { return m_selectedIndex; }

    int getSelectedIndex() const { return *m_selectedIndex; }
    void setSelectedIndex(const int index) const {
        int oldValue = *m_selectedIndex;
        *m_selectedIndex = index;
        if (m_callback && oldValue != index) {
            m_callback(index);
        }
    }
    const std::vector<const char*>& getOptions() const { return *m_options; }

public:
    void clearStrings() override {}
    void resetToDefault() override { setSelectedIndex(0); }
};

class MultiComboSetting final : public ISetting {
    const char* m_name;
    std::vector<bool>* m_selectedItems;
    const std::vector<const char*>* m_options;
    std::function<bool()> m_visibility;
    bool m_isConditional;
    std::function<void(const std::vector<bool>&)> m_callback;

public:
    MultiComboSetting(const char* name, std::vector<bool> *selectedItems, const std::vector<const char*> &options,
                     const std::vector<bool> &defaultValues = {}, std::function<bool()> visibility = nullptr,
                     const bool isConditional = false, std::function<void(const std::vector<bool>&)> callback = nullptr)
        : m_name(name), m_selectedItems(selectedItems), m_options(&options),
          m_visibility(std::move(visibility)), m_isConditional(isConditional), m_callback(std::move(callback)) {

        if (m_selectedItems->size() != m_options->size()) {
            if (!defaultValues.empty() && defaultValues.size() == m_options->size()) {
                *m_selectedItems = defaultValues;
            } else {
                m_selectedItems->assign(m_options->size(), false);
            }
        }
    }

    ~MultiComboSetting() = default;

    void render(const std::unique_ptr<c_widgets> &widgets) override {
        if (!isVisible()) return;
        std::vector<bool> oldValue = *m_selectedItems;
        if (widgets->multi_dropdown(m_name, m_selectedItems, *m_options)) {
            if (m_callback && oldValue != *m_selectedItems) {
                m_callback(*m_selectedItems);
            }
        }
    }

    const char* getName() const override { return m_name; }
    SettingType getType() const override { return SettingType::MULTI_COMBO; }
    bool isVisible() const override { return m_visibility ? m_visibility() : true; }
    bool isConditional() const override { return m_isConditional; }
    void* getValuePtr() const override { return m_selectedItems; }

    const std::vector<bool>& getSelectedItems() const { return *m_selectedItems; }
    void setSelectedItems(const std::vector<bool>& items) const {
        std::vector<bool> oldValue = *m_selectedItems;
        *m_selectedItems = items;
        if (m_callback && oldValue != items) {
            m_callback(items);
        }
    }
    const std::vector<const char*>& getOptions() const { return *m_options; }

    void clearStrings() override {}
    void resetToDefault() override { setSelectedItems(std::vector<bool>(m_options->size(), false)); }
};

class ColorSetting final : public ISetting {
    const char* m_name;
    ImColor* m_value;
    ImColor m_defaultValue;
    std::function<bool()> m_visibility;
    bool m_isConditional;
    std::function<void(const ImVec4&)> m_callback;

public:
    ColorSetting(const char* name, ImColor *value, const ImColor &defaultValue,
                std::function<bool()> visibility = nullptr, const bool isConditional = false,
                std::function<void(const ImVec4&)> callback = nullptr)
        : m_name(name), m_value(value), m_defaultValue(defaultValue), m_visibility(std::move(visibility)),
          m_isConditional(isConditional), m_callback(std::move(callback)) {

    }

    ~ColorSetting() = default;

    void render(const std::unique_ptr<c_widgets> &widgets) override {
        if (!isVisible()) return;
        ImVec4 colorVec = static_cast<ImVec4>(*m_value);
        ImVec4 oldValue = colorVec;
        widgets->color_selector(m_name, &colorVec);

        *m_value = ImColor(colorVec);
        if (m_callback && memcmp(&oldValue, &colorVec, sizeof(ImVec4)) != 0) {
            m_callback(colorVec);
        }
    }

    const char* getName() const override { return m_name; }
    SettingType getType() const override { return SettingType::COLOR; }
    bool isVisible() const override { return m_visibility ? m_visibility() : true; }
    bool isConditional() const override { return m_isConditional; }
    void* getValuePtr() const override { return m_value; }

    ImColor getValue() const { return *m_value; }
    void setValue(const ImColor& value) const {
        ImColor oldValue = *m_value;
        *m_value = value;
        if (m_callback) {
            ImVec4 oldVec = static_cast<ImVec4>(oldValue);
            ImVec4 newVec = static_cast<ImVec4>(value);
            if (memcmp(&oldVec, &newVec, sizeof(ImVec4)) != 0) {
                m_callback(newVec);
            }
        }
    }

public:
    void clearStrings() override {}
    void resetToDefault() override { setValue(m_defaultValue); }
};

class KeybindSetting final : public ISetting {
    const char* m_name;
    int* m_keyCode;
    int m_defaultValue;
    std::function<bool()> m_visibility;
    bool m_capturing = false;
    bool m_isConditional;
    std::function<void(int)> m_callback;
    std::function<void()> m_pressCallback;
    bool m_wasPressed = false;

public:
    KeybindSetting(const char* name, int *keyCode, const int defaultValue,
                   std::function<bool()> visibility = nullptr, const bool isConditional = false,
                   std::function<void(int)> callback = nullptr,
                   std::function<void()> pressCallback = nullptr)
        : m_name(name), m_keyCode(keyCode), m_defaultValue(defaultValue), m_visibility(std::move(visibility)),
          m_isConditional(isConditional), m_callback(std::move(callback)), m_pressCallback(std::move(pressCallback)) {
        *m_keyCode = defaultValue;
    }

    ~KeybindSetting() = default;

    void render(const std::unique_ptr<c_widgets> &widgets) override {
        if (!isVisible()) return;

        static int mode = 0;
        int oldValue = *m_keyCode;
        if (widgets->keybind(m_name, m_keyCode, &mode)) {
            if (m_callback) {
                m_callback(*m_keyCode);
            }
        }
    }

    const char* getName() const override { return m_name; }
    SettingType getType() const override { return SettingType::KEYBIND; }
    bool isVisible() const override { return m_visibility ? m_visibility() : true; }
    bool isConditional() const override { return m_isConditional; }
    void* getValuePtr() const override { return m_keyCode; }

    int getKeyCode() const { return *m_keyCode; }
    void setKeyCode(const int keyCode) const {
        int oldValue = *m_keyCode;
        *m_keyCode = keyCode;
        if (m_callback && oldValue != keyCode) {
            m_callback(keyCode);
        }
    }

    void checkKeyPress() {
        if (*m_keyCode > 0 && m_pressCallback) {
            bool isPressed = GetAsyncKeyState(*m_keyCode) & 0x8000;

            if (isPressed && !m_wasPressed) {
                m_pressCallback();
                m_wasPressed = true;
            } else if (!isPressed) {
                m_wasPressed = false;
            }
        }
    }

public:
    void clearStrings() override {}
    void resetToDefault() override { setKeyCode(m_defaultValue); }
};

class TextSetting final : public ISetting {
    const char* m_name;
    std::string* m_text;
    std::function<bool()> m_visibility;
    bool m_isConditional;

public:
    TextSetting(const char* name, std::string* text,
                std::function<bool()> visibility = nullptr, const bool isConditional = false)
        : m_name(name), m_text(text), m_visibility(std::move(visibility)), m_isConditional(isConditional) {
    }

    ~TextSetting() = default;

    void render(const std::unique_ptr<c_widgets> &widgets) override {
        if (!isVisible()) return;

        widgets->text_line(m_text->c_str(), font->get(my_font, 14), clr->white);

        ImGuiWindow* window = gui->get_window();
        if (window->SkipItems)
            return;

        ImVec2 pos = window->DC.CursorPos;
        ImVec2 size = ImVec2(gui->content_avail().x, SCALE(elements->checkbox.size));
        ImRect total(pos, pos + size);

        draw->text_clipped(window->DrawList, font->get(my_font, 12),
        total.Min + SCALE(elements->padding.x, 0),
        total.Max,
        clr->white,
        m_text->c_str(), 0, 0, { 0, 0.5 });
        }

    const char* getName() const override { return m_name; }
    SettingType getType() const override { return SettingType::TEXT; }
    bool isVisible() const override { return m_visibility ? m_visibility() : true; }
    bool isConditional() const override { return m_isConditional; }
    void* getValuePtr() const override { return m_text; }

    const std::string& getText() const { return *m_text; }
    void setText(const std::string& text) const { *m_text = text; }

public:
    void clearStrings() override {}
    void resetToDefault() override { *m_text = ""; }
};

class TextInputSetting final : public ISetting {
    const char* m_name;
    std::string* m_text;
    const char* m_defaultValue;
    int m_maxLength;
    std::function<bool()> m_visibility;
    bool m_isConditional;
    std::function<void(const std::string&)> m_callback;

    mutable std::vector<char> m_buffer;

public:
    TextInputSetting(const char* name, std::string* text, const char* defaultValue = "",
                     int maxLength = 256, std::function<bool()> visibility = nullptr,
                     const bool isConditional = false, std::function<void(const std::string&)> callback = nullptr)
        : m_name(name), m_text(text), m_defaultValue(defaultValue), m_maxLength(maxLength),
          m_visibility(std::move(visibility)), m_isConditional(isConditional), m_callback(std::move(callback)) {

        m_buffer.resize(m_maxLength + 1, 0);

        if (m_text->empty() && m_defaultValue && m_defaultValue[0] != '\0') {
            *m_text = m_defaultValue;
        }

        syncBufferFromText();
    }

    ~TextInputSetting() {
        if (!m_buffer.empty()) {
            SecureZeroMemory(m_buffer.data(), m_buffer.size());
        }
        m_buffer.clear();
        m_buffer.shrink_to_fit();
    }

    void render(const std::unique_ptr<c_widgets> &widgets) override {
        if (!isVisible()) return;

        syncBufferFromText();

        std::string oldValue = *m_text;

        if (widgets->config_text_field(m_name, m_buffer.data(), static_cast<int>(m_buffer.size()))) {

            *m_text = std::string(m_buffer.data());

            if (m_callback && oldValue != *m_text) {
                m_callback(*m_text);
            }
        }
    }

    const char* getName() const override { return m_name; }
    SettingType getType() const override { return SettingType::TEXT_INPUT; }
    bool isVisible() const override { return m_visibility ? m_visibility() : true; }
    bool isConditional() const override { return m_isConditional; }
    void* getValuePtr() const override { return m_text; }

    const std::string& getText() const { return *m_text; }
    void setText(const std::string& text) {
        std::string oldValue = *m_text;
        *m_text = text;
        syncBufferFromText();

        if (m_callback && oldValue != text) {
            m_callback(text);
        }
    }

    int getMaxLength() const { return m_maxLength; }
    const char* getDefaultValue() const { return m_defaultValue; }

    void clearStrings() override {}
    void resetToDefault() override { setText(m_defaultValue ? m_defaultValue : ""); }

private:
    void syncBufferFromText() const {

        if (!m_buffer.empty()) {
            SecureZeroMemory(m_buffer.data(), m_buffer.size());
        }

        if (!m_text->empty()) {
            size_t copyLen = std::min(m_text->length(), static_cast<size_t>(m_maxLength - 1));
            std::copy(m_text->begin(), m_text->begin() + copyLen, m_buffer.begin());
        }
    }

};
