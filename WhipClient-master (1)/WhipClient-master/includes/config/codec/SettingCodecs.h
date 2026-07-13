#pragma once

#include "ISettingCodec.h"
#include "../../setting/Setting.h"

class BoolCodec : public ISettingCodec {
public:
    whip::WhipJsonValue encode(const ISetting* setting) const override {
        auto* boolSetting = static_cast<const BoolSetting*>(setting);

        whip::WhipJsonValue json;
        json["name"] = boolSetting->getName();
        json["type"] = static_cast<int>(SettingType::BOOL);
        json["value"] = boolSetting->getValue();

        return json;
    }

    CodecResult decode(ISetting* setting, const whip::WhipJsonValue& data) const override {
        auto result = validate(data);
        if (!result.success) return result;

        auto* boolSetting = static_cast<BoolSetting*>(setting);
        boolSetting->setValue(data["value"].get<bool>());
        return CodecResult::ok();
    }

    CodecResult validate(const whip::WhipJsonValue& data) const override {
        if (!data.contains("value")) {
            return CodecResult::fail(CodecError::MISSING_FIELD, "Missing 'value' field");
        }
        if (!data["value"].is_boolean()) {
            return CodecResult::fail(CodecError::INVALID_TYPE, "Value must be boolean");
        }
        return CodecResult::ok();
    }

    SettingType getType() const override { return SettingType::BOOL; }
};

class IntSliderCodec : public ISettingCodec {
public:
    whip::WhipJsonValue encode(const ISetting* setting) const override {
        auto* intSetting = static_cast<const IntSliderSetting*>(setting);

        whip::WhipJsonValue json;
        json["name"] = intSetting->getName();
        json["type"] = static_cast<int>(SettingType::INT_SLIDER);
        json["value"] = intSetting->getValue();

        return json;
    }

    CodecResult decode(ISetting* setting, const whip::WhipJsonValue& data) const override {
        auto result = validate(data);
        if (!result.success) return result;

        auto* intSetting = static_cast<IntSliderSetting*>(setting);
        intSetting->setValue(data["value"].get<int>());
        return CodecResult::ok();
    }

    CodecResult validate(const whip::WhipJsonValue& data) const override {
        if (!data.contains("value")) {
            return CodecResult::fail(CodecError::MISSING_FIELD, "Missing 'value' field");
        }
        if (!data["value"].is_number_integer()) {
            return CodecResult::fail(CodecError::INVALID_TYPE, "Value must be integer");
        }
        return CodecResult::ok();
    }

    SettingType getType() const override { return SettingType::INT_SLIDER; }
};

class FloatSliderCodec : public ISettingCodec {
public:
    whip::WhipJsonValue encode(const ISetting* setting) const override {
        auto* floatSetting = static_cast<const FloatSliderSetting*>(setting);

        whip::WhipJsonValue json;
        json["name"] = floatSetting->getName();
        json["type"] = static_cast<int>(SettingType::FLOAT_SLIDER);
        json["value"] = floatSetting->getValue();

        return json;
    }

    CodecResult decode(ISetting* setting, const whip::WhipJsonValue& data) const override {
        auto result = validate(data);
        if (!result.success) return result;

        auto* floatSetting = static_cast<FloatSliderSetting*>(setting);
        floatSetting->setValue(data["value"].get<float>());
        return CodecResult::ok();
    }

    CodecResult validate(const whip::WhipJsonValue& data) const override {
        if (!data.contains("value")) {
            return CodecResult::fail(CodecError::MISSING_FIELD, "Missing 'value' field");
        }
        if (!data["value"].is_number()) {
            return CodecResult::fail(CodecError::INVALID_TYPE, "Value must be number");
        }
        return CodecResult::ok();
    }

    SettingType getType() const override { return SettingType::FLOAT_SLIDER; }
};

class ComboCodec : public ISettingCodec {
public:
    whip::WhipJsonValue encode(const ISetting* setting) const override {
        auto* comboSetting = static_cast<const ComboSetting*>(setting);

        whip::WhipJsonValue json;
        json["name"] = comboSetting->getName();
        json["type"] = static_cast<int>(SettingType::COMBO);
        json["value"] = comboSetting->getSelectedIndex();

        return json;
    }

    CodecResult decode(ISetting* setting, const whip::WhipJsonValue& data) const override {
        auto result = validate(data);
        if (!result.success) return result;

        auto* comboSetting = static_cast<ComboSetting*>(setting);
        int index = data["value"].get<int>();

        const auto& options = comboSetting->getOptions();
        if (index < 0 || index >= static_cast<int>(options.size())) {
            return CodecResult::fail(CodecError::VALIDATION_FAILED,
                "Index out of range for combo options");
        }

        comboSetting->setSelectedIndex(index);
        return CodecResult::ok();
    }

    CodecResult validate(const whip::WhipJsonValue& data) const override {
        if (!data.contains("value")) {
            return CodecResult::fail(CodecError::MISSING_FIELD, "Missing 'value' field");
        }
        if (!data["value"].is_number_integer()) {
            return CodecResult::fail(CodecError::INVALID_TYPE, "Value must be integer");
        }
        return CodecResult::ok();
    }

    SettingType getType() const override { return SettingType::COMBO; }
};

class MultiComboCodec : public ISettingCodec {
public:
    whip::WhipJsonValue encode(const ISetting* setting) const override {
        auto* multiComboSetting = static_cast<const MultiComboSetting*>(setting);

        whip::WhipJsonValue json;
        json["name"] = multiComboSetting->getName();
        json["type"] = static_cast<int>(SettingType::MULTI_COMBO);
        json["value"] = multiComboSetting->getSelectedItems();

        return json;
    }

    CodecResult decode(ISetting* setting, const whip::WhipJsonValue& data) const override {
        auto result = validate(data);
        if (!result.success) return result;

        auto* multiComboSetting = static_cast<MultiComboSetting*>(setting);
        std::vector<bool> values = data["value"].get<std::vector<bool>>();

        const size_t expected = multiComboSetting->getOptions().size();
        if (values.size() < expected) values.resize(expected, false);
        else if (values.size() > expected) values.resize(expected);
        multiComboSetting->setSelectedItems(values);
        return CodecResult::ok();
    }

    CodecResult validate(const whip::WhipJsonValue& data) const override {
        if (!data.contains("value")) {
            return CodecResult::fail(CodecError::MISSING_FIELD, "Missing 'value' field");
        }
        if (!data["value"].is_array()) {
            return CodecResult::fail(CodecError::INVALID_TYPE, "Value must be array");
        }
        return CodecResult::ok();
    }

    SettingType getType() const override { return SettingType::MULTI_COMBO; }
};

class KeybindCodec : public ISettingCodec {
public:
    whip::WhipJsonValue encode(const ISetting* setting) const override {
        auto* keybindSetting = static_cast<const KeybindSetting*>(setting);

        whip::WhipJsonValue json;
        json["name"] = keybindSetting->getName();
        json["type"] = static_cast<int>(SettingType::KEYBIND);
        json["value"] = keybindSetting->getKeyCode();

        return json;
    }

    CodecResult decode(ISetting* setting, const whip::WhipJsonValue& data) const override {
        auto result = validate(data);
        if (!result.success) return result;

        auto* keybindSetting = static_cast<KeybindSetting*>(setting);
        keybindSetting->setKeyCode(data["value"].get<int>());
        return CodecResult::ok();
    }

    CodecResult validate(const whip::WhipJsonValue& data) const override {
        if (!data.contains("value")) {
            return CodecResult::fail(CodecError::MISSING_FIELD, "Missing 'value' field");
        }
        if (!data["value"].is_number_integer()) {
            return CodecResult::fail(CodecError::INVALID_TYPE, "Value must be integer");
        }
        return CodecResult::ok();
    }

    SettingType getType() const override { return SettingType::KEYBIND; }
};

class ColorCodec : public ISettingCodec {
public:
    whip::WhipJsonValue encode(const ISetting* setting) const override {
        auto* colorSetting = static_cast<const ColorSetting*>(setting);

        whip::WhipJsonValue json;
        json["name"] = colorSetting->getName();
        json["type"] = static_cast<int>(SettingType::COLOR);

        ImColor color = colorSetting->getValue();
        json["value"] = {
            static_cast<double>(color.Value.x),
            static_cast<double>(color.Value.y),
            static_cast<double>(color.Value.z),
            static_cast<double>(color.Value.w)
        };

        return json;
    }

    CodecResult decode(ISetting* setting, const whip::WhipJsonValue& data) const override {
        auto result = validate(data);
        if (!result.success) return result;

        auto* colorSetting = static_cast<ColorSetting*>(setting);
        ImColor color(
            data["value"][0].get<float>(),
            data["value"][1].get<float>(),
            data["value"][2].get<float>(),
            data["value"][3].get<float>()
        );
        colorSetting->setValue(color);
        return CodecResult::ok();
    }

    CodecResult validate(const whip::WhipJsonValue& data) const override {
        if (!data.contains("value")) {
            return CodecResult::fail(CodecError::MISSING_FIELD, "Missing 'value' field");
        }
        if (!data["value"].is_array() || data["value"].size() != 4) {
            return CodecResult::fail(CodecError::INVALID_TYPE,
                "Value must be array of 4 numbers");
        }
        return CodecResult::ok();
    }

    SettingType getType() const override { return SettingType::COLOR; }
};

class TextInputCodec : public ISettingCodec {
public:
    whip::WhipJsonValue encode(const ISetting* setting) const override {
        auto* textInputSetting = static_cast<const TextInputSetting*>(setting);

        whip::WhipJsonValue json;
        json["name"] = textInputSetting->getName();
        json["type"] = static_cast<int>(SettingType::TEXT_INPUT);
        json["value"] = textInputSetting->getText();

        return json;
    }

    CodecResult decode(ISetting* setting, const whip::WhipJsonValue& data) const override {
        auto result = validate(data);
        if (!result.success) return result;

        auto* textInputSetting = static_cast<TextInputSetting*>(setting);
        DynamicTrackedString secureVal = data["value"].getSecureString();
        textInputSetting->setText(std::string(secureVal.c_str()));

        return CodecResult::ok();
    }

    CodecResult validate(const whip::WhipJsonValue& data) const override {
        if (!data.contains("value")) {
            return CodecResult::fail(CodecError::MISSING_FIELD, "Missing 'value' field");
        }
        if (!data["value"].is_string()) {
            return CodecResult::fail(CodecError::INVALID_TYPE, "Value must be string");
        }
        return CodecResult::ok();
    }

    SettingType getType() const override { return SettingType::TEXT_INPUT; }
};

class IntRangeSliderCodec : public ISettingCodec {
public:
    whip::WhipJsonValue encode(const ISetting* setting) const override {
        auto* rangeSetting = static_cast<const IntRangeSliderSetting*>(setting);

        whip::WhipJsonValue json;
        json["name"] = rangeSetting->getName();
        json["type"] = static_cast<int>(SettingType::INT_RANGE_SLIDER);
        json["min"] = rangeSetting->getMinValue();
        json["max"] = rangeSetting->getMaxValue();

        return json;
    }

    CodecResult decode(ISetting* setting, const whip::WhipJsonValue& data) const override {
        auto result = validate(data);
        if (!result.success) return result;

        auto* rangeSetting = static_cast<IntRangeSliderSetting*>(setting);
        int minVal = data["min"].get<int>();
        int maxVal = data["max"].get<int>();

        int rangeMin = rangeSetting->getRangeMin();
        int rangeMax = rangeSetting->getRangeMax();

        if (minVal < rangeMin || minVal > rangeMax ||
            maxVal < rangeMin || maxVal > rangeMax ||
            minVal > maxVal) {
            return CodecResult::fail(CodecError::VALIDATION_FAILED,
                "Values out of range bounds or min > max");
        }

        rangeSetting->setMinValue(minVal);
        rangeSetting->setMaxValue(maxVal);
        return CodecResult::ok();
    }

    CodecResult validate(const whip::WhipJsonValue& data) const override {
        if (!data.contains("min") || !data.contains("max")) {
            return CodecResult::fail(CodecError::MISSING_FIELD, "Missing 'min' or 'max' field");
        }
        if (!data["min"].is_number_integer() || !data["max"].is_number_integer()) {
            return CodecResult::fail(CodecError::INVALID_TYPE, "Values must be integers");
        }
        return CodecResult::ok();
    }

    SettingType getType() const override { return SettingType::INT_RANGE_SLIDER; }
};

class FloatRangeSliderCodec : public ISettingCodec {
public:
    whip::WhipJsonValue encode(const ISetting* setting) const override {
        auto* rangeSetting = static_cast<const FloatRangeSliderSetting*>(setting);

        whip::WhipJsonValue json;
        json["name"] = rangeSetting->getName();
        json["type"] = static_cast<int>(SettingType::FLOAT_RANGE_SLIDER);
        json["min"] = rangeSetting->getMinValue();
        json["max"] = rangeSetting->getMaxValue();

        return json;
    }

    CodecResult decode(ISetting* setting, const whip::WhipJsonValue& data) const override {
        auto result = validate(data);
        if (!result.success) return result;

        auto* rangeSetting = static_cast<FloatRangeSliderSetting*>(setting);
        float minVal = data["min"].get<float>();
        float maxVal = data["max"].get<float>();

        float rangeMin = rangeSetting->getRangeMin();
        float rangeMax = rangeSetting->getRangeMax();

        if (minVal < rangeMin || minVal > rangeMax ||
            maxVal < rangeMin || maxVal > rangeMax ||
            minVal > maxVal) {
            return CodecResult::fail(CodecError::VALIDATION_FAILED,
                "Values out of range bounds or min > max");
        }

        rangeSetting->setMinValue(minVal);
        rangeSetting->setMaxValue(maxVal);
        return CodecResult::ok();
    }

    CodecResult validate(const whip::WhipJsonValue& data) const override {
        if (!data.contains("min") || !data.contains("max")) {
            return CodecResult::fail(CodecError::MISSING_FIELD, "Missing 'min' or 'max' field");
        }
        if (!data["min"].is_number() || !data["max"].is_number()) {
            return CodecResult::fail(CodecError::INVALID_TYPE, "Values must be numbers");
        }
        return CodecResult::ok();
    }

    SettingType getType() const override { return SettingType::FLOAT_RANGE_SLIDER; }
};
