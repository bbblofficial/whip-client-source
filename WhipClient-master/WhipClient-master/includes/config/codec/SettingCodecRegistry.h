#pragma once

#include "ISettingCodec.h"
#include "SettingCodecs.h"
#include <unordered_map>
#include <memory>

class SettingCodecRegistry {
public:
    static SettingCodecRegistry& getInstance() {
        static SettingCodecRegistry instance;
        return instance;
    }

    ISettingCodec* getCodec(SettingType type) const {
        auto it = m_codecs.find(type);
        if (it != m_codecs.end()) {
            return it->second.get();
        }
        return nullptr;
    }

    void registerCodec(SettingType type, std::unique_ptr<ISettingCodec> codec) {
        m_codecs[type] = std::move(codec);
    }

private:
    SettingCodecRegistry() {

        registerCodec(SettingType::BOOL, std::make_unique<BoolCodec>());
        registerCodec(SettingType::INT_SLIDER, std::make_unique<IntSliderCodec>());
        registerCodec(SettingType::FLOAT_SLIDER, std::make_unique<FloatSliderCodec>());
        registerCodec(SettingType::INT_RANGE_SLIDER, std::make_unique<IntRangeSliderCodec>());
        registerCodec(SettingType::FLOAT_RANGE_SLIDER, std::make_unique<FloatRangeSliderCodec>());
        registerCodec(SettingType::COMBO, std::make_unique<ComboCodec>());
        registerCodec(SettingType::MULTI_COMBO, std::make_unique<MultiComboCodec>());
        registerCodec(SettingType::KEYBIND, std::make_unique<KeybindCodec>());
        registerCodec(SettingType::COLOR, std::make_unique<ColorCodec>());
        registerCodec(SettingType::TEXT_INPUT, std::make_unique<TextInputCodec>());
    }

    ~SettingCodecRegistry() = default;
    SettingCodecRegistry(const SettingCodecRegistry&) = delete;
    SettingCodecRegistry& operator=(const SettingCodecRegistry&) = delete;

    std::unordered_map<SettingType, std::unique_ptr<ISettingCodec>> m_codecs;
};
