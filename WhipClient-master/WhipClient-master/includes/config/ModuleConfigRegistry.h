#pragma once

#include <map>
#include <memory>
#include <cctype>
#include "../setting/Setting.h"
#include "../module/IModule.h"
#include "../module/ModuleType.h"
#include "util/TrackedString.h"

inline ModuleType getModuleIdentifier(const IModule* module) {
    if (!module) return ModuleType::NONE;
    return module->getType();
}

inline uint32_t normalizeSettingName(const char* name) {
    if (!name) return 0;

    uint32_t hash = 2166136261u;
    for (const char* p = name; *p != '\0'; ++p) {
        char c = *p;
        if (c == ' ') c = '_';
        else c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        hash ^= static_cast<uint32_t>(c);
        hash *= 16777619u;
    }
    return hash;
}

struct ModuleConfig {
    ModuleType type;
    bool enabled;
    std::map<uint32_t, std::shared_ptr<ISetting>> settings;
};

class ModuleConfigRegistry {
public:
    static ModuleConfigRegistry& getInstance() {
        static ModuleConfigRegistry instance;
        return instance;
    }

    void registerModule(IModule* module, const std::vector<std::shared_ptr<ISetting>>& settings) {
        if (!module) return;

        ModuleType identifier = getModuleIdentifier(module);

        ModuleConfig config;
        config.type = identifier;
        config.enabled = module->isEnabled();

        for (const auto& setting : settings) {
            if (!setting) continue;

            if (setting->getType() == SettingType::TEXT) {
                continue;
            }

            uint32_t settingHash = normalizeSettingName(setting->getName());
            config.settings[settingHash] = setting;
        }

        m_modules[identifier] = config;
    }

    ModuleConfig* getModuleConfig(ModuleType identifier) {
        auto it = m_modules.find(identifier);
        return it != m_modules.end() ? &it->second : nullptr;
    }

    const std::map<ModuleType, ModuleConfig>& getAllModules() const {
        return m_modules;
    }

    void clear() {
        m_modules.clear();
    }

private:
    ModuleConfigRegistry() = default;
    ~ModuleConfigRegistry() = default;
    ModuleConfigRegistry(const ModuleConfigRegistry&) = delete;
    ModuleConfigRegistry& operator=(const ModuleConfigRegistry&) = delete;

    std::map<ModuleType, ModuleConfig> m_modules;
};
