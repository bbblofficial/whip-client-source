#pragma once

#include "../module/IModule.h"
#include "../module/ModuleType.h"
#include "../module/CategoryType.h"
#include "util/MinecraftDetails.h"
#include <array>
#include <vector>
#include <utility>

class ModuleHandler {
public:
    enum class VersionConstraint {
        ALL_VERSIONS,
        ONLY_VERSION,
        EXCEPT_VERSION
    };

    struct ModuleRegistration {
        ModuleType type;
        IModule* module;
        VersionConstraint constraint;
        MinecraftVersion version;
    };

    ModuleHandler() = default;

    void load();
    void unload();
    void enableAll();
    void disableAll();
    void panicAll();
    void clear();

    IModule* getModule(ModuleType type);
    const IModule* getModule(ModuleType type) const;

    template<ModuleType Type>
    IModule* getModule() {
        return getModule(Type);
    }

    template<ModuleType Type>
    const IModule* getModule() const {
        return getModule(Type);
    }

    template<typename T, ModuleType Type>
    T* getTypedModule() {
        return static_cast<T*>(getModule(Type));
    }

    template<typename T, ModuleType Type>
    const T* getTypedModule() const {
        return static_cast<const T*>(getModule(Type));
    }

    bool hasModule(ModuleType type) const;
    size_t getModuleCount() const;
    bool isModuleEnabled(ModuleType type) const;
    void enableModule(ModuleType type);
    void disableModule(ModuleType type);

    std::vector<IModule*> getModulesByCategory(CategoryType category);
    std::vector<const IModule*> getModulesByCategory(CategoryType category) const;
    void enableModulesInCategory(CategoryType category);
    void disableModulesInCategory(CategoryType category);
    size_t getModuleCountInCategory(CategoryType category) const;

    void registerModule(ModuleType type, IModule* module);

    const std::vector<IModule*>& getModules() const {
        return m_activeModules;
    }

    static std::vector<ModuleRegistration>& getPendingRegistrations() {
        static std::vector<ModuleRegistration> pending;
        return pending;
    }

    static ModuleHandler& getInstance();

    ~ModuleHandler() = default;
    ModuleHandler(const ModuleHandler&) = delete;
    ModuleHandler& operator=(const ModuleHandler&) = delete;

private:

    void processPendingRegistrations();
    void rebuildActiveModuleCache();

    std::array<IModule*, static_cast<size_t>(ModuleType::MODULE_COUNT)> m_modules{};
    std::vector<IModule*> m_activeModules;
    bool m_loaded = false;
    bool m_pendingProcessed = false;
};

#define GET_MACRO(_1, _2, _3, NAME, ...) NAME

#define EXPAND(x) x
#define EXPAND2(x) EXPAND(x)

#define REGISTER_MODULE(...) \
EXPAND2(EXPAND(GET_MACRO(__VA_ARGS__, REGISTER_MODULE_3, REGISTER_MODULE_2))(__VA_ARGS__))

#define REGISTER_MODULE_2(ClassName, ModuleTypeEnum) \
static bool ClassName##_registered = []() { \
ModuleHandler::getPendingRegistrations().push_back({ \
    ModuleTypeEnum, \
    &ClassName::getInstance(), \
    ModuleHandler::VersionConstraint::ALL_VERSIONS, \
    MinecraftVersion::V1_7_10 \
}); \
return true; \
}();

#define REGISTER_MODULE_3(ClassName, ModuleTypeEnum, IncludeVersion) \
static bool ClassName##_registered = []() { \
ModuleHandler::getPendingRegistrations().push_back({ \
    ModuleTypeEnum, \
    &ClassName::getInstance(), \
    ModuleHandler::VersionConstraint::ONLY_VERSION, \
    IncludeVersion \
}); \
return true; \
}();

#define REGISTER_MODULE_FOR_VERSION(ClassName, ModuleTypeEnum, IncludeVersion) \
REGISTER_MODULE_3(ClassName, ModuleTypeEnum, IncludeVersion)

#define REGISTER_MODULE_EXCEPT_VERSION(ClassName, ModuleTypeEnum, ExcludeVersion) \
static bool ClassName##_registered = []() { \
ModuleHandler::getPendingRegistrations().push_back({ \
    ModuleTypeEnum, \
    &ClassName::getInstance(), \
    ModuleHandler::VersionConstraint::EXCEPT_VERSION, \
    ExcludeVersion \
}); \
return true; \
}();
