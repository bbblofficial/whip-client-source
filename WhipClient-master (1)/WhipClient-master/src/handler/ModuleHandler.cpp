#include "../../includes/handler/ModuleHandler.h"
#include "../../includes/handler/SettingsHandler.h"
#include "../../includes/manager/ConfigManager.h"
#include "../../includes/util/Debug.h"

void ModuleHandler::processPendingRegistrations() {
    if (m_pendingProcessed) {
        return;
    }

    auto& pending = getPendingRegistrations();

    if (pending.empty()) {
        return;
    }

    const auto currentVersion = MinecraftSession::getInstance().version;

    for (auto& registration : pending) {
        bool shouldRegister = false;

        switch (registration.constraint) {
            case VersionConstraint::ALL_VERSIONS:
                shouldRegister = true;
                break;
            case VersionConstraint::ONLY_VERSION:
                shouldRegister = (currentVersion == registration.version);
                break;
            case VersionConstraint::EXCEPT_VERSION:
                shouldRegister = (currentVersion != registration.version);
                break;
        }

        if (shouldRegister) {
            const auto index = static_cast<size_t>(registration.type);
            if (index < m_modules.size()) {
                m_modules[index] = registration.module;
            }
        }
    }

    pending.clear();
    m_pendingProcessed = true;
    rebuildActiveModuleCache();
}

void ModuleHandler::load() {
    if (m_loaded) {
        return;
    }

    processPendingRegistrations();

    for (auto* module : m_modules) {
        if (module) {
            module->onLoad();

            if (module->enableOnLoad()) {
                module->setEnabled(true);
            }
        }
    }

    m_loaded = true;
}

void ModuleHandler::unload() {
    if (!m_loaded) {
        return;
    }

    for (auto* module : m_modules) {
        if (module && module->isEnabled()) {
            module->setEnabled(false);
        }
    }

    for (auto* module : m_modules) {
        if (module) {
            module->onCleanup();
        }
    }

    m_modules.fill(nullptr);
    m_loaded = false;
}

void ModuleHandler::enableAll() {
    for (auto* module : m_modules) {
        if (module) {
            module->setEnabled(true);
        }
    }
}

void ModuleHandler::disableAll() {
    for (auto* module : m_modules) {
        if (module) {
            module->setEnabled(false);
        }
    }
}

void ModuleHandler::panicAll() {
    disableAll();
    SettingsHandler::getInstance().resetAllToDefaults();
    ConfigManager::getInstance().unloadCurrentConfig();
}

void ModuleHandler::clear() {
    disableAll();
    m_modules.fill(nullptr);
    m_activeModules.clear();
    m_loaded = false;
    m_pendingProcessed = false;
}

IModule* ModuleHandler::getModule(ModuleType type) {
    processPendingRegistrations();
    const auto index = static_cast<size_t>(type);
    if (index < m_modules.size()) {
        return m_modules[index];
    }
    return nullptr;
}

const IModule* ModuleHandler::getModule(ModuleType type) const {
    const auto index = static_cast<size_t>(type);
    if (index < m_modules.size()) {
        return m_modules[index];
    }
    return nullptr;
}

bool ModuleHandler::hasModule(ModuleType type) const {
    return getModule(type) != nullptr;
}

size_t ModuleHandler::getModuleCount() const {
    size_t count = 0;
    for (const auto* module : m_modules) {
        if (module) {
            ++count;
        }
    }
    return count;
}

bool ModuleHandler::isModuleEnabled(ModuleType type) const {
    const auto* module = getModule(type);
    return module && module->isEnabled();
}

void ModuleHandler::enableModule(ModuleType type) {
    auto* module = getModule(type);
    if (module) {
        module->setEnabled(true);
    }
}

void ModuleHandler::disableModule(ModuleType type) {
    auto* module = getModule(type);
    if (module) {
        module->setEnabled(false);
    }
}

void ModuleHandler::registerModule(ModuleType type, IModule* module) {
    const auto index = static_cast<size_t>(type);
    if (index < m_modules.size()) {
        m_modules[index] = module;
    }
    rebuildActiveModuleCache();
}

std::vector<IModule*> ModuleHandler::getModulesByCategory(CategoryType category) {
    processPendingRegistrations();
    std::vector<IModule*> result;
    for (auto* module : m_modules) {
        if (module && module->getCategory() == category) {
            result.push_back(module);
        }
    }
    return result;
}

std::vector<const IModule*> ModuleHandler::getModulesByCategory(CategoryType category) const {
    std::vector<const IModule*> result;
    for (const auto* module : m_modules) {
        if (module && module->getCategory() == category) {
            result.push_back(module);
        }
    }
    return result;
}

void ModuleHandler::enableModulesInCategory(CategoryType category) {
    for (auto* module : m_modules) {
        if (module && module->getCategory() == category) {
            module->setEnabled(true);
        }
    }
}

void ModuleHandler::disableModulesInCategory(CategoryType category) {
    for (auto* module : m_modules) {
        if (module && module->getCategory() == category) {
            module->setEnabled(false);
        }
    }
}

size_t ModuleHandler::getModuleCountInCategory(CategoryType category) const {
    size_t count = 0;
    for (const auto* module : m_modules) {
        if (module && module->getCategory() == category) {
            ++count;
        }
    }
    return count;
}

void ModuleHandler::rebuildActiveModuleCache() {
    m_activeModules.clear();
    for (auto* module : m_modules) {
        if (module) {
            m_activeModules.push_back(module);
        }
    }
}

ModuleHandler& ModuleHandler::getInstance() {
    static ModuleHandler instance;
    return instance;
}
