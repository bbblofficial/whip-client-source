#include "includes/module/impl/visual/ArrayListModule.h"
#include "../../../includes/handler/ModuleHandler.h"
#include "../../../includes/util/JniScope.h"
#include "../../../includes/hud/renderer/IArraylistRenderer.h"

#include <algorithm>
#include <cstring>

ArrayListModule::ArrayListModule()
    : SharedThreadBaseModule(BindType::TOGGLE, 0) {
}

void ArrayListModule::onUpdate(JniScope& scope) {
    auto entries = collectNewSystemModules();

    sortEntriesByWidth(entries);

    for (auto& entry : calculatedEntries) {
        entry.clear();
    }
    calculatedEntries.clear();

    calculatedEntries = std::move(entries);
}

std::vector<ArraylistEntry> ArrayListModule::getCalculatedEntries() const {
    return calculatedEntries;
}

std::vector<ArraylistEntry> ArrayListModule::collectNewSystemModules() {
    std::vector<ArraylistEntry> entries;

    const auto& moduleHandler = ModuleHandler::getInstance();
    auto modules = moduleHandler.getModules();

    for (auto* module : modules) {
        if (!module || !module->isEnabled()) continue;

        if (const auto* renderer = dynamic_cast<IArraylistRenderer*>(module); renderer && renderer->shouldShowInArraylist()) {
            std::string displayName = renderer->getDisplayName();
            std::string displayFlags = renderer->getDisplayFlags();

            ArraylistEntry entry(displayName, displayFlags, displayName);
            entries.push_back(std::move(entry));

            secureStringZero(displayName);
            secureStringZero(displayFlags);
        }
    }

    for (auto& ptr : modules) {
        ptr = nullptr;
    }
    modules.clear();

    return entries;
}

void ArrayListModule::sortEntriesByWidth(std::vector<ArraylistEntry>& entries) {
    std::ranges::sort(entries, [](const ArraylistEntry& a, const ArraylistEntry& b) {

        return (a.name.size() + a.flags.size()) > (b.name.size() + b.flags.size());
    });
}

REGISTER_MODULE(ArrayListModule, ModuleType::ARRAYLIST)
