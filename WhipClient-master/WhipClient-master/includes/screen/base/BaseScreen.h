#ifndef BASESCREEN_H
#define BASESCREEN_H

#include "../../module/IModule.h"
#include "screen/IScreen.h"
#include "../../../includes/handler/ModuleHandler.h"
#include "../../../includes/module/CategoryType.h"
#include "Thirdpary/framework/settings/variables.h"

class BaseScreen : public IScreen {
public:
    BaseScreen() = default;
    ~BaseScreen() override = default;

    static IModule* getCurrentModule() {
        std::vector<CategoryType> orderedCategories;
        for (int i = 0; i < static_cast<int>(CategoryType::CATEGORY_COUNT); ++i) {
            orderedCategories.push_back(static_cast<CategoryType>(i));
        }

        IModule* currentModule = nullptr;
        int tabIndex = 0;
        bool found = false;

        for (const auto& category : orderedCategories) {
            if (found) break;

            auto modulesByCategory = ModuleHandler::getInstance().getModulesByCategory(category);
            if (modulesByCategory.empty()) continue;

            for (auto* module : modulesByCategory) {
                if (tabIndex == var->gui.tab) {
                    currentModule = module;
                    found = true;
                    break;
                }
                tabIndex++;
            }
        }

        return currentModule;
    }
};

#endif
