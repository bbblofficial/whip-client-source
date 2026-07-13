#include "../../../includes/screen/sub/ModuleScreen.h"

#include "functions.h"
#include "../../../includes/handler/ModuleHandler.h"
#include "bus/EventBus.h"
#include "event/sub/ModuleScreenDrawEvent.h"
#include "module/IGuiCustomRender.h"
#include "module/base/BaseModule.h"
#include "util/ClientStrings.h"

void ModuleScreen::drawing(const RECT& rect, const Gui* handler) const {
    IModule* currentModule = getCurrentModule();

    ModuleScreenDrawEvent drawEvent(rect, handler, currentModule);
    EventBus::getInstance().dispatch(drawEvent);

    if (drawEvent.isCancelled()) {
        return;
    }

    gui->easing(elements->child.width, (gui->content_avail().x - SCALE(elements->padding.x * 2)) / 2, 24.f, smooth_easing);

    if (!currentModule) {
        Spacing();
        Text("Contact admin no module found!");
        return;
    }

    gui->begin_group();
    {
        if (currentModule->isExperimental()) {
            Spacing();
            Text("this module is experimental and may not\nfunction as expected or may cause a crash");
        }

        auto* customModuleGuiRender = dynamic_cast<IGuiCustomRender*>(currentModule);
        if (!customModuleGuiRender) return;

        customModuleGuiRender->onFullRender(widgets);

        if (customModuleGuiRender->getRenderType() == IGuiCustomRender::NONE) {
            widgets->child(toName(currentModule->getType()));
            {

                if (!(currentModule->getType() == ModuleType::GUI)) {
                    if (!currentModule->hasKeybind() || currentModule->getBindType() == BindType::TOGGLE) {
                        bool currentState = currentModule->isEnabled();
                        if (widgets->checkbox(Strings::lblEnable(), &currentState, nullptr, true)) {
                            currentModule->setEnabled(currentState);
                        }
                    }
                }

                if (widgets->popup(Strings::lblEnable(), GetCurrentContext()->LastItemData.GearPos, ImVec2(elements->child.width, 0), SCALE(elements->child.rounding)))
                {
                    bool showInArray = currentModule->showInArrayList();
                    if (widgets->checkbox(Strings::lblShowInArrayList(), &showInArray, nullptr, true)) {
                        currentModule->setShowInArrayList(showInArray);
                    }
                    widgets->end_popup();
                }

                customModuleGuiRender->onRender(widgets);
            }
            widgets->end_child();

            gui->sameline();

            widgets->child("Settings");
            {
                customModuleGuiRender->onRenderConditional(widgets);
            }
            widgets->end_child();
        } else {

            customModuleGuiRender->onRender(widgets);
        }
    }
    gui->end_group();
}
