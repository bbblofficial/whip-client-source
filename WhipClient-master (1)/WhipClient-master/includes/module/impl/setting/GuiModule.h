#pragma once
#include "../../../DllMain.h"

#include "../../base/SharedThreadBaseModule.h"
#include "../../ModuleType.h"
#include "../../../setting/SettingMacros.h"
#include "../../../event/sub/ModuleScreenDrawEvent.h"
#include <imgui.h>

#include "util/xor.h"
#include "util/ClientStrings.h"

class GuiModule final : public SettingBaseModule<GuiModule, ModuleType::GUI>, public IArraylistRenderer {
private:
    ImColor color{ 185, 192, 255 };

protected:
    void registerEvents() override {
        SettingBaseModule::registerEvents();

        subscribe<ModuleScreenDrawEvent>([this](const ModuleScreenDrawEvent& event) {
            this->onModuleScreenDraw(event);
        }, EventPriority::DEFAULT, false);
    }

public:
    GuiModule() = default;

    void onLoad() override {
        SettingBaseModule::onLoad();

        REGISTER_KEYBIND(Gui::getInstance().hideBind0, 0);
        REGISTER_KEYBIND(Gui::getInstance().destructBind, VK_F7);
        REGISTER_KEYBIND(Gui::getInstance().panicBind, 0);

        REGISTER_COLOR(color, ImColor(234, 207, 255));
    }

    ~GuiModule() override = default;

    void onRender(const std::unique_ptr<c_widgets> &) override {
        {
            widgets->color_selector(Strings::lblAccentColor(), (ImVec4*)&color);
            widgets->slider_float(Strings::lblScale(), &var->gui.dpi, 1.0f, 2.0f);
        }
    }

    void onRenderConditional(const std::unique_ptr<c_widgets> &) override {
        widgets->tooltip_bind(Strings::lblHide(), "", &Gui::getInstance().hideBind0, nullptr);
        widgets->tooltip_bind(Strings::lblDestruct(), "", &Gui::getInstance().destructBind, nullptr);
        widgets->tooltip_bind(Strings::lblPanic(), "", &Gui::getInstance().panicBind, nullptr);
    }

private:
    void onModuleScreenDraw(const ModuleScreenDrawEvent& event) const {
        clr->accent = color;
    }
};
