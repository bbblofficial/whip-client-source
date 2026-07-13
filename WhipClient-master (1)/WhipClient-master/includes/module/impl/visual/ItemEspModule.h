#pragma once

#include "../../base/Render3dBaseModule.h"
#include "../../ModuleType.h"
#include "../../CategoryType.h"
#include "../../../setting/SettingMacros.h"
#include <imgui.h>

class ItemEspModule final
    : public Render3dBaseModule<ItemEspModule, ModuleType::ITEM_ESP, CategoryType::VISUAL> {
    friend class BaseModule;

    ImColor itemColor = ImColor(1.0f, 0.84f, 0.0f, 1.0f);
    float maxDistance = 32.0f;

    void onRender3d(const Render3dEvent& event) override;

public:
    explicit ItemEspModule(BindType bindType = BindType::TOGGLE, int keyCode = 0);

    void onLoad() override {
        Render3dBaseModule::onLoad();
        COLOR_SETTING(itemColor, ImColor(1.0f, 0.84f, 0.0f, 1.0f));
        FLOAT_SLIDER(maxDistance, 32.0f, 8.0f, 64.0f);
    }

    void onEnable() override { Render3dBaseModule::onEnable(); }
    void onDisable() override { Render3dBaseModule::onDisable(); }

    static ItemEspModule* getInstancePtr() {
        return &BaseModule::getInstance();
    }
};
