#pragma once

#include "../../base/SettingBaseModule.h"
#include "../../ModuleType.h"
#include "../../IGuiCustomRender.h"

class PrivateConfigModule final : public SettingBaseModule<PrivateConfigModule, ModuleType::PRIVATE_CONFIG, CategoryType::CONFIG> {
public:
    PrivateConfigModule() = default;

    void onLoad() override {
        SettingBaseModule::onLoad();
    }

    void onFullRender(const std::unique_ptr<c_widgets>&) override {
        widgets->config_manager();
    }

    IGuiCustomRenderType getRenderType() const override {
        return OVERRIDE;
    }

    bool enableOnLoad() const override {
        return false;
    }

    bool showInArrayList() const override {
        return false;
    }
};
