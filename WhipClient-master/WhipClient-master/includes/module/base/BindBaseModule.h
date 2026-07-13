#pragma once

#include "SettingBaseModule.h"
#include "../../bind/BindType.h"
#include "../../manager/BindManager.h"
#include "../../setting/SettingMacros.h"
#include "handler/ModuleHandler.h"
#include "hud/renderer/IArraylistRenderer.h"
#include "module/impl/visual/NotificationModule.h"

constexpr auto USED_COLOR = ImColor(24, 155, 222);

template<typename Derived, ModuleType Type, CategoryType Category>
class BindBaseModule : public SettingBaseModule<Derived, Type, Category>, public IArraylistRenderer {

public:

    using SettingBaseModule<Derived, Type, Category>::getDisplayName;

    const char* getDisplayName() const override {
        return SettingBaseModule<Derived, Type, Category>::getDisplayName();
    }

    explicit BindBaseModule(const BindType bindType = BindType::TOGGLE, const int keyCode = 0)
        : SettingBaseModule<Derived, Type, Category>(), bindType(bindType), bind(keyCode), render(false) {

    }

    void onLoad() override {
        registerBind();
        SettingBaseModule<Derived, Type, Category>::onLoad();
        KEYBIND_SETTING_CALLBACK(bind, 0, [this](const int newKeyCode) {
            setKeyCode(newKeyCode);

            if (bindType == BindType::HOLD && Category != CategoryType::BACKEND) {
                render = newKeyCode != 0;
                NotificationModule::addModuleNotification(getDisplayName(), render);
            }
        });
    }

    void setKeyCode(const int newKeyCode) {
        bind = newKeyCode;
        registerBind();
    }

    void setBindType(const BindType newBindType) {
        bindType = newBindType;
        registerBind();
    }

    void setEnabled(const bool enabled) override {
        if (bindType == BindType::TOGGLE && Category != CategoryType::BACKEND && shouldNotify()) {
            NotificationModule::addModuleNotification(getDisplayName(), enabled);
        }
        BindManager::getInstance().syncBindStateForModule(this, enabled);
        BaseModule<Derived, Type, Category>::setEnabled2(enabled);
    }

    bool forceRender() const override {
        return bindType == BindType::HOLD && render;
    }

    virtual bool shouldNotify() const { return true; }

    int getKeyCode() const { return bind; }
    BindType getBindType() const override { return bindType; }
    bool hasKeybind() const override { return true; }

    bool showInArrayList() const override { return IArraylistRenderer::shouldShowInArraylist(); }
    void setShowInArrayList(const bool show) override { IArraylistRenderer::setShowInArrayList(show); }

    IArraylistRenderer* asArraylistRenderer() override { return static_cast<IArraylistRenderer*>(this); }
    IGuiCustomRender* asGuiCustomRender() override { return static_cast<IGuiCustomRender*>(this); }

private:
    BindType bindType;
    int bind;
    bool render;

    void registerBind() {
        BindManager::getInstance().registerBindForModule(this, bind, bindType,
            [this] {
                if (bindType == BindType::HOLD && Category != CategoryType::BACKEND && shouldNotify()) {
                    std::string msg = std::string(getDisplayName()) + " used";
                    NotificationModule::addCustomNotification(std::move(msg), USED_COLOR);
                    SecureZeroMemory(msg.data(), msg.capacity());
                    msg.clear();
                }
                this->setEnabled(true);
            },
            [this] {
                this->setEnabled(false);
            }
        );
    }
};
