#pragma once

#include "../IModule.h"
#include "DllMain.h"

class ModuleHandler;

template<typename Derived, ModuleType Type, CategoryType Category>
class BaseModule : public IModule {
public:
    explicit BaseModule()
        : enable(false) {

    }
    bool enable;

    ~BaseModule() override {

    }

    ModuleType getType() const override {
        return Type;
    }

    CategoryType getCategory() const override {
        return Category;
    }

    bool isEnabled() const override {
        return enable;
    }

    void setEnabled(const bool enabled) override {
        if (enable != enabled) {
            enable = enabled;
            if (enabled) {
                onEnable();
            } else {
                onDisable();
            }
        }
    }

    void setEnabled2(const bool enabled) {
        if (enable != enabled) {
            enable = enabled;
            if (enabled) {
                onEnable();
            } else {
                onDisable();
            }
        }
    }

    bool& getEnabledRef() override {
        return enable;
    }

    void setEnabledRef(bool enabled) override {
        this->enable = enabled;
    }

    static Derived& getInstance() {
        static Derived instance;
        return instance;
    }

    static Derived* getInstancePtr() {
        return &getInstance();
    }
};
