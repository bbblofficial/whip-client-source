#pragma once
#include <string>

#include "ModuleType.h"
#include "CategoryType.h"
#include "../bind/BindType.h"

class IModule {
public:
    virtual ~IModule() = default;

    virtual void onLoad() = 0;
    virtual void onEnable() {}
    virtual void onDisable() {}
    virtual void onCleanup() {}

    virtual ModuleType getType() const = 0;
    virtual CategoryType getCategory() const = 0;

    virtual bool isEnabled() const = 0;
    virtual void setEnabled(bool enabled) = 0;
    virtual bool& getEnabledRef() = 0;
    virtual void setEnabledRef(bool enabled) = 0;

    virtual bool isExperimental() const { return false; }
    virtual bool showInArrayList() const { return false; }
    virtual void setShowInArrayList(bool show) {}

    virtual bool enableOnLoad() const { return false; }

    virtual BindType getBindType() const { return BindType::NONE; }
    virtual bool hasKeybind() const { return false; }

    virtual const char* getDisplayName() const { return toName(getType()); }

    virtual class IArraylistRenderer* asArraylistRenderer() { return nullptr; }
    virtual class IGuiCustomRender* asGuiCustomRender() { return nullptr; }
};
