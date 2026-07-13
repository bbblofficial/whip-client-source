#pragma once

#include "ProviderType.h"

class IProvider {
public:
    virtual ~IProvider() = default;

    virtual void onEnable() {}
    virtual void onDisable() {}
    virtual void onCleanup() {}

    virtual ProviderType getType() const = 0;

    virtual bool isEnabled() const = 0;
    virtual void setEnabled(bool enabled) = 0;
};
