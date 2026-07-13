#pragma once

#include "../IProvider.h"

class ProviderHandler;

template<typename Derived, ProviderType Type>
class BaseProvider : public IProvider {
public:
    explicit BaseProvider()
        : enabled(false) {
    }

    bool enabled;

    ~BaseProvider() override = default;

    ProviderType getType() const override {
        return Type;
    }

    bool isEnabled() const override {
        return enabled;
    }

    void setEnabled(const bool enable) override {
        if (enabled == enable) return;

        enabled = enable;
        if (enabled) {
            onEnable();
        } else {
            onDisable();
        }
    }

    static Derived* Get() {
        static Derived instance;
        return &instance;
    }
};
