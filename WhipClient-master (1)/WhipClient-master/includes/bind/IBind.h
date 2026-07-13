#pragma once
#include <functional>

#include "BindType.h"

class IBind {
public:
    virtual ~IBind() = default;

    virtual void onKeyPress() = 0;
    virtual void onKeyRelease() = 0;
    [[nodiscard]] virtual bool isActive() const = 0;
    [[nodiscard]] virtual BindType getBindType() const = 0;

    virtual void setOnActivated(std::function<void()> callback) = 0;
    virtual void setOnDeactivated(std::function<void()> callback) = 0;
    virtual void setActive(bool value) = 0;
};
