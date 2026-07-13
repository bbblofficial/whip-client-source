#pragma once
#include "../base/BaseBind.h"

class ToggleBind final : public BaseBind {
public:
    explicit ToggleBind(int keyCode = 0);
    ~ToggleBind() override = default;

    void onKeyPress() override;
    void onKeyRelease() override;
    bool isActive() const override;
    BindType getBindType() const override;

private:
    bool wasPressed = false;
};
