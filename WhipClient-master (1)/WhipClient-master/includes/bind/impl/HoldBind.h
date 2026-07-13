#pragma once
#include "../base/BaseBind.h"

class HoldBind final : public BaseBind {
public:
    explicit HoldBind(int keyCode = 0);
    ~HoldBind() override = default;

    void onKeyPress() override;
    void onKeyRelease() override;
    bool isActive() const override;
    BindType getBindType() const override;
};
