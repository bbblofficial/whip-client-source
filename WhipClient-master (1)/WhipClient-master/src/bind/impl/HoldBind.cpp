#include "../../../includes/bind/impl/HoldBind.h"

HoldBind::HoldBind(const int keyCode) : BaseBind(keyCode) {
}

void HoldBind::onKeyPress() {
    if (!active) {
        active = true;
        if (onActivatedCallback) {
            onActivatedCallback();
        }
    }
}

void HoldBind::onKeyRelease() {
    if (active) {
        active = false;
        if (onDeactivatedCallback) {
            onDeactivatedCallback();
        }
    }
}

bool HoldBind::isActive() const {
    return active;
}

BindType HoldBind::getBindType() const {
    return BindType::HOLD;
}
