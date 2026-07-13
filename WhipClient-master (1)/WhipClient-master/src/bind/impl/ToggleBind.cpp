#include "../../../includes/bind/impl/ToggleBind.h"

ToggleBind::ToggleBind(const int keyCode) : BaseBind(keyCode) {
}

void ToggleBind::onKeyPress() {
    if (!wasPressed) {
        const bool wasActive = active;
        active = !active;
        wasPressed = true;

        if (active && !wasActive && onActivatedCallback) {
            onActivatedCallback();
        } else if (!active && wasActive && onDeactivatedCallback) {
            onDeactivatedCallback();
        }
    }
}

void ToggleBind::onKeyRelease() {
    wasPressed = false;
}

bool ToggleBind::isActive() const {
    return active;
}

BindType ToggleBind::getBindType() const {
    return BindType::TOGGLE;
}
