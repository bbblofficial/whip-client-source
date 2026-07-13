#include "../../../includes/bind/base/BaseBind.h"

BaseBind::BaseBind(const int keyCode) : keyCode(keyCode), active(false), onActivatedCallback(nullptr), onDeactivatedCallback(nullptr) {
}

void BaseBind::setOnActivated(std::function<void()> callback) {
    onActivatedCallback = std::move(callback);
}

void BaseBind::setOnDeactivated(std::function<void()> callback) {
    onDeactivatedCallback = std::move(callback);
}
