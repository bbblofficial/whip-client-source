#pragma once
#include <functional>
#include "../IBind.h"

class BaseBind : public IBind {
public:
    explicit BaseBind(int keyCode = 0);
    ~BaseBind() override = default;

    void setOnActivated(std::function<void()> callback) override;
    void setOnDeactivated(std::function<void()> callback) override;

    int getKeyCode() const { return keyCode; }
    void setActive(bool value) { active = value; }

protected:
    int keyCode;
    bool active;
    std::function<void()> onActivatedCallback;
    std::function<void()> onDeactivatedCallback;
};
