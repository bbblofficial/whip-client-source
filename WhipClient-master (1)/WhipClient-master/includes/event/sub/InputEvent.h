#pragma once
#ifndef INPUT_EVENT_H
#define INPUT_EVENT_H

#include <typeindex>
#include "../base/BaseEvent.h"
#include "../InputType.h"
#include "../Cancellable.h"

class InputEvent final : public Event, public Cancellable {
private:
    InputType inputType;
    int keyCode;
    bool pressed;

public:
    InputEvent(InputType inputType, int keyCode, bool pressed);

    InputType getInputType() const;
    void setInputType(InputType inputType);

    int getKeyCode() const;
    void setKeyCode(int keyCode);

    bool isPressed() const;
    void setPressed(bool pressed);

    std::type_index getType() const override;

};

#endif
