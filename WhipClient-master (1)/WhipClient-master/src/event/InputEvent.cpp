#include "../../includes/event/sub/InputEvent.h"

InputEvent::InputEvent(InputType inputType, int keyCode, bool pressed)
    : inputType(inputType), keyCode(keyCode), pressed(pressed) {
}

InputType InputEvent::getInputType() const {
    return inputType;
}

void InputEvent::setInputType(InputType inputType) {
    this->inputType = inputType;
}

int InputEvent::getKeyCode() const {
    return keyCode;
}

void InputEvent::setKeyCode(int keyCode) {
    this->keyCode = keyCode;
}

bool InputEvent::isPressed() const {
    return pressed;
}

void InputEvent::setPressed(bool pressed) {
    this->pressed = pressed;
}

std::type_index InputEvent::getType() const {
    return std::type_index(typeid(InputEvent));
}
