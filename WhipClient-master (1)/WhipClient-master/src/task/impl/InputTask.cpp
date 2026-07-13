#include "../../../includes/task/impl/InputTask.h"
#include <Windows.h>
#include "util/Debug.h"
#include "gui/Gui.h"

#define KEYBOARD_KEY_COUNT 256
#define MOUSE_BUTTON_COUNT 5

static bool g_blockGameInputs = false;

InputTask::InputTask() : BaseTask(16) {
    eventBus = &EventBus::getInstance();
    bindManager = &BindManager::getInstance();
}

void InputTask_SetBlockGameInputs(bool block) {
    if (g_blockGameInputs != block) {
        g_blockGameInputs = block;
    }
}

bool shouldBlockGameInputs() {
    return g_blockGameInputs;
}

bool shouldBlockKeyDown() {
    return g_blockGameInputs;
}

static bool isGameWindowFocused() {
    HWND foreground = GetForegroundWindow();
    if (!foreground) return false;
    DWORD foregroundPid = 0;
    GetWindowThreadProcessId(foreground, &foregroundPid);
    return foregroundPid == GetCurrentProcessId();
}

void InputTask::processTaskLogic() {
    if (!running) return;
    if (!isGameWindowFocused()) return;

    checkKeyboardInputs();
    checkMouseInputs();
}

void InputTask::checkKeyboardInputs() {
    for (int keyCode = 0; keyCode < KEYBOARD_KEY_COUNT; ++keyCode) {
        if (keyCode == VK_LBUTTON || keyCode == VK_RBUTTON || keyCode == VK_MBUTTON ||
            keyCode == VK_XBUTTON1 || keyCode == VK_XBUTTON2) {
            continue;
        }

        const bool currentState = (GetAsyncKeyState(keyCode) & 0x8000) != 0;

        if (shouldBlockGameInputs() && currentState) {
            continue;
        }

        processKeyState(keyCode, currentState, InputType::KEYBOARD);
    }
}

void InputTask::checkMouseInputs() {
    constexpr int mouseButtons[] = {
        VK_LBUTTON,
        VK_RBUTTON,
        VK_MBUTTON,
        VK_XBUTTON1,
        VK_XBUTTON2
    };

    for (const int vkCode : mouseButtons) {
        const bool currentState = (GetAsyncKeyState(vkCode) & 0x8000) != 0;

        if (shouldBlockGameInputs() && currentState) {
            continue;
        }

        auto& previousStates = previousMouseStates;

        if (const bool previousState = previousStates[vkCode]; currentState != previousState) {
            previousStates[vkCode] = currentState;

            if (currentState) {
                bindManager->onInputPress(vkCode);
            } else {
                bindManager->onInputRelease(vkCode);
            }

            const auto inputEvent = new InputEvent(InputType::MOUSE, vkCode, currentState);
            eventBus->dispatch(*inputEvent);
            delete inputEvent;
        }
    }
}

void InputTask::processKeyState(const int keyCode, const bool currentState, const InputType inputType) {
    auto& previousStates = (inputType == InputType::KEYBOARD) ? previousKeyStates : previousMouseStates;

    if (const bool previousState = previousStates[keyCode]; currentState != previousState) {
        previousStates[keyCode] = currentState;

        if (currentState) {
            bindManager->onInputPress(keyCode);
        } else {
            bindManager->onInputRelease(keyCode);
        }

        const auto inputEvent = new InputEvent(inputType, keyCode, currentState);
        eventBus->dispatch(*inputEvent);
        delete inputEvent;
    }
}
