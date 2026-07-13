#pragma once

#include <map>

#include "event/sub/InputEvent.h"
#include "bus/EventBus.h"
#include "manager/BindManager.h"
#include "task/base/BaseTask.h"

class InputTask : public BaseTask {
private:
    EventBus* eventBus;
    BindManager* bindManager;

    std::map<int, bool> previousKeyStates;
    std::map<int, bool> previousMouseStates;

    void checkKeyboardInputs();
    void checkMouseInputs();
    void processKeyState(int keyCode, bool currentState, InputType inputType);

protected:
    void processTaskLogic() override;

public:
    InputTask();
    ~InputTask() override = default;
};

void InputTask_SetBlockGameInputs(bool block);
bool shouldBlockGameInputs();
bool shouldBlockKeyDown();
