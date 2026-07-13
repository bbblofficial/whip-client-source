#pragma once

#include "../base/JniBaseTask.h"
#include "../../bus/EventBus.h"

class UpdateTask final : public JniBaseTask {
public:
    UpdateTask();
    ~UpdateTask() override = default;

protected:
    void onRunWithJni(JniScope& env) override;

private:
    EventBus* eventBus;
};
