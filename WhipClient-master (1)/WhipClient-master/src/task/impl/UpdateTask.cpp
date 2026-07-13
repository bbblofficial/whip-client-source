#include "../../../includes/task/impl/UpdateTask.h"
#include "../../../includes/event/sub/UpdateEvent.h"
#include "../../../includes/util/JniScope.h"

UpdateTask::UpdateTask() : JniBaseTask(16) {
    eventBus = &EventBus::getInstance();
}

void UpdateTask::onRunWithJni(JniScope& env) {
    const auto updateEvent = UpdateEvent(env.getEnv());
    eventBus->dispatch(updateEvent);
}
