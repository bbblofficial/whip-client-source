#include "../../includes/handler/TaskHandler.h"
#include "../../includes/task/impl/UpdateTask.h"
#include <algorithm>

void TaskHandler::addTask(std::unique_ptr<ITask> task) {
    if (task) {
        tasks.push_back(std::move(task));
    }
}

void TaskHandler::removeTask(ITask* task) {
    const auto it = std::ranges::find_if(tasks,
                                   [task](const std::unique_ptr<ITask>& t) {
                                       return t.get() == task;
                                   });

    if (it != tasks.end()) {
        if ((*it)->isRunning()) {
            (*it)->stop();
        }
        tasks.erase(it);
    }
}

void TaskHandler::startAllTasks() const {
    for (size_t i = 0; i < tasks.size(); ++i) {
        tasks[i]->start();
    }
}

void TaskHandler::stopAllTasks() const {
    for (size_t i = 0; i < tasks.size(); ++i) {
        tasks[i]->stop();
    }
}

size_t TaskHandler::getTaskCount() const {
    return tasks.size();
}

void TaskHandler::initializeJniSupport(JavaVM* jvm) {
    auto* jvmHolder = JvmHolder::Get();
    if (jvmHolder) {
        jvmHolder->setJavaVM(jvm);
    }
}

void TaskHandler::cleanupJniSupport() {
    auto* jvmHolder = JvmHolder::Get();
    if (jvmHolder) {
        jvmHolder->cleanup();
    }
}

TaskHandler& TaskHandler::getInstance() {
    static TaskHandler instance;
    return instance;
}
