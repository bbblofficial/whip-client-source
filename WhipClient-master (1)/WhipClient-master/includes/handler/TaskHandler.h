#pragma once

#include "../task/ITask.h"
#include "util/JniScope.h"
#include <vector>
#include <memory>
#include <jni.h>

class TaskHandler {
public:
    TaskHandler() = default;

    void addTask(std::unique_ptr<ITask> task);
    void removeTask(ITask* task);

    void startAllTasks() const;
    void stopAllTasks() const;

    size_t getTaskCount() const;

    template<typename T>
    T* getTask() const {
        for (const auto& task : tasks) {
            if (auto* specificTask = static_cast<T*>(task.get())) {
                return specificTask;
            }
        }
        return nullptr;
    }

    void initializeJniSupport(JavaVM* jvm);
    void cleanupJniSupport();

    ~TaskHandler() = default;
    TaskHandler(const TaskHandler&) = delete;
    TaskHandler& operator=(const TaskHandler&) = delete;

    static TaskHandler& getInstance();

private:

    std::vector<std::unique_ptr<ITask>> tasks;
};
