#pragma once

#include "../ITask.h"
#include <Windows.h>
#include <atomic>

class BaseTask : public ITask {
public:
    explicit BaseTask(int delayMs = 0);
    ~BaseTask() override;

    void start() override;
    void stop() override;
    bool isRunning() const override;

    int getDelayMs() const;
    void setDelayMs(int delayMs);

protected:
    std::atomic<bool> running;
    std::atomic<bool> mightRun;
    int delayMs;
    HANDLE threadHandle;

    static DWORD WINAPI threadFunc(LPVOID param);
    virtual void processTaskLogic() = 0;
};
