#include "../../../includes/task/base/BaseTask.h"

#include "wrapper/minecraft/client/minecraft.h"

BaseTask::BaseTask(const int delayMs) : running(false), mightRun(false), delayMs(delayMs), threadHandle(nullptr) {
}

BaseTask::~BaseTask() {
    BaseTask::stop();
}

void BaseTask::start() {
    if (!running.load(std::memory_order_acquire)) {
        mightRun.store(true, std::memory_order_release);
        threadHandle = CreateThread(nullptr, 0, threadFunc, this, 0, nullptr);
        if (threadHandle != nullptr) {
            running.store(true, std::memory_order_release);
        }
    }
}

void BaseTask::stop() {
    if (running.load(std::memory_order_acquire)) {
        mightRun.store(false, std::memory_order_release);
        if (threadHandle != nullptr) {
            DWORD waitResult = WaitForSingleObject(threadHandle, 5000);

            if (waitResult == WAIT_TIMEOUT) {
                TerminateThread(threadHandle, 1);
            }

            CloseHandle(threadHandle);
            threadHandle = nullptr;
        }
        running.store(false, std::memory_order_release);
    }
}

bool BaseTask::isRunning() const {
    return running.load(std::memory_order_acquire);
}

int BaseTask::getDelayMs() const {
    return delayMs;
}

void BaseTask::setDelayMs(const int delayMs) {
    this->delayMs = delayMs;
}

DWORD WINAPI BaseTask::threadFunc(const LPVOID param) {
    const auto self = static_cast<BaseTask *>(param);

    while (self->mightRun.load(std::memory_order_acquire)) {
        self->processTaskLogic();
        if (self->delayMs > 0) {
            Sleep(self->delayMs);
        }
    }

    return 0;
}
