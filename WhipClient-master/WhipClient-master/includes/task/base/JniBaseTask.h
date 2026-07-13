#pragma once

#include "../../includes/util/Debug.h"
#include "BaseTask.h"
#include "util/JniScope.h"
#include <atomic>
#include <Windows.h>

class JniBaseTask : public BaseTask {
public:
    explicit JniBaseTask(const int delayMs = 0)
        : BaseTask(delayMs) {
    }

    ~JniBaseTask() override {
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

    void start() override {
        if (!running.load(std::memory_order_acquire)) {
            mightRun.store(true, std::memory_order_release);
            threadHandle = CreateThread(nullptr, 0, jniThreadFunc, this, 0, nullptr);
            if (threadHandle != nullptr) {
                running.store(true, std::memory_order_release);
            }
        }
    }

    void stop() override {
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

protected:
    virtual void onRunWithJni(JniScope& scope) = 0;

    void processTaskLogic() override {

    }

private:
    static DWORD WINAPI jniThreadFunc(LPVOID param) {
        auto* self = static_cast<JniBaseTask*>(param);

        JniScope jniScope;

        while (self->mightRun.load(std::memory_order_acquire)) {
            if (jniScope.isValid()) {
                JNIEnv* env = jniScope.getEnv();
                if (env && env->PushLocalFrame(64) == 0) {
                    self->onRunWithJni(jniScope);
                    env->PopLocalFrame(nullptr);
                } else {
                    self->onRunWithJni(jniScope);
                }
            }

            if (self->delayMs > 0) {
                Sleep(self->delayMs);
            }
        }

        return 0;
    }
};

#define JNI_TASK_CLASS(className) \
class className : public JniBaseTask { \
public: \
explicit className() : JniBaseTask(#className) {} \
protected: \
void onRunWithJni(JniScope& scope) override; \
};
