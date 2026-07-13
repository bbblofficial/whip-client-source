#pragma once

#include "ListenedBaseModule.h"
#include "util/JniScope.h"
#include <Windows.h>
#include <mmsystem.h>
#include <atomic>

#include "gui/Gui.h"

template<typename Derived, ModuleType Type, CategoryType Category>
class DedicatedThreadBaseModule : public ListenedBaseModule<Derived, Type, Category> {
public:
    explicit DedicatedThreadBaseModule(const BindType bindType = BindType::TOGGLE,
                                     const int keyCode = 0, const int delayMs = 1)
        : ListenedBaseModule<Derived, Type, Category>(bindType, keyCode),
          delayMs(delayMs), mightRun(false), isRunning(false), threadHandle(nullptr) {
    }

    ~DedicatedThreadBaseModule() override {
        stopDedicatedThread();
    }

    void onLoad() override {
        ListenedBaseModule<Derived, Type, Category>::onLoad();
    }

    void onEnable() override {
        ListenedBaseModule<Derived, Type, Category>::onEnable();
        startDedicatedThread();
    }

    void onDisable() override {
        stopDedicatedThread();
        ListenedBaseModule<Derived, Type, Category>::onDisable();
    }

    int getDelayMs() const { return delayMs; }
    void setDelayMs(const int newDelayMs) { delayMs = newDelayMs; }

protected:
    virtual void onUpdate(JniScope& scope) = 0;
    virtual bool shouldRunWithGuiOpen() const { return false; }
    virtual int getThreadPriority() const { return THREAD_PRIORITY_NORMAL; }
    virtual bool wantsHighResolutionTimer() const { return delayMs > 0 && delayMs <= 10; }

    void stopDedicatedThread() {
        if (isRunning) {
            mightRun=false;
            if (threadHandle != nullptr) {
                DWORD waitResult = WaitForSingleObject(threadHandle, 5000);

                if (waitResult == WAIT_TIMEOUT) {
                    TerminateThread(threadHandle, 1);
                }

                CloseHandle(threadHandle);
                threadHandle = nullptr;
            }
            isRunning=false;
        }
    }

    void registerEvents() override {}
private:
    int delayMs = 16;
    std::atomic<bool> mightRun;
    std::atomic<bool> isRunning;
    HANDLE threadHandle;

    static DWORD WINAPI threadFunc(LPVOID param) {
        DedicatedThreadBaseModule* self = static_cast<DedicatedThreadBaseModule *>(param);
        self->isRunning=true;

        const bool hires = self->wantsHighResolutionTimer();
        if (hires) timeBeginPeriod(1);

        JniScope jniScope;
        while (self->mightRun) {
            bool guiOpen = Gui::getInstance().isOpen();
            bool shouldRun = self->enable && (!guiOpen || self->shouldRunWithGuiOpen());

            if (shouldRun) {
                if (!jniScope.isValid()) {
                    continue;
                }

                JNIEnv* env = jniScope.getEnv();
                if (env && env->PushLocalFrame(64) == 0) {
                    self->onUpdate(jniScope);
                    env->PopLocalFrame(nullptr);
                } else {
                    self->onUpdate(jniScope);
                }
            }

            if (self->delayMs > 0) {
                Sleep(self->delayMs);
            }
        }

        if (hires) timeEndPeriod(1);

        self->isRunning=false;
        return 0;
    }

    void startDedicatedThread() {
        if (!isRunning) {
            mightRun=true;
            threadHandle = CreateThread(nullptr, 0, threadFunc, this, 0, nullptr);
            if (threadHandle != nullptr) {
                const int prio = getThreadPriority();
                if (prio != THREAD_PRIORITY_NORMAL) {
                    SetThreadPriority(threadHandle, prio);
                }
            }
        }
    }
};
