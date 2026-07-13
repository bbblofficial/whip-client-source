#pragma once

#include "hook/base/BaseHook.h"
#include <queue>
#include <mutex>

class GetSlotAtPositionHook final : public StaticBaseHook<GetSlotAtPositionHook> {
public:
    GetSlotAtPositionHook() : StaticBaseHook(HookPosition::PRE) {}

    ~GetSlotAtPositionHook() override = default;

    static std::string getHookName() {
        return "GuiContainer#getSlotAtPosition";
    }

    static bool spoofActive;
    static std::queue<int> spoofedSlots;
    static std::mutex slotsMutex;

protected:
    HookResult onPreExecute(JNIEnv* env, jobjectArray args) override;
};
