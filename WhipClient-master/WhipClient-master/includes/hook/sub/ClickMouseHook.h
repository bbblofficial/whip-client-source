#pragma once

#include "bus/EventBus.h"
#include "event/sub/MouseLeftClickEvent.h"
#include "hook/base/BaseHook.h"
#include "module/impl/combat/autorefill/AutoRefillModule.h"

class ClickMouseHook final : public StaticBaseHook<ClickMouseHook> {
public:
    ClickMouseHook() : StaticBaseHook(HookPosition::PRE) {}

    ~ClickMouseHook() override = default;

    static std::string getHookName() {
        return "Minecraft#clickMouse";
    }

protected:
    HookResult onPreExecute(JNIEnv* env, jobjectArray args) override {
        (void)args;
        if (!env) {
            return HookResult::Continue();
        }

        if (AutoRefillModule::isRefilling_()) {
            return HookResult::Cancel(env);
        }

        const MouseLeftClickEvent event(env);
        EventBus::getInstance().dispatch(event);

        if (event.isCancelled()) {
            return HookResult::Cancel(env);
        }

        return HookResult::Continue();
    }
};
