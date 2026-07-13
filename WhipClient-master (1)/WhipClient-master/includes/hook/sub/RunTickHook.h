#pragma once

#include <event/sub/DispatchKeypressesEvent.h>

#include "bus/EventBus.h"
#include "event/sub/RenderNameEvent.h"
#include "hook/base/BaseHook.h"

class OnRunTick final : public StaticBaseHook<OnRunTick> {
public:
    OnRunTick() : StaticBaseHook(HookPosition::PRE) {}

    ~OnRunTick() override = default;

    static std::string getHookName() {
        return "Minecraft#runTick";
    }

protected:
    HookResult onPreExecute(JNIEnv* env, jobjectArray args) override {
        (void)args;
        if (!env) {
            return HookResult::Continue();
        }
        OnRunTickEvent event(env);
        EventBus::getInstance().dispatch(event);

        return HookResult::Continue();
    }
};
