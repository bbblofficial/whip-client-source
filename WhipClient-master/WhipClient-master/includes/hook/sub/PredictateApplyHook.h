#pragma once

#include "hook/base/BaseHook.h"
#include "bus/EventBus.h"
#include "event/sub/ApplyEvent.h"

class PredictateApplyHook final : public StaticBaseHook<PredictateApplyHook> {
public:
    PredictateApplyHook() : StaticBaseHook(HookPosition::PRE) {}

    ~PredictateApplyHook() override = default;

    static std::string getHookName() {
        return "EntityRenderer$1#apply";
    }

protected:
    HookResult onPreExecute(JNIEnv* env, jobjectArray args) override {
        if (!env) {
            return HookResult::Continue();
        }

        jobject entityObj = getArg(env, args, 1);
        if (!entityObj) {
            return HookResult::Continue();
        }

        auto entity = Entity(env, entityObj);
        if (entity.isNull()) {
            return HookResult::Continue();
        }

        ApplyEvent event(env, entity, entity.canBeCollidedWith());
        EventBus::getInstance().dispatch(event);

        return HookResult::ReturnBoolean(env, event.getValue());
    }
};
