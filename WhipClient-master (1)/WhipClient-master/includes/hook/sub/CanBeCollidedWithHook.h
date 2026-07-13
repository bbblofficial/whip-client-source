#pragma once

#include "bus/EventBus.h"
#include "event/sub/CanBeCollidedWithEvent.h"
#include "hook/base/BaseHook.h"

class CanBeCollidedWithHook final : public StaticBaseHook<CanBeCollidedWithHook> {
public:
    CanBeCollidedWithHook() : StaticBaseHook(HookPosition::PRE) {}

    ~CanBeCollidedWithHook() override = default;

    static std::string getHookName() {
        return "EntityLivingBase#canBeCollidedWith";
    }

protected:
    HookResult onPreExecute(JNIEnv* env, jobjectArray args) override {
        if (!env) {
            return HookResult::Continue();
        }

        jobject entityObj = getArg(env, args, 0);
        if (!entityObj) {
            return HookResult::Continue();
        }

        Entity entity(env, entityObj);
        entity.setDeleteRef(false);

        bool val = true;

        CanBeCollidedWithEvent event(env, entity, val);
        EventBus::getInstance().dispatch(event);

        val = event.getValue();

        return HookResult::ReturnBoolean(env, val);
    }
};
