#pragma once
#include "bus/EventBus.h"
#include "event/sub/MouseBlockClickEvent.h"
#include "hook/base/BaseHook.h"
#include "wrapper/minecraft/client/Minecraft.h"

class ClickBlockMouseHook final : public StaticBaseHook<ClickBlockMouseHook> {
public:
    ClickBlockMouseHook() : StaticBaseHook(HookPosition::PRE) {}

    ~ClickBlockMouseHook() override = default;

    static std::string getHookName() {
        return "PlayerControllerMP#clickBlock";
    }

protected:
    HookResult onPreExecute(JNIEnv* env, jobjectArray args) override {
        if (!env) {
            return HookResult::Continue();
        }

        Minecraft minecraft = Minecraft::getMinecraft(env);
        if (!minecraft.isNull()) {
            MovingObjectPosition mouseOver = minecraft.objectMouseOver();

            if (!mouseOver.isNull() && mouseOver.typeOfHit() == MovingObjectPosition::TypeOfHit::BLOCK) {

                MovingObjectPosition::position blockPos = mouseOver.getPosition();
                MouseBlockClickEvent eventWithPos(env, blockPos.x, blockPos.y, blockPos.z, true);
                EventBus::getInstance().dispatch(eventWithPos);

                if (eventWithPos.isCancelled()) {
                    return HookResult::ReturnBoolean(env, false);
                }

                return HookResult::Continue();
            }
        }

        MouseBlockClickEvent event(env);
        EventBus::getInstance().dispatch(event);
        if (event.isCancelled()) {
            return HookResult::ReturnBoolean(env, false);
        }

        return HookResult::Continue();
    }
};
