#pragma once

#include "bus/EventBus.h"
#include "event/sub/EntityLivingUpdateEvent.h"
#include "event/sub/ItemUseEvent.h"
#include "hook/base/BaseHook.h"
#include "wrapper/minecraft/client/Minecraft.h"

class OnLivingUpdateHook final : public StaticBaseHook<OnLivingUpdateHook> {
public:
    OnLivingUpdateHook() : StaticBaseHook(HookPosition::BOTH) {}

    ~OnLivingUpdateHook() override = default;

    static std::string getHookName() {
        return "EntityLivingBase#onLivingUpdate";
    }

protected:
    HookResult onPreExecute(JNIEnv* env, jobjectArray args) override {
        (void)args;
        if (!env) {
            return HookResult::Continue();
        }

        const EntityLivingUpdateEvent event(env, 1.0f, 1.0f, false, false, false);
        EventBus::getInstance().dispatch(event);

        Minecraft mc = Minecraft::getMinecraft(env);
        if (mc.isNull()) {
            return HookResult::Continue();
        }

        EntityClientPlayerMP thePlayer = mc.thePlayer();
        if (thePlayer.isNull()) {
            return HookResult::Continue();
        }

        MouvementInput movementInput = thePlayer.getMovementInput();
        if (movementInput.isNull()) {
            return HookResult::Continue();
        }

        if (event.isStop()) {
            movementInput.setMoveForward(0);
            movementInput.setMoveStrafe(0);
            return HookResult::Continue();
        }

        if (event.getQuickAccel()) {
            constexpr float noSlowFactor = 5.0f;

            const float newMoveForward = thePlayer.getMovementInput().getMoveForward() * noSlowFactor;
            const float newMoveStrafe = thePlayer.getMovementInput().getMoveStrafe() * noSlowFactor;

            GameSettings gameSetting = mc.gameSettings();

            if (!gameSetting.keyBindUseItem().pressed()) {
                movementInput.setMoveForward(newMoveForward);
                movementInput.setMoveStrafe(newMoveStrafe);
            }
        }

        if (event.getMoveForward() != 0.0f || event.getMoveStrafe() != 0.0f) {

            if (!event.getshouldApplySlow()) {
                return HookResult::Continue();
            }

            if (movementInput.getMoveForward() != 0) {
                movementInput.setMoveForward(event.getMoveForward());
                if (event.getMoveForward() > 0) {
                    thePlayer.setSprinting(true);
                }
            }

            if (movementInput.getMoveStrafe() != 0) {
                movementInput.setMoveStrafe(event.getMoveStrafe());
            }
        }

        return HookResult::Continue();
    }

    void onPostExecute(JNIEnv* env, jobject result, jobjectArray args) override {
        (void)result;
        (void)args;
        if (!env) {
            return;
        }

        const ItemUseEvent event(env);
        EventBus::getInstance().dispatch(event);
    }
};
