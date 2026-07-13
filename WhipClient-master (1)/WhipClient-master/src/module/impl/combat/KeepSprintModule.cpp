#include "../../../../includes/module/impl/combat/KeepSprintModule.h"
#include "wrapper/minecraft/client/minecraft.h"
#include "handler/ModuleHandler.h"
#include "module/impl/combat/AntiBotModule.h"

void KeepSprintModule::registerEvents() {
    SharedThreadBaseModule::registerEvents();

    subscribe<AttackEntityEvent>([this](const AttackEntityEvent& event) {
        this->onAttackEntity(event);
    }, EventPriority::HIGH, false);
}

void KeepSprintModule::onUpdate(JniScope& scope) {
}

void KeepSprintModule::onAttackEntity(const AttackEntityEvent& event) {
    if (!enable) {
        return;
    }

    if (chance < 100 && randomInt(0, 100) > chance) {
        return;
    }

    Minecraft theMc = Minecraft::getMinecraft(event.getEnv());
    if (theMc.isNull()) {
        return;
    }

    EntityClientPlayerMP thePlayer = theMc.thePlayer();
    if (thePlayer.isNull()) {
        return;
    }

    if (this->weaponsOnly && !thePlayer.hasWeaponInHand()) {
        return;
    }

    if (this->onlyOnBehind) {
        jobject targetObj = event.getTarget();
        if (!targetObj) return;

        EntityLivingBase target(event.getEnv(), targetObj);
        target.setDeleteRef(false);
        if (!isTargetBehind(thePlayer, target)) return;
    }

    const auto mutableEvent = const_cast<AttackEntityEvent*>(&event);

    if (mode == 0) {
        int hurtTime = thePlayer.hurtTime();

        if (hurtTime > 0 && hurtTime <= hurtTimeThreshold) {
            mutableEvent->setRetainedSpeed(0.6f);
        } else {
            mutableEvent->setRetainedSpeed(speed);
        }
    } else {
        mutableEvent->setRetainedSpeed(speed);
    }
}

bool KeepSprintModule::isTargetBehind(EntityClientPlayerMP& player, EntityLivingBase& target) {
    float playerRot = player.rotationYaw();
    float targetRot = target.rotationYaw();
    while (playerRot < 0)   playerRot += 360.0f;
    while (playerRot > 360) playerRot -= 360.0f;
    while (targetRot < 0)   targetRot += 360.0f;
    while (targetRot > 360) targetRot -= 360.0f;
    float diff = abs(playerRot - targetRot);
    if (diff > 180) diff = 360.0f - diff;
    return diff < 90.0f;
}

REGISTER_MODULE(KeepSprintModule, ModuleType::KEEP_SPRINT)
