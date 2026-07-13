#include "../../../../includes/module/impl/combat/VelocityModule.h"

#include "event/sub/ChannelReadEvent.h"
#include "wrapper/minecraft/network/play/server/s12packetentityvelocity.h"
#include "wrapper/minecraft/network/play/server/S19PacketEntityStatus.h"
#include "wrapper/minecraft/item/ItemStack.h"
#include "wrapper/minecraft/entity/EntityLivingBase.h"
#include <windows.h>
#include <cmath>
#include <chrono>

void VelocityModule::onChannelRead(const ChannelReadEvent& event) {
    if (!this->enable) {
        return;
    }

    const jclass clazz = Mappings::getInstance().getClass("S12PacketEntityVelocity");
    if (!clazz || !event.getEnv()->IsInstanceOf(event.getPacketObject(), clazz)) {
        return;
    }

    S12PacketEntityVelocity velocityPacket(event.getEnv(), event.getPacketObject());
    velocityPacket.setDeleteRef(false);
    if (velocityPacket.isNull()) {
        return;
    }

    Minecraft theMc = Minecraft::getMinecraft(event.getEnv());
    if (theMc.isNull()) {
        return;
    }

    EntityClientPlayerMP entity = theMc.thePlayer();
    if (entity.isNull()) { return; }
    if (entity.entityId() != velocityPacket.pVelocity_entityId()) { return; }

    if (weaponsOnly) {
        ItemStack heldItem = entity.getHeldItem();
        if (heldItem.isNull() || !heldItem.isWeapon()) {
            return;
        }
    }

    if (onlyLookingAtPlayer) {
        Entity pointed = theMc.pointedEntity();
        if (pointed.isNull()) {
            return;
        }
    }

    if (onlyMousePressed && !(GetAsyncKeyState(VK_LBUTTON) & 0x8000)) {
        return;
    }

    bool isMovingForward = isPlayerMovingForward(event.getEnv());
    bool isSprinting = entity.isSprinting();

    if (mode == 2) {
        if (!entity.onGround()) {
            return;
        }

        if (this->chance < 100) {
            int randomValue = randomInt(0, 100);
            if (randomValue > this->chance) {
                return;
            }
        }

        if (onlyWhenMovingForward && !isMovingForward) {
            return;
        }

        pendingJumpDelay = true;
        jumpDelayStart_ = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();

        return;
    }

    if (onlyWhenMovingForward && !isMovingForward) {
        return;
    }

    if (this->chance < 100) {
        int randomValue = randomInt(0, 100);
        if (randomValue > this->chance) {
            return;
        }
    }

    if (this->onGroundOnly && !entity.onGround()) {
        return;
    }

    const auto motionX = velocityPacket.pVelocity_motionX();
    const auto motionY = velocityPacket.pVelocity_motionY();
    const auto motionZ = velocityPacket.pVelocity_motionZ();

    if (mode == 3) {
        bool shouldReduce = isMovingForward && isSprinting;
        if (agcBypass && entity.onGround()) {
            int ht = entity.hurtTime();
            shouldReduce = shouldReduce && (ht >= 1 && ht <= 4);
        }
        if (shouldReduce) {
            const float mult = 1.0f - (this->reduceH / 100.0f);
            velocityPacket.setMotionX(static_cast<int>(motionX * mult));
            velocityPacket.setMotionZ(static_cast<int>(motionZ * mult));
        }
        return;
    }

    int newX, newY, newZ;

    if (mode == 1) {
        const float revMult = this->reverseStrength / 100.0f;
        newX = -(int)(motionX * revMult);
        newY = motionY;
        newZ = -(int)(motionZ * revMult);
    } else {
        const float multiplierX = this->horizontal / 100.0f;
        const float multiplierY = this->vertical / 100.0f;
        const float multiplierZ = this->horizontal / 100.0f;
        newX = (int)(motionX * multiplierX);
        newY = (int)(motionY * multiplierY);
        newZ = (int)(motionZ * multiplierZ);
    }

    velocityPacket.setMotionX(newX);
    velocityPacket.setMotionY(newY);
    velocityPacket.setMotionZ(newZ);
}

bool VelocityModule::isPlayerMovingForward(JNIEnv* env) {
    Minecraft theMc = Minecraft::getMinecraft(env);
    if (theMc.isNull()) {
        return false;
    }

    EntityPlayer thePlayer = theMc.thePlayer();
    if (thePlayer.isNull()) {
        return false;
    }

    GameSettings gameSettings = theMc.gameSettings();
    if (gameSettings.isNull()) {
        return false;
    }

    KeyBinding forwardKey = gameSettings.keyBindForward();
    if (forwardKey.isNull()) {
        return false;
    }

    return forwardKey.pressed();
}

bool VelocityModule::isPlayerSprinting(JNIEnv* env) {
    Minecraft theMc = Minecraft::getMinecraft(env);
    if (theMc.isNull()) {
        return false;
    }

    EntityPlayer thePlayer = theMc.thePlayer();
    if (thePlayer.isNull()) {
        return false;
    }

    const bool result = thePlayer.isSprinting();
    return result;
}

int VelocityModule::inverse(int x) {
    return -x;
}

void VelocityModule::onTick(const OnRunTickEvent& event) {
    if (!this->enable) {
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

    if (mode == 2) {

        if (pendingJumpDelay && !pendingJumpReset) {
            long long now = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count();
            if (now - jumpDelayStart_ >= jumpDelayMs) {
                GameSettings gameSettings = theMc.gameSettings();
                if (!gameSettings.isNull()) {
                    KeyBinding keyBindJump = gameSettings.keyBindJump();
                    if (!keyBindJump.isNull()) {
                        keyBindJump.pressed(true);
                        pendingJumpReset = true;
                        pendingJumpDelay = false;
                    }
                }
            }
        }

        if (pendingJumpReset) {
            GameSettings gameSettings = theMc.gameSettings();
            if (!gameSettings.isNull()) {
                KeyBinding keyBindJump = gameSettings.keyBindJump();
                if (!keyBindJump.isNull()) {
                    keyBindJump.pressed(false);
                    pendingJumpReset = false;
                }
            }
        }
    }
}

REGISTER_MODULE(VelocityModule, ModuleType::VELOCITY);
