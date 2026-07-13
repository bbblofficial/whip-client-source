#include "module/impl/movement/noslow/NoSlowModule.h"

#include "handler/ModuleHandler.h"
#include "module/impl/movement/noslow/mode/NoItemReleaseMode.h"
#include "module/impl/movement/noslow/mode/NoSlowMovementMode.h"
#include "wrapper/minecraft/client/Minecraft.h"

std::unique_ptr<NoSlowMode> NoSlowModule::createMode(const Mode mode) {
    if (mode == Mode::NO_ITEM_RELEASE) {
        return std::make_unique<NoItemReleaseMode>();
    }
    return std::make_unique<NoSlowMovementMode>();
}

void NoSlowModule::registerEvents() {
    subscribe<AddSendQueueEvent>([this](const AddSendQueueEvent& event) {
        onPacketSend(event);
    }, EventPriority::HIGH, false);

    subscribe<EntityLivingUpdateEvent>([this](const EntityLivingUpdateEvent& event) {
        OnEntityLivingUpdate(event);
    }, EventPriority::HIGH, false);
}

void NoSlowModule::onPacketSend(const AddSendQueueEvent& event) {
    if (!enable || mode != 0) return;

    JNIEnv* env = event.getEnv();
    if (env) {
        Minecraft mc = Minecraft::getMinecraft(env);
        if (!mc.isNull()) {
            auto player = mc.thePlayer();
            if (!player.isNull() && player.isSneaking()) return;
        }
    }

    if (onlySprinting) {
        if (env) {
            Minecraft mc = Minecraft::getMinecraft(env);
            if (!mc.isNull()) {
                auto player = mc.thePlayer();
                if (!player.isNull()) {

                    if (player.isSprinting()) {
                        wasSprinting_ = true;
                    } else if (!player.isUsingItem()) {
                        wasSprinting_ = false;
                    }
                    if (!wasSprinting_) return;
                }
            }
        }
    }

    this->noSlowMode->handlePacketSend(event, itemMode);
}

void NoSlowModule::OnEntityLivingUpdate(const EntityLivingUpdateEvent &event) {
    if (!enable || mode != 1) return;

    JNIEnv* env = event.getEnv();
    if (env) {
        Minecraft mc = Minecraft::getMinecraft(env);
        if (!mc.isNull()) {
            auto player = mc.thePlayer();
            if (!player.isNull() && player.isSneaking()) return;
        }
    }

    if (onlySprinting) {
        if (env) {
            Minecraft mc = Minecraft::getMinecraft(env);
            if (!mc.isNull()) {
                auto player = mc.thePlayer();
                if (!player.isNull()) {

                    if (player.isSprinting()) {
                        wasSprinting_ = true;
                    } else if (!player.isUsingItem()) {
                        wasSprinting_ = false;
                    }
                    if (!wasSprinting_) return;
                }
            }
        }
    }

    float powerMultiplier = 0.0f;

    if (itemMode[0] == true) {
        powerMultiplier = swordSlow / 100.0f;
    } else if (itemMode[1] == true) {
        powerMultiplier = bowSlow / 100.0f;
    } else if (itemMode[2] == true) {
        powerMultiplier = consumableSlow / 100.0f;
    } else if (itemMode[3] == true) {
        powerMultiplier = allSlow / 100.0f;
    }

    this->noSlowMode->handleEntityLivingUpdate(event, itemMode, powerMultiplier);
}

REGISTER_MODULE(NoSlowModule, ModuleType::NO_SLOW)
