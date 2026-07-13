#pragma once
#include "../../../DllMain.h"

#include "../../base/ListenedBaseModule.h"
#include "../../ModuleType.h"
#include "../../CategoryType.h"
#include "../../../util/JniScope.h"
#include "../../../handler/ModuleHandler.h"
#include "module/impl/setting/FriendsModule.h"
#include "util/ClientStrings.h"
#include "../setting/EnemiesModule.h"
#include "wrapper/minecraft/client/Minecraft.h"
#include "wrapper/minecraft/client/entity/EntityClientPlayerMP.h"
#include "wrapper/minecraft/entity/Entity.h"
#include "event/sub/CanBeCollidedWithEvent.h"

class PiercingModule final : public ListenedBaseModule<PiercingModule, ModuleType::PIERCING, CategoryType::COMBAT> {
    friend class BaseModule;

    bool weaponsOnly = true;
    bool targetEnemiesOnly = false;
    bool ThroughBlock = false;

    FriendsModule* friendsModule = nullptr;
    EnemiesModule* enemiesModule = nullptr;

    static inline bool hitThroughBlock_ = false;

protected:
    void registerEvents() override;

public:
    PiercingModule() = default;

    void onLoad() override;

    bool shouldTargetEntity(JNIEnv* env, Entity& entity) const;

    bool shouldBypassBlock(JNIEnv* env) const {
        if (!enable || !ThroughBlock) return false;

        if (weaponsOnly) {
            Minecraft mc = Minecraft::getMinecraft(env);
            if (mc.isNull()) return false;
            auto player = mc.thePlayer();
            if (player.isNull() || !player.hasWeaponInHand()) return false;
        }

        return true;
    }

    static void setHitThroughBlock(bool value) { hitThroughBlock_ = value; }
    static bool isHitThroughBlock() { return hitThroughBlock_; }

    static PiercingModule* getInstancePtr() {
        return &BaseModule::getInstance();
    }
};
