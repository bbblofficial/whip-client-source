#include "../../../../includes/module/impl/combat/PiercingModule.h"
#include "../../../../includes/handler/ModuleHandler.h"
#include "../../../../includes/event/sub/ApplyEvent.h"
#include "../../../../includes/event/sub/MouseLeftClickEvent.h"
#include "wrapper/minecraft/client/minecraft.h"
#include "wrapper/minecraft/util/MovingObjectPosition.h"
#include "wrapper/minecraft/util/Vec3.h"
#include "setting/SettingMacros.h"
#include <windows.h>
#include <cmath>
#include <algorithm>

void PiercingModule::onLoad() {
    ListenedBaseModule::onLoad();

    friendsModule = static_cast<FriendsModule*>(ModuleHandler::getInstance().getModule<ModuleType::FRIENDS>());
    enemiesModule = static_cast<EnemiesModule*>(ModuleHandler::getInstance().getModule<ModuleType::ENEMY>());

    BOOL_SETTING_CONDITIONAL(weaponsOnly, true);
    BOOL_SETTING_CONDITIONAL(targetEnemiesOnly, false);
    BOOL_SETTING_CONDITIONAL(ThroughBlock, false);
}

void PiercingModule::registerEvents() {
    subscribe<ApplyEvent>([this](const ApplyEvent& event) {
        auto* mutableEvent = const_cast<ApplyEvent*>(&event);
        Entity& entity = mutableEvent->getApply();
        if (!shouldTargetEntity(event.getEnv(), entity)) {
            mutableEvent->setValue(false);
        }
    }, EventPriority::HIGH, false);

    subscribe<MouseLeftClickEvent>([this](const MouseLeftClickEvent& event) {
        if (!enable || !ThroughBlock) return;

        JNIEnv* env = event.getEnv();
        Minecraft mc = Minecraft::getMinecraft(env);
        if (mc.isNull()) return;

        MovingObjectPosition currentMOP = mc.objectMouseOver();
        if (!currentMOP.isNull() && currentMOP.typeOfHit() == MovingObjectPosition::TypeOfHit::ENTITY)
            return;

        EntityClientPlayerMP player = mc.thePlayer();
        if (player.isNull()) return;
        if (weaponsOnly && !player.hasWeaponInHand()) return;

        WorldClient world = mc.theWorld();
        if (world.isNull()) return;

        double eyeX = player.posX();
        double eyeY = player.posY() + static_cast<double>(player.getEyeHeight());
        double eyeZ = player.posZ();

        float yaw   = player.rotationYaw();
        float pitch = player.rotationPitch();
        float f  = std::cos(-yaw * 0.017453292f - 3.14159265f);
        float f1 = std::sin(-yaw * 0.017453292f - 3.14159265f);
        float f2 = -std::cos(-pitch * 0.017453292f);
        float f3 = std::sin(-pitch * 0.017453292f);
        double lookX = static_cast<double>(f1 * f2);
        double lookY = static_cast<double>(f3);
        double lookZ = static_cast<double>(f  * f2);

        PlayerControllerMP pc = mc.playerController();
        double reach = 3.0;
        if (!pc.isNull() && pc.extendedReach()) reach = 6.0;

        ArrayList playerList = world.playerEntities();
        if (playerList.isNull()) return;

        int count = playerList.size();
        double closestDist = reach;
        jobject closestEntity = nullptr;

        for (int i = 0; i < count; i++) {
            JavaObject jobj = playerList.get(i);
            if (jobj.isNull()) continue;

            Entity entity(env, jobj.getObj());
            if (env->IsSameObject(entity.getObj(), player.getObj())) continue;
            if (entity.isDead()) continue;
            if (!shouldTargetEntity(env, entity)) continue;
            if (!entity.canBeCollidedWith()) continue;

            AxisAlignedBB bb = entity.getBoundingBox();
            if (bb.isNull()) continue;

            float border = entity.getCollisionBorderSize();
            double minX = bb.getMinX() - border;
            double minY = bb.getMinY() - border;
            double minZ = bb.getMinZ() - border;
            double maxX = bb.getMaxX() + border;
            double maxY = bb.getMaxY() + border;
            double maxZ = bb.getMaxZ() + border;

            if (eyeX >= minX && eyeX <= maxX &&
                eyeY >= minY && eyeY <= maxY &&
                eyeZ >= minZ && eyeZ <= maxZ) {
                closestDist = 0.0;
                if (closestEntity) env->DeleteLocalRef(closestEntity);
                closestEntity = env->NewLocalRef(jobj.getObj());
                continue;
            }

            double tmin = -1e30, tmax = 1e30;

            if (std::abs(lookX) > 1e-10) {
                double t1 = (minX - eyeX) / lookX;
                double t2 = (maxX - eyeX) / lookX;
                if (t1 > t2) std::swap(t1, t2);
                tmin = std::max(tmin, t1);
                tmax = std::min(tmax, t2);
            } else if (eyeX < minX || eyeX > maxX) continue;

            if (std::abs(lookY) > 1e-10) {
                double t1 = (minY - eyeY) / lookY;
                double t2 = (maxY - eyeY) / lookY;
                if (t1 > t2) std::swap(t1, t2);
                tmin = std::max(tmin, t1);
                tmax = std::min(tmax, t2);
            } else if (eyeY < minY || eyeY > maxY) continue;

            if (std::abs(lookZ) > 1e-10) {
                double t1 = (minZ - eyeZ) / lookZ;
                double t2 = (maxZ - eyeZ) / lookZ;
                if (t1 > t2) std::swap(t1, t2);
                tmin = std::max(tmin, t1);
                tmax = std::min(tmax, t2);
            } else if (eyeZ < minZ || eyeZ > maxZ) continue;

            if (tmax < 0 || tmin > tmax) continue;

            double hitDist = tmin >= 0.0 ? tmin : tmax;
            if (hitDist < closestDist) {
                closestDist = hitDist;
                if (closestEntity) env->DeleteLocalRef(closestEntity);
                closestEntity = env->NewLocalRef(jobj.getObj());
            }
        }

        if (!closestEntity) return;

        Vec3MC hitVec = Vec3MC::createVec3(env,
            eyeX + lookX * closestDist,
            eyeY + lookY * closestDist,
            eyeZ + lookZ * closestDist);

        Entity hitEntity(env, closestEntity);
        MovingObjectPosition entityMOP = MovingObjectPosition::createFromEntity(env, hitEntity, hitVec);

        if (!entityMOP.isNull()) {
            mc.setObjectMouseOver(entityMOP);
            mc.setPointedEntity(hitEntity);
        }

        env->DeleteLocalRef(closestEntity);
    }, EventPriority::HIGH + 10, false);

    subscribe<CanBeCollidedWithEvent>([this](const CanBeCollidedWithEvent& event) {
        auto* mutableEvent = const_cast<CanBeCollidedWithEvent*>(&event);
        Entity& entity = mutableEvent->getApply();
        if (!shouldTargetEntity(event.getEnv(), entity)) {
            mutableEvent->setValue(false);
        }
    }, EventPriority::HIGH, false);
}

bool PiercingModule::shouldTargetEntity(JNIEnv* env, Entity& entity) const {
    if (!enable) return true;
    if (!entity.getObj()) return true;

    if (weaponsOnly) {
        Minecraft mc = Minecraft::getMinecraft(env);
        if (mc.isNull()) return true;
        EntityClientPlayerMP thePlayer = mc.thePlayer();
        if (thePlayer.isNull() || !thePlayer.hasWeaponInHand()) return true;
    }

    if (friendsModule && friendsModule->enable && friendsModule->isFriend(entity))
        return false;

    if (targetEnemiesOnly && enemiesModule && enemiesModule->enable) {
        JavaUUID entityUUID = entity.getEntityUniqueID();
        if (!entityUUID.isNull()) {
            UUIDData entityUUIDData = entityUUID.toUUIDData();
            for (const auto& enemyUUID : enemiesModule->getEnemyUUIDEntities()) {
                if (entityUUIDData.equals(enemyUUID))
                    return true;
            }
            return false;
        }
    }

    return true;
}

REGISTER_MODULE(PiercingModule, ModuleType::PIERCING)
