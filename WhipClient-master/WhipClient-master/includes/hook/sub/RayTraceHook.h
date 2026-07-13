#pragma once

#include "hook/base/BaseHook.h"

#include "wrapper/minecraft/client/Minecraft.h"
#include "wrapper/minecraft/entity/Entity.h"
#include "wrapper/minecraft/entity/EntityLivingBase.h"
#include "wrapper/minecraft/entity/player/EntityPlayer.h"
#include "wrapper/minecraft/world/World.h"
#include "wrapper/minecraft/entity/axisalignedbb/AxisAlignedBB.h"
#include "wrapper/minecraft/util/Vec3.h"
#include "wrapper/minecraft/util/MovingObjectPosition.h"
#include "wrapper/minecraft/client/multiplayer/PlayerControllerMP.h"
#include "wrapper/java/util/ArrayList.h"
#include "wrapper/minecraft/client/renderer/EntityRenderer.h"
#include "event/sub/ApplyEvent.h"
#include "event/sub/GetMouseOverEvent.h"
#include "bus/EventBus.h"
#include "handler/ModuleHandler.h"
#include "util/Debug.h"
#include <windows.h>
#include <cmath>

class GetMouseOverHook final : public StaticBaseHook<GetMouseOverHook> {
public:
    GetMouseOverHook() : StaticBaseHook(HookPosition::PRE) {}

    ~GetMouseOverHook() override = default;

    static std::string getHookName() {
        return "EntityRenderer#getMouseOver";
    }

protected:
    HookResult onPreExecute(JNIEnv* env, jobjectArray args) override {

    {
        IModule* piercing  = ModuleHandler::getInstance().getModule<ModuleType::PIERCING>();
        IModule* aimAssist = ModuleHandler::getInstance().getModule<ModuleType::AIM_ASSIST>();
        const bool needsHook = (piercing  && piercing->isEnabled())
                             || (aimAssist && aimAssist->isEnabled());
        if (!needsHook) return HookResult::Continue();
    }

    float partialTicks = getFloatArg(env, args, 1);
    bool is18 = MinecraftSession::getInstance().version == MinecraftVersion::V1_8_9;

    if (!env) return HookResult::Continue();

    Minecraft mc = Minecraft::getMinecraft(env);
    if (mc.isNull()) return HookResult::Continue();

    Entity renderViewEntity = mc.getRenderViewEntity();
    if (renderViewEntity.isNull()) return HookResult::Continue();

    WorldClient world = mc.theWorld();
    if (world.isNull()) return HookResult::Continue();

    PlayerControllerMP controller = mc.playerController();
    double reach = controller.isNull() ? 3.0 : static_cast<double>(controller.getBlockReachDistance());

    double ex, ey, ez, lx, ly, lz;

    if (is18) {
        Vec3MC eyePos = renderViewEntity.getPositionEyes(partialTicks);
        if (eyePos.isNull()) return HookResult::Continue();
        ex = eyePos.getX();
        ey = eyePos.getY();
        ez = eyePos.getZ();
        Vec3MC lookVec = renderViewEntity.getLook(partialTicks);
        if (lookVec.isNull()) return HookResult::Continue();
        lx = lookVec.getX();
        ly = lookVec.getY();
        lz = lookVec.getZ();
    } else {
        ex = renderViewEntity.posX();
        ey = renderViewEntity.posY() + static_cast<double>(renderViewEntity.getEyeHeight());
        ez = renderViewEntity.posZ();
        EntityLivingBase& livingBase = renderViewEntity.safeConvertTo<EntityLivingBase>();
        Vec3MC lookVec = livingBase.GetLook(partialTicks);
        if (lookVec.isNull()) return HookResult::Continue();
        lx = lookVec.getX();
        ly = lookVec.getY();
        lz = lookVec.getZ();
    }

    Vec3MC eyeVec = Vec3MC::createVec3(env, ex, ey, ez);
    if (eyeVec.isNull()) return HookResult::Continue();

    Vec3MC endVec = Vec3MC::createVec3(env, ex + lx * reach, ey + ly * reach, ez + lz * reach);
    if (endVec.isNull()) return HookResult::Continue();

    MovingObjectPosition blockHit = world.rayTraceBlocks(eyeVec, endVec);
    double blockDist = reach;

    if (!blockHit.isNull()) {
        bool shouldComputeDist = is18 ? (blockHit.typeOfHit() == MovingObjectPosition::TypeOfHit::BLOCK) : true;
        if (shouldComputeDist) {
            Vec3MC blockHitVec = blockHit.hitVec();
            if (!blockHitVec.isNull()) {
                double hx = blockHitVec.getX(), hy = blockHitVec.getY(), hz = blockHitVec.getZ();
                blockDist = std::sqrt((hx-ex)*(hx-ex) + (hy-ey)*(hy-ey) + (hz-ez)*(hz-ez));
            }
        }
    }

    mc.setObjectMouseOver(blockHit);

    jobject playerBBRef;
    if (is18) {
        AxisAlignedBB temp = renderViewEntity.getEntityBoundingBox();
        if (temp.isNull()) return HookResult::Cancel(env);
        temp.setDeleteRef(false);
        playerBBRef = temp.getObj();
    } else {
        AxisAlignedBB temp = renderViewEntity.getBoundingBox();
        if (temp.isNull()) return HookResult::Cancel(env);
        temp.setDeleteRef(false);
        playerBBRef = temp.getObj();
    }
    AxisAlignedBB playerBB(env, playerBBRef);

    AxisAlignedBB addCoordBB = playerBB.addCoord(lx * reach, ly * reach, lz * reach);
    if (addCoordBB.isNull()) return HookResult::Cancel(env);
    AxisAlignedBB searchBB = addCoordBB.expand(1.0, 1.0, 1.0);
    if (searchBB.isNull()) return HookResult::Cancel(env);

    ArrayList entities = world.getEntitiesWithinAABBExcludingEntity(renderViewEntity, searchBB);
    if (entities.isNull()) return HookResult::Cancel(env);

    Vec3MC startVec = Vec3MC::createVec3(env, ex, ey, ez);
    Vec3MC rayEnd = Vec3MC::createVec3(env, ex + lx * reach, ey + ly * reach, ez + lz * reach);
    if (startVec.isNull() || rayEnd.isNull()) return HookResult::Cancel(env);

    jobject bestEntity = nullptr;
    jobject bestHitVecObj = nullptr;

    GetMouseOverEvent mouseOverEvent(env, blockDist, 3.0);
    EventBus::getInstance().dispatch(mouseOverEvent);
    double bestDist = mouseOverEvent.getEffectiveReach();
    bool trueBlock = mouseOverEvent.shouldBypassBlock();

    int count = entities.size();
    for (int i = 0; i < count; i++) {
        if (env->PushLocalFrame(16) < 0) break;

        JavaObject entityObj = entities.get(i);
        if (entityObj.isNull()) { env->PopLocalFrame(nullptr); continue; }

        Entity entity(env, entityObj.getObj());
        if (entity.isNull() || !entity.canBeCollidedWith()) { env->PopLocalFrame(nullptr); continue; }

        ApplyEvent applyEvent(env, entity, true);
        EventBus::getInstance().dispatch(applyEvent);
        if (!applyEvent.getValue()) { env->PopLocalFrame(nullptr); continue; }

        float borderSize = entity.getCollisionBorderSize();
        jobject entityBBRef;
        if (is18) {
            AxisAlignedBB temp = entity.getEntityBoundingBox();
            if (temp.isNull()) { env->PopLocalFrame(nullptr); continue; }
            temp.setDeleteRef(false);
            entityBBRef = temp.getObj();
        } else {
            AxisAlignedBB temp = entity.getBoundingBox();
            if (temp.isNull()) { env->PopLocalFrame(nullptr); continue; }
            temp.setDeleteRef(false);
            entityBBRef = temp.getObj();
        }
        AxisAlignedBB entityBB(env, entityBBRef);

        AxisAlignedBB expandedBB = entityBB.expand(
            static_cast<double>(borderSize),
            static_cast<double>(borderSize),
            static_cast<double>(borderSize)
        );
        if (expandedBB.isNull()) { env->PopLocalFrame(nullptr); continue; }

        MovingObjectPosition intercept = expandedBB.calculateIntercept(startVec, rayEnd);
        if (intercept.isNull()) {
            if (expandedBB.isVecInside(startVec)) {
                if (0.0 < bestDist || bestDist == 0.0) {
                    if (bestEntity) env->DeleteGlobalRef(bestEntity);
                    if (bestHitVecObj) env->DeleteGlobalRef(bestHitVecObj);
                    bestEntity = env->NewGlobalRef(entityObj.getObj());
                    bestDist = 0.0;
                    double cx = (entityBB.getMinX() + entityBB.getMaxX()) / 2.0;
                    double cy = (entityBB.getMinY() + entityBB.getMaxY()) / 2.0;
                    double cz = (entityBB.getMinZ() + entityBB.getMaxZ()) / 2.0;
                    Vec3MC centerVec = Vec3MC::createVec3(env, cx, cy, cz);
                    bestHitVecObj = centerVec.isNull() ? nullptr : env->NewGlobalRef(centerVec.getObj());
                }
            }
            env->PopLocalFrame(nullptr);
            continue;
        }

        Vec3MC hitVec = intercept.hitVec();
        if (hitVec.isNull()) { env->PopLocalFrame(nullptr); continue; }

        double hx = hitVec.getX(), hy = hitVec.getY(), hz = hitVec.getZ();
        double dist = std::sqrt((hx-ex)*(hx-ex) + (hy-ey)*(hy-ey) + (hz-ez)*(hz-ez));

        if (dist < bestDist || bestDist == 0.0) {
            if (bestEntity) env->DeleteGlobalRef(bestEntity);
            if (bestHitVecObj) env->DeleteGlobalRef(bestHitVecObj);
            bestEntity = env->NewGlobalRef(entityObj.getObj());
            bestHitVecObj = env->NewGlobalRef(hitVec.getObj());
            bestDist = dist;
        }
        env->PopLocalFrame(nullptr);
    }

    mouseOverEvent.setHitThroughBlock(trueBlock && bestEntity);

    if (bestEntity) {
        Entity target(env, bestEntity);
        target.setDeleteRef(false);

        if (bestHitVecObj) {
            Vec3MC bestHitVec(env, bestHitVecObj);
            bestHitVec.setDeleteRef(false);
            MovingObjectPosition entityHit = MovingObjectPosition::createFromEntity(env, target, bestHitVec);
            if (!entityHit.isNull()) {
                mc.setObjectMouseOver(entityHit);
            }
        }

        mc.setPointedEntity(target);

        jobject entityRendererObj = getArg(env, args, 0);
        if (entityRendererObj) {
            EntityRenderer entityRenderer(env, entityRendererObj);
            entityRenderer.setDeleteRef(false);
            entityRenderer.setPointedEntity(target);
        }

        env->DeleteGlobalRef(bestEntity);
        if (bestHitVecObj) env->DeleteGlobalRef(bestHitVecObj);
    } else {
        mc.SetPointedEntity();
        if (blockHit.isNull()) {
            Vec3MC missVec = Vec3MC::createVec3(env, ex, ey, ez);
            if (!missVec.isNull()) {
                MovingObjectPosition missHit = MovingObjectPosition::createFromEntity(env, renderViewEntity, missVec);
                if (!missHit.isNull()) {
                    missHit.setTypeOfHit(MovingObjectPosition::TypeOfHit::MISS);
                    mc.setObjectMouseOver(missHit);
                }
            }
        }
    }

    return HookResult::Cancel(env);
}

};
