#include "../../../../includes/module/impl/combat/AutoRodModule.h"

#include "wrapper/minecraft/client/Minecraft.h"
#include "wrapper/minecraft/client/multiplayer/WorldClient.h"
#include "wrapper/minecraft/client/entity/EntityClientPlayerMP.h"
#include "wrapper/minecraft/entity/Entity.h"
#include "wrapper/minecraft/entity/EntityLivingBase.h"
#include "wrapper/minecraft/entity/player/EntityPlayer.h"
#include "wrapper/minecraft/entity/player/inventoryplayer.h"
#include "wrapper/minecraft/entity/Render/RenderManager.h"
#include "wrapper/minecraft/client/activerenderinfo/ActiveRenderInfo2.h"
#include "wrapper/minecraft/item/ItemStack.h"
#include "wrapper/minecraft/network/play/client/C05PacketPlayerLook.h"
#include "wrapper/CVarsUpdater.h"
#include "handler/MappingHandler.h"
#include "handler/ModuleHandler.h"
#include "bus/EventBus.h"
#include "util/RenderUtils.h"
#include "util/mathutils.h"
#include "util/ModuleUtils.h"

#include <GL/gl.h>
#include <cmath>

void AutoRodModule::onLoad() {
    Render3dBaseModule::onLoad();

    FLOAT_SLIDER(fov,                  180.0f, 20.0f, 180.0f);
    FLOAT_SLIDER(maxTargetLookFovDiff,  90.0f,  0.0f, 180.0f);
    FLOAT_SLIDER(maxRodRange,           10.0f,  0.0f,  20.0f);
    INT_SLIDER(throwCooldownMs,          250,    50,   2000);

    BOOL_SETTING_CONDITIONAL(ignoreEatingTargets,  true);
    BOOL_SETTING_CONDITIONAL(moveFix,              true);
    BOOL_SETTING_CONDITIONAL(disableWhileScaffold, false);
    BOOL_SETTING_CONDITIONAL(onlyRodIfNotInReach,  true);
    FLOAT_SLIDER_OPTIONAL(meleeReach, 3.0f, 2.0f, 6.0f, SETTING_VISIBILITY(onlyRodIfNotInReach));
    BOOL_SETTING_CONDITIONAL(click,                true);
    BOOL_SETTING_CONDITIONAL(rotations,            true);
    BOOL_SETTING_CONDITIONAL(luckyThrow,           false);

    BOOL_SETTING_CONDITIONAL(targetPlayers,        true);
    BOOL_SETTING_CONDITIONAL(targetMobs,           false);

    BOOL_SETTING_CONDITIONAL(esp, true);
    COLOR_SETTING_CONDITIONAL_OPTIONAL(espColor,
        ImColor(0.0f, 1.0f, 0.0f, 1.0f),
        SETTING_VISIBILITY(esp));
}

void AutoRodModule::registerEvents() {
    Render3dBaseModule::registerEvents();

    subscribe<OnRunTickEvent>([this](const OnRunTickEvent& event) {
        if (this->enable) this->onTick(event);
    });
}

int AutoRodModule::findRodSlot(EntityClientPlayerMP& player) const {
    InventoryPlayer inv = player.inventoryPlayer();
    if (inv.isNull()) return -1;
    inv.setDeleteRef(false);

    for (int i = 0; i < 9; i++) {
        ItemStack stack = inv.getItem(i);
        if (stack.isNull()) continue;
        bool isRod = stack.isRod();
        if (isRod) return i;
    }
    return -1;
}

bool AutoRodModule::findClosestTarget(JNIEnv* env, int& outId,
                                       float& outYaw, float& outPitch,
                                       double& outDist) const {
    Minecraft mc = Minecraft::getMinecraft(env);
    if (mc.isNull()) return false;
    EntityClientPlayerMP me = mc.thePlayer();
    if (me.isNull()) return false;
    WorldClient world = mc.theWorld();
    if (world.isNull()) return false;

    ArrayList entityList = world.loadedEntityList();
    if (entityList.isNull()) return false;

    int    bestId    = -1;
    double bestDist  = 1e18;
    float  bestYaw   = 0.0f;
    float  bestPitch = 0.0f;

    double mePos[3]{ me.posX(), me.posY() + me.getEyeHeight(), me.posZ() };

    int n = entityList.size();
    for (int i = 0; i < n; i++) {
        JavaObject entObj = entityList.get(i);
        if (entObj.isNull()) continue;

        Entity entity = entObj.convertTo<Entity>();
        if (entity.isNull()) continue;

        if (entity.entityId() == me.entityId()) continue;

        bool isPlayer = entity.isInstanceOf("EntityPlayer");
        bool isLiving = entity.isInstanceOf("EntityLivingBase");
        if (isPlayer && !targetPlayers) continue;
        if (!isPlayer && !targetMobs)   continue;
        if (!isLiving)                  continue;

        EntityLivingBase living = entObj.convertTo<EntityLivingBase>();
        if (living.getHealth() <= 0.0f) continue;
        if (entity.isInvisible())        continue;

        double tgtPos[3]{
            entity.posX(),
            entity.posY() + entity.getEyeHeight() * 0.5,
            entity.posZ()
        };
        double dist = distance3D(mePos, tgtPos);
        if (dist > maxRodRange) continue;

        if (moveFix) {
            double vx = entity.posX() - entity.lastTickPosX();
            double vy = entity.posY() - entity.lastTickPosY();
            double vz = entity.posZ() - entity.lastTickPosZ();

            constexpr double kBobberAvgSpeed   = 1.0;
            constexpr double kBobberGravityAcc = 0.03;

            double flightTicks = dist / kBobberAvgSpeed;

            if (flightTicks > 40.0) flightTicks = 40.0;

            tgtPos[0] = entity.posX() + vx * flightTicks;
            tgtPos[1] = entity.posY() + entity.getEyeHeight() * 0.5
                      + vy * flightTicks
                      + 0.5 * kBobberGravityAcc * flightTicks * flightTicks;
            tgtPos[2] = entity.posZ() + vz * flightTicks;
        }

        double dirOut[2];
        direction3D(tgtPos, mePos, dirOut);
        float yaw   = angleTo180(static_cast<float>(fmod(dirOut[0], 360.0)) - me.rotationYaw());
        float pitch = angleTo180(static_cast<float>(dirOut[1]) - me.rotationPitch());

        float angleDiff = std::sqrt(yaw * yaw + pitch * pitch);

        if (std::fabs(yaw) > fov) continue;

        if (angleDiff > maxTargetLookFovDiff) continue;

        if (onlyRodIfNotInReach && dist <= meleeReach) continue;

        if (dist < bestDist) {
            bestDist  = dist;
            bestId    = entity.entityId();
            bestYaw   = yaw;
            bestPitch = pitch;
        }
    }

    if (bestId == -1) return false;
    outId    = bestId;
    outYaw   = bestYaw;
    outPitch = bestPitch;
    outDist  = bestDist;
    return true;
}

namespace {
    void sendLookPacket(JNIEnv* env, EntityClientPlayerMP& me, float yaw, float pitch, bool onGround) {
        C05PacketPlayerLook packet = C05PacketPlayerLook::create(env, yaw, pitch, onGround);
        if (packet.isNull()) return;
        packet.setDeleteRef(false);

        static jmethodID getNetHandler = nullptr;
        if (!getNetHandler) getNetHandler = Mappings::getInstance().getMethod("Minecraft#getNetHandler");
        if (!getNetHandler) {
            env->DeleteLocalRef(packet.getObj());
            return;
        }

        jobject netHandler = env->CallObjectMethod(me.getObj(), getNetHandler);
        if (!netHandler || env->ExceptionCheck()) {
            env->ExceptionClear();
            env->DeleteLocalRef(packet.getObj());
            return;
        }

        static jmethodID addToSendQueue = nullptr;
        if (!addToSendQueue) addToSendQueue = Mappings::getInstance().getMethod("NetHandlerPlayClient#addToSendQueue");
        if (addToSendQueue) {
            env->CallVoidMethod(netHandler, addToSendQueue, packet.getObj());
            if (env->ExceptionCheck()) env->ExceptionClear();
        }

        env->DeleteLocalRef(packet.getObj());
        env->DeleteLocalRef(netHandler);
    }
}

void AutoRodModule::onTick(const OnRunTickEvent& event) {
    JNIEnv* env = event.getEnv();
    if (!env) return;

    Minecraft mc = Minecraft::getMinecraft(env);
    if (mc.isNull()) return;
    EntityClientPlayerMP me = mc.thePlayer();
    if (me.isNull()) return;

    switch (state_) {

    case RodState::SWAP_BACK: {

        InventoryPlayer inv = me.inventoryPlayer();
        if (!inv.isNull()) {
            inv.setDeleteRef(false);
            if (pendingOrigSlot_ >= 0)
                inv.currentItem(pendingOrigSlot_);
        }

        Entity ent(env, me.getObj());
        sendLookPacket(env, me, savedYaw_, savedPitch_, !ent.isNull() && ent.onGround());

        lastThrowMs_ = now();
        state_ = RodState::IDLE;
        return;
    }

    case RodState::THROW: {

        float curYaw   = me.rotationYaw();
        float curPitch = me.rotationPitch();
        float curPrevYaw   = me.prevRotationYaw();
        float curPrevPitch = me.prevRotationPitch();

        float aimYaw   = savedYaw_ + currentTargetYaw_;
        float aimPitch = savedPitch_ + currentTargetPitch_;

        me.rotationYaw(aimYaw);
        me.rotationPitch(aimPitch);
        me.prevRotationYaw(aimYaw);
        me.prevRotationPitch(aimPitch);

        mc.rightClickMouse();
        if (env->ExceptionCheck()) env->ExceptionClear();

        me.rotationYaw(curYaw);
        me.rotationPitch(curPitch);
        me.prevRotationYaw(curPrevYaw);
        me.prevRotationPitch(curPrevPitch);

        state_ = RodState::SWAP_BACK;
        return;
    }

    case RodState::AIM: {
        InventoryPlayer inv = me.inventoryPlayer();
        if (!inv.isNull()) {
            inv.setDeleteRef(false);
            pendingOrigSlot_ = inv.currentItem();
            if (click && pendingRodSlot_ != pendingOrigSlot_)
                inv.currentItem(pendingRodSlot_);
        }
        state_ = RodState::THROW;
        return;
    }

    case RodState::IDLE:
    default:
        break;
    }

    if (now() - lastThrowMs_ < throwCooldownMs) {
        currentTargetId_ = -1;
        return;
    }

    if (me.isSwingInProgress()) return;

    int    tgtId   = -1;
    float  tgtYaw  = 0.0f;
    float  tgtPitch= 0.0f;
    double tgtDist = 0.0;
    if (!findClosestTarget(env, tgtId, tgtYaw, tgtPitch, tgtDist)) {
        currentTargetId_ = -1;
        return;
    }

    if (onlyRodIfNotInReach && tgtDist <= meleeReach) {
        currentTargetId_ = -1;
        return;
    }

    int rodSlot = findRodSlot(me);
    if (rodSlot == -1) return;

    currentTargetId_   = tgtId;
    currentTargetYaw_  = tgtYaw;
    currentTargetPitch_= tgtPitch;

    savedYaw_   = me.rotationYaw();
    savedPitch_ = me.rotationPitch();

    float targetYaw   = savedYaw_ + tgtYaw;
    float targetPitch = savedPitch_ + tgtPitch;

    if (luckyThrow) {
        targetYaw   += (randomFloat(0.0f, 1.0f) - 0.5f) * 4.0f;
        targetPitch += (randomFloat(0.0f, 1.0f) - 0.5f) * 4.0f;
    }

    Entity ent(env, me.getObj());
    sendLookPacket(env, me, targetYaw, targetPitch, !ent.isNull() && ent.onGround());

    pendingRodSlot_ = rodSlot;
    state_ = RodState::AIM;
}

void AutoRodModule::onRender3d(const Render3dEvent& event) {
    JNIEnv* env = event.getEnv();
    if (!env || !esp || currentTargetId_ == -1) return;

    Minecraft mc = Minecraft::getMinecraft(env);
    if (mc.isNull()) return;
    WorldClient world = mc.theWorld();
    if (world.isNull()) return;
    Entity target = world.getEntityByID(currentTargetId_);
    if (target.isNull()) return;

    Vec3D renderPos;
    if (MinecraftSession::getInstance().version == MinecraftVersion::V1_8_9) {
        RenderManager rm = mc.getRenderManager();
        if (rm.isNull()) return;
        renderPos = rm.getRenderPos();
        env->DeleteLocalRef(rm.getObj());
    }
    if (MinecraftSession::getInstance().version == MinecraftVersion::V1_7_10) {
        RenderManager rm = RenderManager::getInstance(env);
        if (rm.isNull()) return;
        renderPos = rm.getRenderPos();
        env->DeleteLocalRef(rm.getObj());
    }

    auto timer = mc.timer();
    if (timer.isNull()) return;
    float partial = timer.GetrenderPartialTicks();

    double tx = target.lastTickPosX() + (target.posX() - target.lastTickPosX()) * partial;
    double ty = target.lastTickPosY() + (target.posY() - target.lastTickPosY()) * partial;
    double tz = target.lastTickPosZ() + (target.posZ() - target.lastTickPosZ()) * partial;

    Vector3f minPos(
        static_cast<float>(tx - renderPos.x) - 0.3f,
        static_cast<float>(ty - renderPos.y),
        static_cast<float>(tz - renderPos.z) - 0.3f
    );
    Vector3f maxPos(
        static_cast<float>(tx - renderPos.x) + 0.3f,
        static_cast<float>(ty - renderPos.y) + 1.8f,
        static_cast<float>(tz - renderPos.z) + 0.3f
    );

    auto activeRenderInfo = ActiveRenderInfo2::getInstance(env);
    if (!activeRenderInfo.isNull()) {
        activeRenderInfo.getModelView(CVarsUpdater::ModelView);
        activeRenderInfo.getProjection(CVarsUpdater::Projection);
    }

    // Balance each matrix stack explicitly: CheatBreaker leaves GL_PROJECTION active on entry
    // (stack only 2 deep), so a bare glPushMatrix() overflows it after ~2 frames and corrupts
    // rendering. Save/restore both stacks instead of clobbering the projection. See LagRangeModule.
    glMatrixMode(GL_PROJECTION);
    glPushMatrix();
    glLoadMatrixd(CVarsUpdater::Projection.data());
    glMatrixMode(GL_MODELVIEW);
    glPushMatrix();
    glLoadMatrixd(CVarsUpdater::ModelView.data());

    RenderUtils::setupRenderState(2.0f);
    Color outlineCol(espColor.Value.x, espColor.Value.y,
                     espColor.Value.z, espColor.Value.w);
    RenderUtils::drawBoxLines(minPos, maxPos, outlineCol);

    RenderUtils::restoreRenderState();
    glMatrixMode(GL_PROJECTION);
    glPopMatrix();
    glMatrixMode(GL_MODELVIEW);
    glPopMatrix();
}
