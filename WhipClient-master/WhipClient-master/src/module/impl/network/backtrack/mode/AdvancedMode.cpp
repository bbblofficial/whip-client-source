#include "../../../../../../includes/module/impl/network/backtrack/mode/AdvancedMode.h"
#include "../../../../../../includes/module/impl/network/backtrack/BacktrackModule.h"

#include "../../../../../../includes/wrapper/minecraft/client/Minecraft.h"
#include "../../../../../../includes/wrapper/minecraft/client/multiplayer/WorldClient.h"
#include "../../../../../../includes/wrapper/minecraft/client/entity/EntityClientPlayerMP.h"
#include "../../../../../../includes/wrapper/minecraft/entity/Entity.h"
#include "../../../../../../includes/wrapper/minecraft/entity/EntityLivingBase.h"
#include "../../../../../../includes/wrapper/minecraft/entity/render/RenderManager.h"
#include "../../../../../../includes/wrapper/minecraft/client/activerenderinfo/ActiveRenderInfo2.h"
#include "../../../../../../includes/wrapper/minecraft/network/play/server/S12PacketEntityVelocity.h"
#include "../../../../../../includes/wrapper/minecraft/network/play/server/S13PacketDestroyEntities.h"
#include "../../../../../../includes/wrapper/minecraft/network/play/server/S14PacketEntity.h"
#include "../../../../../../includes/wrapper/minecraft/network/play/server/S18PacketEntityTeleport.h"
#include "../../../../../../includes/wrapper/minecraft/network/play/server/S19PacketEntityStatus.h"
#include "../../../../../../includes/handler/MappingHandler.h"
#include "../../../../../../includes/handler/ProviderHandler.h"
#include "../../../../../../includes/provider/impl/PacketProvider.h"
#include "../../../../../../includes/util/RenderUtils.h"
#include "../../../../../../includes/wrapper/CVarsUpdater.h"

#include <GL/gl.h>
#include <cmath>


static constexpr const char* ADV_IGNORED_PACKETS_1_8[] = {
    "S02PacketChat",
    "S06PacketUpdateHealth",
    "S47PacketPlayerListHeaderFooter",
    "S41PacketServerDifficulty",
    "S0BPacketAnimation",
    "S32PacketConfirmTransaction"
};

static constexpr const char* ADV_IGNORED_PACKETS_1_7[] = {
    "S02PacketChat",
    "S06PacketUpdateHealth",
    "S0BPacketAnimation",
    "S32PacketConfirmTransaction"
};

static bool isInstanceOfClass(JNIEnv* env, jobject obj, const char* className) {
    jclass clazz = Mappings::getInstance().getClass(className);
    return clazz && env->IsInstanceOf(obj, clazz);
}

static bool isIgnoredPacket(JNIEnv* env, jobject packet) {
    if (MinecraftSession::getInstance().version == MinecraftVersion::V1_8_9) {
        for (const char* name : ADV_IGNORED_PACKETS_1_8) {
            if (isInstanceOfClass(env, packet, name)) return true;
        }
    } else {
        for (const char* name : ADV_IGNORED_PACKETS_1_7) {
            if (isInstanceOfClass(env, packet, name)) return true;
        }
    }
    return false;
}


void AdvancedMode::onEnable(JNIEnv* env) {
    target_.clear();
    inBacktrackWindow_ = false;
    windowStartMs_     = 0;
    lastFlushMs_       = 0;
    lastAttackMs_      = 0;
    wasHoldingSword_   = false;
    renderAlpha_       = 0.0f;
    clickedThisTick_   = false;
}

void AdvancedMode::onDisable(JNIEnv* env) {
    if (env) flushAndClear(env);
}


void AdvancedMode::onPacketReceived(const ChannelReadEvent& event) {
    JNIEnv* env = event.getEnv();
    jobject packet = event.getPacketObject();
    if (!env || !packet) return;

    if (isIgnoredPacket(env, packet)) return;


    if (isInstanceOfClass(env, packet, "S08PacketPlayerPosLook")) {
        flushAndClear(env);
        return;
    }
    if (isInstanceOfClass(env, packet, "S40PacketDisconnect")) {
        flushAndClear(env);
        return;
    }
    if (isInstanceOfClass(env, packet, "S12PacketEntityVelocity")) {
        S12PacketEntityVelocity vel(env, packet);
        vel.setDeleteRef(false);
        Minecraft mc = Minecraft::getMinecraft(env);
        if (!mc.isNull()) {
            EntityClientPlayerMP me = mc.thePlayer();
            if (!me.isNull() && vel.pVelocity_entityId() == me.entityId()) {
                flushAndClear(env);
                return;
            }
        }
    }
    if (isInstanceOfClass(env, packet, "S13PacketDestroyEntities")) {
        S13PacketDestroyEntities destroy(env, packet);
        destroy.setDeleteRef(false);
        if (destroy.containsEntityId(target_.entityId)) {
            flushAndClear(env);
            return;
        }
    }
    if (isInstanceOfClass(env, packet, "S19PacketEntityStatus")) {
        S19PacketEntityStatus status(env, packet);
        status.setDeleteRef(false);
        if (status.entityId() == target_.entityId && status.isDeath()) {
            flushAndClear(env);
            return;
        }
    }

    if (!target_.valid) return;

    auto* provider = static_cast<PacketProvider*>(
        ProviderHandler::getInstance().getProvider(ProviderType::PACKET));
    if (!provider) return;


    if (isInstanceOfClass(env, packet, "S14PacketEntity")) {
        S14PacketEntity s14(env, packet);
        s14.setDeleteRef(false);
        if (s14.entityId() == target_.entityId) {
            target_.serverPosX += s14.posX();
            target_.serverPosY += s14.posY();
            target_.serverPosZ += s14.posZ();
            target_.newPosition = {
                static_cast<double>(target_.serverPosX) / 32.0,
                static_cast<double>(target_.serverPosY) / 32.0,
                static_cast<double>(target_.serverPosZ) / 32.0
            };
            target_.posRotationIncrements = 3;
        }
    }
    if (isInstanceOfClass(env, packet, "S18PacketEntityTeleport")) {
        S18PacketEntityTeleport s18(env, packet);
        s18.setDeleteRef(false);
        if (s18.entityId() == target_.entityId) {
            target_.serverPosX = s18.posX();
            target_.serverPosY = s18.posY();
            target_.serverPosZ = s18.posZ();
            target_.newPosition = {
                static_cast<double>(target_.serverPosX) / 32.0,
                static_cast<double>(target_.serverPosY) / 32.0,
                static_cast<double>(target_.serverPosZ) / 32.0
            };
            target_.posRotationIncrements = 3;
        }
    }

    if (!module_.isAdvFixPacketOrder()) return;

    provider->setDelay(module_.getAdvMaxDelay());
    provider->queuePacket(env, packet);
    const_cast<ChannelReadEvent&>(event).setCancelled(true);
}


void AdvancedMode::onTick(const OnRunTickEvent& event) {
    JNIEnv* env = event.getEnv();
    if (!env) return;

    auto* provider = static_cast<PacketProvider*>(
        ProviderHandler::getInstance().getProvider(ProviderType::PACKET));
    if (!provider) return;

    Minecraft mc = Minecraft::getMinecraft(env);
    if (mc.isNull()) return;

    EntityClientPlayerMP player = mc.thePlayer();
    if (player.isNull()) return;


    if (target_.valid && target_.posRotationIncrements > 0) {
        target_.lastPosition = target_.position;
        double inc = static_cast<double>(target_.posRotationIncrements);
        target_.position = {
            target_.position.x + (target_.newPosition.x - target_.position.x) / inc,
            target_.position.y + (target_.newPosition.y - target_.position.y) / inc,
            target_.position.z + (target_.newPosition.z - target_.position.z) / inc
        };
        --target_.posRotationIncrements;
    }


    if (player.hasEnderPearl()) {
        if (target_.valid) flushAndClear(env);
        clickedThisTick_ = false;
        return;
    }


    if (target_.valid) {
        auto held = player.getHeldItem();
        bool holdingSword = !held.isNull() && held.isSword();
        if (wasHoldingSword_ && !holdingSword) {
            flushAndClear(env);
            clickedThisTick_ = false;
            return;
        }
        wasHoldingSword_ = holdingSword;
    }


    if (target_.valid && module_.isAdvOnlyWhenNeeded()) {
        if (!targetInRange(env, target_.entityId, 6.0f)) {
            flushAndClear(env);
            clickedThisTick_ = false;
            return;
        }
    }


    int abortCriterion = module_.getAdvAbortCriterion();
    if (target_.valid && abortCriterion != 0) {
        bool shouldAbort = false;
        switch (abortCriterion) {
            case 1:
                if (lastAttackMs_ > 0 && (now() - lastAttackMs_) < 50)
                    shouldAbort = true;
                break;
            case 2:
                if (targetInRange(env, target_.entityId, module_.getAdvStopOnAttackRange()))
                    shouldAbort = true;
                break;
            case 3:
                if (clickedThisTick_) shouldAbort = true;
                break;
        }
        if (shouldAbort) {
            flushAndClear(env);
            clickedThisTick_ = false;
            return;
        }
    }


    if (target_.valid && !module_.isAdvContinueAtHurtTime()) {
        WorldClient world = mc.theWorld();
        if (!world.isNull()) {
            Entity targetEntity = world.getEntityByID(target_.entityId);
            if (!targetEntity.isNull()) {
                EntityLivingBase living = targetEntity.UHQConvertTo<EntityLivingBase>();
                int hurt = living.hurtTime();
                if (hurt > 0 && hurt < module_.getAdvStopAtHurt()) {
                    flushAndClear(env);
                    clickedThisTick_ = false;
                    return;
                }
            }
        }
    }


    if (target_.valid && lastFlushMs_ > 0) {
        long long sinceFlush = now() - lastFlushMs_;
        if (sinceFlush < module_.getAdvDelayBetweenLags()) {
            provider->processDelayedPackets(env);
            clickedThisTick_ = false;
            return;
        }
    }


    if (target_.valid && !inBacktrackWindow_) {
        inBacktrackWindow_ = true;
        windowStartMs_     = now();
    }

    if (inBacktrackWindow_) {
        long long age = now() - windowStartMs_;
        long long delay = module_.getAdvMaxDelay();
        if (delay < module_.getAdvMinDelay()) delay = module_.getAdvMinDelay();

        if (age >= delay) {
            flushAndClear(env);
        }
    }

    provider->processDelayedPackets(env);
    clickedThisTick_ = false;
}


void AdvancedMode::onPlayerAttack(const PlayerAttackEvent& event) {
    JNIEnv* env = event.getEnv();
    if (!env) return;

    int targetId = event.getTargetEntityId();
    if (targetId == -1) return;

    Minecraft mc = Minecraft::getMinecraft(env);
    if (mc.isNull()) return;
    EntityClientPlayerMP me = mc.thePlayer();
    if (me.isNull() || targetId == me.entityId()) return;

    if (module_.isAdvOnlyWhenNeeded() && !targetInRange(env, targetId, 6.0f)) return;

    if (targetId != target_.entityId) {
        constexpr long long SWAP_COOLDOWN_MS = 350;
        if (target_.valid && lastAttackMs_ > 0 && (now() - lastAttackMs_) < SWAP_COOLDOWN_MS) {
            return;
        }
        lastAttackMs_ = now();
        auto* provider = static_cast<PacketProvider*>(
            ProviderHandler::getInstance().getProvider(ProviderType::PACKET));
        if (!provider) return;
        flushAndClear(env);
        if (provider->getQueueSize() <= 0) {
            setTarget(env, targetId);
        }
    } else {
        lastAttackMs_ = now();
        target_.targetTime = now();
    }
}


void AdvancedMode::onMouseLeftClick(const MouseLeftClickEvent& event) {
    clickedThisTick_ = true;
}


void AdvancedMode::setTarget(JNIEnv* env, int entityId) {
    if (!env || entityId == -1) return;

    Minecraft mc = Minecraft::getMinecraft(env);
    if (mc.isNull()) return;
    WorldClient world = mc.theWorld();
    if (world.isNull()) return;
    Entity entity = world.getEntityByID(entityId);
    if (entity.isNull()) return;

    target_.entityId   = entityId;
    target_.serverPosX = entity.serverPosX();
    target_.serverPosY = entity.serverPosY();
    target_.serverPosZ = entity.serverPosZ();

    double posX = static_cast<double>(target_.serverPosX) / 32.0;
    double posY = static_cast<double>(target_.serverPosY) / 32.0;
    double posZ = static_cast<double>(target_.serverPosZ) / 32.0;
    target_.position     = {posX, posY, posZ};
    target_.lastPosition = target_.position;
    target_.newPosition  = target_.position;
    target_.posRotationIncrements = 0;
    target_.targetTime = now();
    target_.valid = true;
}

void AdvancedMode::flushAndClear(JNIEnv* env) {
    target_.valid = false;
    target_.clear();
    inBacktrackWindow_ = false;
    windowStartMs_     = 0;
    lastFlushMs_       = now();
    if (auto* p = static_cast<PacketProvider*>(
            ProviderHandler::getInstance().getProvider(ProviderType::PACKET))) {
        if (env) p->processAndClearQueue(env);
    }
}

bool AdvancedMode::targetInRange(JNIEnv* env, int entityId, float maxRange) const {
    if (!env || entityId == -1) return false;
    Minecraft mc = Minecraft::getMinecraft(env);
    if (mc.isNull()) return false;
    EntityClientPlayerMP me = mc.thePlayer();
    if (me.isNull()) return false;
    WorldClient world = mc.theWorld();
    if (world.isNull()) return false;
    Entity entity = world.getEntityByID(entityId);
    if (entity.isNull()) return false;

    double dx = me.posX() - entity.posX();
    double dy = me.posY() - entity.posY();
    double dz = me.posZ() - entity.posZ();
    return std::sqrt(dx*dx + dy*dy + dz*dz) <= maxRange;
}


void AdvancedMode::onRender3d(const Render3dEvent& event) {
    JNIEnv* env = event.getEnv();
    if (!env || !target_.valid || !module_.isDrawBox()) return;

    renderAlpha_ = std::lerp(renderAlpha_, 1.0f, 0.15f);

    Minecraft mc = Minecraft::getMinecraft(env);
    if (mc.isNull()) return;

    Vec3D renderPos;
    if (MinecraftSession::getInstance().version == MinecraftVersion::V1_8_9) {
        RenderManager renderManager = mc.getRenderManager();
        if (renderManager.isNull()) return;
        renderPos = renderManager.getRenderPos();
        /* explicit DeleteLocalRef removed: renderManager's destructor frees it (double-free crashed Java 25 GC on CheatBreaker) */
    }
    if (MinecraftSession::getInstance().version == MinecraftVersion::V1_7_10) {
        RenderManager renderManager = RenderManager::getInstance(env);
        if (renderManager.isNull()) return;
        renderPos = renderManager.getRenderPos();
        /* explicit DeleteLocalRef removed: renderManager's destructor frees it (double-free crashed Java 25 GC on CheatBreaker) */
    }

    auto timer = mc.timer();
    if (timer.isNull()) return;
    float partialTicks = timer.GetrenderPartialTicks();

    Vector3d drawPos{
        target_.lastPosition.x + (target_.position.x - target_.lastPosition.x) * partialTicks,
        target_.lastPosition.y + (target_.position.y - target_.lastPosition.y) * partialTicks,
        target_.lastPosition.z + (target_.position.z - target_.lastPosition.z) * partialTicks
    };

    Vector3f minPos(
        static_cast<float>(drawPos.x - renderPos.x) - 0.3f,
        static_cast<float>(drawPos.y - renderPos.y),
        static_cast<float>(drawPos.z - renderPos.z) - 0.3f
    );
    Vector3f maxPos(
        static_cast<float>(drawPos.x - renderPos.x) + 0.3f,
        static_cast<float>(drawPos.y - renderPos.y) + 1.8f,
        static_cast<float>(drawPos.z - renderPos.z) + 0.3f
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

    ImColor bc = module_.getBoxColor();
    ImColor oc = module_.getOutlineColor();

    RenderUtils::setupRenderState(2.0f);
    Color outlineCol(oc.Value.x, oc.Value.y, oc.Value.z, oc.Value.w * renderAlpha_);
    Color fillCol(bc.Value.x, bc.Value.y, bc.Value.z, bc.Value.w * renderAlpha_);

    RenderUtils::drawBoxLines(minPos, maxPos, outlineCol);
    RenderUtils::drawBoxFilled(minPos, maxPos, fillCol);

    RenderUtils::restoreRenderState();
    glMatrixMode(GL_PROJECTION);
    glPopMatrix();
    glMatrixMode(GL_MODELVIEW);
    glPopMatrix();
}
