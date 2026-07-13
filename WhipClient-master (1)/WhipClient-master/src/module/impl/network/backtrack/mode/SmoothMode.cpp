#include "../../../../../../includes/module/impl/network/backtrack/mode/SmoothMode.h"
#include "../../../../../../includes/module/impl/network/backtrack/BacktrackModule.h"
#include "../../../../../../includes/wrapper/minecraft/client/Minecraft.h"
#include "../../../../../../includes/wrapper/minecraft/client/multiplayer/WorldClient.h"
#include "../../../../../../includes/wrapper/minecraft/network/play/server/S12PacketEntityVelocity.h"
#include "../../../../../../includes/wrapper/minecraft/network/play/server/S13PacketDestroyEntities.h"
#include "../../../../../../includes/wrapper/minecraft/network/play/server/S14PacketEntity.h"
#include "../../../../../../includes/wrapper/minecraft/network/play/server/S18PacketEntityTeleport.h"
#include "../../../../../../includes/wrapper/minecraft/network/play/server/S19PacketEntityStatus.h"
#include "../../../../../../includes/wrapper/minecraft/client/activerenderinfo/ActiveRenderInfo2.h"
#include "../../../../../../includes/wrapper/minecraft/entity/Entity.h"
#include "../../../../../../includes/wrapper/minecraft/entity/EntityLivingBase.h"
#include "../../../../../../includes/wrapper/minecraft/entity/player/EntityPlayer.h"
#include "../../../../../../includes/wrapper/minecraft/entity/render/RenderManager.h"
#include "../../../../../../includes/wrapper/minecraft/client/network/NetHandlerPlayClient.h"
#include "../../../../../../includes/handler/MappingHandler.h"
#include "../../../../../../includes/util/RenderUtils.h"

#include "wrapper/CVarsUpdater.h"

#include <GL/gl.h>
#include <cmath>
#include <chrono>

long long SmoothMode::now() const {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
}

void SmoothMode::onEnable(JNIEnv* env) {
    target_.clear();
    lastAttackTime_ = 0;
    renderAlpha_ = 0.0f;
    delayedServerPosX_ = 0;
    delayedServerPosY_ = 0;
    delayedServerPosZ_ = 0;
    processPacketCached_ = false;
    processPacketMethod_ = nullptr;
    simState_.reset();
    simActive_ = false;
    ticksSinceLastServerPos_ = 0;
}

void SmoothMode::onDisable(JNIEnv* env) {
    if (env) releaseAll(env);
    target_.clear();
}


void SmoothMode::onPacketReceived(const ChannelReadEvent& event) {
    JNIEnv* env = event.getEnv();
    jobject packet = event.getPacketObject();
    if (!env || !packet) return;


    if (target_.valid) {
        if (isInstanceOf(env, packet, "S08PacketPlayerPosLook") ||
            isInstanceOf(env, packet, "S40PacketDisconnect")) {
            reset(env);
            return;
        }


        if (isVelocityForSelf(env, packet)) {
            reset(env);
            return;
        }


        if (isInstanceOf(env, packet, "S27PacketExplosion")) {
            reset(env);
            return;
        }


        if (isInstanceOf(env, packet, "S20PacketEntityProperties")) {
            reset(env);
            return;
        }

        if (isInstanceOf(env, packet, "S13PacketDestroyEntities")) {
            S13PacketDestroyEntities destroyPacket(env, packet);
            destroyPacket.setDeleteRef(false);
            if (destroyPacket.containsEntityId(target_.entityId)) {
                reset(env);
                return;
            }
        }

        if (isInstanceOf(env, packet, "S19PacketEntityStatus")) {
            S19PacketEntityStatus statusPacket(env, packet);
            statusPacket.setDeleteRef(false);
            if (statusPacket.entityId() == target_.entityId && statusPacket.isDeath()) {
                reset(env);
                return;
            }
        }
    }

    if (!target_.valid) return;


    if (isInstanceOf(env, packet, "S18PacketEntityTeleport")) {
        S18PacketEntityTeleport s18(env, packet);
        s18.setDeleteRef(false);
        if (s18.entityId() == target_.entityId) {

            delayedServerPosX_ = s18.posX();
            delayedServerPosY_ = s18.posY();
            delayedServerPosZ_ = s18.posZ();

            double gx = static_cast<double>(delayedServerPosX_) / 32.0;
            double gy = static_cast<double>(delayedServerPosY_) / 32.0;
            double gz = static_cast<double>(delayedServerPosZ_) / 32.0;


            if (simActive_) {
                simState_.reconcile(gx, gy, gz);
                ticksSinceLastServerPos_ = 0;
            }

            if (target_.posRotationIncrements > 0) {
                target_.position = target_.newPosition;
            }
            target_.lastPosition = target_.position;
            target_.newPosition = {gx, gy, gz};
            target_.posRotationIncrements = 3;


            std::lock_guard lock(queueMutex_);
            jobject globalPkt = env->NewGlobalRef(packet);
            packetQueue_.push({globalPkt, now()});
            const_cast<ChannelReadEvent&>(event).setCancelled(true);
            return;
        }
    }

    if (isInstanceOf(env, packet, "S14PacketEntity")) {
        S14PacketEntity s14(env, packet);
        s14.setDeleteRef(false);
        if (s14.entityId() == target_.entityId) {

            delayedServerPosX_ += s14.posX();
            delayedServerPosY_ += s14.posY();
            delayedServerPosZ_ += s14.posZ();

            double gx = static_cast<double>(delayedServerPosX_) / 32.0;
            double gy = static_cast<double>(delayedServerPosY_) / 32.0;
            double gz = static_cast<double>(delayedServerPosZ_) / 32.0;


            if (simActive_) {
                simState_.reconcile(gx, gy, gz);
                ticksSinceLastServerPos_ = 0;
            }

            if (target_.posRotationIncrements > 0) {
                target_.position = target_.newPosition;
            }
            target_.lastPosition = target_.position;
            target_.newPosition = {gx, gy, gz};
            target_.posRotationIncrements = 3;

            std::lock_guard lock(queueMutex_);
            jobject globalPkt = env->NewGlobalRef(packet);
            packetQueue_.push({globalPkt, now()});
            const_cast<ChannelReadEvent&>(event).setCancelled(true);
            return;
        }
    }


    if (isInstanceOf(env, packet, "S12PacketEntityVelocity")) {
        S12PacketEntityVelocity velPacket(env, packet);
        velPacket.setDeleteRef(false);
        if (velPacket.pVelocity_entityId() == target_.entityId) {


            double ghostX = target_.position.x;
            double ghostY = target_.position.y;
            double ghostZ = target_.position.z;


            float targetYaw = 0;
            bool targetSprinting = false;
            auto mc2 = Minecraft::getMinecraft(env);
            if (!mc2.isNull()) {
                auto world2 = mc2.theWorld();
                if (!world2.isNull()) {
                    auto targetEnt = world2.getEntityByID(target_.entityId);
                    if (!targetEnt.isNull()) {
                        targetYaw = targetEnt.rotationYaw();
                        targetSprinting = targetEnt.isSprinting();
                    }
                }
            }

            simState_.applyKnockback(
                velPacket.pVelocity_motionX(),
                velPacket.pVelocity_motionY(),
                velPacket.pVelocity_motionZ(),
                ghostX, ghostY, ghostZ,
                false,
                targetYaw,
                targetSprinting
            );
            simActive_ = true;
            ticksSinceLastServerPos_ = 0;

            std::lock_guard lock(queueMutex_);
            jobject globalPkt = env->NewGlobalRef(packet);
            packetQueue_.push({globalPkt, now()});
            const_cast<ChannelReadEvent&>(event).setCancelled(true);
            return;
        }
    }


    if (isSmoothDelayedPacket(env, packet)) {
        std::lock_guard lock(queueMutex_);
        jobject globalPkt = env->NewGlobalRef(packet);
        packetQueue_.push({globalPkt, now()});
        const_cast<ChannelReadEvent&>(event).setCancelled(true);
        return;
    }


}


void SmoothMode::onTick(const OnRunTickEvent& event) {
    JNIEnv* env = event.getEnv();
    if (!env) return;


    if (!target_.valid) return;

    auto mc = Minecraft::getMinecraft(env);
    if (mc.isNull()) return;
    auto world = mc.theWorld();
    if (world.isNull()) return;
    auto player = mc.thePlayer();
    if (player.isNull()) return;


    if (!player.isSprinting()) {
        nonSprintTicks_++;
    } else {
        nonSprintTicks_ = 0;
    }


    constexpr int SPRINT_GRACE_PERIOD = 4;
    if (module_.isOnlySprinting() && nonSprintTicks_ >= SPRINT_GRACE_PERIOD) {
        reset(env);
        return;
    }

    auto targetEntity = world.getEntityByID(target_.entityId);
    if (targetEntity.isNull() || targetEntity.isDead()) {
        reset(env);
        return;
    }


    double dx = player.posX() - targetEntity.posX();
    double dy = player.posY() - targetEntity.posY();
    double dz = player.posZ() - targetEntity.posZ();
    if (std::sqrt(dx * dx + dy * dy + dz * dz) > 10.0) {
        reset(env);
        return;
    }


    if (shouldDisable(env)) {
        reset(env);
        return;
    }


    if (simActive_ && simState_.active) {

        simState_.updateTargetState(
            targetEntity.rotationYaw(),
            targetEntity.isSprinting(),
            targetEntity.onGround()
        );
        simState_.simulateTick();
        ++ticksSinceLastServerPos_;

        target_.lastPosition = target_.position;

        target_.position = {simState_.posX, simState_.posY, simState_.posZ};
        target_.newPosition = target_.position;
        target_.posRotationIncrements = 0;

        if (!simState_.active) simActive_ = false;
    } else if (target_.posRotationIncrements > 0) {

        target_.lastPosition = target_.position;
        double inc = static_cast<double>(target_.posRotationIncrements);
        target_.position = {
            target_.position.x + (target_.newPosition.x - target_.position.x) / inc,
            target_.position.y + (target_.newPosition.y - target_.position.y) / inc,
            target_.position.z + (target_.newPosition.z - target_.position.z) / inc
        };
        --target_.posRotationIncrements;
    } else {
        target_.lastPosition = target_.position;
    }


    processQueue(env);
}


bool SmoothMode::shouldDisable(JNIEnv* env) const {
    if (!target_.valid) return false;


    if (module_.getForceFlushMs() != 1001 && lastAttackTime_ > 0) {
        long long elapsed = now() - lastAttackTime_;
        if (elapsed > module_.getForceFlushMs()) {
            return true;
        }
    }

    auto mc = Minecraft::getMinecraft(env);
    if (mc.isNull()) return false;
    auto player = mc.thePlayer();
    if (player.isNull()) return false;
    auto world = mc.theWorld();
    if (world.isNull()) return false;

    auto targetEntity = world.getEntityByID(target_.entityId);
    if (targetEntity.isNull()) return false;

    float distToTarget = player.getDistanceToEntity(targetEntity);


    double bx = target_.position.x - player.posX();
    double by = target_.position.y - player.posY();
    double bz = target_.position.z - player.posZ();
    float distToBox = static_cast<float>(std::sqrt(bx * bx + by * by + bz * bz));


    return (distToBox < distToTarget) && (distToTarget - distToBox >= 0.36f);
}


void SmoothMode::onPlayerAttack(const PlayerAttackEvent& event) {
    JNIEnv* env = event.getEnv();
    if (!env) return;

    int targetId = event.getTargetEntityId();
    if (targetId == -1) return;

    auto mc = Minecraft::getMinecraft(env);
    if (mc.isNull()) return;
    auto player = mc.thePlayer();
    if (player.isNull() || targetId == player.entityId()) return;


    if (target_.valid && targetId == target_.entityId) {
        lastAttackTime_ = now();
        return;
    }

    constexpr long long SWAP_COOLDOWN_MS = 350;
    if (target_.valid && lastAttackTime_ > 0 && (now() - lastAttackTime_) < SWAP_COOLDOWN_MS) {
        return;
    }

    if (target_.valid) {
        reset(env);
    }

    setTarget(env, targetId);
    lastAttackTime_ = now();
}


void SmoothMode::onRender3d(const Render3dEvent& event) {
    JNIEnv* env = event.getEnv();
    if (!env || !target_.valid || !module_.isDrawBox()) return;

    renderAlpha_ = std::lerp(renderAlpha_, 1.0f, 0.15f);

    auto minecraft = Minecraft::getMinecraft(env);
    if (minecraft.isNull()) return;

    Vec3D renderPos;
    if (MinecraftSession::getInstance().version == MinecraftVersion::V1_8_9) {
        RenderManager renderManager = minecraft.getRenderManager();
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

    auto timer = minecraft.timer();
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

    auto bc = module_.getBoxColor();
    auto oc = module_.getOutlineColor();
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


void SmoothMode::setTarget(JNIEnv* env, int entityId) {
    if (!env || entityId == -1) return;

    auto mc = Minecraft::getMinecraft(env);
    if (mc.isNull()) return;
    auto world = mc.theWorld();
    if (world.isNull()) return;
    auto entity = world.getEntityByID(entityId);
    if (entity.isNull()) return;

    target_.entityId = entityId;
    target_.valid = true;

    delayedServerPosX_ = entity.serverPosX();
    delayedServerPosY_ = entity.serverPosY();
    delayedServerPosZ_ = entity.serverPosZ();

    target_.serverPosX = delayedServerPosX_;
    target_.serverPosY = delayedServerPosY_;
    target_.serverPosZ = delayedServerPosZ_;

    double posX = static_cast<double>(delayedServerPosX_) / 32.0;
    double posY = static_cast<double>(delayedServerPosY_) / 32.0;
    double posZ = static_cast<double>(delayedServerPosZ_) / 32.0;

    target_.position = {posX, posY, posZ};
    target_.lastPosition = target_.position;
    target_.newPosition = target_.position;
    target_.posRotationIncrements = 0;
    target_.targetTime = now();
}

void SmoothMode::reset(JNIEnv* env) {
    if (env) releaseAll(env);
    target_.clear();
    lastAttackTime_ = 0;
    renderAlpha_ = 0.0f;
    delayedServerPosX_ = 0;
    delayedServerPosY_ = 0;
    delayedServerPosZ_ = 0;
    simState_.reset();
    simActive_ = false;
    ticksSinceLastServerPos_ = 0;
}


void SmoothMode::processQueue(JNIEnv* env) {
    if (!env) return;

    std::lock_guard lock(queueMutex_);
    if (packetQueue_.empty()) return;

    cacheProcessPacketMethod(env);
    long long currentTime = now();
    int delayMs = module_.getSmoothDelayMs();


    if (!packetQueue_.empty()) {
        auto& front = packetQueue_.front();
        if ((currentTime - front.timestamp) >= delayMs) {
            if (front.packet && !env->IsSameObject(front.packet, nullptr)) {
                processPacket(env, front.packet);
            }
            if (front.packet) env->DeleteGlobalRef(front.packet);
            packetQueue_.pop();
        }
    }
}

void SmoothMode::releaseAll(JNIEnv* env) {
    if (!env) return;

    std::lock_guard lock(queueMutex_);
    if (packetQueue_.empty()) return;

    cacheProcessPacketMethod(env);

    while (!packetQueue_.empty()) {
        auto& front = packetQueue_.front();
        if (front.packet && !env->IsSameObject(front.packet, nullptr)) {
            processPacket(env, front.packet);
        }
        if (front.packet) env->DeleteGlobalRef(front.packet);
        packetQueue_.pop();
    }
}

void SmoothMode::processPacket(JNIEnv* env, jobject packet) {
    if (!processPacketCached_ || !processPacketMethod_) return;

    auto mc = Minecraft::getMinecraft(env);
    if (mc.isNull()) return;
    auto nh = mc.getNetHandler();
    if (nh.isNull()) return;

    env->CallVoidMethod(packet, processPacketMethod_, nh.getObj());
    if (env->ExceptionCheck()) env->ExceptionClear();
}

void SmoothMode::cacheProcessPacketMethod(JNIEnv* env) {
    if (processPacketCached_ || !env) return;
    processPacketMethod_ = Mappings::getInstance().getMethod("Packet#processPacket");
    processPacketCached_ = processPacketMethod_ != nullptr;
}


bool SmoothMode::isInstanceOf(JNIEnv* env, jobject obj, const char* className) {
    jclass clazz = Mappings::getInstance().getClass(className);
    return clazz && env->IsInstanceOf(obj, clazz);
}

bool SmoothMode::isVelocityForSelf(JNIEnv* env, jobject packet) const {
    if (!isInstanceOf(env, packet, "S12PacketEntityVelocity")) return false;
    auto mc = Minecraft::getMinecraft(env);
    if (mc.isNull()) return false;
    auto player = mc.thePlayer();
    if (player.isNull()) return false;
    S12PacketEntityVelocity velPacket(env, packet);
    velPacket.setDeleteRef(false);
    return velPacket.pVelocity_entityId() == player.entityId();
}

bool SmoothMode::isSmoothDelayedPacket(JNIEnv* env, jobject packet) const {
    return isInstanceOf(env, packet, "S03PacketTimeUpdate") ||
           isInstanceOf(env, packet, "S00PacketKeepAlive");
}
