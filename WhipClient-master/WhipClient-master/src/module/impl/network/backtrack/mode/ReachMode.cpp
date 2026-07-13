#include "../../../../../../includes/module/impl/network/backtrack/mode/ReachMode.h"
#include "../../../../../../includes/module/impl/network/backtrack/BacktrackModule.h"
#include "../../../../../../includes/wrapper/minecraft/client/Minecraft.h"
#include "../../../../../../includes/wrapper/minecraft/client/multiplayer/WorldClient.h"
#include "../../../../../../includes/wrapper/minecraft/client/multiplayer/PlayerControllerMP.h"
#include "../../../../../../includes/wrapper/minecraft/network/play/server/S12PacketEntityVelocity.h"
#include "../../../../../../includes/wrapper/minecraft/network/play/server/S13PacketDestroyEntities.h"
#include "../../../../../../includes/wrapper/minecraft/network/play/server/S14PacketEntity.h"
#include "../../../../../../includes/wrapper/minecraft/network/play/server/S18PacketEntityTeleport.h"
#include "../../../../../../includes/wrapper/minecraft/network/play/server/S19PacketEntityStatus.h"
#include "../../../../../../includes/wrapper/minecraft/client/activerenderinfo/ActiveRenderInfo2.h"
#include "../../../../../../includes/wrapper/minecraft/entity/Entity.h"
#include "../../../../../../includes/wrapper/minecraft/entity/EntityLivingBase.h"
#include "../../../../../../includes/wrapper/minecraft/entity/player/EntityPlayer.h"
#include "../../../../../../includes/wrapper/minecraft/item/ItemStack.h"
#include "../../../../../../includes/wrapper/minecraft/entity/render/RenderManager.h"
#include "../../../../../../includes/wrapper/minecraft/network/Packet.h"
#include "../../../../../../includes/wrapper/minecraft/client/network/NetHandlerPlayClient.h"
#include "../../../../../../includes/handler/MappingHandler.h"
#include "../../../../../../includes/util/RenderUtils.h"

#include "wrapper/CVarsUpdater.h"

#include <GL/gl.h>
#include <cmath>
#include <algorithm>
#include <chrono>


constexpr double HITBOX_HALF_W = 0.3;
constexpr double HITBOX_HEIGHT = 1.8;
constexpr double HITBOX_EXPAND = 0.1;

jclass ReachMode::C00KeepAliveClass_ = nullptr;
jclass ReachMode::C0FConfirmTransactionClass_ = nullptr;
jclass ReachMode::S14PacketEntityClass_ = nullptr;
jclass ReachMode::S18PacketEntityTeleportClass_ = nullptr;
jclass ReachMode::S12VelocityClass_ = nullptr;

long long ReachMode::now() const {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
}

void ReachMode::onEnable(JNIEnv* env) {
    reset(env);
    wasHoldingSword_ = false;
    renderAlpha_ = 0.0f;
    nonSprintTicks_ = 0;
}

void ReachMode::onDisable(JNIEnv* env) {
    reset(env);
}


void ReachMode::onPacketReceived(const ChannelReadEvent& event) {
    JNIEnv* env = event.getEnv();
    jobject packet = event.getPacketObject();
    if (!env || !packet || !tracking_) return;


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

    if (isInstanceOf(env, packet, "S08PacketPlayerPosLook")) {
        reset(env);
        return;
    }

    if (isInstanceOf(env, packet, "S19PacketEntityStatus")) {
        S19PacketEntityStatus statusPacket(env, packet);
        statusPacket.setDeleteRef(false);
        if (statusPacket.entityId() == targetEntityId_ && statusPacket.isDeath()) {
            reset(env);
            return;
        }
    }

    if (isInstanceOf(env, packet, "S13PacketDestroyEntities")) {
        S13PacketDestroyEntities destroyPacket(env, packet);
        destroyPacket.setDeleteRef(false);
        if (destroyPacket.containsEntityId(targetEntityId_)) {
            reset(env);
            return;
        }
    }


    if (cachedIsInstanceOf(env, packet, S18PacketEntityTeleportClass_, "S18PacketEntityTeleport")) {
        S18PacketEntityTeleport s18(env, packet);
        s18.setDeleteRef(false);
        if (s18.entityId() == targetEntityId_) {
            lastServerPosX_ = s18.posX();
            lastServerPosY_ = s18.posY();
            lastServerPosZ_ = s18.posZ();
            lastPosWasTeleport_ = true;
        }
        return;
    }


    if (cachedIsInstanceOf(env, packet, S14PacketEntityClass_, "S14PacketEntity")) {
        S14PacketEntity s14(env, packet);
        s14.setDeleteRef(false);
        if (s14.entityId() == targetEntityId_) {
            lastServerPosX_ += s14.posX();
            lastServerPosY_ += s14.posY();
            lastServerPosZ_ += s14.posZ();
            lastPosWasTeleport_ = false;
        }
    }
}


void ReachMode::onPacketSend(const AddSendQueueEvent& event) {
    JNIEnv* env = event.getEnv();
    jobject packet = event.getPacketObject();
    if (!env || !packet || !tracking_) return;

    if (flushing_) return;


    bool isTransaction = cachedIsInstanceOf(env, packet, C0FConfirmTransactionClass_, "C0FPacketConfirmTransaction");
    if (!isTransaction) return;

    {
        std::lock_guard lock(keepAliveMutex_);
        jobject globalPkt = env->NewGlobalRef(packet);
        keepAliveQueue_.push({globalPkt, now()});
    }

    const_cast<AddSendQueueEvent&>(event).setCancelled(true);
}


void ReachMode::onPlayerAttack(const PlayerAttackEvent& event) {
    JNIEnv* env = event.getEnv();
    if (!env) return;

    int targetId = event.getTargetEntityId();
    if (targetId == -1) return;

    auto mc = Minecraft::getMinecraft(env);
    if (mc.isNull()) return;
    auto player = mc.thePlayer();
    if (player.isNull() || targetId == player.entityId()) return;

    if (tracking_ && targetId != targetEntityId_) {
        constexpr long long SWAP_COOLDOWN_MS = 350;
        if (lastAttackTime_ > 0 && (now() - lastAttackTime_) < SWAP_COOLDOWN_MS) {
            return;
        }
        reset(env);
    }

    targetEntityId_ = targetId;
    tracking_ = true;
    lastAttackTime_ = now();


    auto world = mc.theWorld();
    if (!world.isNull()) {
        auto targetEntity = world.getEntityByID(targetEntityId_);
        if (!targetEntity.isNull()) {
            lastServerPosX_ = static_cast<int>(targetEntity.serverPosX());
            lastServerPosY_ = static_cast<int>(targetEntity.serverPosY());
            lastServerPosZ_ = static_cast<int>(targetEntity.serverPosZ());
            lastPosWasTeleport_ = false;
        }
    }
}


void ReachMode::onMouseLeftClick(const MouseLeftClickEvent& event) {
    JNIEnv* env = event.getEnv();
    if (!env || !tracking_ || positionHistory_.empty()) return;

    double hitDist = 0;
    if (!findHittableGhost(env, hitDist)) return;

    auto mc = Minecraft::getMinecraft(env);
    if (mc.isNull()) return;
    auto world = mc.theWorld();
    if (world.isNull()) return;
    auto player = mc.thePlayer();
    if (player.isNull()) return;

    auto targetEntity = world.getEntityByID(targetEntityId_);
    if (targetEntity.isNull() || targetEntity.isDead()) {
        reset(env);
        return;
    }


    player.swingItem();
    sendAttack(env, targetEntity.getObj());
    lastAttackTime_ = now();

    const_cast<MouseLeftClickEvent&>(event).setCancelled(true);
}


void ReachMode::onTick(const OnRunTickEvent& event) {
    JNIEnv* env = event.getEnv();
    if (!env) return;


    if (!tracking_) return;

    auto mc = Minecraft::getMinecraft(env);
    if (mc.isNull()) return;
    auto world = mc.theWorld();
    if (world.isNull()) return;

    auto targetEntity = world.getEntityByID(targetEntityId_);
    if (targetEntity.isNull() || targetEntity.isDead()) {
        reset(env);
        return;
    }


    if (lastAttackTime_ > 0 && (now() - lastAttackTime_) > module_.getCooldownTime()) {
        reset(env);
        return;
    }

    auto player = mc.thePlayer();
    if (!player.isNull()) {

        if (!player.isSprinting()) {
            nonSprintTicks_++;
        } else {
            nonSprintTicks_ = 0;
        }


        constexpr int SPRINT_GRACE_PERIOD = 20;
        if (module_.isOnlySprinting() && nonSprintTicks_ >= SPRINT_GRACE_PERIOD) {
            softReset(env);
            return;
        }


        auto heldItem = player.getHeldItem();
        bool holdingSword = !heldItem.isNull() && heldItem.isSword();
        if (wasHoldingSword_ && !holdingSword) {
            reset(env);
            return;
        }
        wasHoldingSword_ = holdingSword;
    }


    BTPositionSample sample;
    sample.x = targetEntity.posX();
    sample.y = targetEntity.posY();
    sample.z = targetEntity.posZ();
    sample.serverPosX = lastServerPosX_;
    sample.serverPosY = lastServerPosY_;
    sample.serverPosZ = lastServerPosZ_;
    sample.fromTeleport = lastPosWasTeleport_;
    sample.timestamp = now();
    positionHistory_.push_back(sample);


    if (!player.isNull() && module_.isDynamicDelay()) {
        computeDynamicDelay(player.posX(), player.posY(), player.posZ(),
                            sample.x, sample.y, sample.z);
    }

    long long activeDelay = module_.isDynamicDelay()
        ? static_cast<long long>(effectiveDelayMs_)
        : module_.getMaxDelayMs();


    long long cutoff = now() - activeDelay;
    while (!positionHistory_.empty() && positionHistory_.front().timestamp < cutoff) {
        positionHistory_.pop_front();
    }


    if (!positionHistory_.empty()) {
        auto& oldest = positionHistory_.front();


        double newGhostX = oldest.x;
        double newGhostY = oldest.y;
        double newGhostZ = oldest.z;

        if (!ghostValid_) {

            ghostTargetX_ = newGhostX;
            ghostTargetY_ = newGhostY;
            ghostTargetZ_ = newGhostZ;
            ghostPosX_ = newGhostX;
            ghostPosY_ = newGhostY;
            ghostPosZ_ = newGhostZ;
            ghostLastTickPosX_ = newGhostX;
            ghostLastTickPosY_ = newGhostY;
            ghostLastTickPosZ_ = newGhostZ;
            ghostPosIncrements_ = 0;
            ghostValid_ = true;
        } else {

            double dx = newGhostX - ghostTargetX_;
            double dy = newGhostY - ghostTargetY_;
            double dz = newGhostZ - ghostTargetZ_;
            double distSq = dx * dx + dy * dy + dz * dz;

            if (distSq > 0.0001) {


                ghostTargetX_ = newGhostX;
                ghostTargetY_ = newGhostY;
                ghostTargetZ_ = newGhostZ;
                ghostPosIncrements_ = 3;
            }
        }
    } else {
        ghostValid_ = false;
    }


    if (ghostValid_) {
        ghostLastTickPosX_ = ghostPosX_;
        ghostLastTickPosY_ = ghostPosY_;
        ghostLastTickPosZ_ = ghostPosZ_;

        if (ghostPosIncrements_ > 0) {
            double inc = static_cast<double>(ghostPosIncrements_);
            ghostPosX_ += (ghostTargetX_ - ghostPosX_) / inc;
            ghostPosY_ += (ghostTargetY_ - ghostPosY_) / inc;
            ghostPosZ_ += (ghostTargetZ_ - ghostPosZ_) / inc;
            --ghostPosIncrements_;
        }
    }


    processKeepAliveQueue(env);
}


void ReachMode::onRender3d(const Render3dEvent& event) {
    JNIEnv* env = event.getEnv();
    if (!env || !tracking_ || !ghostValid_ || !module_.isDrawBox()) return;

    renderAlpha_ = std::lerp(renderAlpha_, 1.0f, 0.15f);

    float partialTicks = event.getPartialTicks();


    double interpX = ghostLastTickPosX_ + (ghostPosX_ - ghostLastTickPosX_) * partialTicks;
    double interpY = ghostLastTickPosY_ + (ghostPosY_ - ghostLastTickPosY_) * partialTicks;
    double interpZ = ghostLastTickPosZ_ + (ghostPosZ_ - ghostLastTickPosZ_) * partialTicks;

    auto mc = Minecraft::getMinecraft(env);
    if (mc.isNull()) return;

    Vec3D renderPos{};
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

    Vector3f minPos(
        static_cast<float>(interpX - renderPos.x) - static_cast<float>(HITBOX_HALF_W),
        static_cast<float>(interpY - renderPos.y),
        static_cast<float>(interpZ - renderPos.z) - static_cast<float>(HITBOX_HALF_W)
    );
    Vector3f maxPos(
        static_cast<float>(interpX - renderPos.x) + static_cast<float>(HITBOX_HALF_W),
        static_cast<float>(interpY - renderPos.y) + static_cast<float>(HITBOX_HEIGHT),
        static_cast<float>(interpZ - renderPos.z) + static_cast<float>(HITBOX_HALF_W)
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


bool ReachMode::findHittableGhost(JNIEnv* env, double& bestDist) {
    if (!ghostValid_) return false;

    auto mc = Minecraft::getMinecraft(env);
    if (mc.isNull()) return false;
    auto player = mc.thePlayer();
    if (player.isNull()) return false;

    double eyeX = player.posX();
    double eyeY = player.posY() + player.getEyeHeight();
    double eyeZ = player.posZ();

    float yaw = player.rotationYaw();
    float pitch = player.rotationPitch();
    double yawRad = yaw * M_PI / 180.0;
    double pitchRad = pitch * M_PI / 180.0;

    double dirX = -std::sin(yawRad) * std::cos(pitchRad);
    double dirY = -std::sin(pitchRad);
    double dirZ = std::cos(yawRad) * std::cos(pitchRad);


    constexpr double reach = 3.0;


    double gx = ghostTargetX_;
    double gy = ghostTargetY_;
    double gz = ghostTargetZ_;


    double dx = gx - eyeX;
    double dy = (gy + HITBOX_HEIGHT * 0.5) - eyeY;
    double dz = gz - eyeZ;
    double centerDist = std::sqrt(dx * dx + dy * dy + dz * dz);
    if (centerDist > reach + 2.0) return false;

    double dist = 0;
    if (rayIntersectsBoxAt(gx, gy, gz,
                            eyeX, eyeY, eyeZ, dirX, dirY, dirZ, dist)) {
        if (dist >= 0.0 && dist <= reach) {
            bestDist = dist;
            return true;
        }
    }

    return false;
}

bool ReachMode::rayIntersectsBoxAt(double bx, double by, double bz,
                                    double eyeX, double eyeY, double eyeZ,
                                    double dirX, double dirY, double dirZ,
                                    double& hitDist) {

    double hw = HITBOX_HALF_W + HITBOX_EXPAND;
    double minX = bx - hw, maxX = bx + hw;
    double minY = by - HITBOX_EXPAND, maxY = by + HITBOX_HEIGHT + HITBOX_EXPAND;
    double minZ = bz - hw, maxZ = bz + hw;

    double tmin = -1e30, tmax = 1e30;

    auto slabCheck = [&](double origin, double dir, double bmin, double bmax) -> bool {
        if (std::abs(dir) < 1e-12) {
            return origin >= bmin && origin <= bmax;
        }
        double t1 = (bmin - origin) / dir;
        double t2 = (bmax - origin) / dir;
        if (t1 > t2) std::swap(t1, t2);
        tmin = std::max(tmin, t1);
        tmax = std::min(tmax, t2);
        return tmin <= tmax && tmax >= 0.0;
    };

    if (!slabCheck(eyeX, dirX, minX, maxX)) return false;
    if (!slabCheck(eyeY, dirY, minY, maxY)) return false;
    if (!slabCheck(eyeZ, dirZ, minZ, maxZ)) return false;

    hitDist = tmin >= 0.0 ? tmin : tmax;
    return hitDist >= 0.0;
}

void ReachMode::sendAttack(JNIEnv* env, jobject targetEntity) {
    auto mc = Minecraft::getMinecraft(env);
    if (mc.isNull()) return;
    auto player = mc.thePlayer();
    if (player.isNull()) return;
    auto playerController = mc.playerController();
    if (playerController.isNull()) return;


    playerController.attackEntity(player, targetEntity);
    if (env->ExceptionCheck()) env->ExceptionClear();
}


void ReachMode::softReset(JNIEnv* env) {


    if (env) flushKeepAliveQueue(env);


    positionHistory_.clear();
    ghostTargetX_ = ghostTargetY_ = ghostTargetZ_ = 0;
    ghostPosX_ = ghostPosY_ = ghostPosZ_ = 0;
    ghostLastTickPosX_ = ghostLastTickPosY_ = ghostLastTickPosZ_ = 0;
    ghostPosIncrements_ = 0;
    ghostValid_ = false;


    nonSprintTicks_ = 0;
}

void ReachMode::reset(JNIEnv* env) {


    if (env) flushKeepAliveQueue(env);

    targetEntityId_ = -1;
    tracking_ = false;
    lastAttackTime_ = 0;
    positionHistory_.clear();
    ghostTargetX_ = ghostTargetY_ = ghostTargetZ_ = 0;
    ghostPosX_ = ghostPosY_ = ghostPosZ_ = 0;
    ghostLastTickPosX_ = ghostLastTickPosY_ = ghostLastTickPosZ_ = 0;
    ghostPosIncrements_ = 0;
    ghostValid_ = false;
    effectiveDelayMs_ = module_.getMaxDelayMs();
    lastServerPosX_ = lastServerPosY_ = lastServerPosZ_ = 0;
    lastPosWasTeleport_ = false;
    flushing_ = false;
    nonSprintTicks_ = 0;
}


void ReachMode::computeDynamicDelay(double playerX, double playerY, double playerZ,
                                     double targetX, double targetY, double targetZ) {
    if (positionHistory_.size() < 2) return;

    auto& newest = positionHistory_.back();
    auto& prev = positionHistory_[positionHistory_.size() - 2];
    double dtSec = (newest.timestamp - prev.timestamp) / 1000.0;
    if (dtSec < 0.001) return;

    double velX = (newest.x - prev.x) / dtSec;
    double velY = (newest.y - prev.y) / dtSec;
    double velZ = (newest.z - prev.z) / dtSec;

    double dx = playerX - targetX;
    double dy = playerY - targetY;
    double dz = playerZ - targetZ;
    double dist = std::sqrt(dx * dx + dy * dy + dz * dz);
    if (dist < 0.01) return;

    double nx = dx / dist, ny = dy / dist, nz = dz / dist;
    double vRadial = velX * nx + velY * ny + velZ * nz;

    constexpr double MIN_SPEED = 0.5;
    double idealDelayMs;

    if (vRadial < -MIN_SPEED) {
        idealDelayMs = (static_cast<double>(module_.getDesiredOffset()) / (-vRadial)) * 1000.0;
    } else if (vRadial > MIN_SPEED) {
        idealDelayMs = 50.0;
    } else {
        idealDelayMs = static_cast<double>(module_.getMaxDelayMs()) * 0.5;
    }

    idealDelayMs = std::clamp(idealDelayMs, 50.0, static_cast<double>(module_.getMaxDelayMs()));

    constexpr double ALPHA = 0.3;
    double newDelay = effectiveDelayMs_ + ALPHA * (idealDelayMs - effectiveDelayMs_);


    constexpr double MAX_DECREASE_PER_TICK = 55.0;
    if (newDelay < effectiveDelayMs_ - MAX_DECREASE_PER_TICK) {
        newDelay = effectiveDelayMs_ - MAX_DECREASE_PER_TICK;
    }

    effectiveDelayMs_ = std::clamp(newDelay, 50.0, static_cast<double>(module_.getMaxDelayMs()));
}


void ReachMode::processKeepAliveQueue(JNIEnv* env) {
    std::lock_guard lock(keepAliveMutex_);
    if (keepAliveQueue_.empty()) return;

    auto mc = Minecraft::getMinecraft(env);
    if (mc.isNull()) return;
    auto netHandler = mc.getNetHandler();
    if (netHandler.isNull()) return;

    long long currentTime = now();
    long long activeDelay = module_.isDynamicDelay()
        ? static_cast<long long>(effectiveDelayMs_)
        : module_.getMaxDelayMs();

    flushing_ = true;


    if (!keepAliveQueue_.empty()) {
        auto& front = keepAliveQueue_.front();
        if ((currentTime - front.second) >= activeDelay) {
            if (front.first && !env->IsSameObject(front.first, nullptr)) {
                netHandler.addToSendQueue(Packet(env, front.first));
                if (env->ExceptionCheck()) env->ExceptionClear();
            }
            if (front.first) env->DeleteGlobalRef(front.first);
            keepAliveQueue_.pop();
        }
    }

    flushing_ = false;
}

void ReachMode::flushKeepAliveQueue(JNIEnv* env) {
    std::lock_guard lock(keepAliveMutex_);
    if (keepAliveQueue_.empty()) return;

    auto mc = Minecraft::getMinecraft(env);
    if (mc.isNull()) {
        while (!keepAliveQueue_.empty()) {
            if (env && keepAliveQueue_.front().first)
                env->DeleteGlobalRef(keepAliveQueue_.front().first);
            keepAliveQueue_.pop();
        }
        return;
    }
    auto netHandler = mc.getNetHandler();
    if (netHandler.isNull()) {
        while (!keepAliveQueue_.empty()) {
            if (keepAliveQueue_.front().first)
                env->DeleteGlobalRef(keepAliveQueue_.front().first);
            keepAliveQueue_.pop();
        }
        return;
    }

    flushing_ = true;

    while (!keepAliveQueue_.empty()) {
        auto& front = keepAliveQueue_.front();
        if (front.first && !env->IsSameObject(front.first, nullptr)) {
            netHandler.addToSendQueue(Packet(env, front.first));
            if (env->ExceptionCheck()) env->ExceptionClear();
        }
        if (front.first) env->DeleteGlobalRef(front.first);
        keepAliveQueue_.pop();
    }

    flushing_ = false;
}


bool ReachMode::cachedIsInstanceOf(JNIEnv* env, jobject obj, jclass& cached, const char* className) {
    if (!cached) cached = Mappings::getInstance().getClass(className);
    return cached && env->IsInstanceOf(obj, cached);
}

bool ReachMode::isInstanceOf(JNIEnv* env, jobject obj, const char* className) {
    jclass clazz = Mappings::getInstance().getClass(className);
    return clazz && env->IsInstanceOf(obj, clazz);
}

bool ReachMode::isVelocityForSelf(JNIEnv* env, jobject packet) const {
    if (!isInstanceOf(env, packet, "S12PacketEntityVelocity")) return false;
    auto mc = Minecraft::getMinecraft(env);
    if (mc.isNull()) return false;
    auto player = mc.thePlayer();
    if (player.isNull()) return false;
    S12PacketEntityVelocity velPacket(env, packet);
    velPacket.setDeleteRef(false);
    return velPacket.pVelocity_entityId() == player.entityId();
}
