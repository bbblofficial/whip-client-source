#include "../../../../../../includes/module/impl/network/backtrack/mode/LagMode.h"
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
#include "../../../../../../includes/wrapper/minecraft/item/ItemStack.h"
#include "../../../../../../includes/wrapper/minecraft/entity/render/RenderManager.h"
#include "../../../../../../includes/handler/MappingHandler.h"
#include "../../../../../../includes/util/RenderUtils.h"

#include "provider/impl/PacketProvider.h"
#include "handler/ProviderHandler.h"
#include "wrapper/CVarsUpdater.h"

#include <GL/gl.h>
#include <cmath>
#include <chrono>

constexpr const char* LAG_IGNORED_PACKETS_1_8[] = {
    "S02PacketChat",
    "S06PacketUpdateHealth",
    "S47PacketPlayerListHeaderFooter",
    "S41PacketServerDifficulty",
    "S0BPacketAnimation"
};

constexpr const char* LAG_IGNORED_PACKETS_1_7[] = {
    "S02PacketChat",
    "S06PacketUpdateHealth",
    "S0BPacketAnimation"
};

long long LagMode::now() const {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
}

void LagMode::onEnable(JNIEnv* env) {
    target_.clear();
    lastAttackTime_ = 0;
    wasHoldingSword_ = false;
    renderAlpha_ = 0.0f;
}

void LagMode::onDisable(JNIEnv* env) {
    flushAndClear(env);
}

void LagMode::flushAndClear(JNIEnv* env) {
    target_.valid = false;
    target_.clear();
    if (auto* p = static_cast<PacketProvider*>(ProviderHandler::getInstance().getProvider(ProviderType::PACKET))) {
        if (env) p->processAndClearQueue(env);
    }
}


void LagMode::onPacketReceived(const ChannelReadEvent& event) {
    JNIEnv* env = event.getEnv();
    jobject packet = event.getPacketObject();
    if (!env || !packet) return;

    if (isIgnoredPacket(env, packet)) return;

    if (isInstanceOf(env, packet, "S08PacketPlayerPosLook")) {
        flushAndClear(env);
        return;
    }

    if (isVelocityForSelf(env, packet)) {
        flushAndClear(env);
        return;
    }

    if (isInstanceOf(env, packet, "S40PacketDisconnect")) {
        flushAndClear(env);
        return;
    }

    if (isInstanceOf(env, packet, "S13PacketDestroyEntities")) {
        S13PacketDestroyEntities destroyPacket(env, packet);
        destroyPacket.setDeleteRef(false);
        if (destroyPacket.containsEntityId(target_.entityId)) {
            flushAndClear(env);
            return;
        }
    }

    if (isInstanceOf(env, packet, "S19PacketEntityStatus")) {
        S19PacketEntityStatus statusPacket(env, packet);
        statusPacket.setDeleteRef(false);
        if (statusPacket.entityId() == target_.entityId && statusPacket.isDeath()) {
            flushAndClear(env);
            return;
        }
    }

    if (!target_.valid) return;

    if (isInstanceOf(env, packet, "S14PacketEntity")) {
        S14PacketEntity s14Packet(env, packet);
        s14Packet.setDeleteRef(false);
        if (s14Packet.entityId() == target_.entityId) {
            target_.serverPosX += s14Packet.posX();
            target_.serverPosY += s14Packet.posY();
            target_.serverPosZ += s14Packet.posZ();

            target_.newPosition = {
                static_cast<double>(target_.serverPosX) / 32.0,
                static_cast<double>(target_.serverPosY) / 32.0,
                static_cast<double>(target_.serverPosZ) / 32.0
            };
            target_.posRotationIncrements = 3;
        }
    }

    if (isInstanceOf(env, packet, "S18PacketEntityTeleport")) {
        S18PacketEntityTeleport s18Packet(env, packet);
        s18Packet.setDeleteRef(false);
        if (s18Packet.entityId() == target_.entityId) {
            target_.serverPosX = s18Packet.posX();
            target_.serverPosY = s18Packet.posY();
            target_.serverPosZ = s18Packet.posZ();

            target_.newPosition = {
                static_cast<double>(target_.serverPosX) / 32.0,
                static_cast<double>(target_.serverPosY) / 32.0,
                static_cast<double>(target_.serverPosZ) / 32.0
            };
            target_.posRotationIncrements = 3;
        }
    }

    auto* provider = static_cast<PacketProvider*>(ProviderHandler::getInstance().getProvider(ProviderType::PACKET));
    if (!provider) return;

    provider->setDelay(module_.getDelayInTicks() * 50);
    provider->queuePacket(env, packet);
    const_cast<ChannelReadEvent&>(event).setCancelled(true);
}


void LagMode::onTick(const OnRunTickEvent& event) {
    JNIEnv* env = event.getEnv();
    if (!env) return;

    auto* provider = static_cast<PacketProvider*>(ProviderHandler::getInstance().getProvider(ProviderType::PACKET));
    if (!provider) return;

    auto minecraft = Minecraft::getMinecraft(env);
    if (!minecraft.isNull()) {
        auto player = minecraft.thePlayer();
        if (!player.isNull() && player.hasEnderPearl()) {
            if (target_.valid) flushAndClear(env);
            return;
        }
    }

    if (target_.valid) {
        target_.lastPosition = target_.position;
        if (target_.posRotationIncrements > 0) {
            double inc = static_cast<double>(target_.posRotationIncrements);
            target_.position = {
                target_.position.x + (target_.newPosition.x - target_.position.x) / inc,
                target_.position.y + (target_.newPosition.y - target_.position.y) / inc,
                target_.position.z + (target_.newPosition.z - target_.position.z) / inc
            };
            --target_.posRotationIncrements;
        }
    }

    if (target_.valid && lastAttackTime_ > 0) {
        if ((now() - lastAttackTime_) > module_.getCooldown()) {
            flushAndClear(env);
            return;
        }
    }


    if (target_.valid) {
        auto mc = Minecraft::getMinecraft(env);
        if (!mc.isNull()) {
            auto player = mc.thePlayer();
            if (!player.isNull()) {
                auto heldItem = player.getHeldItem();
                bool holdingSword = !heldItem.isNull() && heldItem.isSword();
                if (wasHoldingSword_ && !holdingSword) {
                    flushAndClear(env);
                    return;
                }
                wasHoldingSword_ = holdingSword;
            }
        }
    }

    if (module_.isDistanceCheck() && target_.valid) {
        auto mc = Minecraft::getMinecraft(env);
        if (!mc.isNull()) {
            auto player = mc.thePlayer();
            auto world = mc.theWorld();
            if (!player.isNull() && !world.isNull()) {
                auto targetEntity = world.getEntityByID(target_.entityId);
                if (!targetEntity.isNull()) {
                    double dx = player.posX() - targetEntity.posX();
                    double dy = player.posY() - targetEntity.posY();
                    double dz = player.posZ() - targetEntity.posZ();
                    double dist = std::sqrt(dx * dx + dy * dy + dz * dz);

                    if (dist < module_.getDistance() || dist > module_.getDistanceMax()) {
                        flushAndClear(env);
                        return;
                    }
                }
            }
        }
    }

    provider->processDelayedPackets(env);
}


void LagMode::onPlayerAttack(const PlayerAttackEvent& event) {
    JNIEnv* env = event.getEnv();
    if (!env) return;

    int targetId = event.getTargetEntityId();
    if (targetId == -1) return;

    auto minecraft = Minecraft::getMinecraft(env);
    if (minecraft.isNull()) return;
    auto player = minecraft.thePlayer();
    if (player.isNull() || targetId == player.entityId()) return;

    if (module_.isDistanceCheck()) {
        auto world = minecraft.theWorld();
        if (!world.isNull()) {
            auto targetEntity = world.getEntityByID(targetId);
            if (!targetEntity.isNull()) {
                double dx = player.posX() - targetEntity.posX();
                double dy = player.posY() - targetEntity.posY();
                double dz = player.posZ() - targetEntity.posZ();
                double dist = std::sqrt(dx * dx + dy * dy + dz * dz);
                if (dist < module_.getDistance() || dist > module_.getDistanceMax()) return;
            }
        }
    }

    if (targetId != target_.entityId) {
        constexpr long long SWAP_COOLDOWN_MS = 350;
        if (target_.valid && lastAttackTime_ > 0 && (now() - lastAttackTime_) < SWAP_COOLDOWN_MS) {
            return;
        }
        lastAttackTime_ = now();
        auto* provider = static_cast<PacketProvider*>(ProviderHandler::getInstance().getProvider(ProviderType::PACKET));
        if (!provider) return;
        clearTarget(env);
        if (provider->getQueueSize() <= 0) {
            setTarget(env, targetId);
        }
    } else {
        lastAttackTime_ = now();
        target_.targetTime = now();
    }
}


void LagMode::onRender3d(const Render3dEvent& event) {
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


void LagMode::setTarget(JNIEnv* env, int entityId) {
    if (!env || entityId == -1) return;

    auto minecraft = Minecraft::getMinecraft(env);
    if (minecraft.isNull()) return;
    auto world = minecraft.theWorld();
    if (world.isNull()) return;
    auto entity = world.getEntityByID(entityId);
    if (entity.isNull()) return;

    target_.entityId = entityId;
    target_.serverPosX = entity.serverPosX();
    target_.serverPosY = entity.serverPosY();
    target_.serverPosZ = entity.serverPosZ();

    double posX = static_cast<double>(target_.serverPosX) / 32.0;
    double posY = static_cast<double>(target_.serverPosY) / 32.0;
    double posZ = static_cast<double>(target_.serverPosZ) / 32.0;

    target_.position = {posX, posY, posZ};
    target_.lastPosition = target_.position;
    target_.newPosition = target_.position;
    target_.posRotationIncrements = 0;
    target_.targetTime = now();
    target_.valid = true;
}

void LagMode::clearTarget(JNIEnv* env) {
    flushAndClear(env);
}

bool LagMode::isInstanceOf(JNIEnv* env, jobject obj, const char* className) {
    jclass clazz = Mappings::getInstance().getClass(className);
    return clazz && env->IsInstanceOf(obj, clazz);
}

bool LagMode::isIgnoredPacket(JNIEnv* env, jobject packet) const {
    if (MinecraftSession::getInstance().version == MinecraftVersion::V1_8_9) {
        for (const char* packetName : LAG_IGNORED_PACKETS_1_8) {
            if (isInstanceOf(env, packet, packetName)) return true;
        }
    } else {
        for (const char* packetName : LAG_IGNORED_PACKETS_1_7) {
            if (isInstanceOf(env, packet, packetName)) return true;
        }
    }
    return false;
}

bool LagMode::isVelocityForSelf(JNIEnv* env, jobject packet) const {
    if (!isInstanceOf(env, packet, "S12PacketEntityVelocity")) return false;

    auto minecraft = Minecraft::getMinecraft(env);
    if (minecraft.isNull()) return false;
    auto player = minecraft.thePlayer();
    if (player.isNull()) return false;

    S12PacketEntityVelocity velocityPacket(env, packet);
    velocityPacket.setDeleteRef(false);
    if (velocityPacket.pVelocity_entityId() != player.entityId()) return false;

    constexpr int KB_THRESHOLD = 800;
    return std::abs(velocityPacket.pVelocity_motionX()) > KB_THRESHOLD ||
           std::abs(velocityPacket.pVelocity_motionY()) > KB_THRESHOLD ||
           std::abs(velocityPacket.pVelocity_motionZ()) > KB_THRESHOLD;
}
