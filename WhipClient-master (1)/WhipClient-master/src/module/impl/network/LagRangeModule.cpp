#include "../../../../includes/module/impl/network/LagRangeModule.h"
#include "../../../../includes/wrapper/minecraft/client/Minecraft.h"
#include "../../../../includes/wrapper/minecraft/client/multiplayer/WorldClient.h"
#include "../../../../includes/wrapper/minecraft/entity/EntityLivingBase.h"
#include "../../../../includes/wrapper/minecraft/entity/player/EntityPlayer.h"
#include "../../../../includes/wrapper/minecraft/entity/render/RenderManager.h"
#include "../../../../includes/wrapper/minecraft/client/activerenderinfo/ActiveRenderInfo2.h"
#include "../../../../includes/wrapper/minecraft/item/ItemStack.h"
#include "../../../../includes/provider/impl/PacketProvider.h"
#include "../../../../includes/provider/impl/GameStateProvider.h"
#include "../../../../includes/handler/ProviderHandler.h"
#include "../../../../includes/handler/MappingHandler.h"
#include "../../../../includes/util/Debug.h"
#include "../../../../includes/util/RenderUtils.h"

#include "ClientMain.h"
#include "setting/SettingMacros.h"
#include "wrapper/CVarsUpdater.h"
#include "wrapper/primitive/JavaObject.h"

#include <GL/gl.h>
#include <cmath>

// Crash tracer disabled (CheatBreaker GC crash root-caused to JNI double-free, now fixed).
// Counters kept as harmless no-ops; LR_TRACE compiles to nothing (no per-frame disk I/O).
namespace {
    unsigned long long g_lrFrame = 0;
    unsigned long long g_lrUse = 0;
}
#define LR_TRACE(s) ((void)0)

jclass LagRangeModule::C02PacketUseEntityClass_ = nullptr;
jclass LagRangeModule::C08PacketBlockPlacementClass_ = nullptr;
jclass LagRangeModule::C17PacketCustomPayloadClass_ = nullptr;
jclass LagRangeModule::C00PacketKeepAliveClass_ = nullptr;
jclass LagRangeModule::C0FPacketConfirmTransactionClass_ = nullptr;
jclass LagRangeModule::S07PacketRespawnClass_ = nullptr;
jclass LagRangeModule::S08PacketPlayerPosLookClass_ = nullptr;

void LagRangeModule::onLoad() {
    Render3dBaseModule::onLoad();
    COMBO_SETTING(mode, "Static", "Dynamic");
    FLOAT_SLIDER(activationDistance, 6.0f, 4.0f, 10.0f);
    FLOAT_SLIDER(flushDistance, 4.0f, 0.0f, 10.0f);
    INT_SLIDER_OPTIONAL(delay, 300, 100, 1000, SETTING_VISIBILITY(mode == 1));
    BOOL_SETTING_CONDITIONAL(onlyWeapon, true);
    BOOL_SETTING_CONDITIONAL(onlySprinting, false);
    BOOL_SETTING_CONDITIONAL(drawBox, true);
    COLOR_SETTING_CONDITIONAL_OPTIONAL(boxColor, ImColor(0.58f, 0.12f, 0.14f, 0.34f), SETTING_VISIBILITY(drawBox));
    COLOR_SETTING_CONDITIONAL_OPTIONAL(outlineColor, ImColor(1.0f, 0.3f, 0.3f, 1.0f), SETTING_VISIBILITY(drawBox));
}

void LagRangeModule::onEnable() {
    ++g_lrUse;
    LR_TRACE("onEnable");
    Render3dBaseModule::onEnable();
    resetState();
    LR_TRACE("onEnable done");
}

void LagRangeModule::onDisable() {
    LR_TRACE("onDisable");
    Render3dBaseModule::onDisable();

    JNIEnv* env = nullptr;
    JavaVM* jvm = nullptr;
    if (JNI_GetCreatedJavaVMs(&jvm, 1, nullptr) == JNI_OK && jvm) {
        jvm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_8);
    }

    if (env) {
        flushQueue(env);
    }

    resetState();
    LR_TRACE("onDisable done");
}

void LagRangeModule::registerEvents() {
    Render3dBaseModule::registerEvents();

    subscribe<AddSendQueueEvent>([this](const AddSendQueueEvent& event) {
        onPacketSend(event);
    }, EventPriority::HIGH, false);

    subscribe<ChannelReadEvent>([this](const ChannelReadEvent& event) {
        onPacketReceived(event);
    });
}

void LagRangeModule::onPacketSend(const AddSendQueueEvent& event) {
    if (!this->enable) return;

    JNIEnv* env = event.getEnv();
    jobject packet = event.getPacketObject();
    if (!env || !packet) return;

    auto* provider = static_cast<PacketProvider*>(ProviderHandler::getInstance().getProvider(ProviderType::PACKET));
    if (!provider) return;

    if (isLagging_ && lagStartTime_ > 0 && (getCurrentTime() - lagStartTime_) > 1000) {
        flushQueue(env);
        return;
    }

    if (fixPing && isLagging_) {
        if (isInstanceOf(env, packet, C00PacketKeepAliveClass_, "C00PacketKeepAlive") ||
            isInstanceOf(env, packet, C0FPacketConfirmTransactionClass_, "C0FPacketConfirmTransaction")) {
            return;
        }
    }

    if (usedSplashPotion && isHoldingSplashPotion(env)) {
        if (isLagging_) flushQueue(env);
        return;
    }

    if (isFlushTrigger(env, packet)) {
        if (isLagging_) {
            flushQueue(env);

            auto mc = Minecraft::getMinecraft(env);
            if (!mc.isNull()) {
                auto netHandler = mc.getNetHandler();
                if (!netHandler.isNull()) {
                    NetworkManager netManager = netHandler.getNetworkManager();
                    if (!netManager.isNull()) {
                        netManager.dispatchPacket(packet);
                    }
                }
            }
            const_cast<AddSendQueueEvent&>(event).setCancelled(true);
        }
        return;
    }

    ticksSinceRespawn_++;

    if (ticksSinceRespawn_ < 100) {
        return;
    }

    auto mc = Minecraft::getMinecraft(env);
    if (mc.isNull()) {
        flushQueue(env);
        return;
    }

    auto player = mc.thePlayer();
    if (player.isNull()) {
        flushQueue(env);
        return;
    }

    if (player.isDead()) {
        flushQueue(env);
        return;
    }

    if (onlyWeapon) {
        auto* gameState = static_cast<GameStateProvider*>(ProviderHandler::getInstance().getProvider(ProviderType::GAME_STATE));
        bool hasWeapon = gameState ? gameState->hasWeaponInHand() : false;
        if (!hasWeapon) {
            if (isLagging_) flushQueue(env);
            return;
        }
    }

    if (onlySprinting && !player.isSprinting()) {
        if (isLagging_) flushQueue(env);
        return;
    }

    Vector3d currentPos(player.posX(), player.posY(), player.posZ());

    if (sprintReset && isLagging_) {
        bool currentlySprinting = player.isSprinting();
        if (wasSprinting_ && !currentlySprinting) {
            flushQueue(env);
            lastLocalPosition_ = currentPos;
            wasSprinting_ = currentlySprinting;
            return;
        }
        wasSprinting_ = currentlySprinting;
    }

    if (!shouldActivateLag(env)) {
        if (isLagging_) flushQueue(env);
        lastLocalPosition_ = currentPos;
        return;
    }

    if (!isLagging_) {
        LR_TRACE("lag ACTIVATE");
        lastServerPosition_ = currentPos;
        lastDrawPosition_ = currentPos;
        currentDrawPosition_ = currentPos;
        lagStartTime_ = getCurrentTime();
        isLagging_ = true;
    }

    long long now = getCurrentTime();

    provider->setOutboundDelay(delay);
    LR_TRACE("queueOutboundPacket pre");
    provider->queueOutboundPacket(env, packet);
    LR_TRACE("queueOutboundPacket post");
    lastQueueTime_ = now;
    lastLocalPosition_ = currentPos;

    if (mode == 1) {
        positionHistory_.push_back({now, currentPos});
        long long cutoff = now - delay * 2;
        while (!positionHistory_.empty() && positionHistory_.front().timestamp < cutoff) {
            positionHistory_.pop_front();
        }
    }

    const_cast<AddSendQueueEvent&>(event).setCancelled(true);
}

void LagRangeModule::onPacketReceived(const ChannelReadEvent& event) {
    if (!this->enable) return;

    JNIEnv* env = event.getEnv();
    jobject packet = event.getPacketObject();
    if (!env || !packet) return;

    bool shouldReset = isInstanceOf(env, packet, S07PacketRespawnClass_, "S07PacketRespawn")
                    || isInstanceOf(env, packet, S08PacketPlayerPosLookClass_, "S08PacketPlayerPosLook");

    if (shouldReset) {
        ticksSinceRespawn_ = 0;
        isLagging_ = false;
        flushQueue(env);
    }
}

void LagRangeModule::onTick(const OnTickEvent& event) {
}

bool LagRangeModule::isHoldingSplashPotion(JNIEnv* env) const {
    auto mc = Minecraft::getMinecraft(env);
    if (mc.isNull()) return false;

    auto player = mc.thePlayer();
    if (player.isNull()) return false;

    ItemStack heldItem = player.getCurrentEquippedItem();
    if (heldItem.isNull()) return false;

    if (!heldItem.isPotion()) return false;

    int meta = heldItem.metadata();
    return (meta & 16384) != 0;
}

bool LagRangeModule::shouldActivateLag(JNIEnv* env) const {
    auto mc = Minecraft::getMinecraft(env);
    if (mc.isNull()) return false;

    auto player = mc.thePlayer();
    if (player.isNull()) return false;

    EntityLivingBase playerLiving(env, player.getObj());
    playerLiving.setDeleteRef(false);
    if (playerLiving.hurtTime() > 0) return false;

    if (player.isDead()) return false;

    auto world = mc.theWorld();
    if (world.isNull()) return false;

    double myX = player.posX();
    double myY = player.posY();
    double myZ = player.posZ();
    float myYaw = player.rotationYaw();
    float myPitch = player.rotationPitch();

    const ArrayList entityList = world.playerEntities();
    if (entityList.isNull()) return false;

    int closestId = -1;
    double closestDist = 999.0;
    double closestX = 0, closestY = 0, closestZ = 0;

    const int size = entityList.size();
    for (int i = 0; i < size; i++) {
        JavaObject entityObj = entityList.get(i);
        if (entityObj.isNull()) continue;

        // entityObj owns the local ref. convertTo() returns a COPY that points at the SAME
        // jobject with deleteRef=true, so without this each copy's destructor would call
        // DeleteLocalRef on the same handle (double/triple free). Java 17 tolerated it; Java 25
        // (CheatBreaker) corrupts the JNI handle block -> GC crash. Only entityObj may delete.
        auto entity = entityObj.convertTo<Entity>();
        entity.setDeleteRef(false);
        if (entity.isNull()) continue;

        if (entity.entityId() == player.entityId()) continue;

        auto livingEntity = entityObj.convertTo<EntityLivingBase>();
        livingEntity.setDeleteRef(false);
        if (livingEntity.getHealth() <= 0) continue;

        double dx = myX - entity.posX();
        double dy = myY - entity.posY();
        double dz = myZ - entity.posZ();
        double dist = std::sqrt(dx * dx + dy * dy + dz * dz);

        if (dist < closestDist) {
            closestDist = dist;
            closestId = entity.entityId();
            closestX = entity.posX();
            closestY = entity.posY();
            closestZ = entity.posZ();
        }
    }

    if (closestId == -1) return false;
    if (closestDist < flushDistance || closestDist > activationDistance) return false;

    double dirX = closestX - myX;
    double dirY = (closestY + 0.9) - (myY + 1.62);
    double dirZ = closestZ - myZ;

    double horizontalDist = std::sqrt(dirX * dirX + dirZ * dirZ);

    double targetYaw = std::atan2(-dirX, dirZ) * 180.0 / PI;
    double targetPitch = -std::atan2(dirY, horizontalDist) * 180.0 / PI;

    float normalizedYaw = std::fmod(myYaw, 360.0f);
    if (normalizedYaw < 0) normalizedYaw += 360.0f;

    double normalizedTargetYaw = std::fmod(targetYaw, 360.0);
    if (normalizedTargetYaw < 0) normalizedTargetYaw += 360.0;

    double yawDiff = std::abs(static_cast<double>(normalizedYaw) - normalizedTargetYaw);
    if (yawDiff > 180.0) yawDiff = 360.0 - yawDiff;

    double pitchDiff = std::abs(static_cast<double>(myPitch) - targetPitch);
    double totalAngle = std::sqrt(yawDiff * yawDiff + pitchDiff * pitchDiff);

    if (totalAngle > 45.0) return false;

    if (isLagging_) return true;

    double distToTarget = std::sqrt(dirX * dirX + dirY * dirY + dirZ * dirZ);
    if (distToTarget < 0.001) return false;

    Vector3d velocity(
        myX - lastLocalPosition_.x,
        myY - lastLocalPosition_.y,
        myZ - lastLocalPosition_.z
    );

    Vector3d dirNorm(dirX / distToTarget, dirY / distToTarget, dirZ / distToTarget);
    double approachSpeed = velocity.x * dirNorm.x + velocity.y * dirNorm.y + velocity.z * dirNorm.z;

    if (approachSpeed <= 0.01) return false;

    return true;
}

bool LagRangeModule::isFlushTrigger(JNIEnv* env, jobject packet) const {
    return isInstanceOf(env, packet, C02PacketUseEntityClass_, "C02PacketUseEntity")
        || isInstanceOf(env, packet, C08PacketBlockPlacementClass_, "C08PacketPlayerBlockPlacement");
}

bool LagRangeModule::isSkippedPacket(JNIEnv* env, jobject packet) const {
    return false;
}

void LagRangeModule::flushQueue(JNIEnv* env) {
    LR_TRACE("flushQueue pre");
    auto* provider = static_cast<PacketProvider*>(ProviderHandler::getInstance().getProvider(ProviderType::PACKET));
    if (provider) {
        provider->processAndClearOutboundQueue(env);
    }
    isLagging_ = false;
    positionHistory_.clear();
    LR_TRACE("flushQueue post");
}

void LagRangeModule::resetState() {
    lastServerPosition_ = Vector3d(0.0, 0.0, 0.0);
    lastLocalPosition_ = Vector3d(0.0, 0.0, 0.0);
    dynamicServerPosition_ = Vector3d(0.0, 0.0, 0.0);
    lastDrawPosition_ = Vector3d(0.0, 0.0, 0.0);
    currentDrawPosition_ = Vector3d(0.0, 0.0, 0.0);
    positionHistory_.clear();
    ticksSinceRespawn_ = 0;
    isLagging_ = false;
    lastQueueTime_ = 0;
    lagStartTime_ = 0;
    renderAlpha_ = 0.0f;
    wasSprinting_ = false;
}

bool LagRangeModule::isInstanceOf(JNIEnv* env, jobject obj, jclass& cached, const char* className) {
    if (!cached) {
        cached = Mappings::getInstance().getClass(className);
        if (!cached) {
        }
    }
    return cached && env->IsInstanceOf(obj, cached);
}

void LagRangeModule::onRender3d(const Render3dEvent& event) {
    if (!this->enable) return;

    JNIEnv* env = event.getEnv();
    if (!env) return;

    ++g_lrFrame;
    LR_TRACE("enter");

    {
        auto mc = Minecraft::getMinecraft(env);
        if (mc.isNull() || mc.theWorld().isNull() || mc.thePlayer().isNull()) {
            if (isLagging_) flushQueue(env);
            resetState();
            renderAlpha_ = 0.0f;
            return;
        }
    }

    LR_TRACE("after mc-check");

    if (mode == 1 && isLagging_) {
        LR_TRACE("dynamic block enter");
        auto* provider = static_cast<PacketProvider*>(ProviderHandler::getInstance().getProvider(ProviderType::PACKET));
        if (provider) {
            provider->processOutboundPackets(env);

            long long now = getCurrentTime();
            long long releaseTime = now - delay;

            lastDrawPosition_ = currentDrawPosition_;

            Vector3d targetPos = lastServerPosition_;
            bool found = false;

            for (size_t i = 1; i < positionHistory_.size(); i++) {
                if (positionHistory_[i].timestamp >= releaseTime) {
                    auto& prev = positionHistory_[i - 1];
                    auto& next = positionHistory_[i];
                    long long dt = next.timestamp - prev.timestamp;
                    if (dt > 0) {
                        double t = static_cast<double>(releaseTime - prev.timestamp) / static_cast<double>(dt);
                        t = std::clamp(t, 0.0, 1.0);
                        targetPos.x = prev.position.x + (next.position.x - prev.position.x) * t;
                        targetPos.y = prev.position.y + (next.position.y - prev.position.y) * t;
                        targetPos.z = prev.position.z + (next.position.z - prev.position.z) * t;
                    } else {
                        targetPos = prev.position;
                    }
                    found = true;
                    break;
                }
            }

            if (!found && !positionHistory_.empty()) {
                targetPos = positionHistory_.back().position;
            }

            currentDrawPosition_ = targetPos;
        }
        LR_TRACE("dynamic block done");
    }

    if (!isLagging_) {
        renderAlpha_ = std::lerp(renderAlpha_, 0.0f, 0.15f);
        if (renderAlpha_ < 0.01f) return;
    } else {
        renderAlpha_ = std::lerp(renderAlpha_, 1.0f, 0.15f);
    }

    if (!drawBox || renderAlpha_ < 0.01f) return;

    LR_TRACE("will render box");

    auto minecraft = Minecraft::getMinecraft(env);
    if (minecraft.isNull()) return;

    Vec3D renderPos{0, 0, 0};

    if (MinecraftSession::getInstance().version == MinecraftVersion::V1_8_9) {
        LR_TRACE("getRenderManager 1.8.9 pre");
        RenderManager renderManager = minecraft.getRenderManager();
        if (renderManager.isNull()) return;
        renderPos = renderManager.getRenderPos();
        // renderManager's destructor already deletes this local ref (deleteRef=true). Calling
        // DeleteLocalRef here too is a double-free of the same handle -> JNI handle-block
        // corruption on Java 25 (CheatBreaker) -> GC crash. Let the destructor own it.
        LR_TRACE("getRenderManager 1.8.9 post");
    }
    if (MinecraftSession::getInstance().version == MinecraftVersion::V1_7_10) {
        LR_TRACE("getRenderManager 1.7.10 pre");
        RenderManager renderManager = RenderManager::getInstance(env);
        if (renderManager.isNull()) return;
        renderPos = renderManager.getRenderPos();
        renderPos.y += 1.62;
        // Destructor deletes this local ref; no explicit DeleteLocalRef (double-free on Java 25).
        LR_TRACE("getRenderManager 1.7.10 post");
    }

    Vector3d drawPos;
    if (mode == 1) {
        LR_TRACE("timer pre");
        float partialTicks = minecraft.timer().GetrenderPartialTicks();
        LR_TRACE("timer post");
        drawPos.x = lastDrawPosition_.x + (currentDrawPosition_.x - lastDrawPosition_.x) * partialTicks;
        drawPos.y = lastDrawPosition_.y + (currentDrawPosition_.y - lastDrawPosition_.y) * partialTicks;
        drawPos.z = lastDrawPosition_.z + (currentDrawPosition_.z - lastDrawPosition_.z) * partialTicks;
    } else {
        drawPos = lastServerPosition_;
    }

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

    LR_TRACE("activeRenderInfo pre");
    auto activeRenderInfo = ActiveRenderInfo2::getInstance(env);
    if (!activeRenderInfo.isNull()) {
        activeRenderInfo.getModelView(CVarsUpdater::ModelView);
        activeRenderInfo.getProjection(CVarsUpdater::Projection);
    }
    LR_TRACE("activeRenderInfo post");

    // Push/restore each matrix stack explicitly. The incoming matrix mode is host-dependent:
    // Lunar/vanilla leave GL_MODELVIEW active (deep stack), but CheatBreaker leaves GL_PROJECTION
    // active, whose stack is only guaranteed 2 deep. Relying on the incoming mode for a bare
    // glPushMatrix() overflows the projection stack after ~2 frames on CheatBreaker (GL_STACK_OVERFLOW),
    // which corrupts the matrix and stops the box from rendering. Always save/restore both stacks.
    glMatrixMode(GL_PROJECTION);
    glPushMatrix();
    glLoadMatrixd(CVarsUpdater::Projection.data());
    glMatrixMode(GL_MODELVIEW);
    glPushMatrix();
    glLoadMatrixd(CVarsUpdater::ModelView.data());

    LR_TRACE("gl matrices set");

    RenderUtils::setupRenderState(2.0f);
    Color outlineCol(outlineColor.Value.x, outlineColor.Value.y, outlineColor.Value.z, outlineColor.Value.w * renderAlpha_);
    Color fillCol(boxColor.Value.x, boxColor.Value.y, boxColor.Value.z, boxColor.Value.w * renderAlpha_);
    RenderUtils::drawBoxLines(minPos, maxPos, outlineCol);
    RenderUtils::drawBoxFilled(minPos, maxPos, fillCol);
    RenderUtils::restoreRenderState();

    glMatrixMode(GL_PROJECTION);
    glPopMatrix();
    glMatrixMode(GL_MODELVIEW);
    glPopMatrix();

    LR_TRACE("frame end");
}

REGISTER_MODULE(LagRangeModule, ModuleType::LAG_RANGE)
