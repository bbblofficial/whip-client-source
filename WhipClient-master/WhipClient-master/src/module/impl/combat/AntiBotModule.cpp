#include "module/impl/combat/AntiBotModule.h"
#include "wrapper/minecraft/client/Minecraft.h"
#include "wrapper/minecraft/client/entity/EntityClientPlayerMP.h"
#include "wrapper/minecraft/entity/EntityLivingBase.h"
#include "wrapper/minecraft/entity/player/EntityPlayer.h"
#include "wrapper/minecraft/network/Packet.h"
#include "wrapper/minecraft/network/play/server/S0CPacketSpawnPlayer.h"
#include "wrapper/minecraft/network/play/server/S14PacketEntity.h"
#include "wrapper/minecraft/network/play/server/S18PacketEntityTeleport.h"
#include "wrapper/java/util/ArrayList.h"
#include "handler/MappingHandler.h"
#include "util/MinecraftDetails.h"

#include <cmath>

void AntiBotModule::resolveJni(JNIEnv* env) {
    if (jniResolved_) return;
    jniResolved_ = true;

    clsS14Packet_ = Mappings::getInstance().getClass("S14PacketEntity");
    clsS18Packet_ = Mappings::getInstance().getClass("S18PacketEntityTeleport");
    clsNetHandler_ = Mappings::getInstance().getClass("NetHandlerPlayClient");
}

void AntiBotModule::populateExistingPlayers(JNIEnv* env) {
    Minecraft mc = Minecraft::getMinecraft(env);
    if (mc.isNull()) return;
    EntityClientPlayerMP player = mc.thePlayer();
    if (player.isNull()) return;
    World world = player.worldObj();
    if (world.isNull()) return;
    world.setDeleteRef(false);

    ArrayList playerList = world.playerEntities();
    if (playerList.isNull()) return;

    int count = playerList.size();
    if (env->ExceptionCheck()) { env->ExceptionClear(); return; }
    std::lock_guard lock(mutex_);
    for (int i = 0; i < count; i++) {
        JavaObject obj = playerList.get(i);
        if (env->ExceptionCheck()) { env->ExceptionClear(); break; }
        if (obj.isNull()) continue;
        Entity entity(env, obj.getObj());
        entity.setDeleteRef(false);
        int eid = entity.entityId();

        spawnedPlayerIds_.insert(eid);
        receivedMovementPacket_.insert(eid);
    }
}

void AntiBotModule::registerEvents() {
    subscribe<ChannelReadEvent>([this](const ChannelReadEvent& event) {
        if (this->enable) this->onPacketReceived(event);
    }, EventPriority::HIGH, false);

    subscribe<OnRunTickEvent>([this](const OnRunTickEvent& event) {
        if (this->enable) this->onTick(event);
    });
}

void AntiBotModule::onPacketReceived(const ChannelReadEvent& event) {
    JNIEnv* env = event.getEnv();
    jobject packet = event.getPacketObject();
    if (!env || !packet) return;

    resolveJni(env);

    if (S0CPacketSpawnPlayer::isInstance(env, packet)) {
        S0CPacketSpawnPlayer spawn(env, packet);
        spawn.setDeleteRef(false);
        int entityId = spawn.getEntityID();
        if (entityId >= 0) {
            std::lock_guard lock(mutex_);
            spawnedPlayerIds_.insert(entityId);
            confirmedBotIds_.erase(entityId);
        }
    }

    if (clsS14Packet_ && env->IsInstanceOf(packet, clsS14Packet_)) {
        S14PacketEntity s14(env, packet);
        s14.setDeleteRef(false);
        int eid = s14.entityId();
        if (eid > 0) {
            std::lock_guard lock(mutex_);
            receivedMovementPacket_.insert(eid);
        }
    }

    if (clsS18Packet_ && env->IsInstanceOf(packet, clsS18Packet_)) {
        S18PacketEntityTeleport s18(env, packet);
        s18.setDeleteRef(false);
        int eid = s18.entityId();
        if (eid > 0) {
            std::lock_guard lock(mutex_);
            receivedMovementPacket_.insert(eid);
        }
    }
}

bool AntiBotModule::isInTabList(JNIEnv* env, jobject entityObj) {

    const bool is17 = MinecraftSession::getInstance().version == MinecraftVersion::V1_7_10;

    EntityPlayer player(env, entityObj);
    player.setDeleteRef(false);
    GameProfile gp = player.gameProfile();
    if (gp.isNull()) return false;
    gp.setDeleteRef(false);
    jobject profile = gp.getObj();

    static jmethodID midGetKey = nullptr;
    if (!midGetKey) {
        jclass gpClass = env->GetObjectClass(profile);
        if (gpClass) {
            const char* getter    = is17 ? "getName" : "getId";
            const char* getterSig = is17 ? "()Ljava/lang/String;" : "()Ljava/util/UUID;";
            midGetKey = env->GetMethodID(gpClass, getter, getterSig);
            if (env->ExceptionCheck()) { env->ExceptionClear(); midGetKey = nullptr; }
            env->DeleteLocalRef(gpClass);
        }
    }
    if (!midGetKey) { env->DeleteLocalRef(profile); return true; }

    jobject key = env->CallObjectMethod(profile, midGetKey);
    env->DeleteLocalRef(profile);
    if (env->ExceptionCheck()) { env->ExceptionClear(); return true; }
    if (!key) return false;

    Minecraft mc = Minecraft::getMinecraft(env);
    if (mc.isNull()) { env->DeleteLocalRef(key); return true; }

    auto netHandler = mc.getNetHandler();
    if (netHandler.isNull()) { env->DeleteLocalRef(key); return true; }
    netHandler.setDeleteRef(false);

    jobject mapObj = netHandler.getPlayerInfoMap();
    if (!mapObj) { env->DeleteLocalRef(key); return true; }

    static jmethodID midContainsKey = nullptr;
    if (!midContainsKey) {
        jclass mapClass = env->FindClass("java/util/Map");
        if (mapClass) {
            midContainsKey = env->GetMethodID(mapClass, "containsKey", "(Ljava/lang/Object;)Z");
            if (env->ExceptionCheck()) { env->ExceptionClear(); midContainsKey = nullptr; }
            env->DeleteLocalRef(mapClass);
        }
    }

    bool inTab = true;
    if (midContainsKey) {
        inTab = env->CallBooleanMethod(mapObj, midContainsKey, key) == JNI_TRUE;
        if (env->ExceptionCheck()) { env->ExceptionClear(); inTab = true; }
    }

    env->DeleteLocalRef(mapObj);
    env->DeleteLocalRef(key);
    return inTab;
}

void AntiBotModule::onTick(const OnRunTickEvent& event) {
    JNIEnv* env = event.getEnv();
    if (!env) return;

    resolveJni(env);

    if (!populated_) {
        populated_ = true;
        populateExistingPlayers(env);
    }

    Minecraft mc = Minecraft::getMinecraft(env);
    if (mc.isNull()) return;
    EntityClientPlayerMP player = mc.thePlayer();
    if (player.isNull()) return;
    World world = player.worldObj();
    if (world.isNull()) return;
    world.setDeleteRef(false);

    ArrayList playerList = world.playerEntities();
    if (playerList.isNull()) return;

    int count = playerList.size();
    if (env->ExceptionCheck()) { env->ExceptionClear(); return; }

    std::unordered_set<int> worldEntityIds;
    std::unordered_set<int> botsThisTick;

    for (int i = 0; i < count; i++) {
        JavaObject obj = playerList.get(i);
        if (env->ExceptionCheck()) { env->ExceptionClear(); break; }
        if (obj.isNull()) continue;

        Entity entity(env, obj.getObj());
        entity.setDeleteRef(false);
        if (env->IsSameObject(entity.getObj(), player.getObj())) continue;

        int eid = entity.entityId();
        worldEntityIds.insert(eid);
        bool flagged = false;

        int ticks = entity.ticksExisted();

        if (!flagged && checkTabList && ticks > 10) {
            if (!isInTabList(env, entity.getObj())) {
                flagged = true;
            }
        }

        if (!flagged) {
            EntityLivingBase living = entity.UHQConvertTo<EntityLivingBase>();
            if (!living.isNull()) {
                living.setDeleteRef(false);
                if (living.getHealth() <= 0.0f) {
                    flagged = true;
                }
            }
        }

        if (!flagged) {
            std::lock_guard lock(mutex_);
            if (ticks > minTicksExisted + 10 && !spawnedPlayerIds_.contains(eid)) {
                flagged = true;
            }
            if (!flagged && ticks < minTicksExisted && !spawnedPlayerIds_.contains(eid)) {
                flagged = true;
            }
            if (!flagged && checkServerPackets && ticks > packetGraceTicks && !receivedMovementPacket_.contains(eid)) {
                flagged = true;
            }
        }

        if (flagged) {
            botsThisTick.insert(eid);
        }
    }

    {
        std::lock_guard lock(mutex_);

        for (int eid : botsThisTick) {
            confirmedBotIds_.insert(eid);
        }

        std::erase_if(confirmedBotIds_, [&](int eid) {
            return !worldEntityIds.contains(eid);
        });
    }
}

bool AntiBotModule::isBot(JNIEnv* env, jobject entityObj) {
    if (!enable || !entityObj) return false;
    Entity entity(env, entityObj);
    entity.setDeleteRef(false);
    return isBot(env, entity);
}

bool AntiBotModule::isBot(JNIEnv* env, Entity& entity) {
    if (!enable) return false;

    int eid = entity.entityId();

    {
        std::lock_guard lock(mutex_);

        if (confirmedBotIds_.contains(eid)) return true;

        int ticks = entity.ticksExisted();
        if (ticks < minTicksExisted && !spawnedPlayerIds_.contains(eid)) {
            return true;
        }
        if (checkServerPackets && ticks > packetGraceTicks && !receivedMovementPacket_.contains(eid)) {
            return true;
        }
    }

    return false;
}

REGISTER_MODULE(AntiBotModule, ModuleType::ANTI_BOT)
