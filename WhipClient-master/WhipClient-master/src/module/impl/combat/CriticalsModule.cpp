#include "../../../../includes/module/impl/combat/CriticalsModule.h"
#include "../../../../includes/handler/ModuleHandler.h"
#include "../../../../includes/handler/MappingHandler.h"
#include "../../../../includes/handler/ProviderHandler.h"
#include "../../../../includes/provider/impl/GameStateProvider.h"
#include "../../../../includes/provider/impl/PacketProvider.h"

#include "wrapper/minecraft/client/Minecraft.h"
#include "wrapper/minecraft/client/network/NetHandlerPlayClient.h"
#include "wrapper/minecraft/network/NetworkManager.h"
#include "wrapper/minecraft/entity/Entity.h"
#include "wrapper/minecraft/entity/EntityLivingBase.h"
#include "wrapper/minecraft/potion/Potion.h"
#include "wrapper/minecraft/util/Timer.h"
#include "wrapper/minecraft/client/settings/GameSettings.h"
#include "wrapper/minecraft/client/settings/KeyBinding.h"

#include "util/MathUtils.h"
#include "util/Debug.h"
#include "util/MinecraftDetails.h"

#include "setting/SettingMacros.h"

jclass CriticalsModule::C02PacketUseEntityClass_ = nullptr;
jclass CriticalsModule::S07PacketRespawnClass_ = nullptr;
jclass CriticalsModule::S08PacketPlayerPosLookClass_ = nullptr;

void CriticalsModule::onLoad() {
    ListenedBaseModule::onLoad();

    COMBO_SETTING(mode, "Packet", "Timer");
    INT_SLIDER(chance, 100, 0, 100);
    FLOAT_SLIDER_OPTIONAL(timerSpeed, 0.5f, 0.1f, 0.9f, SETTING_VISIBILITY(mode == 1));
    INT_SLIDER_OPTIONAL(maxQueueTime, 500, 200, 1000, SETTING_VISIBILITY(mode == 0));
}

void CriticalsModule::onEnable() {
    ListenedBaseModule::onEnable();
    isLagging_ = false;
    lagStartTime_ = 0;
    timerActive_ = false;
    wasHitAirborne_ = false;
    lastHurtTime_ = 0;
}

void CriticalsModule::onDisable() {

    if (isLagging_) {
        JNIEnv* env = nullptr;
        JavaVM* jvm = nullptr;
        if (JNI_GetCreatedJavaVMs(&jvm, 1, nullptr) == JNI_OK && jvm) {
            jvm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_8);
        }
        if (env) {
            flushQueue(env);
        }
    }

    if (timerActive_) {
        JNIEnv* env = nullptr;
        JavaVM* jvm = nullptr;
        if (JNI_GetCreatedJavaVMs(&jvm, 1, nullptr) == JNI_OK && jvm) {
            jvm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_8);
        }
        if (env) {
            Minecraft mc = Minecraft::getMinecraft(env);
            if (!mc.isNull()) {
                Timer timer = mc.timer();
                if (!timer.isNull()) {
                    timer.setTicksPerSecond(20.0f);
                }
            }
        }
        timerActive_ = false;
    }

    isLagging_ = false;
    lagStartTime_ = 0;
    wasHitAirborne_ = false;
    lastHurtTime_ = 0;
    ListenedBaseModule::onDisable();
}

void CriticalsModule::registerEvents() {
    subscribe<AddSendQueueEvent>([this](const AddSendQueueEvent& event) {
        onPacketSend(event);
    }, EventPriority::HIGH, false);

    subscribe<ChannelReadEvent>([this](const ChannelReadEvent& event) {
        onPacketReceived(event);
    });

    subscribe<OnRunTickEvent>([this](const OnRunTickEvent& event) {
        onTick(event);
    });
}

bool CriticalsModule::isAttackPacket(JNIEnv* env, jobject obj) {
    if (!C02PacketUseEntityClass_) {
        C02PacketUseEntityClass_ = Mappings::getInstance().getClass("C02PacketUseEntity");
    }
    return C02PacketUseEntityClass_ && env->IsInstanceOf(obj, C02PacketUseEntityClass_);
}

bool CriticalsModule::isInstanceOf(JNIEnv* env, jobject obj, jclass& cached, const char* className) {
    if (!cached) {
        cached = Mappings::getInstance().getClass(className);
    }
    return cached && env->IsInstanceOf(obj, cached);
}

bool CriticalsModule::canQueueForCrit(JNIEnv* env) {
    try {
        Minecraft mc = Minecraft::getMinecraft(env);
        if (mc.isNull()) return false;

        EntityClientPlayerMP player = mc.thePlayer();
        if (player.isNull()) return false;

        if (player.onGround()) return false;
        if (player.motionY() >= 0) return false;

        if (player.isOnLadder()) return false;
        if (player.isInWater()) return false;

        Potion blindness = Potion::blindness(env);
        if (!blindness.isNull() && player.isPotionActive(blindness)) return false;

        Entity riding = player.getRidingEntity();
        if (!riding.isNull()) return false;

        if ((GetAsyncKeyState(VK_LBUTTON) & 0x8000) == 0) return false;

        if (chance < 100 && randomInt(0, 100) > chance) return false;

        if (env->ExceptionCheck()) { env->ExceptionClear(); return false; }
        return true;
    } catch (...) {
        if (env->ExceptionCheck()) env->ExceptionClear();
        return false;
    }
}

void CriticalsModule::flushQueue(JNIEnv* env) {
    try {
        auto* provider = static_cast<PacketProvider*>(
            ProviderHandler::getInstance().getProvider(ProviderType::PACKET));
        if (provider) {
            provider->processAndClearOutboundQueue(env);
        }
    } catch (...) {
        if (env && env->ExceptionCheck()) env->ExceptionClear();
    }
    isLagging_ = false;
    lagStartTime_ = 0;
}

void CriticalsModule::onPacketSend(const AddSendQueueEvent& event) {
    if (!this->enable) return;
    if (mode != 0) return;

    JNIEnv* env = event.getEnv();
    jobject packet = event.getPacketObject();
    if (!env || !packet) return;

    if (env->ExceptionCheck()) {
        env->ExceptionClear();
        if (isLagging_) { isLagging_ = false; lagStartTime_ = 0; }
        return;
    }

    auto* provider = static_cast<PacketProvider*>(
        ProviderHandler::getInstance().getProvider(ProviderType::PACKET));
    if (!provider) return;

    if (isLagging_) {
        bool timeout = lagStartTime_ > 0 && (getCurrentTime() - lagStartTime_) > maxQueueTime;
        bool overflow = provider->getOutboundQueueSize() > 50;
        if (timeout || overflow) {
            flushQueue(env);
            return;
        }
    }

    if (isAttackPacket(env, packet)) {
        if (isLagging_) {

            flushQueue(env);

            Minecraft mc = Minecraft::getMinecraft(env);
            if (!mc.isNull()) {
                NetHandlerPlayClient netHandler = mc.getNetHandler();
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

    if (!canQueueForCrit(env)) {
        if (isLagging_) flushQueue(env);
        return;
    }

    if (!isLagging_) {
        lagStartTime_ = getCurrentTime();
        isLagging_ = true;
    }

    provider->queueOutboundPacket(env, packet);
    const_cast<AddSendQueueEvent&>(event).setCancelled(true);
}

void CriticalsModule::onPacketReceived(const ChannelReadEvent& event) {
    if (!this->enable) return;
    if (mode != 0) return;

    JNIEnv* env = event.getEnv();
    jobject packet = event.getPacketObject();
    if (!env || !packet) return;

    bool shouldReset = isInstanceOf(env, packet, S07PacketRespawnClass_, "S07PacketRespawn")
                    || isInstanceOf(env, packet, S08PacketPlayerPosLookClass_, "S08PacketPlayerPosLook");

    if (shouldReset && isLagging_) {
        flushQueue(env);
    }
}

void CriticalsModule::onTick(const OnRunTickEvent& event) {
    if (!this->enable) return;

    JNIEnv* env = event.getEnv();
    if (!env) return;

    auto* gameState = ProviderHandler::getInstance()
        .getTypedProvider<GameStateProvider, ProviderType::GAME_STATE>();
    if (!gameState || !gameState->inGameHasFocus()) return;

    Minecraft mc = Minecraft::getMinecraft(env);
    if (mc.isNull()) return;

    EntityClientPlayerMP player = mc.thePlayer();
    if (player.isNull()) return;

    if (mode == 0) {
        if (isLagging_ && player.onGround()) {
            flushQueue(env);
        }
        return;
    }

    if (mode != 1) return;

    Timer timer = mc.timer();
    if (timer.isNull()) return;

    EntityLivingBase playerLiving(env, player.getObj());
    playerLiving.setDeleteRef(false);
    int currentHurtTime = playerLiving.hurtTime();
    bool onGround = player.onGround();
    double motionY = player.motionY();

    if (currentHurtTime > 0 && lastHurtTime_ == 0) {
        wasHitAirborne_ = true;
    }

    if (!timerActive_) {

        if (wasHitAirborne_ && !onGround && motionY < 0) {

            if (!player.isOnLadder() && !player.isInWater()) {
                Potion blindness = Potion::blindness(env);
                bool blinded = !blindness.isNull() && player.isPotionActive(blindness);
                Entity riding = player.getRidingEntity();

                if (!blinded && riding.isNull()) {

                    if (chance >= 100 || randomInt(0, 100) <= chance) {

                        timer.setTicksPerSecond(20.0f * timerSpeed);
                        timerActive_ = true;
                    }
                }
            }
        }

        if (wasHitAirborne_ && onGround && currentHurtTime == 0) {
            wasHitAirborne_ = false;
        }
    } else {

        if (onGround) {
            timer.setTicksPerSecond(20.0f);
            timerActive_ = false;
            wasHitAirborne_ = false;
        }
    }

    lastHurtTime_ = currentHurtTime;
}

