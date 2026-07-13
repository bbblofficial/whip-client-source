#include "../../../../includes/module/impl/combat/BlockHitModule.h"
#include <widgets.h>

#include "bus/EventBus.h"
#include "module/impl/combat/throw/ThrowModule.h"
#include "module/impl/combat/AntiBotModule.h"
#include "handler/ModuleHandler.h"
#include "handler/ProviderHandler.h"
#include "provider/impl/GameStateProvider.h"
#include "event/sub/AttackEntityEvent.h"
#include "event/sub/MouseBlockClickEvent.h"
#include "event/sub/VelocityEvent.h"
#include "wrapper/minecraft/client/minecraft.h"
#include "wrapper/minecraft/client/settings/gamesettings.h"
#include "wrapper/minecraft/client/network/NetHandlerPlayClient.h"

static constexpr int INVULN_TICKS    = 10;
static constexpr int MS_PER_TICK     = 50;
static constexpr int INVULN_MS       = INVULN_TICKS * MS_PER_TICK;
static constexpr int SAFETY_MS       = MS_PER_TICK;
static constexpr int HURT_TIME_FRESH = 10;

void BlockHitModule::registerEvents() {
    EventBus::getInstance().subscribe<MouseLeftClickEvent>(
        this,
        [this](const MouseLeftClickEvent& event) { this->onMouseClick(event); },
        EventPriority::HIGH,
        false
    );
}

bool BlockHitModule::isTargetBehind(EntityClientPlayerMP& player, EntityLivingBase& target) {
    float playerRot = player.rotationYaw();
    float targetRot = target.rotationYaw();
    while (playerRot < 0)   playerRot += 360.0f;
    while (playerRot > 360) playerRot -= 360.0f;
    while (targetRot < 0)   targetRot += 360.0f;
    while (targetRot > 360) targetRot -= 360.0f;
    float diff = abs(playerRot - targetRot);
    if (diff > 180) diff = 360.0f - diff;
    return diff < 90.0f;
}

int BlockHitModule::getRawPingMs(Minecraft& mc) {
    auto netHandler = mc.getNetHandler();
    if (netHandler.isNull()) return 60;
    netHandler.setDeleteRef(false);
    int ping = netHandler.getCurrentPlayerPing();
    return (ping > 0 && ping < 2000) ? ping : 60;
}

int BlockHitModule::getSmoothedPingMs(Minecraft& mc) {
    int raw = getRawPingMs(mc);
    if (smoothedPingMs_ <= 0) {
        smoothedPingMs_ = raw;
    } else {

        smoothedPingMs_ = (smoothedPingMs_ * 4 + raw) / 5;
    }
    return smoothedPingMs_;
}

void BlockHitModule::startBlock(JNIEnv* env, Minecraft& mc) {
    if (isBlocking_) return;
    auto settings = mc.gameSettings();
    if (settings.isNull()) return;
    settings.setDeleteRef(false);
    KeyBinding useItem = settings.keyBindUseItem();
    if (useItem.isNull()) return;
    useItem.setDeleteRef(false);
    useItem.pressed(true);
    isBlocking_ = true;
    blockStart_  = std::chrono::steady_clock::now();
}

void BlockHitModule::stopBlock(JNIEnv* env, Minecraft& mc) {
    if (!isBlocking_) return;
    auto settings = mc.gameSettings();
    if (settings.isNull()) return;
    settings.setDeleteRef(false);
    KeyBinding useItem = settings.keyBindUseItem();
    if (useItem.isNull()) return;
    useItem.setDeleteRef(false);
    useItem.pressed(false);
    isBlocking_ = false;
}

void BlockHitModule::updatePredict(JNIEnv* env, Minecraft& mc) {
    if (ThrowModule::isThrowing()) {
        if (isBlocking_) stopBlock(env, mc);
        return;
    }

    auto* gameState = ProviderHandler::getInstance()
        .getTypedProvider<GameStateProvider, ProviderType::GAME_STATE>();
    if (!gameState || !gameState->inGameHasFocus()) {
        if (isBlocking_) stopBlock(env, mc);
        return;
    }

    EntityClientPlayerMP player = mc.thePlayer();
    if (player.isNull()) {
        if (isBlocking_) stopBlock(env, mc);
        return;
    }

    int pingMs = getSmoothedPingMs(mc);

    int myHurtTime = player.hurtTime();
    if (isBlocking_ && myHurtTime == HURT_TIME_FRESH && prevMyHurtTime_ != HURT_TIME_FRESH) {
        stopBlock(env, mc);
        prevTargetHurtTime_ = 0;
        prevMyHurtTime_ = myHurtTime;
        return;
    }
    prevMyHurtTime_ = myHurtTime;

    EntityLivingBase target = mc.pointedEntity().UHQConvertTo<EntityLivingBase>();
    if (target.isNull()) {
        if (isBlocking_) stopBlock(env, mc);
        prevTargetHurtTime_ = 0;
        return;
    }

    {
        auto* antiBot = AntiBotModule::getInstancePtr();
        if (antiBot && antiBot->isBot(env, target.getObj())) {
            if (isBlocking_) stopBlock(env, mc);
            prevTargetHurtTime_ = 0;
            return;
        }
    }

    int targetHurtTime = target.hurtTime();

    if (targetHurtTime == HURT_TIME_FRESH && prevTargetHurtTime_ != HURT_TIME_FRESH) {

        int blockMs = INVULN_MS - pingMs - SAFETY_MS;

        static constexpr int MAX_BLOCK_MS = 250;
        blockDurationMs_ = std::max(MS_PER_TICK, std::min(blockMs, MAX_BLOCK_MS));

        startBlock(env, mc);
    }
    prevTargetHurtTime_ = targetHurtTime;

    if (isBlocking_) {
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - blockStart_).count();

        bool leftClickHeld = (GetAsyncKeyState(VK_LBUTTON) & 0x8000) != 0;
        int effectiveMax = leftClickHeld
            ? std::max(MS_PER_TICK, std::min(blockDurationMs_, MS_PER_TICK * 2))
            : blockDurationMs_;

        if (elapsed >= effectiveMax) {
            stopBlock(env, mc);
        }
    }
}

void BlockHitModule::onMouseClick(const MouseLeftClickEvent& event) {
    if (!isEnabled() || mode != 0) return;
    if (ThrowModule::isThrowing()) return;

    const HWND hWnd = GetForegroundWindow();
    if (!hWnd) return;
    DWORD pId = 0;
    GetWindowThreadProcessId(hWnd, &pId);
    if (pId != this->currentPID) return;

    Minecraft mc = Minecraft::getMinecraft(event.getEnv());
    if (mc.isNull()) return;

    EntityLivingBase pointedEntity = mc.pointedEntity().UHQConvertTo<EntityLivingBase>();
    if (pointedEntity.isNull()) return;
    { auto* ab = AntiBotModule::getInstancePtr(); if (ab && ab->isBot(event.getEnv(), pointedEntity.getObj())) return; }
    if (pointedEntity.hurtTime() != HURT_TIME_FRESH) return;

    if (this->chance < 100 && randomInt(0, 100) > this->chance) return;

    EntityClientPlayerMP thePlayer = mc.thePlayer();
    if (thePlayer.isNull()) return;

    auto* gameState = ProviderHandler::getInstance()
        .getTypedProvider<GameStateProvider, ProviderType::GAME_STATE>();
    if (!gameState || !gameState->inGameHasFocus()) return;

    if (disableOnBehind && isTargetBehind(thePlayer, pointedEntity)) return;

    const int minDur = std::min(minDuration, maxDuration);
    const int maxDur = std::max(minDuration, maxDuration);
    playingDuration = randomInt(minDur, maxDur) * MS_PER_TICK;
}

void BlockHitModule::onUpdate(JniScope& scope) {
    JNIEnv* env = scope.getEnv();
    if (!env) return;

    Minecraft mc = Minecraft::getMinecraft(env);
    if (mc.isNull()) return;

    if (mode == 1) {
        updatePredict(env, mc);
        return;
    }

    if (playingDuration == -1) return;
    if (ThrowModule::isThrowing()) {
        playingDuration = -1;
        return;
    }

    KeyBinding useItemKey = mc.gameSettings().keyBindUseItem();
    if (useItemKey.isNull()) return;

    useItemKey.pressed(true);

    int currentDuration = 0;
    EntityPlayer pointedEntity = mc.pointedEntity().UHQConvertTo<EntityPlayer>();
    const int checkInterval = 1;
    while (true) {
        if (ThrowModule::isThrowing()) break;
        if (pointedEntity.isNull() || pointedEntity.hurtTime() <= 0) break;
        if (currentDuration >= playingDuration) break;
        currentDuration += checkInterval;
        Sleep(checkInterval);
    }

    useItemKey.pressed(false);
    playingDuration = -1;
}

REGISTER_MODULE(BlockHitModule, ModuleType::BLOCK_HIT)
