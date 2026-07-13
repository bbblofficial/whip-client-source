#include "provider/impl/GameStateProvider.h"
#include "wrapper/minecraft/client/Minecraft.h"
#include "wrapper/minecraft/client/gui/GuiScreen.h"
#include "wrapper/minecraft/client/entity/EntityClientPlayerMP.h"

void GameStateProvider::onEnable() {
    EventBus::getInstance().subscribe<UpdateEvent>(this, [this](const UpdateEvent& event) {
        onUpdate(event);
    });
}

void GameStateProvider::onDisable() {
    EventBus::getInstance().unsubscribe(this);

    cache.inGameHasFocus.store(false, std::memory_order_release);
    cache.clearScreenFlags();
    cache.hasWeapon.store(false, std::memory_order_release);
}

void GameStateProvider::onUpdate(const UpdateEvent& event) {
    JNIEnv* env = event.getEnv();
    if (!env) {
        return;
    }

    Minecraft mc = Minecraft::getMinecraft(env);
    if (mc.isNull()) {
        cache.inGameHasFocus.store(false, std::memory_order_release);
        cache.clearScreenFlags();
        cache.hasWeapon.store(false, std::memory_order_release);
        return;
    }

    const bool hasFocus = mc.inGameHasFocus();
    cache.inGameHasFocus.store(hasFocus, std::memory_order_release);

    EntityClientPlayerMP thePlayer = mc.thePlayer();
    if (!thePlayer.isNull()) {
        const bool hasWeapon = thePlayer.hasWeaponInHand();
        cache.hasWeapon.store(hasWeapon, std::memory_order_release);
    } else {
        cache.hasWeapon.store(false, std::memory_order_release);
    }

    if (GuiScreen currentScreen = mc.currentScreen(); currentScreen.isNull()) {
        cache.clearScreenFlags();
    } else {
        cache.hasScreen.store(true, std::memory_order_release);

        cache.setScreenFlag(ScreenState::INVENTORY, currentScreen.isInventory());
        cache.setScreenFlag(ScreenState::CHEST, currentScreen.isChest());
        cache.setScreenFlag(ScreenState::CHAT, currentScreen.isChat());
        cache.setScreenFlag(ScreenState::OPTIONS, currentScreen.isOptions());
    }
}
