#include "../../../../../../includes/module/impl/combat/throw/mode/ThrowDebuffMode.h"
#include "../../../../../../includes/handler/ProviderHandler.h"
#include "../../../../../../includes/provider/impl/GameStateProvider.h"
#include <windows.h>

ThrowDebuffMode::ThrowDebuffMode() {
}

void ThrowDebuffMode::execute(int speed, bool doubleOption, bool smartMode, TickLockerModule* tickLocker, JNIEnv* env) {

    auto* gameState = ProviderHandler::getInstance()
        .getTypedProvider<GameStateProvider, ProviderType::GAME_STATE>();
    if (!gameState || !gameState->inGameHasFocus()) return;

    Minecraft theMc = Minecraft::getMinecraft(env);
    if (theMc.isNull()) return;

    WorldClient theWorld = theMc.theWorld();
    EntityClientPlayerMP thePlayer = theMc.thePlayer();
    if (theWorld.isNull() || thePlayer.isNull()) {
        return;
    }

    InventoryPlayer inventoryPlayer = thePlayer.inventoryPlayer();
    int currentItem = inventoryPlayer.currentItem();

    if (doubleOption) {
        throwAllDebuffs(inventoryPlayer, currentItem, theMc, env, speed);
        return;
    }

    int slot = findSlot(inventoryPlayer, env);
    if (slot == -1) {
        return;
    }

    int throwCount = getThrowCount(0, doubleOption);
    for (int i = 0; i < throwCount; i++) {
        handleThrow(slot, speed, inventoryPlayer, currentItem, theMc, tickLocker, doubleOption, smartMode, env);
        if (i < throwCount - 1) {
            Sleep(1);
        }
    }
    NotificationModule::addCustomNotification(Strings::msgThrowDebuffUsed(), ImColor(135, 206, 235, 255));
}

int ThrowDebuffMode::findSlot(InventoryPlayer& inventoryPlayer, JNIEnv* env) {
    for (int i = 0; i < 9; i++) {
        ItemStack currentItemStack = inventoryPlayer.getItem(i);
        if (currentItemStack.isNull()) continue;

        int itemDamage = currentItemStack.metadata();
        if (isValidItem(itemDamage, false)) {
            return i;
        }
    }
    return -1;
}

void ThrowDebuffMode::handleThrow(int slot, int speed, InventoryPlayer& inventoryPlayer, int originalSlot, Minecraft& mc, TickLockerModule* tickLocker, bool doubleOption, bool smartMode, JNIEnv* env, bool autoDrop) {
    if (speed > 0) {
        Sleep(speed * 50);
    }
    performThrow(slot, inventoryPlayer, originalSlot, mc, tickLocker, doubleOption, smartMode, env, autoDrop);
}

void ThrowDebuffMode::performThrow(int slot, InventoryPlayer& inventoryPlayer, int originalSlot, Minecraft& mc, TickLockerModule* tickLocker, bool doubleOption, bool smartMode, JNIEnv* env, bool autoDrop) {

    GameSettings gameSettings = mc.gameSettings();
    if (!gameSettings.isNull()) {
        KeyBinding keyBindUseItem = gameSettings.keyBindUseItem();
        if (!keyBindUseItem.isNull()) {
            keyBindUseItem.setDeleteRef(false);
            keyBindUseItem.pressed(false);
        }
    }

    inventoryPlayer.currentItem(slot);

    if (tickLocker && tickLocker->enable) {
        Sleep(50);
    }

    PostMessageA(GetForegroundWindow(), WM_RBUTTONDOWN, 0, 0);
    Sleep(10);
    PostMessageA(GetForegroundWindow(), WM_RBUTTONUP, 0, 0);
    Sleep(50);

    inventoryPlayer.currentItem(originalSlot);
}

bool ThrowDebuffMode::isValidItem(int itemDamage, bool isSoup) {

    if ((itemDamage & 16384) == 0) return false;

    int effectBase = itemDamage & 15;

    return effectBase == 4 ||
           effectBase == 8 ||
           effectBase == 10 ||
           effectBase == 12;
}

void ThrowDebuffMode::throwAllDebuffs(InventoryPlayer& inventoryPlayer, int originalSlot, Minecraft& mc, JNIEnv* env, int speed) {

    GameSettings gameSettings = mc.gameSettings();
    if (!gameSettings.isNull()) {
        KeyBinding keyBindUseItem = gameSettings.keyBindUseItem();
        if (!keyBindUseItem.isNull()) {
            keyBindUseItem.setDeleteRef(false);
            keyBindUseItem.pressed(false);
        }
    }

    for (int i = 0; i < 9; i++) {
        ItemStack currentItemStack = inventoryPlayer.getItem(i);
        if (currentItemStack.isNull()) continue;

        int itemDamage = currentItemStack.metadata();
        if (isValidItem(itemDamage, false)) {
            if (speed > 0) Sleep(speed * 50);

            inventoryPlayer.currentItem(i);
            PostMessageA(GetForegroundWindow(), WM_RBUTTONDOWN, 0, 0);
            Sleep(10);
            PostMessageA(GetForegroundWindow(), WM_RBUTTONUP, 0, 0);
            Sleep(50);
        }
    }
    inventoryPlayer.currentItem(originalSlot);
}

int ThrowDebuffMode::getThrowCount(float health, bool doubleThrow) {
    return 1;
}

float ThrowDebuffMode::getHealthThreshold() {
    return 21.0f;
}
