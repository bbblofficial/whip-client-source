#include "../../../../../../includes/module/impl/combat/throw/mode/ThrowPearlMode.h"
#include "../../../../../../includes/handler/ProviderHandler.h"
#include "../../../../../../includes/provider/impl/GameStateProvider.h"
#include <windows.h>

ThrowPearlMode::ThrowPearlMode() {
}

void ThrowPearlMode::execute(int speed, bool doubleOption, bool smartMode, TickLockerModule* tickLocker, JNIEnv* env) {

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
    NotificationModule::addCustomNotification(Strings::msgThrowPearlUsed(), ImColor(135, 206, 235, 255));
}

int ThrowPearlMode::findSlot(InventoryPlayer& inventoryPlayer, JNIEnv* env) {
    for (int i = 0; i < 9; i++) {
        ItemStack currentItemStack = inventoryPlayer.getItem(i);
        if (currentItemStack.isNull()) continue;

        bool isPearl = currentItemStack.IsPearl();
        if (isValidItem(0, isPearl)) {
            return i;
        }
    }
    return -1;
}

void ThrowPearlMode::handleThrow(int slot, int speed, InventoryPlayer& inventoryPlayer, int originalSlot, Minecraft& mc, TickLockerModule* tickLocker, bool doubleOption, bool smartMode, JNIEnv* env, bool autoDrop) {
    if (speed > 0) {
        Sleep(speed * 50);
    }
    performThrow(slot, inventoryPlayer, originalSlot, mc, tickLocker, doubleOption, smartMode, env, autoDrop);
}

void ThrowPearlMode::performThrow(int slot, InventoryPlayer& inventoryPlayer, int originalSlot, Minecraft& mc, TickLockerModule* tickLocker, bool doubleOption, bool smartMode, JNIEnv* env, bool autoDrop) {
    GameSettings gameSettings = mc.gameSettings();
    if (gameSettings.isNull()) {
        return;
    }

    EntityClientPlayerMP thePlayer = mc.thePlayer();
    if (thePlayer.isNull()) {
        return;
    }

    KeyBinding keyBindDrop = gameSettings.keyBindDrop();
    if (keyBindDrop.isNull()) {
        return;
    }

    KeyBinding keyBindUseItem = gameSettings.keyBindUseItem();
    if (!keyBindUseItem.isNull()) {
        keyBindUseItem.setDeleteRef(false);
        keyBindUseItem.pressed(false);
    }

    inventoryPlayer.currentItem(slot);
    PostMessageA(GetForegroundWindow(), WM_RBUTTONDOWN, 0, 0);
    Sleep(1);
    PostMessageA(GetForegroundWindow(), WM_RBUTTONUP, 0, 0);
    Sleep(50);
    inventoryPlayer.currentItem(originalSlot);
}

bool ThrowPearlMode::isValidItem(int itemDamage, bool isPearl) {
    return isPearl;
}

int ThrowPearlMode::getThrowCount(float health, bool doubleThrow) {
    return 1;
}

float ThrowPearlMode::getHealthThreshold() {
    return 21.0f;
}
