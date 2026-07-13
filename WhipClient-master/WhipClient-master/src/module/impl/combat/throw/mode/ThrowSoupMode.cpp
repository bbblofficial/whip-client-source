#include "../../../../../../includes/module/impl/combat/throw/mode/ThrowSoupMode.h"
#include "../../../../../../includes/handler/ProviderHandler.h"
#include "../../../../../../includes/provider/impl/GameStateProvider.h"
#include <windows.h>

int excludedSlot = -1;

ThrowSoupMode::ThrowSoupMode() {
}

void ThrowSoupMode::execute(int speed, bool doubleOption, bool smartMode, TickLockerModule* tickLocker, JNIEnv* env) {

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

    float health = thePlayer.getHealth();
    if (smartMode && !shouldHealSmart(health, 20.0f, 6.5f)) {
        return;
    }

    InventoryPlayer inventoryPlayer = thePlayer.inventoryPlayer();
    int currentItem = inventoryPlayer.currentItem();

    int useCount = getThrowCount(health, doubleOption);

    excludedSlot = -1;

    for (int i = 0; i < useCount; i++) {
        int slot = findSlot(inventoryPlayer, env);
        if (slot == -1) {
            return;
        }

        handleThrow(slot, speed, inventoryPlayer, currentItem, theMc, tickLocker, doubleOption, smartMode, env, true);

        excludedSlot = slot;

        if (i < useCount - 1) {
            Sleep(1);
        }
    }

    excludedSlot = -1;

    NotificationModule::addCustomNotification(Strings::msgThrowSoupUsed(), ImColor(135, 206, 235, 255));
}

int ThrowSoupMode::findSlot(InventoryPlayer& inventoryPlayer, JNIEnv* env) {
    for (int i = 0; i < 9; i++) {
        if (i == excludedSlot) continue;

        ItemStack currentItemStack = inventoryPlayer.getItem(i);
        if (currentItemStack.isNull()) continue;

        bool isSoup = currentItemStack.isSoup();
        if (isValidItem(0, isSoup)) {
            return i;
        }
    }
    return -1;
}

void ThrowSoupMode::handleThrow(int slot, int speed, InventoryPlayer& inventoryPlayer, int originalSlot, Minecraft& mc, TickLockerModule* tickLocker, bool doubleOption, bool smartMode, JNIEnv* env, bool autoDrop) {
    if (speed > 0) {
        Sleep(speed * 50);
    }
    performThrow(slot, inventoryPlayer, originalSlot, mc, tickLocker, doubleOption, smartMode, env, autoDrop);
}

void ThrowSoupMode::performThrow(int slot, InventoryPlayer& inventoryPlayer, int originalSlot, Minecraft& mc, TickLockerModule* tickLocker, bool doubleOption, bool smartMode, JNIEnv* env, bool autoDrop) {
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

    int KeyDrop = keyBindDrop.keyCode();

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

    if (autoDrop) {
        thePlayer.dropOneItem(false);
    }

    inventoryPlayer.currentItem(originalSlot);
}

bool ThrowSoupMode::isValidItem(int itemDamage, bool isSoup) {
    return isSoup;
}

int ThrowSoupMode::getThrowCount(const float health, const bool doubleThrow) {
    return (doubleThrow && health <= 6.0) ? 2 : 1;
}

float ThrowSoupMode::getHealthThreshold() {
    return 15.0f;
}
