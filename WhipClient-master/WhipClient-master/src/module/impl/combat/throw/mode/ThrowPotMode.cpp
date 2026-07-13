#include "../../../../../../includes/module/impl/combat/throw/mode/ThrowPotMode.h"
#include "../../../../../../includes/handler/ProviderHandler.h"
#include "../../../../../../includes/provider/impl/GameStateProvider.h"
#include <windows.h>

ThrowPotMode::ThrowPotMode() {
}

void ThrowPotMode::execute(int speed, bool doubleOption, bool smartMode, TickLockerModule* tickLocker, JNIEnv* env) {

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

    const float health = thePlayer.getHealth();
    if (smartMode && !shouldHealSmart(health)) {
        return;
    }

    if (tickLocker && tickLocker->enable) {
        Sleep(50);
    }

    InventoryPlayer inventoryPlayer = thePlayer.inventoryPlayer();
    const int currentItem = inventoryPlayer.currentItem();

    const int throwCount = getThrowCount(health, doubleOption);

    for (int i = 0; i < throwCount; i++) {
        int slot = findSlot(inventoryPlayer, env);
        if (slot == -1) {
            return;
        }

        handleThrow(slot, speed, inventoryPlayer, currentItem, theMc, tickLocker, doubleOption, smartMode, env);

        if (i < throwCount - 1) {
            Sleep(1);
        }
    }
    NotificationModule::addCustomNotification(Strings::msgThrowPotUsed(), ImColor(135, 206, 235, 255));
}

int ThrowPotMode::findSlot(InventoryPlayer& inventoryPlayer, JNIEnv* env) {
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

void ThrowPotMode::handleThrow(int slot, int speed, InventoryPlayer& inventoryPlayer, int originalSlot, Minecraft& mc, TickLockerModule* tickLocker, bool doubleOption, bool smartMode, JNIEnv* env, bool autoDrop) {
    if (speed > 0) {
        Sleep(speed * 50);
    }
    performThrow(slot, inventoryPlayer, originalSlot, mc, tickLocker, doubleOption, smartMode, env, autoDrop);
}

void ThrowPotMode::performThrow(int slot, InventoryPlayer& inventoryPlayer, int originalSlot, Minecraft& mc, TickLockerModule* tickLocker, bool doubleOption, bool smartMode, JNIEnv* env, bool autoDrop) {

    GameSettings gameSettings = mc.gameSettings();
    if (!gameSettings.isNull()) {
        KeyBinding keyBindUseItem = gameSettings.keyBindUseItem();
        if (!keyBindUseItem.isNull()) {
            keyBindUseItem.setDeleteRef(false);
            keyBindUseItem.pressed(false);
        }
    }

    inventoryPlayer.currentItem(slot);

    PostMessageA(GetForegroundWindow(), WM_RBUTTONDOWN, 0, 0);
    Sleep(1);
    PostMessageA(GetForegroundWindow(), WM_RBUTTONUP, 0, 0);
    Sleep(50);

    inventoryPlayer.currentItem(originalSlot);
}

bool ThrowPotMode::isValidItem(int itemDamage, bool isSoup) {
    return (itemDamage == 16421 || itemDamage == 16453);
}

int ThrowPotMode::getThrowCount(const float health, const bool doubleThrow) {
    return (doubleThrow && health <= 4.0) ? 2 : 1;
}

float ThrowPotMode::getHealthThreshold() {
    return 16.0f;
}
