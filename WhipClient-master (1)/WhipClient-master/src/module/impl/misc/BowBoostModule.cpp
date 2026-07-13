#include "../../../../includes/module/impl/misc/BowBoostModule.h"

#include <windows.h>
#include "wrapper/minecraft/client/minecraft.h"
#include "handler/ModuleHandler.h"
#include "handler/ProviderHandler.h"
#include "provider/impl/GameStateProvider.h"

void BowBoostModule::onUpdate(JniScope& scope) {

    if (!this->isEnabled()) {
        resetFlyState();
        resetPunchState();
        return;
    }

    auto* gameState = ProviderHandler::getInstance()
        .getTypedProvider<GameStateProvider, ProviderType::GAME_STATE>();
    if (!gameState || !gameState->inGameHasFocus()) return;

    Minecraft theMc = Minecraft::getMinecraft(scope.getEnv());
    if (theMc.isNull()) {
        return;
    }

    const WorldClient theWorld = theMc.theWorld();
    EntityClientPlayerMP thePlayer = theMc.thePlayer();

    if (theWorld.isNull() || thePlayer.isNull()) {
        return;
    }

    InventoryPlayer inventoryPlayer = thePlayer.inventoryPlayer();
    if (inventoryPlayer.isNull()) {
        return;
    }

    if (this->mode == 0) {
        handlePunchMode(scope, inventoryPlayer);
    } else {
        handleFlyMode(scope, inventoryPlayer);
    }
}

void BowBoostModule::handlePunchMode(JniScope& scope, InventoryPlayer& inventoryPlayer) {
    if (!this->isEnabled()) {
        resetPunchState();
        return;
    }

    if (!punchExecuted && hasPunchBow(inventoryPlayer)) {
        const int bowSlot = findPunchBowSlot(inventoryPlayer);
        if (bowSlot == -1) return;

        const int lastSlot = inventoryPlayer.currentItem();

        inventoryPlayer.currentItem(bowSlot);
        PostMessageA(GetForegroundWindow(), 0x204, 0, 0);
        Sleep(static_cast<DWORD>(firstChargeTime));
        PostMessageA(GetForegroundWindow(), 0x205, 0, 0);
        Sleep(50);
        inventoryPlayer.currentItem(lastSlot);

        punchExecuted = true;
    }
}

void BowBoostModule::handleFlyMode(JniScope& scope, InventoryPlayer& inventoryPlayer) {
    if (!this->isEnabled()) {

        if (flyActive) {
            stopFlyAndCleanup(inventoryPlayer);
        }
        return;
    }

    if (!hasFlyBow(inventoryPlayer)) {
        if (flyActive) {
            stopFlyAndCleanup(inventoryPlayer);
        }
        return;
    }

    if (!flyActive) {
        flyActive = true;
        originalSlot = inventoryPlayer.currentItem();

        if (!holdingFlyBow(inventoryPlayer) && autoSwitch) {
            switchToFlyBow(inventoryPlayer);
        }

        if (holdingFlyBow(inventoryPlayer)) {
            boostState = 1;
            isCharging = true;
            chargeStartTime = GetTickCount();
            startCharge();
        } else {
            resetFlyState();
            return;
        }
    }

    DWORD currentTime = GetTickCount();

    switch (boostState) {
        case 1:
        case 2:
            if (isCharging) {
                DWORD elapsedChargeTime = currentTime - chargeStartTime;
                DWORD targetChargeTime = static_cast<DWORD>((boostState == 1) ? firstChargeTime : secondChargeTime);

                if (elapsedChargeTime >= targetChargeTime) {
                    releaseArrow();
                    isCharging = false;
                    lastShotTime = currentTime;
                    boostState = 3;
                }
            }
            break;

        case 3:
            {
                DWORD elapsedDelayTime = currentTime - lastShotTime;

                if (elapsedDelayTime >= static_cast<DWORD>(delayBetweenShots)) {
                    boostState = 2;
                    isCharging = true;
                    chargeStartTime = currentTime;
                    startCharge();
                }
            }
            break;
    }
}

bool BowBoostModule::isPunchBow(ItemStack& itemStack) {
    if (itemStack.isNull()) return false;
    return itemStack.isPunch();
}

bool BowBoostModule::hasPunchBow(InventoryPlayer& inventoryPlayer) {
    return findPunchBowSlot(inventoryPlayer) != -1;
}

bool BowBoostModule::hasFlyBow(InventoryPlayer& inventoryPlayer) {
    return findFlyBowSlot(inventoryPlayer) != -1;
}

int BowBoostModule::findPunchBowSlot(InventoryPlayer& inventoryPlayer) {
    for (int i = 0; i < 9; i++) {
        ItemStack currentItemStack = inventoryPlayer.getItem(i);
        if (!currentItemStack.isNull() && currentItemStack.isPunch() && isPunchBow(currentItemStack)) {
            return i;
        }
    }
    return -1;
}

int BowBoostModule::findFlyBowSlot(InventoryPlayer& inventoryPlayer) {
    for (int i = 0; i < 9; i++) {
        ItemStack currentItemStack = inventoryPlayer.getItem(i);
        if (!currentItemStack.isNull() && currentItemStack.isPunch()) {
            return i;
        }
    }
    return -1;
}

int BowBoostModule::findSwordSlot(InventoryPlayer& inventoryPlayer) {
    for (int i = 0; i < 9; i++) {
        ItemStack currentItemStack = inventoryPlayer.getItem(i);
        if (!currentItemStack.isNull() && currentItemStack.isSword()) {
            return i;
        }
    }
    return -1;
}

bool BowBoostModule::holdingPunchBow(InventoryPlayer& inventoryPlayer) {
    ItemStack heldItem = inventoryPlayer.getItem(inventoryPlayer.currentItem());
    return !heldItem.isNull() && heldItem.isPunch() && isPunchBow(heldItem);
}

bool BowBoostModule::holdingFlyBow(InventoryPlayer& inventoryPlayer) {
    ItemStack heldItem = inventoryPlayer.getItem(inventoryPlayer.currentItem());
    return !heldItem.isNull() && heldItem.isPunch();
}

void BowBoostModule::switchToPunchBow(InventoryPlayer& inventoryPlayer) {
    int bowSlot = findPunchBowSlot(inventoryPlayer);
    if (bowSlot != -1) {
        inventoryPlayer.currentItem(bowSlot);
    }
}

void BowBoostModule::switchToFlyBow(InventoryPlayer& inventoryPlayer) {
    int bowSlot = findFlyBowSlot(inventoryPlayer);
    if (bowSlot != -1) {
        inventoryPlayer.currentItem(bowSlot);
    }
}

void BowBoostModule::switchToSword(InventoryPlayer& inventoryPlayer) {
    int swordSlot = findSwordSlot(inventoryPlayer);
    if (swordSlot != -1) {
        inventoryPlayer.currentItem(swordSlot);
    }
}

void BowBoostModule::startCharge() {
    INPUT input = {0};
    input.type = INPUT_MOUSE;
    input.mi.dwFlags = MOUSEEVENTF_RIGHTDOWN;
    SendInput(1, &input, sizeof(INPUT));
}

void BowBoostModule::releaseArrow() {
    INPUT input = {0};
    input.type = INPUT_MOUSE;
    input.mi.dwFlags = MOUSEEVENTF_RIGHTUP;
    SendInput(1, &input, sizeof(INPUT));
}

void BowBoostModule::resetFlyState() {
    flyActive = false;
    isCharging = false;
    boostState = 0;
    chargeStartTime = 0;
    lastShotTime = 0;

    PostMessageA(GetForegroundWindow(), 0x205, 0, 0);
}

void BowBoostModule::resetPunchState() {
    punchExecuted = false;
}

void BowBoostModule::stopFlyAndCleanup(InventoryPlayer& inventoryPlayer) {

    PostMessageA(GetForegroundWindow(), 0x205, 0, 0);

    if (returnToSlot) {

        int swordSlot = findSwordSlot(inventoryPlayer);
        if (swordSlot != -1) {
            inventoryPlayer.currentItem(swordSlot);
        } else {
            inventoryPlayer.currentItem(originalSlot);
        }
    }

    resetFlyState();
}

REGISTER_MODULE(BowBoostModule, ModuleType::BOW_BOOST)
