#include "module/impl/misc/AutoToolModule.h"
#include "wrapper/minecraft/client/Minecraft.h"
#include "wrapper/minecraft/client/multiplayer/PlayerControllerMP.h"
#include "wrapper/minecraft/entity/player/EntityPlayer.h"
#include "wrapper/minecraft/entity/player/inventoryplayer.h"
#include "wrapper/minecraft/item/ItemStack.h"
#include "wrapper/minecraft/util/MovingObjectPosition.h"
#include "wrapper/minecraft/world/World.h"
#include "wrapper/minecraft/block/state/IBlockstate.h"
#include "wrapper/minecraft/block/Block.h"
#include "setting/SettingMacros.h"
#include "util/MinecraftDetails.h"
#include "handler/ModuleHandler.h"
#include <windows.h>

void AutoToolModule::onLoad() {
    DedicatedThreadBaseModule::onLoad();

    INT_SLIDER(delayTicks, 4, 0, 20);
    BOOL_SETTING_CONDITIONAL(instantOnShift, false);
}

void AutoToolModule::onUpdate(JniScope& scope) {
    JNIEnv* env = scope.getEnv();

    auto mc = Minecraft::getMinecraft(env);
    if (mc.isNull()) return;

    auto thePlayer = mc.thePlayer();
    if (thePlayer.isNull()) return;

    if (!(GetAsyncKeyState(VK_LBUTTON) & 0x8000)) {
        if (hasEverSwitchedSlot_) {
            switchToSword(env);
        }
        isAimingBlock_ = false;
        hasEverSwitchedSlot_ = false;
        return;
    }

    auto objectMouseOver = mc.objectMouseOver();
    if (objectMouseOver.isNull() || objectMouseOver.typeOfHit() != MovingObjectPosition::TypeOfHit::BLOCK) {
        if (hasEverSwitchedSlot_) {
            switchToSword(env);
        }
        isAimingBlock_ = false;
        hasEverSwitchedSlot_ = false;
        return;
    }

    auto blockPos = objectMouseOver.getPosition();
    bool blockChanged = (blockPos.x != lastBlockX_ || blockPos.y != lastBlockY_ || blockPos.z != lastBlockZ_);

    if (!isAimingBlock_ || blockChanged) {
        if (!isAimingBlock_) {
            auto inventory = thePlayer.inventoryPlayer();
            if (!inventory.isNull()) {
                originalSlot_ = inventory.currentItem();
            }
        }

        isAimingBlock_ = true;
        lastBlockAimTime_ = std::chrono::steady_clock::now();
        hasSwitched_ = false;

        lastBlockX_ = blockPos.x;
        lastBlockY_ = blockPos.y;
        lastBlockZ_ = blockPos.z;
    }

    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - lastBlockAimTime_).count();

    bool isShiftPressed = (GetAsyncKeyState(VK_SHIFT) & 0x8000) != 0;
    bool shouldBypassDelay = instantOnShift && isShiftPressed;

    if (!shouldBypassDelay && elapsed < (delayTicks * 50)) {
        return;
    }

    if (hasSwitched_) {
        return;
    }

    auto theWorld = mc.theWorld();
    if (theWorld.isNull()) return;

    Block block = theWorld.getBlockAt(blockPos.x, blockPos.y, blockPos.z);
    if (block.isNull()) return;
    jobject blockRef = block.getObj();

    auto inventory = thePlayer.inventoryPlayer();
    if (inventory.isNull()) return;

    float bestSpeed = 1.0f;
    int bestSlot = originalSlot_;

    auto currentStack = inventory.getItem(originalSlot_);
    if (!currentStack.isNull()) {
        auto currentItem = currentStack.theItem();
        if (!currentItem.isNull()) {
            bestSpeed = currentStack.getStrVsBlock(blockRef);
        }
    }

    for (int slotIndex = 0; slotIndex < 9; slotIndex++) {
        if (slotIndex == originalSlot_) continue;

        auto itemStack = inventory.getItem(slotIndex);
        if (itemStack.isNull()) continue;

        auto item = itemStack.theItem();
        if (item.isNull()) continue;

        float blockBreakSpeed = itemStack.getStrVsBlock(blockRef);

        if (blockBreakSpeed > bestSpeed) {
            bestSpeed = blockBreakSpeed;
            bestSlot = slotIndex;
        }
    }

    int currentSlot = inventory.currentItem();
    if (currentSlot != bestSlot) {
        if (!hasSwitched_) {
            hasSwitched_ = true;
        }
        hasEverSwitchedSlot_ = true;

        inventory.currentItem(bestSlot);

        if (ModuleHandler::getInstance().isModuleEnabled(ModuleType::AUTOCLICKER)) {

            Sleep(10);

            INPUT inputs[2] = {};

            inputs[0].type = INPUT_MOUSE;
            inputs[0].mi.dwFlags = MOUSEEVENTF_LEFTUP;

            inputs[1].type = INPUT_MOUSE;
            inputs[1].mi.dwFlags = MOUSEEVENTF_LEFTDOWN;

            SendInput(2, inputs, sizeof(INPUT));
        }
    }
}

void AutoToolModule::switchToSword(JNIEnv* env) {
    auto mc = Minecraft::getMinecraft(env);
    if (mc.isNull()) return;

    auto thePlayer = mc.thePlayer();
    if (thePlayer.isNull()) return;

    auto inventory = thePlayer.inventoryPlayer();
    if (inventory.isNull()) return;

    int swordSlot = findBestSwordSlot(env);
    if (swordSlot != -1) {
        inventory.currentItem(swordSlot);
    } else {
        inventory.currentItem(originalSlot_);
    }

    hasSwitched_ = false;
}

int AutoToolModule::findBestSwordSlot(JNIEnv* env) {
    auto mc = Minecraft::getMinecraft(env);
    if (mc.isNull()) return -1;

    auto thePlayer = mc.thePlayer();
    if (thePlayer.isNull()) return -1;

    auto inventory = thePlayer.inventoryPlayer();
    if (inventory.isNull()) return -1;

    int bestSlot = -1;

    for (int i = 0; i < 9; i++) {
        auto itemStack = inventory.getItem(i);
        if (!itemStack.isNull() && itemStack.isSword()) {
            bestSlot = i;
            break;
        }
    }

    return bestSlot;
}

REGISTER_MODULE(AutoToolModule, ModuleType::AUTO_TOOL)
