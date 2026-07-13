#pragma once
#include "../../../hud/renderer/IArraylistRenderer.h"
#include "../../base/BindBaseModule.h"
#include "../../ModuleType.h"
#include "../../CategoryType.h"
#include "../../bind/BindType.h"
#include "module/base/DedicatedThreadBaseModule.h"
#include "module/base/SharedThreadBaseModule.h"
#include "util/xor.h"
#include "util/ClientStrings.h"
#include "wrapper/minecraft/entity/player/inventoryplayer.h"
#include "wrapper/minecraft/item/ItemStack.h"

class BowBoostModule final : public DedicatedThreadBaseModule<BowBoostModule, ModuleType::BOW_BOOST, CategoryType::MISC> {
private:

    int mode = 0;
    bool autoSwitch = true;
    int firstChargeTime = 200;
    int secondChargeTime = 100;
    bool returnToSlot = true;
    int delayBetweenShots = 150;

    bool flyActive = false;
    int originalSlot = 0;
    bool isCharging = false;
    int boostState = 0;

    bool punchExecuted = false;

    DWORD chargeStartTime = 0;
    DWORD lastShotTime = 0;

    static inline bool simulatingRightClick = false;

    bool isPunchBow(ItemStack& itemStack);
    bool hasFlyBow(InventoryPlayer& inventoryPlayer);
    bool hasPunchBow(InventoryPlayer& inventoryPlayer);

    int findPunchBowSlot(InventoryPlayer& inventoryPlayer);
    int findFlyBowSlot(InventoryPlayer& inventoryPlayer);
    int findSwordSlot(InventoryPlayer& inventoryPlayer);

    bool holdingPunchBow(InventoryPlayer& inventoryPlayer);
    bool holdingFlyBow(InventoryPlayer& inventoryPlayer);

    void switchToPunchBow(InventoryPlayer& inventoryPlayer);
    void switchToFlyBow(InventoryPlayer& inventoryPlayer);
    void switchToSword(InventoryPlayer& inventoryPlayer);

    void startCharge();
    void releaseArrow();
    void resetFlyState();
    void resetPunchState();
    void stopFlyAndCleanup(InventoryPlayer& inventoryPlayer);

    void handlePunchMode(JniScope& scope, InventoryPlayer& inventoryPlayer);
    void handleFlyMode(JniScope& scope, InventoryPlayer& inventoryPlayer);

protected:
    void onUpdate(JniScope& scope) override;

public:
    BowBoostModule() : DedicatedThreadBaseModule(BindType::HOLD, 0, 10) {}

    static bool isSimulatingRightClick() {
        return simulatingRightClick;
    }

    void onEnable() override {
        DedicatedThreadBaseModule::onEnable();
        resetFlyState();
        resetPunchState();
    }

    void onDisable() override {
        DedicatedThreadBaseModule::onDisable();
        resetFlyState();
        resetPunchState();
    }

    void onCleanup() override { clearInstanceBuffer(); }

    void onLoad() override {
        DedicatedThreadBaseModule::onLoad();

        INT_SLIDER(firstChargeTime, 200, 50, 300);
    }

private:
	mutable char instanceBuffer[64] = {0};

public:

    FORMAT_FLAGS("%s", (this->mode == 0 ? Strings::modeAgro() : Strings::modeFly()))
};
