#pragma once
#include "ThrowMode.h"

class ThrowPearlMode : public ThrowMode {
public:
    ThrowPearlMode();

    void execute(int speed, bool doubleOption, bool smartMode, TickLockerModule* tickLocker, JNIEnv* env) override;

    int findSlot(InventoryPlayer& inventoryPlayer, JNIEnv* env) override;

    void handleThrow(int slot, int speed, InventoryPlayer& inventoryPlayer, int originalSlot, Minecraft& mc, TickLockerModule* tickLocker, bool doubleOption, bool smartMode, JNIEnv* env, bool autoDrop = false) override;

    void performThrow(int slot, InventoryPlayer& inventoryPlayer, int originalSlot, Minecraft& mc, TickLockerModule* tickLocker, bool doubleOption, bool smartMode, JNIEnv* env, bool autoDrop = false) override;

    bool isValidItem(int itemDamage, bool isPearl) override;

    int getThrowCount(float health, bool doubleThrow) override;

    float getHealthThreshold() override;
};
