#pragma once
#include "module/impl/misc/TickLockerModule.h"
#include "wrapper/minecraft/client/minecraft.h"
#include "wrapper/minecraft/entity/player/inventoryplayer.h"

class ThrowMode {
public:
    virtual ~ThrowMode() = default;

    virtual void execute(int speed, bool doubleOption, bool smartMode, TickLockerModule* tickLocker, JNIEnv* env) = 0;

    virtual int findSlot(InventoryPlayer& inventoryPlayer, JNIEnv* env) = 0;

    virtual void handleThrow(int slot, int speed, InventoryPlayer& inventoryPlayer, int originalSlot, Minecraft& mc, TickLockerModule* tickLocker, bool doubleOption, bool smartMode, JNIEnv* env, bool autoDrop = false) = 0;

    virtual void performThrow(int slot, InventoryPlayer& inventoryPlayer, int originalSlot, Minecraft& mc, TickLockerModule* tickLocker, bool doubleOption, bool smartMode, JNIEnv* env, bool autoDrop = false) = 0;

    virtual bool isValidItem(int itemDamage, bool isSoup) = 0;

    virtual int getThrowCount(float health, bool doubleThrow) = 0;

    virtual float getHealthThreshold() = 0;

    virtual bool shouldHealSmart(const float currentHealth, const float maxHealth = 20.0, const float potionHeal = 8.0) {
        const float healthLost = maxHealth - currentHealth;
        return healthLost >= potionHeal;
    }
};
