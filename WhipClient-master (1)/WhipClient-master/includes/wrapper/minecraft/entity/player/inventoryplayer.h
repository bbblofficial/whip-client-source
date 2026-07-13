#pragma once
#include "../../../../../includes/wrapper/primitive/JavaObject.h"
#include "../../item/ItemStack.h"

class InventoryPlayer : public JavaObject {
    static jfieldID mainInventoryId;
    static jfieldID currentItemId;
    static jfieldID armorInventoryId;

public:
    InventoryPlayer(JNIEnv* env, jobject obj) : JavaObject(env, obj) {}

    ItemStack getArmorItem(int slot) {
        if (!armorInventoryId) armorInventoryId = mappings->getField("InventoryPlayer#armorInventory");
        jobjectArray armorInv = (jobjectArray)this->env->GetObjectField(this->obj, armorInventoryId);
        if (!armorInv) return { NULL, NULL };
        jobject item = this->env->GetObjectArrayElement(armorInv, slot);
        this->env->DeleteLocalRef(armorInv);
        if (!item) return { NULL, NULL };
        return { this->env, item };
    }

    jobjectArray getArmorArray() {
        if (!armorInventoryId) armorInventoryId = mappings->getField("InventoryPlayer#armorInventory");
        if (!armorInventoryId) return nullptr;
        return (jobjectArray)this->env->GetObjectField(this->obj, armorInventoryId);
    }

    ItemStack getItem(int slot) {
        if (!mainInventoryId) mainInventoryId = mappings->getField("InventoryPlayer#mainInventory");
        jobjectArray armorInv = (jobjectArray)this->env->GetObjectField(this->obj, mainInventoryId);
        if (!armorInv) return { NULL, NULL };
        jobject item = this->env->GetObjectArrayElement(armorInv, slot);
        this->env->DeleteLocalRef(armorInv);
        if (!item) return { NULL, NULL };
        return { this->env, item };
    }

    bool isHotbarFull() const {
        if (!mainInventoryId) mainInventoryId = mappings->getField("InventoryPlayer#mainInventory");

        JavaObject armorInv = { env, this->env->GetObjectField(this->obj, mainInventoryId) };
        if (armorInv.isNull()) return false;

        for (int i = 0; i < 9; i++) {
            if (ItemStack item = {
                env, this->env->GetObjectArrayElement(static_cast<jobjectArray>(armorInv.getObj()), i)
            }; !item.isNull()) {
                continue;
            }

            return false;
        }

        return true;
    }

    int countEmptyHotbarSlots() const {
        if (!mainInventoryId) mainInventoryId = mappings->getField("InventoryPlayer#mainInventory");

        JavaObject armorInv = { env, this->env->GetObjectField(this->obj, mainInventoryId) };
        if (armorInv.isNull()) return 0;

        int emptyCount = 0;
        for (int i = 0; i < 9; i++) {
            ItemStack item = {
                env, this->env->GetObjectArrayElement(static_cast<jobjectArray>(armorInv.getObj()), i)
            };

            if (item.isNull() || item.getStackSize() <= 0) {
                emptyCount++;
            }
        }

        return emptyCount;
    }

    int currentItem() {
        if (!currentItemId) currentItemId = mappings->getField("InventoryPlayer#currentItem");
        return this->env->GetIntField(this->obj, this->currentItemId);
    }

    void currentItem(int i) {
        if (!currentItemId) currentItemId = mappings->getField("InventoryPlayer#currentItem");
        this->env->SetIntField(this->obj, currentItemId, i);
    }
};
