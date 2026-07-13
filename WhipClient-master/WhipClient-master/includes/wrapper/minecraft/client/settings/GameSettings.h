#pragma once
#include "../../../../../includes/wrapper/primitive/JavaObject.h"
#include "KeyBinding.h"
class GameSettings : public JavaObject {
private:
    static jfieldID mouseSensitivityId;
    static jfieldID gammaSettingId;
    static jfieldID gammaSettingIdd;
    static jfieldID keyBindInventoryId;
    static jfieldID keyBindForwardId;
    static jfieldID keyBindRightId;
    static jfieldID keyBindLeftId;
    static jfieldID keyBindJumpId;
    static jfieldID keyBindPickBlockId;
    static jfieldID keyBindUseItemId;
    static jfieldID keyBindSprintId;
    static jfieldID keyBindSneakId;
    static jfieldID keyBindBackId;
    static jfieldID guiScaleId;
    static jfieldID keyBindDropId;
    static jfieldID keyBindsHotbarId;
    static jfieldID entityShadowsId;
public:
    GameSettings(JNIEnv* env, jobject obj) : JavaObject::JavaObject(env, obj) {}
    float mouseSensitivity() {
        if (!mouseSensitivityId) mouseSensitivityId = mappings->getField("GameSettings#mouseSensitivity");
        return this->env->GetFloatField(this->obj, mouseSensitivityId);
    }
    void SetGamma(float v) {
        if (!gammaSettingId) gammaSettingId = mappings->getField("GameSettings#gammaSetting");
        this->env->SetFloatField(this->obj, gammaSettingId, v);
    }
    float GetGamma() {
        if (!gammaSettingIdd) gammaSettingIdd = mappings->getField("GameSettings#gammaSetting");

        return this->env->GetFloatField(this->obj, gammaSettingIdd);
    }

    int guiScale() {
        if (!guiScaleId) guiScaleId = mappings->getField("GameSettings#guiScale");

        return this->env->GetIntField(this->obj, guiScaleId);
    }

    KeyBinding keyBindInventory() {
        if (!keyBindInventoryId) keyBindInventoryId = mappings->getField("GameSettings#keyBindInventory");
        jobject obj = this->env->GetObjectField(this->obj, keyBindInventoryId);
        if (!obj) return { NULL, NULL };
        return { this->env, obj };
    }

    KeyBinding keyBindForward() {
        if (!keyBindForwardId) keyBindForwardId = mappings->getField("GameSettings#keyBindForward");
        jobject obj = this->env->GetObjectField(this->obj, keyBindForwardId);
        if (!obj) return { NULL, NULL };
        return { this->env, obj };
    }

    KeyBinding keyBindRight() {
        if (!keyBindRightId) keyBindRightId = mappings->getField("GameSettings#keyBindRight");
        jobject obj = this->env->GetObjectField(this->obj, keyBindRightId);
        if (!obj) return { NULL, NULL };
        return { this->env, obj };
    }

    KeyBinding keyBindLeft() {
        if (!keyBindLeftId) keyBindLeftId = mappings->getField("GameSettings#keyBindLeft");
        jobject obj = this->env->GetObjectField(this->obj, keyBindLeftId);
        if (!obj) return { NULL, NULL };
        return { this->env, obj };
    }

    KeyBinding keyBindJump() {
        if (!keyBindJumpId) keyBindJumpId = mappings->getField("GameSettings#keyBindJump");
        jobject obj = this->env->GetObjectField(this->obj, keyBindJumpId);
        if (!obj) return { NULL, NULL };
        return { this->env, obj };
    }

    KeyBinding keyBindPickBlock() {
        if (!keyBindPickBlockId) keyBindPickBlockId = mappings->getField("GameSettings#keyBindPickBlock");
        jobject obj = this->env->GetObjectField(this->obj, keyBindPickBlockId);
        if (!obj) return { NULL, NULL };
        return { this->env, obj };
    }

    KeyBinding keyBindUseItem() {
        if (!keyBindUseItemId) keyBindUseItemId = mappings->getField("GameSettings#keyBindUseItem");
        jobject obj = this->env->GetObjectField(this->obj, keyBindUseItemId);
        if (!obj) return { NULL, NULL };
        return { this->env, obj };
    }

    KeyBinding keyBindSprint() {
        if (!keyBindSprintId) keyBindSprintId = mappings->getField("GameSettings#keyBindSprint");
        jobject obj = this->env->GetObjectField(this->obj, keyBindSprintId);
        if (!obj) return { NULL, NULL };
        return { this->env, obj };
    }

    KeyBinding keyBindSneak() {
        if (!keyBindSneakId) keyBindSneakId = mappings->getField("GameSettings#keyBindSneak");
        jobject obj = this->env->GetObjectField(this->obj, keyBindSneakId);
        if (!obj) return { NULL, NULL };
        return { this->env, obj };
    }

    KeyBinding keyBindBack() {
        if (!keyBindBackId) keyBindBackId = mappings->getField("GameSettings#keyBindBack");
        jobject obj = this->env->GetObjectField(this->obj, keyBindBackId);
        if (!obj) return { NULL, NULL };
        return { this->env, obj };
    }

    KeyBinding keyBindDrop() {
        if (!keyBindDropId) keyBindDropId = mappings->getField("GameSettings#keyBindDrop");
        jobject obj = this->env->GetObjectField(this->obj, keyBindDropId);
        if (!obj) return { NULL, NULL };
        return { this->env, obj };
    }

    bool entityShadows() {
        if (!entityShadowsId) entityShadowsId = mappings->getField("GameSettings#entityShadows");
        if (!entityShadowsId) return true;
        return this->env->GetBooleanField(this->obj, entityShadowsId);
    }

    void setEntityShadows(bool v) {
        if (!entityShadowsId) entityShadowsId = mappings->getField("GameSettings#entityShadows");
        if (!entityShadowsId) return;
        this->env->SetBooleanField(this->obj, entityShadowsId, (jboolean)v);
    }

    KeyBinding getHotbarKeyBinding(int slot) {
        if (!keyBindsHotbarId) keyBindsHotbarId = mappings->getField("GameSettings#keyBindsHotbar");
        jobjectArray arr = (jobjectArray)this->env->GetObjectField(this->obj, keyBindsHotbarId);
        if (!arr) return { NULL, NULL };
        jobject obj = this->env->GetObjectArrayElement(arr, slot);
        this->env->DeleteLocalRef(arr);
        if (!obj) return { NULL, NULL };
        return { this->env, obj };
    }
};
