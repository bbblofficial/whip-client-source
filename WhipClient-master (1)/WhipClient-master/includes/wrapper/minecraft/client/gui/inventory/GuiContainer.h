#pragma once
#include "../../../../../../includes/wrapper/primitive/JavaObject.h"
#include "../../../../../../includes/wrapper/minecraft/inventory/Container.h"

class GuiContainer : public JavaObject {
private:
    static jfieldID inventorySlotsId;

public:
    GuiContainer(JNIEnv* env, jobject obj) : JavaObject(env, obj) {}

    Container inventorySlots() {
        if (!inventorySlotsId) inventorySlotsId = mappings->getField("GuiContainer#inventorySlots");
        jobject obj = this->env->GetObjectField(this->obj, inventorySlotsId);
        if (!obj) return { nullptr, nullptr };
        return { this->env, obj };
    }

    int guiLeft() {
        static jfieldID guiLeftId = nullptr;
        if (!guiLeftId) {
            guiLeftId = mappings->getField("GuiContainer#guiLeft");
            if (!guiLeftId) {
                jclass guiContainerClass = env->GetObjectClass(this->obj);
                if (guiContainerClass) {
                    guiLeftId = env->GetFieldID(guiContainerClass, "guiLeft", "I");
                    if (!guiLeftId) {
                        env->ExceptionClear();
                        guiLeftId = env->GetFieldID(guiContainerClass, "field_147003_i", "I");
                        if (!guiLeftId) env->ExceptionClear();
                    }
                    env->DeleteLocalRef(guiContainerClass);
                }
            }
        }
        if (!guiLeftId) return -1;
        return env->GetIntField(this->obj, guiLeftId);
    }

    int guiTop() {
        static jfieldID guiTopId = nullptr;
        if (!guiTopId) {
            guiTopId = mappings->getField("GuiContainer#guiTop");
            if (!guiTopId) {
                jclass guiContainerClass = env->GetObjectClass(this->obj);
                if (guiContainerClass) {
                    guiTopId = env->GetFieldID(guiContainerClass, "guiTop", "I");
                    if (!guiTopId) {
                        env->ExceptionClear();
                        guiTopId = env->GetFieldID(guiContainerClass, "field_147009_r", "I");
                        if (!guiTopId) env->ExceptionClear();
                    }
                    env->DeleteLocalRef(guiContainerClass);
                }
            }
        }
        if (!guiTopId) return -1;
        return env->GetIntField(this->obj, guiTopId);
    }
};
