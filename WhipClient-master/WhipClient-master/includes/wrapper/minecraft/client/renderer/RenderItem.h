#pragma once

#include "../../../primitive/JavaObject.h"
#include "../../item/ItemStack.h"

class RenderItem : public JavaObject {
private:
    static jmethodID renderItemAndEffectIntoGUIId;

public:
    RenderItem(JNIEnv* env, jobject obj) : JavaObject(env, obj) {}

    void renderItemAndEffectIntoGUI(ItemStack& itemStack, int x, int y) {
        if (!renderItemAndEffectIntoGUIId) {
            renderItemAndEffectIntoGUIId = mappings->getMethod("RenderItem#renderItemAndEffectIntoGUI");
        }
        if (!renderItemAndEffectIntoGUIId || itemStack.isNull()) return;

        this->env->CallVoidMethod(this->obj, renderItemAndEffectIntoGUIId, itemStack.getObj(), x, y);
    }
};
