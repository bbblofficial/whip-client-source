#include "../../../includes/hook/sub/GetSlotAtPositionHook.h"
#include "../../../includes/wrapper/minecraft/client/gui/inventory/GuiContainer.h"
#include "util/Debug.h"

bool GetSlotAtPositionHook::spoofActive = false;
std::queue<int> GetSlotAtPositionHook::spoofedSlots;
std::mutex GetSlotAtPositionHook::slotsMutex;

HookResult GetSlotAtPositionHook::onPreExecute(JNIEnv* env, jobjectArray args) {
    std::lock_guard lock(slotsMutex);

    if (!env || !spoofActive || spoofedSlots.empty()) {
        return HookResult::Continue();
    }

    int slot = spoofedSlots.front();
    spoofedSlots.pop();

    if (spoofedSlots.empty()) {
        spoofActive = false;

    }

    jobject guiContainerObj = getArg(env, args, 0);
    if (!guiContainerObj) {
        return HookResult::Continue();
    }

    GuiContainer guiContainer(env, guiContainerObj);

    Container container = guiContainer.inventorySlots();
    if (container.isNull()) {
        return HookResult::Continue();
    }

    ArrayList slots = container.inventorySlots();
    if (slots.isNull() || slot >= slots.size()) {
        return HookResult::Continue();
    }

    JavaObject slotObj = slots.get(slot);
    if (slotObj.isNull()) {
        return HookResult::Continue();
    }

    slotObj.setDeleteRef(false);
    jobject slotObject = slotObj.getObj();

    if (!slotObject) {
        return HookResult::Continue();
    }

    return HookResult::ReturnObject(env, slotObject);
}
