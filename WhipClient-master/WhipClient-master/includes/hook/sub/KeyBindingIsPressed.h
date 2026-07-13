#pragma once

#include "hook/base/BaseHook.h"
#include "manager/BindManager.h"
#include "util/LWJGLKeyConverter.h"
#include "wrapper/minecraft/client/settings/KeyBinding.h"
#include "util/Debug.h"

class KeyBindingIsPressed final : public StaticBaseHook<KeyBindingIsPressed> {
public:
    KeyBindingIsPressed() : StaticBaseHook(HookPosition::PRE) {}

    ~KeyBindingIsPressed() override = default;

    static std::string getHookName() {
        return "KeyBinding#isPressed";
    }

protected:
    HookResult onPreExecute(JNIEnv* env, const jobjectArray args) override {
        if (!env) {
            return HookResult::Continue();
        }

        const jobject keyBindingObj = getArg(env, args, 0);
        if (!keyBindingObj) {
            return HookResult::Continue();
        }

        KeyBinding keyBinding(env, keyBindingObj);
        const int lwjglKey = keyBinding.keyCode();

        const int vkKey = LWJGLKeyConverter::lwjglToVK(lwjglKey);
        if (vkKey == 0) {
            return HookResult::Continue();
        }

        if (BindManager::getInstance().hasKeyBind(vkKey)) {
            return HookResult::ReturnBoolean(env, false);
        }

        return HookResult::Continue();
    }
};
