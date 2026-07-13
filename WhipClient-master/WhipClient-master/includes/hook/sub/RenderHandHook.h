#pragma once

#include "hook/base/BaseHook.h"
#include "module/impl/visual/ChamsModule.h"
#include "module/impl/visual/PlayerESPModule.h"

class RenderHandHook final : public StaticBaseHook<RenderHandHook> {
public:
    RenderHandHook() : StaticBaseHook(HookPosition::PRE) {}
    ~RenderHandHook() override = default;

    static std::string getHookName() {
        return "EntityRenderer#renderHand";
    }

protected:
    HookResult onPreExecute(JNIEnv* env, jobjectArray args) override {

        auto* chamsMod = ChamsModule::getInstancePtr();
        if (chamsMod && chamsMod->isEnabled()) {
            chamsMod->renderChamsOverlay(env);
        }

        auto* espMod = PlayerESPModule::getInstancePtr();
        if (espMod && espMod->isEnabled()) {
            espMod->renderOutlineOverlay(env);
        }

        return HookResult::Continue();
    }
};
