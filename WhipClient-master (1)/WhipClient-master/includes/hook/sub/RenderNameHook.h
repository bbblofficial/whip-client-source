#pragma once
#include "bus/EventBus.h"
#include "event/sub/RenderNameEvent.h"
#include "hook/base/BaseHook.h"
#include "module/impl/visual/ChamsModule.h"
#include "module/impl/visual/PlayerESPModule.h"
#include "hook/sub/RenderEntitySimpleHook.h"
#include <gl/GL.h>

class RenderNameHook final : public StaticBaseHook<RenderNameHook> {
public:
    RenderNameHook() : StaticBaseHook(HookPosition::PRE) {}

    ~RenderNameHook() override = default;

    static std::string getHookName() {
        return "RendererLivingEntity#renderName";
    }

protected:
    HookResult onPreExecute(JNIEnv* env, jobjectArray args) override {
        (void)args;
        if (!env) {
            return HookResult::Continue();
        }

        if (RenderEntitySimpleHook::isInChamsHook) {
            glTexEnvi(GL_TEXTURE_ENV, GL_TEXTURE_ENV_MODE, GL_MODULATE);
            glEnable(GL_LIGHTING);
            glColor4f(1.0f, 1.0f, 1.0f, 1.0f);
        }

        if (ChamsModule::isRenderingChams) {
            return HookResult::Cancel(env);
        }

        if (PlayerESPModule::isRenderingOutline) {
            return HookResult::Cancel(env);
        }

        RenderNameEvent event(env);
        EventBus::getInstance().dispatch(event);

        if (event.isCancelled()) {
            return HookResult::Cancel(env);
        }

        return HookResult::Continue();
    }
};
