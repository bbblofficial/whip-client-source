#pragma once

#include "bus/EventBus.h"
#include "event/sub/PreMotionEvent.h"
#include "event/sub/PostMotionEvent.h"
#include "hook/base/BaseHook.h"

class OnUpdateWalkingPlayerHook final : public StaticBaseHook<OnUpdateWalkingPlayerHook> {
public:
    OnUpdateWalkingPlayerHook() : StaticBaseHook(HookPosition::BOTH) {}

    ~OnUpdateWalkingPlayerHook() override = default;

    static std::string getHookName() {
        return "EntityPlayerSP#onUpdateWalkingPlayer";
    }

protected:
    HookResult onPreExecute(JNIEnv* env, jobjectArray args) override {
        (void)args;
        if (!env) return HookResult::Continue();

        PreMotionEvent event(env);
        EventBus::getInstance().dispatch(event);

        return HookResult::Continue();
    }

    void onPostExecute(JNIEnv* env, jobject result, jobjectArray args) override {
        (void)result;
        (void)args;
        if (!env) return;

        PostMotionEvent event(env);
        EventBus::getInstance().dispatch(event);
    }
};
