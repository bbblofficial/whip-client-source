#pragma once

#include "bus/EventBus.h"
#include "event/sub/PreOrientCameraEvent.h"
#include "event/sub/PostOrientCameraEvent.h"
#include "hook/base/BaseHook.h"
#include "util/RenderMatrixSnapshot.h"

class OrientCameraHook final : public StaticBaseHook<OrientCameraHook> {
public:
    OrientCameraHook() : StaticBaseHook(HookPosition::BOTH) {}

    ~OrientCameraHook() override = default;

    static std::string getHookName() {
        return "EntityRenderer#orientCamera";
    }

protected:
    HookResult onPreExecute(JNIEnv* env, jobjectArray args) override {
        (void)args;
        if (!env) return HookResult::Continue();

        PreOrientCameraEvent event(env);
        EventBus::getInstance().dispatch(event);

        return HookResult::Continue();
    }

    void onPostExecute(JNIEnv* env, jobject result, jobjectArray args) override {
        (void)result;
        (void)args;
        if (!env) return;

        RenderMatrixSnapshot::get().capture();

        PostOrientCameraEvent event(env);
        EventBus::getInstance().dispatch(event);
    }
};
