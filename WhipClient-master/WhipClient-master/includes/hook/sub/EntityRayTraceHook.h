#pragma once
#include "hook/base/BaseHook.h"

class EntityRayTraceHook final : public StaticBaseHook<EntityRayTraceHook> {
public:
    EntityRayTraceHook() : StaticBaseHook(HookPosition::BOTH) {}

    ~EntityRayTraceHook() override = default;

    static std::string getHookName() {
        return "Entity#rayTrace";
    }

protected:
    HookResult onPreExecute(JNIEnv* env, jobjectArray args) override;
    void onPostExecute(JNIEnv* env, jobject result, jobjectArray args) override;
};
