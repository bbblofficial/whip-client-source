#include "hook/sub/EntityRayTraceHook.h"
#include "module/impl/combat/PiercingModule.h"
#include "bus/EventBus.h"
#include "event/sub/PreRayTraceEvent.h"
#include "event/sub/PostRayTraceEvent.h"

HookResult EntityRayTraceHook::onPreExecute(JNIEnv* env, jobjectArray args) {
    if (!env) return HookResult::Continue();

    auto* piercingMod = PiercingModule::getInstancePtr();
    if (piercingMod && piercingMod->shouldBypassBlock(env)) {
        return HookResult::CancelNull();
    }

    PreRayTraceEvent event(env);
    EventBus::getInstance().dispatch(event);

    return HookResult::Continue();
}

void EntityRayTraceHook::onPostExecute(JNIEnv* env, jobject result, jobjectArray args) {
    (void)result;
    (void)args;
    if (!env) return;

    PostRayTraceEvent event(env);
    EventBus::getInstance().dispatch(event);
}
