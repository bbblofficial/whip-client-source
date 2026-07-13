#pragma once

#include "bus/EventBus.h"
#include "event/sub/ChannelReadEvent.h"
#include "hook/base/BaseHook.h"
#include "wrapper/minecraft/client/minecraft.h"

class ChannelReadHook final : public StaticBaseHook<ChannelReadHook> {
public:
    ChannelReadHook() : StaticBaseHook(HookPosition::PRE) {}

    ~ChannelReadHook() override = default;

    static std::string getHookName() {
        return "NetworkManager#channelRead0";
    }

protected:
    HookResult onPreExecute(JNIEnv* env, jobjectArray args) override {
        if (!env) {
            return HookResult::Continue();
        }

        jobject packetObj = getArg(env, args, 2);
        if (!packetObj) {
            return HookResult::Continue();
        }

        ChannelReadEvent event(env, packetObj);
        EventBus::getInstance().dispatch(event);
        if (event.isCancelled()) {
            return HookResult::Cancel(env);
        }

        return HookResult::Continue();
    }
};
