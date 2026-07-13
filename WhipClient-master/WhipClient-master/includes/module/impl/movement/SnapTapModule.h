#pragma once
#include "../../base/ListenedBaseModule.h"
#include "../../ModuleType.h"
#include "../../CategoryType.h"
#include "event/sub/DispatchKeypressesEvent.h"
#include "util/ClientStrings.h"

class SnapTapModule final : public ListenedBaseModule<SnapTapModule, ModuleType::SNAP_TAP, CategoryType::MOVEMENT> {

protected:
    void registerEvents() override;

private:

    int  axis           = 0;
    bool onlyOnGround   = false;
    bool disableOnSneak = false;

    bool prevLeft_    = false;
    bool prevRight_   = false;
    bool prevForward_ = false;
    bool prevBack_    = false;

    bool suppLeft_    = false;
    bool suppRight_   = false;
    bool suppForward_ = false;
    bool suppBack_    = false;

    jclass    lwjglKeyboardClass_  = nullptr;
    jmethodID isKeyDownMethodId_   = nullptr;

    bool isPhysDown(JNIEnv* env, int keyCode);
    void onTick(const OnRunTickEvent& event);

public:
    SnapTapModule() {}

    void onLoad() override {
        ListenedBaseModule::onLoad();
        COMBO_SETTING(axis, Strings::snapTapAxisBoth(), Strings::snapTapAxisStrafe(), Strings::snapTapAxisFwdBack());
        BOOL_SETTING_CONDITIONAL(onlyOnGround, false);
        BOOL_SETTING_CONDITIONAL(disableOnSneak, false);
    }
};
