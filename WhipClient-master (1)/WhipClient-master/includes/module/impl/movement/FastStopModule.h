#pragma once
#include "../../base/ListenedBaseModule.h"
#include "../../ModuleType.h"
#include "../../CategoryType.h"
#include "event/sub/DispatchKeypressesEvent.h"
#include "util/ClientStrings.h"

class FastStopModule final : public ListenedBaseModule<FastStopModule, ModuleType::FAST_STOP, CategoryType::MOVEMENT> {

protected:
    void registerEvents() override;

private:

    int  axis           = 0;
    bool disableOnSneak = false;

    bool prevForward_ = false;
    bool prevBack_    = false;
    bool prevLeft_    = false;
    bool prevRight_   = false;

    int forwardHeldTicks_ = 0;
    int backHeldTicks_    = 0;
    int leftHeldTicks_    = 0;
    int rightHeldTicks_   = 0;

    bool csActiveF_  = false;
    bool csActiveB_  = false;

    bool csActiveL_  = false;
    bool csActiveR_  = false;

    jclass    lwjglKeyboardClass_ = nullptr;
    jmethodID isKeyDownMethodId_  = nullptr;

    bool isPhysDown(JNIEnv* env, int keyCode);
    void onTick(const OnRunTickEvent& event);

public:
    FastStopModule() {}

    void onLoad() override {
        ListenedBaseModule::onLoad();
        COMBO_SETTING(axis, Strings::snapTapAxisBoth(), Strings::snapTapAxisStrafe(), Strings::snapTapAxisFwdBack());
        BOOL_SETTING_CONDITIONAL(disableOnSneak, false);
    }
};
