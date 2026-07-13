#pragma once
#include "../../../hud/renderer/IArraylistRenderer.h"
#include "../../base/DedicatedThreadBaseModule.h"
#include "../../ModuleType.h"
#include "../../CategoryType.h"
#include "../../../util/JniScope.h"
#include "util/xor.h"
#include "util/ClientStrings.h"
#include "util/MathUtils.h"
#include <windows.h>

class FastPlaceModule final : public DedicatedThreadBaseModule<FastPlaceModule, ModuleType::FAST_PLACE, CategoryType::MISC> {
    int mode = 0;
    int tickDelay = 0;
    bool onlyBlock = true;

    float average = 15.0f;
    bool holdToClick = true;
    bool exhaust = true;
    int currentPId = 0;
    ULONGLONG lastClickTime = 0;

protected:
    void onUpdate(JniScope& scope) override;

public:
    FastPlaceModule() : DedicatedThreadBaseModule(BindType::TOGGLE, 0, 0) {}

    void onCleanup() override { clearInstanceBuffer(); }

    void onLoad() override {
        DedicatedThreadBaseModule::onLoad();

        COMBO_SETTING(mode, Strings::modeDelay(), Strings::modeClick());

        INT_SLIDER_OPTIONAL(tickDelay, 0, 0, 3, SETTING_VISIBILITY(mode == 0));
        BOOL_SETTING_CONDITIONAL(onlyBlock, true);

        FLOAT_SLIDER_OPTIONAL(average, 15.0f, 1.0f, 25.0f, SETTING_VISIBILITY(mode == 1));
        BOOL_SETTING_CONDITIONAL_OPTIONAL(holdToClick, true, SETTING_VISIBILITY(mode == 1));
        BOOL_SETTING_CONDITIONAL_OPTIONAL(exhaust, true, SETTING_VISIBILITY(mode == 1));

        currentPId = GetCurrentProcessId();
        lastClickTime = GetTickCount64();
    }

private:
    mutable char instanceBuffer[64] = {0};

public:
    FORMAT_FLAGS("%s", (this->mode == 0 ? Strings::modeDelay() : Strings::modeClick()))
};
