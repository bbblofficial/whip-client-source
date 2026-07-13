#pragma once
#include "../../../hud/renderer/IArraylistRenderer.h"
#include "../../base/SharedThreadBaseModule.h"
#include "../../ModuleType.h"
#include "../../CategoryType.h"
#include "../../../util/JniScope.h"
#include "util/xor.h"
#include "util/ClientStrings.h"

class FastBreakModule final : public SharedThreadBaseModule<FastBreakModule, ModuleType::FAST_BREAK, CategoryType::MISC> {
    int mode = 0;
    float power = 0.0f;
    float multiplier = 1.0f;

    float lastBlockDamageMP = 0.0f;

protected:
    void onUpdate(JniScope& scope) override;

public:
    FastBreakModule();

    void onCleanup() override { clearInstanceBuffer(); }

    void onLoad() override {
        SharedThreadBaseModule::onLoad();

        COMBO_SETTING(mode, Strings::modeNormal(), Strings::modeTimer());
        FLOAT_SLIDER_OPTIONAL(power, 0.0f, 0.0f, 100.0f, SETTING_VISIBILITY(mode == 0));
        FLOAT_SLIDER_OPTIONAL(multiplier, 1.0f, 0.0f, 100.0f, SETTING_VISIBILITY(mode == 1));
    }

private:
	mutable char instanceBuffer[64] = {0};

public:

    FORMAT_FLAGS("%s %.1f%s",
       (this->mode == 0 ? Strings::modeNormal() : Strings::modeTimer()),
       (this->mode == 0 ? this->power : this->multiplier),
       (this->mode == 0 ? "%" : "x"))
};
