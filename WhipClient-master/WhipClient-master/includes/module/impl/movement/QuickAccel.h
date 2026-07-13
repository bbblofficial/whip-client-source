#pragma once
#include "../../base/ListenedBaseModule.h"
#include "../../ModuleType.h"
#include "../../CategoryType.h"
#include "event/sub/EntityLivingUpdateEvent.h"
#include "module/base/SharedThreadBaseModule.h"
#include "util/xor.h"
#include "util/ClientStrings.h"

class QuickAccelModule final : public ListenedBaseModule<QuickAccelModule, ModuleType::QUICK_ACCEL, CategoryType::MOVEMENT> {

protected:
    void registerEvents() override;

private:
    bool disableOnSneak = true;

public:
    QuickAccelModule() {}

    void OnEntityLivingUpdate(const EntityLivingUpdateEvent& event);

    void onLoad() override {
        ListenedBaseModule::onLoad();
        BOOL_SETTING_CONDITIONAL_OPTIONAL(disableOnSneak, true, SETTING_VISIBILITY(TRUE));
    }
};
