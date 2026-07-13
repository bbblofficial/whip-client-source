#pragma once
#include "../../../hud/renderer/IArraylistRenderer.h"
#include "../../base/SharedThreadBaseModule.h"
#include "../../ModuleType.h"
#include "../../CategoryType.h"
#include "../../../util/JniScope.h"
#include "../../../event/sub/AttackEntityEvent.h"
#include "wrapper/minecraft/client/entity/EntityClientPlayerMP.h"
#include "util/xor.h"
#include "util/ClientStrings.h"

class KeepSprintModule final : public SharedThreadBaseModule<KeepSprintModule, ModuleType::KEEP_SPRINT, CategoryType::COMBAT> {
    float speed = 0.8f;
    int chance = 100;
    bool weaponsOnly = true;
    bool onlyOnBehind = false;
    int mode = 0;
    int hurtTimeThreshold = 10;

protected:
    void onUpdate(JniScope& scope) override;
    void registerEvents() override;

public:
    KeepSprintModule() = default;

    void onCleanup() override { clearInstanceBuffer(); }

    void onLoad() override {
        SharedThreadBaseModule::onLoad();

        COMBO_SETTING(mode, Strings::optDynamic(), Strings::optStatic());
        FLOAT_SLIDER(speed, 0.8f, 0.6f, 1.0f);
        INT_SLIDER(chance, 100, 0, 100);
        BOOL_SETTING_CONDITIONAL(weaponsOnly, true);
        BOOL_SETTING_CONDITIONAL(onlyOnBehind, false);
    }

private:
	mutable char instanceBuffer[64] = {0};

public:

    FORMAT_FLAGS("%s %.1f", (this->mode == 0 ? Strings::optDynamic() : Strings::optStatic()), this->speed)

private:
    void onAttackEntity(const AttackEntityEvent& event);
    static bool isTargetBehind(EntityClientPlayerMP& player, EntityLivingBase& target);
};
