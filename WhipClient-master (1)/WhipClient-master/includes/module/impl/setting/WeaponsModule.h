#pragma once

#include "../../base/SharedThreadBaseModule.h"
#include "../../ModuleType.h"
#include "../../../util/JniScope.h"
#include "util/ClientStrings.h"
#include "wrapper/minecraft/item/Item.h"

class WeaponsModule final : public SettingBaseModule<WeaponsModule, ModuleType::WEAPONS> {
    std::vector<bool> weapons;

public:
    WeaponsModule() = default;

    void onLoad() override {
        SettingBaseModule::onLoad();

        weapons = {true, false, false};
        updateSelections();

        MULTI_COMBO_SETTING_CALLBACK(weapons,  [this](const std::vector<bool>& selections) {
            updateSelections();
        }, Strings::itemSword(), Strings::itemBow(), Strings::itemAxe());
    }

    void updateSelections() const {
        Item::updateWeaponSelections(isSwordSelected(), isAxeSelected(), isBowSelected());
    }

    bool shouldShowInArraylist() const {
        return false;
    }

    bool enableOnLoad() const {
        return true;
    }

    bool isSwordSelected() const { return weapons.at(0); }
    bool isBowSelected() const { return weapons.at(1); }
    bool isAxeSelected() const { return weapons.at(2); }
};
